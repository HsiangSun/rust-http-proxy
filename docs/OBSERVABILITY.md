# 可观测：VictoriaMetrics 抓取 + Grafana Dashboard

适用拓扑：
- **rust-http-proxy** 跑在 EKS **集群外**的 EC2 上（Amazon Linux 2023）。
- **VictoriaMetrics（k8s-stack）** 跑在集群内，含 VMOperator + VMAgent。
- 由 **VMAgent 主动拉取** 代理的 `/metrics`。
- 用 `proxy_group` 标签区分多组代理（如 `sevenpay-proxy`）。

---

## 1. 让 VMAgent 抓取代理服务器

`VMScrapeConfig` CR 与 helm values 解耦管理，存放路径：
`k8s/victoriametrics/scrape-configs/`。每个文件一个抓取组。

VMOperator 监听整个集群的 `VMScrapeConfig`，无需 helm upgrade，
`kubectl apply` 即生效，回滚也只 `kubectl delete` 单个文件，
变更影响面与排查路径都更小。

示例文件 `rust-http-proxy-sevenpay.yaml`：

```yaml
apiVersion: operator.victoriametrics.com/v1beta1
kind: VMScrapeConfig
metadata:
  name: rust-http-proxy-sevenpay
  namespace: monitoring
  labels:
    app.kubernetes.io/name: rust-http-proxy
    proxy-group: sevenpay-proxy
spec:
  interval: 15s
  scrapeTimeout: 10s
  metricsPath: /metrics
  scheme: http
  staticConfigs:
    - targets:
        - 10.3.27.196:9090
        - 10.3.27.97:9090
      labels:
        proxy_group: sevenpay-proxy   # ← 业务组标签，Grafana 变量消费它
        job: rust-http-proxy
  relabelConfigs:
    - sourceLabels: [__address__]
      targetLabel: instance
    - sourceLabels: [__address__]
      regex: '([^:]+)(?::\d+)?'
      targetLabel: private_ip
      replacement: '$1'
```

应用 / 更新 / 撤回：

```bash
# 应用全部
kubectl apply -f scrape-configs/

# 单组
kubectl apply  -f scrape-configs/rust-http-proxy-sevenpay.yaml
kubectl delete -f scrape-configs/rust-http-proxy-sevenpay.yaml

# 查看
kubectl -n monitoring get vmscrapeconfig
```

### 验证抓取生效
```bash
# 1. 进 VMAgent UI 看 targets（或 kubectl port-forward）
kubectl -n monitoring port-forward svc/vmagent-<name> 8429:8429
# 浏览器打开 http://localhost:8429/targets
# 应能看到 rust-http-proxy-sevenpay 的 2 个 endpoint 状态为 UP

# 2. 在 VMSelect 上直接查
curl -G 'http://<vmselect>/select/0/prometheus/api/v1/query' \
  --data-urlencode 'query=proxy_requests_total{proxy_group="sevenpay-proxy"}'
```

### 添加新组
复制现有文件后改三处即可，互不影响：

```bash
cd scrape-configs/
cp rust-http-proxy-sevenpay.yaml rust-http-proxy-foopay.yaml
# 改: metadata.name、labels.proxy-group、spec.staticConfigs[].labels.proxy_group、targets
kubectl apply -f rust-http-proxy-foopay.yaml
```

### 安全建议
- 9090 端口建议仅对 **EKS 节点的 VPC 内网** 放行，云上用 Security Group 限制源 IP。
- 不要把 `/metrics` 直接暴露到公网。

---

## 2. 导入 Grafana Dashboard

文件：[`grafana-dashboard.json`](./grafana-dashboard.json)

### 导入步骤
1. Grafana 左侧 → **Dashboards → New → Import**
2. 上传 `grafana-dashboard.json`，或粘贴文件内容
3. 在 `DS_VM` 处选择你的 **VictoriaMetrics**（Prometheus 类型）数据源
4. 保存

### 顶部变量
| 变量 | 作用 | 来源 |
|------|------|------|
| `Datasource` | 选 VM 数据源 | Grafana 自带 |
| `Proxy Group` | 按业务组过滤（sevenpay-proxy / 其它组） | `label_values(proxy_requests_total, proxy_group)` |
| `Instance` | 按单台代理过滤 | `label_values(...{proxy_group=~"$proxy_group"}, instance)` |
| `Upstream Host` | 按上游域名过滤（影响"按 host" 面板） | `label_values(proxy_request_duration_by_host_seconds_count{...}, host)` |

三个过滤变量都支持 **多选 + All**，默认 All 即查看全部。

### 面板布局
| 区块 | 面板 |
|------|------|
| 总览 | QPS / 成功率 / 活跃连接 / HTTPS 隧道总数 |
| 流量与错误 | 按 status 堆叠的 QPS / 上下行字节速率 |
| 延迟 | 全局 P50/P95/P99 / 按 host 的 P99 |
| DNS / 上游建连 | DNS 缓存命中率 / 建连耗时分位 |
| 进程资源 | 每实例 CPU% / 每实例 RSS 内存 |
| 按 host 明细 | host × {QPS, P99, 错误率} 的表格（错误率有色阶） |

### 常用查询模板（自定义面板时可直接复制）

QPS（含分组过滤）：
```
sum(rate(proxy_requests_total{proxy_group=~"$proxy_group", instance=~"$instance"}[1m]))
```

按 host 的 P99：
```
histogram_quantile(
  0.99,
  sum by (host, le) (
    rate(proxy_request_duration_by_host_seconds_bucket{
      proxy_group=~"$proxy_group", instance=~"$instance", host=~"$host"
    }[5m])
  )
)
```

按 host 的 5xx + error 错误率：
```
sum by (host) (rate(proxy_request_duration_by_host_seconds_count{
  proxy_group=~"$proxy_group", instance=~"$instance", host=~"$host", status=~"5xx|error"
}[5m]))
/
sum by (host) (rate(proxy_request_duration_by_host_seconds_count{
  proxy_group=~"$proxy_group", instance=~"$instance", host=~"$host"
}[5m]))
```

---

## 3. 把代理日志 push 到 OpenObserve

代理通过 HTTP `POST /api/{org}/{stream}/_json` 主动推日志。当代理跑在
**集群外** 而 OpenObserve 跑在集群内时，需要把 router 经 **Internal NLB**
暴露给 VPC。

### 3.1 在集群内创建 Internal NLB Service

文件：`k8s/openobserve/router-internal-nlb.yaml`

```yaml
apiVersion: v1
kind: Service
metadata:
  name: o2-openobserve-router-internal
  namespace: openobserve
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
    service.beta.kubernetes.io/aws-load-balancer-scheme: internal
spec:
  type: LoadBalancer
  selector:
    app.kubernetes.io/instance: o2
    app.kubernetes.io/name: openobserve
    role: router
  ports:
    - name: http
      port: 5080
      protocol: TCP
      targetPort: http
```

```bash
kubectl apply -f k8s/openobserve/router-internal-nlb.yaml

# 等 NLB 起来（约 2-3 分钟），拿到内网 hostname
kubectl -n openobserve get svc o2-openobserve-router-internal \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
# 形如: internal-k8s-openobserv-xxxx-xxxx.elb.us-west-2.amazonaws.com
```

### 3.2 在代理服务器上启用上报

编辑 `/opt/rust-http-proxy/config.toml` 的 `[openobserve]` 段：

```toml
[openobserve]
enabled = true
endpoint = "http://internal-k8s-openobserv-xxxx.elb.us-west-2.amazonaws.com:5080"
organization = "default"
stream = "proxy_logs"
username = "<OO 登录邮箱>"
password = "<OO 登录密码>"
proxy_group = "sevenpay-proxy"   # 与 VMScrapeConfig 中保持一致
```

或通过环境变量在 systemd unit 里覆盖（避免密码进配置文件 + git）：

```ini
# /etc/systemd/system/rust-http-proxy.service [Service] 段加：
Environment=OO_ENABLED=true
Environment=OO_ENDPOINT=http://internal-k8s-...elb.amazonaws.com:5080
Environment=OO_USERNAME=root@example.com
Environment=OO_PASSWORD=********
Environment=OO_PROXY_GROUP=sevenpay-proxy
```

重启：

```bash
sudo systemctl daemon-reload
sudo systemctl restart rust-http-proxy
journalctl -u rust-http-proxy -f | head -5
# 启动日志应不再有 "OpenObserve 未启用..." 字样
```

### 3.3 验证 OpenObserve 收到日志

OpenObserve UI → Logs → Stream 选 `proxy_logs` → 时间窗 last 5 min →
应能看到代理的 `proxy.request` / `proxy.connect` 事件，过滤条件加：

```
proxy_group='sevenpay-proxy'
```

### 3.4 安全建议
- NLB 必须用 `scheme: internal`，**绝不要 internet-facing**。
- 在 OpenObserve 给代理建一个专用账号（最小权限：仅指定 stream 的写权限），
  比直接用 root 凭证更安全。
- 走 Secret 而非明文环境变量；systemd 支持 `EnvironmentFile=/etc/rust-http-proxy/secrets.env`。

---

## 4. 排错速查

| 现象 | 排查 |
|------|------|
| Dashboard 全部 No data | 数据源没选对；或 VMAgent target 抓不通 |
| `proxy_group` 变量空 | 看 VMAgent /targets 是否 UP；relabel 是否生效 |
| QPS 是 0，但代理日志显示有流量 | 抓取间隔 15s × 5min 滑窗，新启动后等 1 分钟再看 |
| 错误率列报 NaN | 该 host 在窗口内无请求，是分母为 0 的预期表现 |
