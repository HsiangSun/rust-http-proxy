//! 请求体 / 响应体处理：让单个请求占用的内存与 body 大小无关。
//!
//! - 请求体：总长不超过上限时整体缓冲（用于从 JSON 中提取 `dis_order_no`），
//!   超过则把已读部分与剩余部分串成流式请求体（[`buffer_or_stream`]）；
//! - 响应体：上游响应流式转发给客户端，不再整体读入内存（[`ResponseBody`]），
//!   同时统计下行字节、施加空闲超时，并在结束时回调一次；
//! - 超时按"空闲"计算（[`Activity`] / [`idle_timeout`]）：只要持续有数据流动，
//!   大文件上传 / 下载就不会被误杀；停滞超过 `io_timeout` 才中断。

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};
use prometheus::IntCounter;
use tokio::time::{Instant, Sleep};

/// 代理内部统一的错误类型。
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// 代理内部统一的请求 / 响应体类型。
pub type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

/// 由完整字节构造 body。
pub fn full(bytes: impl Into<Bytes>) -> ProxyBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// 一次请求的上行数据流动记录：最近一次有数据的时间与累计字节数，
/// 供 [`idle_timeout`] 与访问日志使用。克隆后共享同一份状态。
#[derive(Clone)]
pub struct Activity {
    inner: Arc<ActivityInner>,
}

struct ActivityInner {
    start: Instant,
    /// 最近一次数据流动距 `start` 的毫秒数。
    last_ms: AtomicU64,
    bytes: AtomicU64,
    /// 实时累加的全局计数器（`proxy_bytes_up_total`）。
    counter: IntCounter,
}

impl Activity {
    pub fn new(counter: IntCounter) -> Self {
        Self {
            inner: Arc::new(ActivityInner {
                start: Instant::now(),
                last_ms: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                counter,
            }),
        }
    }

    fn record(&self, len: usize) {
        let i = &self.inner;
        i.last_ms
            .store(i.start.elapsed().as_millis() as u64, Ordering::Relaxed);
        i.bytes.fetch_add(len as u64, Ordering::Relaxed);
        i.counter.inc_by(len as u64);
    }

    /// 已经流过的上行字节数。
    pub fn bytes(&self) -> u64 {
        self.inner.bytes.load(Ordering::Relaxed)
    }

    fn last(&self) -> Instant {
        self.inner.start + Duration::from_millis(self.inner.last_ms.load(Ordering::Relaxed))
    }
}

/// 运行 `fut`；超过 `idle` 没有任何数据流动（见 [`Activity`]）就放弃并返回 `None`。
///
/// 与固定总时长的超时不同，只要请求体还在持续上传，就不会被中断；请求体
/// 结束后，"空闲"即为等待上游响应头的时间。
pub async fn idle_timeout<F: Future>(
    idle: Duration,
    activity: &Activity,
    fut: F,
) -> Option<F::Output> {
    tokio::pin!(fut);
    loop {
        let deadline = activity.last() + idle;
        tokio::select! {
            out = &mut fut => return Some(out),
            _ = tokio::time::sleep_until(deadline) => {
                if activity.last() + idle <= Instant::now() {
                    return None;
                }
            }
        }
    }
}

/// 客户端请求体的两种转发方式。
pub enum RequestBody {
    /// 不超过上限，已整体读入内存。
    Buffered(Bytes),
    /// 超过上限：已读部分 + 剩余部分组成的流式请求体。
    Streaming(ProxyBody),
}

/// 读取请求体：总长不超过 `limit` 时整体缓冲；一旦超过就停止缓冲，把已读部分
/// 与剩余部分串成流式请求体返回，内存占用约为 `limit`。每个帧都记入 `activity`。
///
/// 缓冲路径与原先的 `collect().to_bytes()` 一致：只保留数据帧，丢弃 trailers；
/// 流式路径原样透传全部帧。
pub async fn buffer_or_stream<B>(
    mut body: B,
    limit: usize,
    activity: &Activity,
) -> Result<RequestBody, BoxError>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<BoxError>,
{
    let mut chunks = VecDeque::new();
    let mut total = 0usize;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(Into::into)?;
        activity.record(frame.data_ref().map_or(0, Bytes::len));
        let Ok(data) = frame.into_data() else {
            continue;
        };
        total += data.len();
        chunks.push_back(data);
        if total > limit {
            let streaming = PrefixedBody {
                prefix: chunks,
                rest: body,
                activity: activity.clone(),
            };
            return Ok(RequestBody::Streaming(streaming.boxed_unsync()));
        }
    }
    Ok(RequestBody::Buffered(concat(chunks, total)))
}

fn concat(mut chunks: VecDeque<Bytes>, total: usize) -> Bytes {
    if chunks.len() == 1 {
        if let Some(only) = chunks.pop_front() {
            return only;
        }
    }
    let mut buf = BytesMut::with_capacity(total);
    for chunk in chunks {
        buf.extend_from_slice(&chunk);
    }
    buf.freeze()
}

/// 先吐出已缓冲的前缀，再透传剩余请求体；剩余部分的每个帧都记入 `activity`。
struct PrefixedBody<B> {
    prefix: VecDeque<Bytes>,
    rest: B,
    activity: Activity,
}

impl<B> Body for PrefixedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Some(chunk) = self.prefix.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        match Pin::new(&mut self.rest).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                self.activity.record(frame.data_ref().map_or(0, Bytes::len));
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.is_empty() && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let prefix: u64 = self.prefix.iter().map(|b| b.len() as u64).sum();
        let rest = self.rest.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(rest.lower() + prefix);
        if let Some(upper) = rest.upper() {
            hint.set_upper(upper + prefix);
        }
        hint
    }
}

/// 结束回调：`(已转发字节数, 错误)`，错误为 `None` 表示正常读完。
type OnFinish = Box<dyn FnOnce(u64, Option<String>) + Send>;

/// 上游响应体：流式转发给客户端，并
/// - 每个帧把字节数累加到 `counter`（`proxy_bytes_down_total`）；
/// - 等待上游数据超过 `idle` 时以错误结束，避免停滞的上游一直占着连接；
/// - 结束时（读完、出错、超时或客户端提前断开）调用一次 `on_finish`。
pub struct ResponseBody<B: Body> {
    inner: B,
    idle: Duration,
    sleep: Pin<Box<Sleep>>,
    /// 是否正在等待上游数据。空闲计时只在等待上游时进行，客户端读得慢
    /// （背压，hyper 暂不 poll）不算上游空闲。
    waiting: bool,
    bytes: u64,
    counter: IntCounter,
    on_finish: Option<OnFinish>,
}

impl<B: Body> ResponseBody<B> {
    pub fn new(
        inner: B,
        idle: Duration,
        counter: IntCounter,
        on_finish: impl FnOnce(u64, Option<String>) + Send + 'static,
    ) -> Self {
        Self {
            inner,
            idle,
            sleep: Box::pin(tokio::time::sleep(idle)),
            waiting: false,
            bytes: 0,
            counter,
            on_finish: Some(Box::new(on_finish)),
        }
    }

    fn finish(&mut self, error: Option<String>) {
        if let Some(f) = self.on_finish.take() {
            f(self.bytes, error);
        }
    }
}

impl<B> Body for ResponseBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.waiting = false;
                if let Some(data) = frame.data_ref() {
                    this.bytes += data.len() as u64;
                    this.counter.inc_by(data.len() as u64);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                let e: BoxError = e.into();
                this.finish(Some(e.to_string()));
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.finish(None);
                Poll::Ready(None)
            }
            Poll::Pending => {
                if !this.waiting {
                    this.waiting = true;
                    let deadline = Instant::now() + this.idle;
                    this.sleep.as_mut().reset(deadline);
                }
                if this.sleep.as_mut().poll(cx).is_ready() {
                    let msg = format!("上游响应体空闲超过 {:?}", this.idle);
                    this.finish(Some(msg.clone()));
                    return Poll::Ready(Some(Err(msg.into())));
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B: Body> Drop for ResponseBody<B> {
    fn drop(&mut self) {
        // 没走到流结尾就被丢弃：要么本来就没有响应体（HEAD / 204 / 304 等，
        // hyper 不会 poll），要么客户端提前断开。
        if self.on_finish.is_some() {
            let error = (!self.inner.is_end_stream()).then(|| "客户端提前断开".to_string());
            self.finish(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use http_body_util::StreamBody;
    use std::sync::Mutex;

    type TestFrame = Result<Frame<Bytes>, std::io::Error>;

    fn chunks(parts: &[&'static str]) -> Vec<TestFrame> {
        parts
            .iter()
            .map(|p| Ok(Frame::data(Bytes::from(*p))))
            .collect()
    }

    fn body_of(
        parts: &[&'static str],
    ) -> StreamBody<futures::stream::Iter<std::vec::IntoIter<TestFrame>>> {
        StreamBody::new(futures::stream::iter(chunks(parts)))
    }

    fn counter() -> IntCounter {
        IntCounter::new("test_bytes", "test").unwrap()
    }

    type Finished = Arc<Mutex<Vec<(u64, Option<String>)>>>;

    fn recorder() -> (Finished, impl FnOnce(u64, Option<String>) + Send + 'static) {
        let calls: Finished = Arc::default();
        let sink = calls.clone();
        (calls, move |bytes, err| {
            sink.lock().unwrap().push((bytes, err))
        })
    }

    #[tokio::test]
    async fn buffers_small_bodies() {
        let activity = Activity::new(counter());
        match buffer_or_stream(body_of(&["ab", "cd", "e"]), 16, &activity)
            .await
            .unwrap()
        {
            RequestBody::Buffered(b) => assert_eq!(b, Bytes::from("abcde")),
            RequestBody::Streaming(_) => panic!("5 字节不应走流式"),
        }
        assert_eq!(activity.bytes(), 5);
        assert_eq!(activity.inner.counter.get(), 5);
    }

    #[tokio::test]
    async fn streams_large_bodies_without_losing_data() {
        let activity = Activity::new(counter());
        let body = body_of(&["0123", "4567", "89", "ab", "cdef"]);
        let RequestBody::Streaming(streaming) = buffer_or_stream(body, 6, &activity).await.unwrap()
        else {
            panic!("超过上限应转为流式");
        };
        // 只缓冲了超限前的两个块。
        assert_eq!(activity.bytes(), 8);
        let all = streaming.collect().await.unwrap().to_bytes();
        assert_eq!(all, Bytes::from("0123456789abcdef"));
        assert_eq!(activity.bytes(), 16, "流式部分同样计入上行字节");
    }

    #[tokio::test]
    async fn response_body_counts_and_finishes_once() {
        let (calls, on_finish) = recorder();
        let c = counter();
        let body = ResponseBody::new(
            body_of(&["hello", " ", "world"]),
            Duration::from_secs(5),
            c.clone(),
            on_finish,
        );
        let all = body.collect().await.unwrap().to_bytes();
        assert_eq!(all, Bytes::from("hello world"));
        assert_eq!(c.get(), 11);
        assert_eq!(*calls.lock().unwrap(), vec![(11, None)]);
    }

    #[tokio::test]
    async fn response_body_times_out_when_upstream_stalls() {
        let (calls, on_finish) = recorder();
        let stalled = StreamBody::new(
            futures::stream::iter(chunks(&["partial"])).chain(futures::stream::pending()),
        );
        let body = ResponseBody::new(stalled, Duration::from_millis(50), counter(), on_finish);
        let started = Instant::now();
        assert!(body.collect().await.is_err());
        assert!(started.elapsed() >= Duration::from_millis(50));
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 7);
        assert!(calls[0].1.as_deref().unwrap().contains("空闲"));
    }

    #[tokio::test]
    async fn response_body_reports_client_abort_on_drop() {
        let (calls, on_finish) = recorder();
        let open = StreamBody::new(
            futures::stream::iter(chunks(&["abc"])).chain(futures::stream::pending()),
        );
        let mut body = ResponseBody::new(open, Duration::from_secs(5), counter(), on_finish);
        assert!(body.frame().await.is_some());
        drop(body);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 3);
        assert!(calls[0].1.is_some());
    }

    #[tokio::test]
    async fn empty_response_body_reports_completion_on_drop() {
        let (calls, on_finish) = recorder();
        drop(ResponseBody::new(
            Full::new(Bytes::new()),
            Duration::from_secs(5),
            counter(),
            on_finish,
        ));
        assert_eq!(*calls.lock().unwrap(), vec![(0, None)]);
    }

    #[tokio::test]
    async fn idle_timeout_extends_while_data_flows() {
        let activity = Activity::new(counter());
        let feeder = activity.clone();
        // 每 20ms 有一次数据，总共 200ms；空闲阈值 80ms，不应超时。
        let busy = async move {
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                feeder.record(1);
            }
        };
        assert!(idle_timeout(Duration::from_millis(80), &activity, busy)
            .await
            .is_some());

        // 没有任何数据流动：80ms 后超时。
        let stuck = tokio::time::sleep(Duration::from_secs(5));
        let started = Instant::now();
        assert!(
            idle_timeout(Duration::from_millis(80), &Activity::new(counter()), stuck)
                .await
                .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
