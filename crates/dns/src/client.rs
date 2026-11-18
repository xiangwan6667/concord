use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use concord_config::dns::Upstream;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::dialer::Cx;
use crate::msg;

pub(crate) const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type BoxIo = Box<dyn Io>;

#[async_trait]
pub(crate) trait Client: Send + Sync {
    async fn exchange(&self, req: &Message, cx: Cx) -> io::Result<Message>;

    fn address(&self) -> String;

    fn reset(&self) {}

    fn is_rcode(&self) -> bool {
        false
    }
}

pub(crate) type ClientRef = Arc<dyn Client>;

const TIMED_OUT: &str = "dns exchange timed out";

pub(crate) fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, TIMED_OUT)
}

pub(crate) async fn with_timeout<T>(fut: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    concord_common::timeout::with_timeout(EXCHANGE_TIMEOUT, fut, TIMED_OUT).await
}

pub(crate) fn with_random_id(req: &Message) -> Message {
    let mut copy = req.clone();
    copy.metadata.id = rand::random();
    copy
}

pub(crate) fn decode(bytes: &[u8]) -> io::Result<Message> {
    Message::from_vec(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

pub(crate) fn encode(msg: &Message) -> io::Result<Vec<u8>> {
    msg.to_vec()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
}

/// A response to this request: a response message that repeats the question. Servers
/// that refuse or fail a query may leave the question out.
pub(crate) fn is_answer_to(req: &Message, resp: &Message) -> bool {
    if resp.metadata.message_type != MessageType::Response {
        return false;
    }
    match (req.queries.as_slice(), resp.queries.as_slice()) {
        ([asked], [echoed]) => {
            asked.name == echoed.name
                && asked.query_type == echoed.query_type
                && asked.query_class == echoed.query_class
        }
        (_, []) => matches!(
            resp.metadata.response_code,
            ResponseCode::FormErr
                | ResponseCode::NotImp
                | ResponseCode::ServFail
                | ResponseCode::Refused
        ),
        _ => false,
    }
}

pub(crate) fn checked(req: &Message, resp: Message) -> io::Result<Message> {
    if is_answer_to(req, &resp) {
        Ok(resp)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns response does not match its query",
        ))
    }
}

/// One framed message over a stream: a two byte length, then the message.
pub(crate) async fn exchange_framed<S>(io: &mut S, req: &Message) -> io::Result<Message>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let bytes = encode(req)?;
    let len = u16::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dns query too large"))?;
    let mut frame = Vec::with_capacity(bytes.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&bytes);
    io.write_all(&frame).await?;
    io.flush().await?;
    loop {
        let mut head = [0u8; 2];
        io.read_exact(&mut head).await?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(head))];
        io.read_exact(&mut body).await?;
        let resp = decode(&body)?;
        if resp.metadata.id == req.metadata.id && is_answer_to(req, &resp) {
            return Ok(resp);
        }
    }
}

pub(crate) struct RcodeClient {
    rcode: hickory_proto::op::ResponseCode,
    address: String,
}

impl RcodeClient {
    pub(crate) fn new(rcode: hickory_proto::op::ResponseCode, name: &str) -> Self {
        RcodeClient {
            rcode,
            address: format!("rcode://{name}"),
        }
    }
}

#[async_trait]
impl Client for RcodeClient {
    async fn exchange(&self, req: &Message, _cx: Cx) -> io::Result<Message> {
        let mut resp = req.clone();
        resp.metadata.message_type = hickory_proto::op::MessageType::Response;
        resp.metadata.response_code = self.rcode;
        Ok(resp)
    }

    fn address(&self) -> String {
        self.address.clone()
    }

    fn is_rcode(&self) -> bool {
        true
    }
}

/// `disable-ipv4`, `disable-ipv6` and `disable-qtype-N`: such a question gets
/// an empty answer without leaving, and such records are cut from an answer.
pub(crate) struct DisableTypes {
    inner: ClientRef,
    types: HashSet<u16>,
}

impl DisableTypes {
    pub(crate) fn wrap(inner: ClientRef, params: &Params<'_>) -> ClientRef {
        let mut types = HashSet::new();
        if params.is_true("disable-ipv4") {
            types.insert(u16::from(RecordType::A));
        }
        if params.is_true("disable-ipv6") {
            types.insert(u16::from(RecordType::AAAA));
        }
        for (key, value) in params.iter() {
            let Some(code) = key.strip_prefix("disable-qtype-") else {
                continue;
            };
            if value != "true" {
                continue;
            }
            if let Ok(code) = code.parse::<u16>()
                && !matches!(RecordType::from(code), RecordType::Unknown(_))
            {
                types.insert(code);
            }
        }
        if types.is_empty() {
            inner
        } else {
            Arc::new(DisableTypes { inner, types })
        }
    }
}

#[async_trait]
impl Client for DisableTypes {
    async fn exchange(&self, req: &Message, cx: Cx) -> io::Result<Message> {
        if req
            .queries
            .iter()
            .any(|query| self.types.contains(&u16::from(query.query_type)))
        {
            return Ok(msg::empty_answer(req));
        }
        let mut resp = self.inner.exchange(req, cx).await?;
        let drop = |records: &mut Vec<hickory_proto::rr::Record>| {
            records.retain(|record| !self.types.contains(&u16::from(record.record_type())));
        };
        drop(&mut resp.answers);
        drop(&mut resp.authorities);
        drop(&mut resp.additionals);
        Ok(resp)
    }

    fn address(&self) -> String {
        self.inner.address()
    }

    fn reset(&self) {
        self.inner.reset();
    }
}

pub(crate) struct EcsClient {
    inner: ClientRef,
    addr: IpAddr,
    bits: u8,
    overwrite: bool,
}

impl EcsClient {
    pub(crate) fn wrap(inner: ClientRef, params: &Params<'_>) -> ClientRef {
        let Some(text) = params.get("ecs").filter(|text| !text.is_empty()) else {
            return inner;
        };
        let parsed = match text.split_once('/') {
            Some((addr, bits)) => addr
                .parse::<IpAddr>()
                .ok()
                .zip(bits.parse::<u8>().ok())
                .filter(|(addr, bits)| *bits <= if addr.is_ipv4() { 32 } else { 128 }),
            None => text
                .parse::<IpAddr>()
                .ok()
                .map(|addr| (addr, if addr.is_ipv4() { 32 } else { 128 })),
        };
        let Some((addr, bits)) = parsed else {
            tracing::warn!("DNS [{}] config with invalid ecs: {text}", inner.address());
            return inner;
        };
        Arc::new(EcsClient {
            inner,
            addr,
            bits,
            overwrite: params.is_true("ecs-override"),
        })
    }
}

#[async_trait]
impl Client for EcsClient {
    async fn exchange(&self, req: &Message, cx: Cx) -> io::Result<Message> {
        let mut req = req.clone();
        let edns = req.edns.get_or_insert_with(Default::default);
        let present = edns.option(EdnsCode::Subnet).is_some();
        if !present || self.overwrite {
            edns.options_mut().remove(EdnsCode::Subnet);
            edns.options_mut()
                .insert(EdnsOption::Subnet(ClientSubnet::new(
                    self.addr, self.bits, 0,
                )));
        }
        self.inner.exchange(&req, cx).await
    }

    fn address(&self) -> String {
        self.inner.address()
    }

    fn reset(&self) {
        self.inner.reset();
    }
}

pub(crate) struct Params<'a>(pub &'a Upstream);

impl<'a> Params<'a> {
    pub(crate) fn get(&self, key: &str) -> Option<&'a str> {
        self.0.params.get(key).map(String::as_str)
    }

    pub(crate) fn is_true(&self, key: &str) -> bool {
        self.get(key) == Some("true")
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> + use<'a> {
        self.0.params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::OpCode;
    use hickory_proto::rr::RecordType;
    use tokio::io::duplex;

    use super::*;

    fn reply(req: &Message) -> Message {
        msg::empty_answer(req)
    }

    #[test]
    fn a_response_must_repeat_the_question_whatever_the_name_case() {
        let req = msg::build_query("Example.Test", RecordType::A).unwrap();
        assert!(is_answer_to(&req, &reply(&req)));

        let mut lower = reply(&req);
        lower.queries = msg::build_query("example.test", RecordType::A)
            .unwrap()
            .queries;
        assert!(is_answer_to(&req, &lower));

        let mut other_name = reply(&req);
        other_name.queries = msg::build_query("other.test", RecordType::A)
            .unwrap()
            .queries;
        assert!(!is_answer_to(&req, &other_name));

        let mut other_type = reply(&req);
        other_type.queries = msg::build_query("example.test", RecordType::AAAA)
            .unwrap()
            .queries;
        assert!(!is_answer_to(&req, &other_type));

        let mut other_class = reply(&req);
        other_class.queries[0].query_class = hickory_proto::rr::DNSClass::CH;
        assert!(!is_answer_to(&req, &other_class));

        let mut query = reply(&req);
        query.metadata.message_type = MessageType::Query;
        assert!(!is_answer_to(&req, &query));
    }

    #[test]
    fn an_answer_without_a_question_is_only_accepted_as_a_refusal_of_the_query() {
        let req = msg::build_query("example.test", RecordType::A).unwrap();
        let mut bare = Message::response(req.metadata.id, OpCode::Query);
        assert!(!is_answer_to(&req, &bare));
        bare.metadata.response_code = ResponseCode::FormErr;
        assert!(is_answer_to(&req, &bare));
    }

    #[tokio::test]
    async fn a_stream_skips_a_response_to_another_question() {
        let req = msg::build_query("example.test", RecordType::A).unwrap();
        let mut stray = reply(&req);
        stray.queries = msg::build_query("other.test", RecordType::A)
            .unwrap()
            .queries;
        let (mut client, mut server) = duplex(4096);
        let sent = req.clone();
        let task = tokio::spawn(async move { exchange_framed(&mut client, &sent).await });
        let mut head = [0u8; 2];
        server.read_exact(&mut head).await.unwrap();
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(head))];
        server.read_exact(&mut body).await.unwrap();
        for resp in [&stray, &reply(&req)] {
            let bytes = encode(resp).unwrap();
            server
                .write_all(&(bytes.len() as u16).to_be_bytes())
                .await
                .unwrap();
            server.write_all(&bytes).await.unwrap();
        }
        let got = task.await.unwrap().unwrap();
        assert_eq!(got.queries, req.queries);
    }
}
