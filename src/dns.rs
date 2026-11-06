use crate::{rules::Matcher, upstream::Upstream};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata::{A, AAAA}, RData, Record, RecordType};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::{atomic::{AtomicU64, Ordering::Relaxed}, Arc, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use tracing::{debug, warn};

const BLOCK_TTL: u32 = 300;

pub struct State {
    matcher: RwLock<Arc<Matcher>>,
    upstream: Upstream,
    pub total: AtomicU64,
    pub blocked: AtomicU64,
}

impl State {
    pub fn new(matcher: Matcher, upstream: Upstream) -> Self {
        Self { matcher: RwLock::new(Arc::new(matcher)), upstream, total: AtomicU64::new(0), blocked: AtomicU64::new(0) }
    }
    pub fn set_matcher(&self, m: Matcher) {
        *self.matcher.write().unwrap() = Arc::new(m);
    }
    pub fn rule_count(&self) -> usize {
        self.matcher().len()
    }
    fn matcher(&self) -> Arc<Matcher> {
        self.matcher.read().unwrap().clone()
    }
}

fn base_response(req: &Message, rcode: ResponseCode) -> Message {
    let mut resp = Message::error_msg(req.id, req.op_code, rcode);
    resp.metadata.recursion_desired = req.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.add_queries(req.queries.iter().cloned());
    resp
}

fn blocked_response(req: &Message, q: &Query) -> Option<Vec<u8>> {
    let mut resp = base_response(req, ResponseCode::NoError);
    match q.query_type() {
        RecordType::A => {
            resp.add_answer(Record::from_rdata(q.name().clone(), BLOCK_TTL, RData::A(A(Ipv4Addr::UNSPECIFIED))));
        }
        RecordType::AAAA => {
            resp.add_answer(Record::from_rdata(q.name().clone(), BLOCK_TTL, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))));
        }
        // HTTPS/SVCB and everything else: NOERROR with an empty answer (NODATA)
        _ => {}
    }
    resp.to_vec().ok()
}

/// Core logic shared by UDP and TCP: block locally or forward upstream.
async fn handle(packet: &[u8], state: &State) -> Option<Vec<u8>> {
    let req = Message::from_vec(packet).ok()?;
    state.total.fetch_add(1, Relaxed);

    if req.message_type == MessageType::Query && req.op_code == OpCode::Query && req.queries.len() == 1 {
        let q = &req.queries[0];
        let name = q.name().to_ascii().trim_end_matches('.').to_ascii_lowercase();

        // Tells Firefox not to bypass us with its built-in DoH.
        if name == "use-application-dns.net" {
            return base_response(&req, ResponseCode::NXDomain).to_vec().ok();
        }
        if state.matcher().is_blocked(&name) {
            state.blocked.fetch_add(1, Relaxed);
            debug!(%name, "blocked");
            return blocked_response(&req, q);
        }
    }

    match state.upstream.resolve(packet).await {
        Ok(r) => Some(r),
        Err(e) => {
            debug!(error = %e, "upstream failure");
            base_response(&req, ResponseCode::ServFail).to_vec().ok()
        }
    }
}

/// Large DoH answers can exceed what a UDP client accepts; set TC so it retries over TCP.
fn fit_udp(req: &[u8], resp: Vec<u8>) -> Vec<u8> {
    if resp.len() <= 512 {
        return resp;
    }
    let limit = Message::from_vec(req)
        .ok()
        .and_then(|m| m.edns.as_ref().map(|e| e.max_payload()))
        .map(|p| p.max(512) as usize)
        .unwrap_or(512);
    if resp.len() <= limit {
        return resp;
    }
    match Message::from_vec(&resp) {
        Ok(m) => m.truncate().to_vec().unwrap_or(resp),
        Err(_) => resp,
    }
}

pub async fn serve_udp(sock: UdpSocket, state: Arc<State>) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            // Windows reports ICMP "port unreachable" from earlier replies as a recv error; harmless.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(e) => {
                warn!(error = %e, "UDP receive error");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let pkt = buf[..n].to_vec();
        let sock = sock.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Some(resp) = handle(&pkt, &state).await {
                let resp = fit_udp(&pkt, resp);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
    }
}

pub async fn serve_tcp(listener: TcpListener, state: Arc<State>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = state.clone();
                tokio::spawn(tcp_conn(stream, state));
            }
            Err(e) => {
                warn!(error = %e, "TCP accept error");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn tcp_conn(mut s: TcpStream, state: Arc<State>) {
    loop {
        let mut len = [0u8; 2];
        match timeout(Duration::from_secs(10), s.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let n = u16::from_be_bytes(len) as usize;
        if n == 0 { return; }
        let mut buf = vec![0u8; n];
        match timeout(Duration::from_secs(5), s.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let Some(resp) = handle(&buf, &state).await else { return };
        let mut out = (resp.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&resp);
        if s.write_all(&out).await.is_err() { return; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use hickory_proto::rr::Name;

    fn query(name: &str, t: RecordType) -> Message {
        let mut m = Message::query();
        m.metadata.id = 0x1234;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_str(name).unwrap(), t));
        m
    }

    #[test]
    fn blocked_a_roundtrip() {
        let req = query("ads.example.com.", RecordType::A);
        let bytes = blocked_response(&req, &req.queries[0]).unwrap();
        let r = Message::from_vec(&bytes).unwrap();
        assert_eq!(r.id, 0x1234);
        assert_eq!(r.message_type, MessageType::Response);
        assert!(r.recursion_desired && r.recursion_available);
        assert_eq!(r.response_code, ResponseCode::NoError);
        assert_eq!(r.queries.len(), 1);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn blocked_aaaa_and_https() {
        let req = query("ads.example.com.", RecordType::AAAA);
        let r = Message::from_vec(&blocked_response(&req, &req.queries[0]).unwrap()).unwrap();
        assert_eq!(r.answers[0].data, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
        let req = query("ads.example.com.", RecordType::HTTPS);
        let r = Message::from_vec(&blocked_response(&req, &req.queries[0]).unwrap()).unwrap();
        assert!(r.answers.is_empty());
        assert_eq!(r.response_code, ResponseCode::NoError);
    }

    #[test]
    fn servfail_keeps_id_and_question() {
        let req = query("example.com.", RecordType::A);
        let r = Message::from_vec(&base_response(&req, ResponseCode::ServFail).to_vec().unwrap()).unwrap();
        assert_eq!(r.id, 0x1234);
        assert_eq!(r.response_code, ResponseCode::ServFail);
        assert_eq!(r.queries.len(), 1);
    }

    #[test]
    fn fit_udp_truncates_oversized() {
        let req = query("big.example.com.", RecordType::A);
        let mut resp = base_response(&req, ResponseCode::NoError);
        for i in 0..100u8 {
            resp.add_answer(Record::from_rdata(req.queries[0].name().clone(), 60, RData::A(A(Ipv4Addr::new(10, 0, 0, i)))));
        }
        let wire = resp.to_vec().unwrap();
        assert!(wire.len() > 512);
        let out = fit_udp(&req.to_vec().unwrap(), wire);
        assert!(out.len() <= 512);
        let r = Message::from_vec(&out).unwrap();
        assert!(r.truncation);
        assert_eq!(r.id, 0x1234);
        assert!(r.answers.is_empty());
        assert_eq!(r.queries.len(), 1);
    }

    #[test]
    fn name_string_used_by_blocklist_match() {
        let q = query("ADS.Example.COM.", RecordType::A);
        assert_eq!(q.queries[0].name().to_ascii().trim_end_matches('.').to_ascii_lowercase(), "ads.example.com");
    }
}