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
    let mut resp = Message::new();
    resp.set_id(req.id())
        .set_message_type(MessageType::Response)
        .set_op_code(req.op_code())
        .set_recursion_desired(req.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(rcode);
    for q in req.queries() {
        resp.add_query(q.clone());
    }
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

    if req.message_type() == MessageType::Query && req.op_code() == OpCode::Query && req.queries().len() == 1 {
        let q = &req.queries()[0];
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
        .and_then(|m| m.extensions().as_ref().map(|e| e.max_payload()))
        .map(|p| p.max(512) as usize)
        .unwrap_or(512);
    if resp.len() <= limit {
        return resp;
    }
    match Message::from_vec(&resp) {
        Ok(mut m) => {
            m.take_answers();
            m.take_name_servers();
            m.take_additionals();
            m.set_truncated(true);
            m.to_vec().unwrap_or(resp)
        }
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
