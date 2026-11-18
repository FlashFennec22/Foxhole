//! In-memory cache of upstream answers, capped by size. Nothing is written to disk, so it
//! starts empty every time the service starts.
//!
//! Only forwarded answers are cached: blocked names are answered before the cache is checked,
//! so a blocklist update takes effect at once without flushing anything.

use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{atomic::{AtomicU64, Ordering::Relaxed}, Mutex},
    time::{Duration, Instant},
};

/// Total memory budget for cached answers, including bookkeeping.
pub const DEFAULT_CAPACITY: usize = 2 * 1024 * 1024;
/// Upper limit on how long a positive answer is kept, whatever its TTL says.
const MAX_TTL: u32 = 86_400;
/// Upper limit for "no such name" / "no such record" answers (RFC 2308 suggests 1-3 hours).
const MAX_NEGATIVE_TTL: u32 = 3_600;
/// Rough per-entry cost of the maps and structs, on top of the name and the answer bytes.
const ENTRY_OVERHEAD: usize = 128;

/// What an answer depends on: the question, plus the DNSSEC bits that change what upstream returns.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Key {
    /// Lowercase, without the trailing dot (as used for blocklist matching).
    name: String,
    qtype: u16,
    qclass: u16,
    dnssec_ok: bool,
    checking_disabled: bool,
}

impl Key {
    /// `name` must already be lowercased; `req` must hold exactly one query.
    pub fn new(req: &Message, name: &str) -> Self {
        let q = &req.queries[0];
        Self {
            name: name.to_owned(),
            qtype: q.query_type().into(),
            qclass: q.query_class().into(),
            dnssec_ok: req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
            checking_disabled: req.checking_disabled,
        }
    }

    fn cost(&self, wire_len: usize) -> usize {
        // The name is stored twice: once in the map, once in the LRU index.
        2 * self.name.len() + wire_len + ENTRY_OVERHEAD
    }
}

struct Entry {
    wire: Vec<u8>,
    stored: Instant,
    expires: Instant,
    /// Position in `Inner::lru`.
    tick: u64,
}

#[derive(Default)]
struct Inner {
    map: HashMap<Key, Entry>,
    /// Least recently used first.
    lru: BTreeMap<u64, Key>,
    next_tick: u64,
    bytes: usize,
}

impl Inner {
    fn remove(&mut self, key: &Key) {
        if let Some(e) = self.map.remove(key) {
            self.lru.remove(&e.tick);
            self.bytes -= key.cost(e.wire.len());
        }
    }

    fn tick(&mut self) -> u64 {
        self.next_tick += 1;
        self.next_tick
    }
}

pub struct Cache {
    inner: Mutex<Inner>,
    capacity: usize,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl Cache {
    pub fn new(capacity: usize) -> Self {
        Self { inner: Mutex::default(), capacity, hits: AtomicU64::new(0), misses: AtomicU64::new(0) }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().map.len()
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.map.clear();
        inner.lru.clear();
        inner.bytes = 0;
    }

    /// A ready-to-send answer to `req`, if one is cached and still fresh.
    pub fn get(&self, key: &Key, req: &Message) -> Option<Vec<u8>> {
        self.get_at(key, req, Instant::now())
    }

    fn get_at(&self, key: &Key, req: &Message, now: Instant) -> Option<Vec<u8>> {
        let found = {
            let mut inner = self.inner.lock().unwrap();
            let tick = inner.tick();
            match inner.map.get_mut(key) {
                Some(e) if e.expires > now => {
                    let old = std::mem::replace(&mut e.tick, tick);
                    let found = (e.wire.clone(), now.duration_since(e.stored));
                    inner.lru.remove(&old);
                    inner.lru.insert(tick, key.clone());
                    Some(found)
                }
                Some(_) => {
                    inner.remove(key);
                    None
                }
                None => None,
            }
        };
        // Rebuild outside the lock: parsing and encoding is the slow part.
        let resp = found.and_then(|(wire, age)| rebuild(&wire, req, age));
        if resp.is_some() {
            self.hits.fetch_add(1, Relaxed);
        } else {
            self.misses.fetch_add(1, Relaxed);
        }
        resp
    }

    /// Stores upstream's answer to `req` if it is safe to reuse.
    pub fn insert(&self, key: Key, req: &Message, wire: &[u8]) {
        self.insert_at(key, req, wire, Instant::now())
    }

    fn insert_at(&self, key: Key, req: &Message, wire: &[u8], now: Instant) {
        let Some(ttl) = cacheable_ttl(req, wire) else { return };
        let cost = key.cost(wire.len());
        // A single huge answer shouldn't push out dozens of ordinary ones.
        if cost > self.capacity / 64 {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.remove(&key);
        while inner.bytes + cost > self.capacity {
            let Some((_, oldest)) = inner.lru.pop_first() else { break };
            if let Some(e) = inner.map.remove(&oldest) {
                inner.bytes -= oldest.cost(e.wire.len());
            }
        }
        let tick = inner.tick();
        inner.lru.insert(tick, key.clone());
        inner.bytes += cost;
        let expires = now + Duration::from_secs(ttl.into());
        inner.map.insert(key, Entry { wire: wire.to_vec(), stored: now, expires, tick });
    }
}

/// How long `wire` (upstream's answer to `req`) may be reused, or `None` if it must not be.
fn cacheable_ttl(req: &Message, wire: &[u8]) -> Option<u32> {
    let resp = Message::from_vec(wire).ok()?;
    if resp.message_type != MessageType::Response || resp.truncation || resp.signature.is_some() {
        return None;
    }
    // Only keep an answer to the question that was asked.
    let (q, rq) = (&req.queries[0], resp.queries.first()?);
    if resp.queries.len() != 1
        || q.query_type() != rq.query_type()
        || q.query_class() != rq.query_class()
        || q.name() != rq.name() // case-insensitive
    {
        return None;
    }
    let records = || resp.answers.iter().chain(&resp.authorities).chain(&resp.additionals);
    let ttl = match resp.response_code {
        ResponseCode::NoError if !resp.answers.is_empty() => records().map(|r| r.ttl).min()?.min(MAX_TTL),
        // Negative answer: cacheable only for as long as the zone's SOA allows (RFC 2308 section 5).
        ResponseCode::NoError | ResponseCode::NXDomain => {
            negative_ttl(&resp.authorities)?.min(records().map(|r| r.ttl).min()?).min(MAX_NEGATIVE_TTL)
        }
        _ => return None,
    };
    (ttl > 0).then_some(ttl)
}

fn negative_ttl(authorities: &[Record]) -> Option<u32> {
    authorities.iter().find_map(|r| match &r.data {
        RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
        _ => None,
    })
}

/// Turns a cached answer into a reply to `req`: its ID and question (some clients randomise the
/// letter case and check it), TTLs reduced by `age`, and EDNS only if the client used it.
fn rebuild(wire: &[u8], req: &Message, age: Duration) -> Option<Vec<u8>> {
    let mut resp = Message::from_vec(wire).ok()?;
    let age = u32::try_from(age.as_secs()).unwrap_or(u32::MAX);
    resp.metadata.id = req.id;
    resp.metadata.recursion_desired = req.recursion_desired;
    resp.queries = req.queries.clone();
    for r in resp.answers.iter_mut().chain(&mut resp.authorities).chain(&mut resp.additionals) {
        r.ttl = r.ttl.saturating_sub(age);
    }
    // Don't replay upstream's EDNS options (padding, cookies meant for another client).
    resp.edns = match (&req.edns, &resp.edns) {
        (Some(_), Some(cached)) => {
            let mut e = Edns::new();
            e.set_max_payload(cached.max_payload())
                .set_version(cached.version())
                .set_dnssec_ok(cached.flags().dnssec_ok);
            Some(e)
        }
        _ => None,
    };
    resp.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::{rdata::{A, SOA}, Name, RecordType};
    use std::{net::Ipv4Addr, str::FromStr};

    fn query(name: &str, t: RecordType, id: u16) -> Message {
        let mut m = Message::query();
        m.metadata.id = id;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_str(name).unwrap(), t));
        m
    }

    fn key(req: &Message) -> Key {
        let name = req.queries[0].name().to_ascii().trim_end_matches('.').to_ascii_lowercase();
        Key::new(req, &name)
    }

    fn answer(req: &Message, ttl: u32) -> Vec<u8> {
        let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
        resp.metadata.recursion_desired = true;
        resp.metadata.recursion_available = true;
        resp.add_queries(req.queries.iter().cloned());
        let name = req.queries[0].name().clone();
        resp.add_answer(Record::from_rdata(name, ttl, RData::A(A(Ipv4Addr::new(93, 184, 216, 34)))));
        resp.to_vec().unwrap()
    }

    fn negative(req: &Message, rcode: ResponseCode, soa_ttl: u32, minimum: u32) -> Vec<u8> {
        let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
        resp.metadata.response_code = rcode;
        resp.add_queries(req.queries.iter().cloned());
        let zone = Name::from_str("example.com.").unwrap();
        let soa = SOA::new(zone.clone(), Name::from_str("hostmaster.example.com.").unwrap(), 1, 7200, 900, 86400, minimum);
        resp.add_authority(Record::from_rdata(zone, soa_ttl, RData::SOA(soa)));
        resp.to_vec().unwrap()
    }

    #[test]
    fn hit_uses_new_id_question_case_and_aged_ttl() {
        let cache = Cache::new(DEFAULT_CAPACITY);
        let t0 = Instant::now();
        let first = query("www.example.com.", RecordType::A, 1);
        cache.insert_at(key(&first), &first, &answer(&first, 300), t0);

        // Name::from_str lowercases, so mix the case in the wire bytes, as a client would send it.
        let mut raw = query("www.example.com.", RecordType::A, 0xBEEF).to_vec().unwrap();
        raw[13] = b'W';
        raw[15] = b'W';
        raw[17] = b'E';
        raw[19] = b'A';
        let again = Message::from_vec(&raw).unwrap();
        let wire = cache.get_at(&key(&again), &again, t0 + Duration::from_secs(100)).unwrap();
        let r = Message::from_vec(&wire).unwrap();
        assert_eq!(r.id, 0xBEEF);
        assert_eq!(r.queries[0].name().to_ascii(), "WwW.ExAmple.com.");
        assert_eq!(r.answers[0].ttl, 200);
        assert_eq!(cache.hits.load(Relaxed), 1);
    }

    #[test]
    fn expires_after_ttl() {
        let cache = Cache::new(DEFAULT_CAPACITY);
        let t0 = Instant::now();
        let req = query("www.example.com.", RecordType::A, 1);
        cache.insert_at(key(&req), &req, &answer(&req, 60), t0);
        assert!(cache.get_at(&key(&req), &req, t0 + Duration::from_secs(59)).is_some());
        assert!(cache.get_at(&key(&req), &req, t0 + Duration::from_secs(60)).is_none());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.misses.load(Relaxed), 1);
    }

    #[test]
    fn type_is_part_of_the_key() {
        let cache = Cache::new(DEFAULT_CAPACITY);
        let a = query("www.example.com.", RecordType::A, 1);
        cache.insert(key(&a), &a, &answer(&a, 300));
        let aaaa = query("www.example.com.", RecordType::AAAA, 2);
        assert!(cache.get(&key(&aaaa), &aaaa).is_none());
    }

    #[test]
    fn skips_zero_ttl_servfail_truncated_and_mismatched() {
        let cache = Cache::new(DEFAULT_CAPACITY);
        let req = query("www.example.com.", RecordType::A, 1);
        cache.insert(key(&req), &req, &answer(&req, 0));

        let mut fail = Message::from_vec(&answer(&req, 300)).unwrap();
        fail.metadata.response_code = ResponseCode::ServFail;
        cache.insert(key(&req), &req, &fail.to_vec().unwrap());

        let mut tc = Message::from_vec(&answer(&req, 300)).unwrap();
        tc.metadata.truncation = true;
        cache.insert(key(&req), &req, &tc.to_vec().unwrap());

        let other = query("other.example.com.", RecordType::A, 1);
        cache.insert(key(&req), &req, &answer(&other, 300));

        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn caps_positive_ttl() {
        let req = query("www.example.com.", RecordType::A, 1);
        assert_eq!(cacheable_ttl(&req, &answer(&req, 7 * 86_400)), Some(MAX_TTL));
    }

    #[test]
    fn negative_answers_use_soa() {
        let req = query("nope.example.com.", RecordType::A, 1);
        assert_eq!(cacheable_ttl(&req, &negative(&req, ResponseCode::NXDomain, 3600, 300)), Some(300));
        assert_eq!(cacheable_ttl(&req, &negative(&req, ResponseCode::NoError, 120, 900)), Some(120));
        assert_eq!(cacheable_ttl(&req, &negative(&req, ResponseCode::NXDomain, 86400, 86400)), Some(MAX_NEGATIVE_TTL));

        // No SOA: we don't know how long "no such name" holds, so don't keep it.
        let mut bare = Message::new(1, MessageType::Response, OpCode::Query);
        bare.metadata.response_code = ResponseCode::NXDomain;
        bare.add_queries(req.queries.iter().cloned());
        assert_eq!(cacheable_ttl(&req, &bare.to_vec().unwrap()), None);
    }

    #[test]
    fn evicts_least_recently_used_to_stay_within_capacity() {
        // Same-length names, so every entry costs the same.
        let reqs: Vec<_> = (0..65).map(|i| query(&format!("a{i:02}.example.com."), RecordType::A, 1)).collect();
        let per_entry = key(&reqs[0]).cost(answer(&reqs[0], 300).len());
        // Room for exactly 64 entries; the per-entry limit is capacity / 64.
        let cache = Cache::new(per_entry * 64);
        let t0 = Instant::now();
        for r in &reqs[..64] {
            cache.insert_at(key(r), r, &answer(r, 300), t0);
        }
        // Touch the oldest so the second-oldest is evicted instead.
        assert!(cache.get_at(&key(&reqs[0]), &reqs[0], t0).is_some());
        cache.insert_at(key(&reqs[64]), &reqs[64], &answer(&reqs[64], 300), t0);

        assert_eq!(cache.len(), 64);
        assert!(cache.inner.lock().unwrap().bytes <= per_entry * 64);
        assert!(cache.get_at(&key(&reqs[0]), &reqs[0], t0).is_some());
        assert!(cache.get_at(&key(&reqs[1]), &reqs[1], t0).is_none());
        assert!(cache.get_at(&key(&reqs[64]), &reqs[64], t0).is_some());
    }

    #[test]
    fn edns_only_when_client_asked_and_without_options() {
        let cache = Cache::new(DEFAULT_CAPACITY);
        let mut req = query("www.example.com.", RecordType::A, 1);
        let mut e = Edns::new();
        e.set_max_payload(1232);
        req.set_edns(e);
        let mut resp = Message::from_vec(&answer(&req, 300)).unwrap();
        let mut re = Edns::new();
        re.set_max_payload(1232);
        resp.set_edns(re);
        cache.insert(key(&req), &req, &resp.to_vec().unwrap());

        let r = Message::from_vec(&cache.get(&key(&req), &req).unwrap()).unwrap();
        assert_eq!(r.edns.as_ref().map(|e| e.max_payload()), Some(1232));

        let plain = query("www.example.com.", RecordType::A, 2);
        let r = Message::from_vec(&cache.get(&key(&plain), &plain).unwrap()).unwrap();
        assert!(r.edns.is_none());
    }

    #[test]
    fn clear_empties_everything() {
        let cache = Cache::new(DEFAULT_CAPACITY);
        let req = query("www.example.com.", RecordType::A, 1);
        cache.insert(key(&req), &req, &answer(&req, 300));
        cache.clear();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.inner.lock().unwrap().bytes, 0);
    }
}
