//! Parsing of AdGuard/ABP-style, hosts-style and plain-domain blocklists into
//! DNS-level rules, plus the suffix matcher.
//!
//! Supported:  `||example.com^`, `||example.com^|`, `@@||example.com^`, `||example.com^$important`,
//!             `0.0.0.0 example.com [more.example.com ...]`, `example.com`
//! Skipped (not meaningful at DNS level): cosmetic rules, regexes, path/wildcard rules,
//!             and rules with modifiers other than `important`.

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub struct Rule {
    pub domain: String,
    /// `@@` exception rule.
    pub allow: bool,
    /// `$important`: beats non-important rules of the opposite kind.
    pub important: bool,
}

const IGNORED_HOSTS: &[&str] = &[
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
];

/// Parses one list line. Most lines yield zero or one rule; hosts-style lines can name several hosts.
pub fn parse_line(line: &str) -> Vec<Rule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
        return vec![];
    }
    if ["##", "#@#", "#?#", "#$#", "#%#"].iter().any(|m| line.contains(m)) {
        return vec![];
    }

    let (allow, rest) = match line.strip_prefix("@@") {
        Some(r) => (true, r),
        None => (false, line),
    };

    // ||domain^  (optionally with a trailing `|` anchor and/or $important)
    if let Some(body) = rest.strip_prefix("||") {
        let (pat, mods) = match body.split_once('$') {
            Some((p, m)) => (p, Some(m)),
            None => (body, None),
        };
        let mut important = false;
        for m in mods.into_iter().flat_map(|m| m.split(',')) {
            if m.trim().eq_ignore_ascii_case("important") {
                important = true;
            } else {
                return vec![];
            }
        }
        // `^` (separator) and `|` (end of address) mean the same thing for a bare hostname.
        let pat = pat.strip_suffix('|').unwrap_or(pat);
        let pat = pat.strip_suffix('^').unwrap_or(pat);
        return host(pat).map(|domain| Rule { domain, allow, important }).into_iter().collect();
    }
    if allow || rest.starts_with('|') {
        return vec![];
    }

    // hosts-style (`0.0.0.0 a.example b.example  # comment`) or a plain domain
    let rest = rest.split('#').next().unwrap_or_default();
    let mut parts = rest.split_whitespace();
    let Some(first) = parts.next() else { return vec![] };
    if first.parse::<IpAddr>().is_ok() {
        parts.filter_map(host).map(block).collect()
    } else if parts.next().is_none() {
        host(first).map(block).into_iter().collect()
    } else {
        vec![]
    }
}

fn block(domain: String) -> Rule {
    Rule { domain, allow: false, important: false }
}

/// A normalized hostname from a list, unless it is one that must never be blocked.
fn host(s: &str) -> Option<String> {
    normalize(s).filter(|d| !IGNORED_HOSTS.contains(&d.as_str()))
}

pub fn parse_list(text: &str) -> impl Iterator<Item = Rule> + '_ {
    text.lines().flat_map(parse_line)
}

pub fn normalize(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 || s.parse::<IpAddr>().is_ok() {
        return None;
    }
    if s.split('.').all(valid_label) {
        Some(s)
    } else {
        None
    }
}

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

// Rule kinds, kept as bit flags so a domain listed in several ways keeps all of them.
// Precedence, highest first: the user's own config, then `$important` rules, then plain rules;
// within each level an allow beats a block (AdGuard semantics).
const BLOCK: u8 = 1 << 0;
const ALLOW: u8 = 1 << 1;
const BLOCK_IMPORTANT: u8 = 1 << 2;
const ALLOW_IMPORTANT: u8 = 1 << 3;
const BLOCK_USER: u8 = 1 << 4;
const ALLOW_USER: u8 = 1 << 5;
const ANY_BLOCK: u8 = BLOCK | BLOCK_IMPORTANT | BLOCK_USER;
const LEVELS: [(u8, u8); 3] = [(ALLOW_USER, BLOCK_USER), (ALLOW_IMPORTANT, BLOCK_IMPORTANT), (ALLOW, BLOCK)];

#[derive(Default)]
pub struct Matcher {
    rules: HashMap<Box<str>, u8>,
    block_count: usize,
}

impl Matcher {
    fn insert(&mut self, domain: String, flag: u8) {
        let flags = self.rules.entry(domain.into_boxed_str()).or_insert(0);
        if *flags & ANY_BLOCK == 0 && flag & ANY_BLOCK != 0 {
            self.block_count += 1;
        }
        *flags |= flag;
    }

    pub fn add_list(&mut self, text: &str) {
        for r in parse_list(text) {
            let flag = match (r.allow, r.important) {
                (false, false) => BLOCK,
                (true, false) => ALLOW,
                (false, true) => BLOCK_IMPORTANT,
                (true, true) => ALLOW_IMPORTANT,
            };
            self.insert(r.domain, flag);
        }
    }

    /// The user's own block list: beats every list rule except the user's own allow list.
    pub fn block_domain(&mut self, d: &str) {
        if let Some(d) = normalize(d) { self.insert(d, BLOCK_USER); }
    }

    /// The user's own allow list: always wins.
    pub fn allow_domain(&mut self, d: &str) {
        if let Some(d) = normalize(d) { self.insert(d, ALLOW_USER); }
    }

    /// Number of distinct blocked domains.
    pub fn len(&self) -> usize {
        self.block_count
    }

    /// `name` must be lowercase without a trailing dot. Rules for the domain and every
    /// parent domain apply; see the precedence notes above for conflicts.
    pub fn is_blocked(&self, name: &str) -> bool {
        let mut flags = 0;
        let mut s = name;
        loop {
            if let Some(f) = self.rules.get(s) {
                flags |= f;
            }
            match s.find('.') {
                Some(i) => s = &s[i + 1..],
                None => break,
            }
        }
        LEVELS
            .iter()
            .find(|(allow, block)| flags & (allow | block) != 0)
            .is_some_and(|(allow, _)| flags & allow == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(d: &str, allow: bool, important: bool) -> Vec<Rule> {
        vec![Rule { domain: d.into(), allow, important }]
    }

    #[test]
    fn parses_common_forms() {
        assert_eq!(parse_line("||ads.example.com^"), rule("ads.example.com", false, false));
        assert_eq!(parse_line("@@||ok.example.com^"), rule("ok.example.com", true, false));
        assert_eq!(parse_line("@@||ok.example.com^|"), rule("ok.example.com", true, false));
        assert_eq!(parse_line("||Track.Example.com^$important"), rule("track.example.com", false, true));
        assert_eq!(parse_line("||nocaret.example$important"), rule("nocaret.example", false, true));
        assert_eq!(parse_line("0.0.0.0 bad.example.net # c"), rule("bad.example.net", false, false));
        assert_eq!(parse_line("plain.example.org"), rule("plain.example.org", false, false));
        assert_eq!(parse_line("plain.example.org # trailing comment"), rule("plain.example.org", false, false));
    }

    #[test]
    fn hosts_line_with_several_names() {
        let got: Vec<String> = parse_line("0.0.0.0 a.example b.example localhost c.example #x d.example")
            .into_iter()
            .map(|r| r.domain)
            .collect();
        assert_eq!(got, ["a.example", "b.example", "c.example"]);
    }

    #[test]
    fn skips_non_dns_rules() {
        for l in ["! comment", "# comment", "[Adblock Plus 2.0]", "example.com##.ad", "||x.com^$third-party",
                  "||x.com/path^", "/regex/", "||*.x.com^", "127.0.0.1 localhost", "0.0.0.0 0.0.0.0", "",
                  "localhost", "||localhost^", "two words"] {
            assert_eq!(parse_line(l), vec![], "{l}");
        }
    }

    #[test]
    fn suffix_matching_and_allow_precedence() {
        let mut m = Matcher::default();
        m.add_list("||example.com^\n@@||ok.example.com^\n");
        assert!(m.is_blocked("example.com"));
        assert!(m.is_blocked("a.b.example.com"));
        assert!(!m.is_blocked("ok.example.com"));
        assert!(!m.is_blocked("x.ok.example.com"));
        assert!(!m.is_blocked("notexample.com"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn important_and_user_precedence() {
        let mut m = Matcher::default();
        m.add_list("@@||tracker.example^\n||tracker.example^$important\n\
                    ||cdn.example^$important\n@@||cdn.example^$important\n\
                    ||ads.example^\n");
        assert!(m.is_blocked("tracker.example"), "important block beats plain allow");
        assert!(!m.is_blocked("cdn.example"), "important allow beats important block");

        m.allow_domain("tracker.example");
        assert!(!m.is_blocked("x.tracker.example"), "user allow beats important block");

        m.add_list("@@||mine.example^\n");
        m.block_domain("mine.example");
        assert!(m.is_blocked("mine.example"), "user block beats list allow");

        m.block_domain("both.example");
        m.allow_domain("both.example");
        assert!(!m.is_blocked("both.example"), "user allow beats user block");
        assert!(m.is_blocked("ads.example"));
    }
}
