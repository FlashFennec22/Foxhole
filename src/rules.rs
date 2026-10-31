//! Parsing of AdGuard/ABP-style, hosts-style and plain-domain blocklists into
//! DNS-level rules, plus the suffix matcher.
//!
//! Supported:  `||example.com^`, `@@||example.com^`, `||example.com^$important`,
//!             `0.0.0.0 example.com`, `example.com`
//! Skipped (not meaningful at DNS level): cosmetic rules, regexes, path/wildcard rules,
//!             and rules with modifiers other than `important`.

use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub enum Rule {
    Block(String),
    Allow(String),
}

const IGNORED_HOSTS: &[&str] = &[
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
];

pub fn parse_line(line: &str) -> Option<Rule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
        return None;
    }
    if ["##", "#@#", "#?#", "#$#", "#%#"].iter().any(|m| line.contains(m)) {
        return None;
    }

    let (allow, rest) = match line.strip_prefix("@@") {
        Some(r) => (true, r),
        None => (false, line),
    };

    // ||domain^  (optionally with $important)
    if let Some(body) = rest.strip_prefix("||") {
        let (pat, mods) = match body.split_once('$') {
            Some((p, m)) => (p, Some(m)),
            None => (body, None),
        };
        if let Some(m) = mods {
            if !m.split(',').all(|x| x.trim().eq_ignore_ascii_case("important")) {
                return None;
            }
        }
        let pat = pat.strip_suffix('^').unwrap_or(pat);
        let d = normalize(pat)?;
        return Some(if allow { Rule::Allow(d) } else { Rule::Block(d) });
    }
    if allow || rest.starts_with('|') {
        return None;
    }

    // hosts-style or plain domain
    let mut parts = rest.split_whitespace();
    let first = parts.next()?;
    match parts.next() {
        None => normalize(first).map(Rule::Block),
        Some(second) => {
            if first.parse::<IpAddr>().is_ok() && !second.starts_with('#') {
                if IGNORED_HOSTS.contains(&second.to_ascii_lowercase().as_str()) {
                    return None;
                }
                normalize(second).map(Rule::Block)
            } else {
                None
            }
        }
    }
}

pub fn parse_list(text: &str) -> impl Iterator<Item = Rule> + '_ {
    text.lines().filter_map(parse_line)
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

#[derive(Default)]
pub struct Matcher {
    block: HashSet<Box<str>>,
    allow: HashSet<Box<str>>,
}

impl Matcher {
    pub fn add_list(&mut self, text: &str) {
        for rule in parse_list(text) {
            match rule {
                Rule::Block(d) => { self.block.insert(d.into_boxed_str()); }
                Rule::Allow(d) => { self.allow.insert(d.into_boxed_str()); }
            }
        }
    }

    pub fn block_domain(&mut self, d: &str) {
        if let Some(d) = normalize(d) { self.block.insert(d.into_boxed_str()); }
    }

    pub fn allow_domain(&mut self, d: &str) {
        if let Some(d) = normalize(d) { self.allow.insert(d.into_boxed_str()); }
    }

    pub fn len(&self) -> usize {
        self.block.len()
    }

    /// `name` must be lowercase without a trailing dot. Matches the domain and every
    /// parent domain; an allow entry at any level beats a block entry.
    pub fn is_blocked(&self, name: &str) -> bool {
        let mut s = name;
        let mut blocked = false;
        loop {
            if self.allow.contains(s) {
                return false;
            }
            if self.block.contains(s) {
                blocked = true;
            }
            match s.find('.') {
                Some(i) => s = &s[i + 1..],
                None => break,
            }
        }
        blocked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_forms() {
        assert_eq!(parse_line("||ads.example.com^"), Some(Rule::Block("ads.example.com".into())));
        assert_eq!(parse_line("@@||ok.example.com^"), Some(Rule::Allow("ok.example.com".into())));
        assert_eq!(parse_line("||Track.Example.com^$important"), Some(Rule::Block("track.example.com".into())));
        assert_eq!(parse_line("0.0.0.0 bad.example.net # c"), Some(Rule::Block("bad.example.net".into())));
        assert_eq!(parse_line("plain.example.org"), Some(Rule::Block("plain.example.org".into())));
    }

    #[test]
    fn skips_non_dns_rules() {
        for l in ["! comment", "# comment", "[Adblock Plus 2.0]", "example.com##.ad", "||x.com^$third-party",
                  "||x.com/path^", "/regex/", "||*.x.com^", "127.0.0.1 localhost", "0.0.0.0 0.0.0.0", ""] {
            assert_eq!(parse_line(l), None, "{l}");
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
    }
}
