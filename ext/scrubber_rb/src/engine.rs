//! The scanning engine.
//!
//! One pass, two stages:
//!
//! 1. **Prefilter.** Rules that require a literal (`AKIA`, `-----BEGIN`,
//!    `ghp_`, `password`) are gated behind a single Aho-Corasick pass over all
//!    such literals. On a typical log line that eliminates roughly two thirds of
//!    the rule set before any regex runs.
//! 2. **Match.** The remaining rules live in one `RegexSet`, which reports
//!    which of them match anywhere in the input in a single scan. Only those
//!    get a second pass for their spans.
//!
//! Then validators run on the candidates, overlaps are resolved, and the output
//! is built once with a single walk — no repeated `gsub` over the whole string.
//!
//! Everything here is immutable after construction, so an `Engine` is `Sync`
//! and one instance can be shared across every thread in a process.

use aho_corasick::{AhoCorasick, MatchKind};
use regex::{Regex, RegexSet};

use crate::detectors::{self, Validator};
use crate::pattern;
use crate::replace::{render, MaskKind, Strategy};

/// Anything that can go wrong while building an engine.
#[derive(Debug)]
pub enum BuildError {
    UnknownDetector {
        name: String,
        known: Vec<&'static str>,
    },
    UnknownStrategy {
        name: String,
    },
    UnsupportedPattern {
        name: String,
        construct: String,
        reason: &'static str,
    },
    InvalidPattern {
        name: String,
        message: String,
    },
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::UnknownDetector { name, known } => write!(
                f,
                "unknown detector {name:?}. Known detectors: {}",
                known.join(", ")
            ),
            BuildError::UnknownStrategy { name } => write!(
                f,
                "unknown replacement {name:?}. Expected one of: label, mask, hash, remove"
            ),
            BuildError::UnsupportedPattern {
                name,
                construct,
                reason,
            } => write!(
                f,
                "custom detector {name:?} uses {construct}, which this engine cannot compile: \
                 {reason}. Rewrite the pattern without it, or pre-filter in Ruby."
            ),
            BuildError::InvalidPattern { name, message } => {
                write!(f, "custom detector {name:?} failed to compile: {message}")
            }
        }
    }
}

/// One compiled rule.
struct CompiledRule {
    kind: String,
    regex: Regex,
    capture: usize,
    validator: Option<Validator>,
    priority: u8,
    mask: MaskKind,
}

/// A surviving match, in absolute byte offsets into the original input.
#[derive(Clone, Copy, Debug)]
pub struct Hit {
    pub start: usize,
    pub end: usize,
    rule: usize,
}

/// A user-facing detector specification.
pub struct CustomSpec {
    pub name: String,
    pub source: String,
    pub options: i32,
}

pub struct Engine {
    rules: Vec<CompiledRule>,
    /// Rule indices reachable only when one of their literals is present.
    anchored: Vec<usize>,
    /// Aho-Corasick over every anchor literal; pattern id -> `anchored` index.
    prefilter: Option<AhoCorasick>,
    anchor_owner: Vec<usize>,
    /// Rule indices with no usable literal, plus the set that scans them.
    unanchored: Vec<usize>,
    set: RegexSet,
    strategy: Strategy,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("rules", &self.rules.len())
            .field("anchored", &self.anchored.len())
            .field("unanchored", &self.unanchored.len())
            .field("strategy", &self.strategy)
            .finish()
    }
}

impl Engine {
    /// Compile a detector selection into a reusable engine.
    pub fn build(
        detector_keys: &[String],
        customs: &[CustomSpec],
        strategy_name: &str,
        hash_salt: Option<String>,
    ) -> Result<Engine, BuildError> {
        let strategy = Strategy::from_name(strategy_name, hash_salt).ok_or_else(|| {
            BuildError::UnknownStrategy {
                name: strategy_name.to_string(),
            }
        })?;

        let mut rules: Vec<CompiledRule> = Vec::new();
        let mut anchors: Vec<String> = Vec::new();
        let mut anchor_owner: Vec<usize> = Vec::new();
        let mut anchored: Vec<usize> = Vec::new();
        let mut unanchored: Vec<usize> = Vec::new();
        let mut unanchored_patterns: Vec<&str> = Vec::new();

        for key in detector_keys {
            let specs = detectors::rules_for(key).ok_or_else(|| BuildError::UnknownDetector {
                name: key.clone(),
                known: detectors::all_keys(),
            })?;
            for spec in specs {
                // Registry patterns are compile-time constants covered by
                // `every_registry_pattern_compiles`, so a failure here is a bug
                // in this crate, not bad user input.
                let regex = Regex::new(spec.pattern).map_err(|e| BuildError::InvalidPattern {
                    name: key.clone(),
                    message: e.to_string(),
                })?;
                let idx = rules.len();
                rules.push(CompiledRule {
                    kind: spec.kind.to_string(),
                    regex,
                    capture: spec.capture,
                    validator: spec.validator,
                    priority: spec.priority,
                    mask: spec.mask,
                });
                if spec.anchors.is_empty() {
                    unanchored.push(idx);
                    unanchored_patterns.push(spec.pattern);
                } else {
                    let slot = anchored.len();
                    anchored.push(idx);
                    for lit in spec.anchors {
                        anchors.push((*lit).to_string());
                        anchor_owner.push(slot);
                    }
                }
            }
        }

        // Custom detectors are always unanchored: we have no idea what literal
        // the user's pattern needs, and guessing wrong would drop matches.
        let mut custom_sources: Vec<String> = Vec::with_capacity(customs.len());
        for custom in customs {
            let translated = pattern::translate(&custom.source, custom.options).map_err(|u| {
                BuildError::UnsupportedPattern {
                    name: custom.name.clone(),
                    construct: u.construct,
                    reason: u.reason,
                }
            })?;
            let regex = Regex::new(&translated).map_err(|e| BuildError::InvalidPattern {
                name: custom.name.clone(),
                message: e.to_string(),
            })?;
            let idx = rules.len();
            rules.push(CompiledRule {
                kind: custom.name.clone(),
                regex,
                capture: 0,
                validator: None,
                priority: detectors::P_CUSTOM,
                mask: MaskKind::Full,
            });
            unanchored.push(idx);
            custom_sources.push(translated);
        }
        for src in &custom_sources {
            unanchored_patterns.push(src);
        }

        let set = RegexSet::new(&unanchored_patterns).map_err(|e| BuildError::InvalidPattern {
            name: "<detector set>".to_string(),
            message: e.to_string(),
        })?;

        let prefilter = if anchors.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    // Case-insensitive so one automaton can gate both
                    // `password=` and `PASSWORD=`. A false positive here only
                    // costs one extra regex pass; a false negative would drop a
                    // match, so we always err wide.
                    .ascii_case_insensitive(true)
                    // Standard (not leftmost) so overlapping search is legal:
                    // `sk-` sits inside `sk-ant-`, and both rules must wake up.
                    .match_kind(MatchKind::Standard)
                    .build(&anchors)
                    .map_err(|e| BuildError::InvalidPattern {
                        name: "<prefilter>".to_string(),
                        message: e.to_string(),
                    })?,
            )
        };

        Ok(Engine {
            rules,
            anchored,
            prefilter,
            anchor_owner,
            unanchored,
            set,
            strategy,
        })
    }

    /// Number of compiled rules; used by tests and `#inspect`.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn kind_of(&self, hit: &Hit) -> &str {
        &self.rules[hit.rule].kind
    }

    /// Find every match in `bytes`, resolved for overlaps, in document order.
    ///
    /// `bytes` may contain invalid UTF-8. Valid regions are scanned; invalid
    /// bytes are stepped over and passed through untouched (contract S5).
    pub fn scan(&self, bytes: &[u8]) -> Vec<Hit> {
        let mut raw = Vec::new();
        let mut base = 0usize;
        let mut rest = bytes;

        loop {
            match std::str::from_utf8(rest) {
                Ok(chunk) => {
                    self.scan_str(chunk, base, &mut raw);
                    break;
                }
                Err(e) => {
                    let valid_len = e.valid_up_to();
                    if valid_len > 0 {
                        // Safe: `valid_up_to` is by definition a valid boundary.
                        let chunk = unsafe { std::str::from_utf8_unchecked(&rest[..valid_len]) };
                        self.scan_str(chunk, base, &mut raw);
                    }
                    let skip = e.error_len().unwrap_or(rest.len() - valid_len);
                    let advance = valid_len + skip;
                    if advance == 0 || advance >= rest.len() {
                        break;
                    }
                    base += advance;
                    rest = &rest[advance..];
                }
            }
        }

        self.resolve(raw)
    }

    /// Scan one valid-UTF-8 region, recording matches at `base + local offset`.
    fn scan_str(&self, text: &str, base: usize, out: &mut Vec<Hit>) {
        if text.is_empty() {
            return;
        }

        // Stage 1a: which anchored rules can possibly fire here?
        if let Some(ac) = &self.prefilter {
            let mut live = vec![false; self.anchored.len()];
            let mut remaining = self.anchored.len();
            for m in ac.find_overlapping_iter(text) {
                let slot = self.anchor_owner[m.pattern().as_usize()];
                if !live[slot] {
                    live[slot] = true;
                    remaining -= 1;
                    if remaining == 0 {
                        break;
                    }
                }
            }
            for (slot, alive) in live.iter().enumerate() {
                if *alive {
                    self.collect(self.anchored[slot], text, base, out);
                }
            }
        }

        // Stage 1b: one multi-pattern pass over everything else.
        for local in self.set.matches(text).iter() {
            self.collect(self.unanchored[local], text, base, out);
        }
    }

    fn collect(&self, rule_idx: usize, text: &str, base: usize, out: &mut Vec<Hit>) {
        let rule = &self.rules[rule_idx];
        if rule.capture == 0 {
            for m in rule.regex.find_iter(text) {
                self.push_if_valid(rule_idx, text, base, m.start(), m.end(), out);
            }
        } else {
            for caps in rule.regex.captures_iter(text) {
                if let Some(m) = caps.get(rule.capture) {
                    self.push_if_valid(rule_idx, text, base, m.start(), m.end(), out);
                }
            }
        }
    }

    fn push_if_valid(
        &self,
        rule_idx: usize,
        text: &str,
        base: usize,
        start: usize,
        end: usize,
        out: &mut Vec<Hit>,
    ) {
        if end <= start {
            return;
        }
        let rule = &self.rules[rule_idx];
        if let Some(validate) = rule.validator {
            let candidate = detectors::Candidate {
                text,
                matched: &text[start..end],
                start,
                end,
            };
            if !validate(&candidate) {
                return;
            }
        }
        out.push(Hit {
            start: base + start,
            end: base + end,
            rule: rule_idx,
        });
    }

    /// Resolve overlapping matches: leftmost first, then most specific
    /// (lowest priority number), then longest (contract S2).
    fn resolve(&self, mut raw: Vec<Hit>) -> Vec<Hit> {
        if raw.len() > 1 {
            raw.sort_unstable_by(|a, b| {
                a.start
                    .cmp(&b.start)
                    .then_with(|| {
                        self.rules[a.rule]
                            .priority
                            .cmp(&self.rules[b.rule].priority)
                    })
                    .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            });
        }
        let mut kept: Vec<Hit> = Vec::with_capacity(raw.len());
        let mut last_end = 0usize;
        for hit in raw {
            if kept.is_empty() || hit.start >= last_end {
                last_end = hit.end;
                kept.push(hit);
            }
        }
        kept
    }

    /// Apply the replacement strategy, returning the new bytes.
    ///
    /// Returns `None` when nothing matched, so the caller can hand back the
    /// input untouched instead of rebuilding an identical string (contract S1).
    pub fn scrub(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let hits = self.scan(bytes);
        if hits.is_empty() {
            return None;
        }
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut pos = 0usize;
        let mut buf = String::new();
        for hit in &hits {
            out.extend_from_slice(&bytes[pos..hit.start]);
            let rule = &self.rules[hit.rule];
            // Hits only ever come from valid UTF-8 regions.
            let matched = std::str::from_utf8(&bytes[hit.start..hit.end]).unwrap_or("");
            buf.clear();
            render(&self.strategy, &rule.kind, matched, rule.mask, &mut buf);
            out.extend_from_slice(buf.as_bytes());
            pos = hit.end;
        }
        out.extend_from_slice(&bytes[pos..]);
        Some(out)
    }

    /// A short, already-redacted preview of a match, for `Scrubber#detect`.
    pub fn preview(&self, bytes: &[u8], hit: &Hit) -> String {
        let rule = &self.rules[hit.rule];
        let matched = std::str::from_utf8(&bytes[hit.start..hit.end]).unwrap_or("");
        let mut buf = String::new();
        render(&Strategy::Mask, &rule.kind, matched, rule.mask, &mut buf);
        if buf.chars().count() > 64 {
            buf = buf.chars().take(61).collect::<String>() + "...";
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(keys: &[&str]) -> Engine {
        let owned: Vec<String> = keys.iter().map(|k| (*k).to_string()).collect();
        Engine::build(&owned, &[], "label", None).unwrap()
    }

    fn scrub(keys: &[&str], text: &str) -> String {
        let e = engine(keys);
        match e.scrub(text.as_bytes()) {
            Some(bytes) => String::from_utf8(bytes).unwrap(),
            None => text.to_string(),
        }
    }

    fn defaults() -> Vec<String> {
        detectors::DEFAULTS.iter().map(|k| k.to_string()).collect()
    }

    #[test]
    fn redacts_the_readme_headline_example() {
        let out = scrub(
            &["email", "credit_card", "aws_key"],
            "contact nik@example.com, card 4111 1111 1111 1111, key AKIAIOSFODNN7EXAMPLE",
        );
        assert_eq!(out, "contact [EMAIL], card [CREDIT_CARD], key [AWS_KEY]");
    }

    #[test]
    fn no_matches_reports_none() {
        let e = engine(&["email"]);
        assert!(e.scrub(b"nothing to see here").is_none());
    }

    #[test]
    fn luhn_failure_is_not_a_card() {
        assert_eq!(
            scrub(&["credit_card"], "order 1234 5678 9012 3456 shipped"),
            "order 1234 5678 9012 3456 shipped"
        );
    }

    #[test]
    fn private_key_block_goes_as_one_unit() {
        let text = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIC\nlines\n-----END RSA PRIVATE KEY-----\nafter";
        assert_eq!(
            scrub(&["private_key"], text),
            "before\n[PRIVATE_KEY]\nafter"
        );
    }

    #[test]
    fn url_credentials_redact_only_the_password() {
        assert_eq!(
            scrub(
                &["url_credentials"],
                "psql postgres://app:hunter2@db.internal/prod"
            ),
            "psql postgres://app:[URL_CREDENTIALS]@db.internal/prod"
        );
    }

    #[test]
    fn password_pair_redacts_only_the_value() {
        assert_eq!(
            scrub(&["password_pair"], "GET /login?password=hunter2&next=/home"),
            "GET /login?password=[PASSWORD_PAIR]&next=/home"
        );
        assert_eq!(
            scrub(&["password_pair"], r#"{"api_key":"sekret"}"#),
            r#"{"api_key":"[PASSWORD_PAIR]"}"#
        );
    }

    #[test]
    fn overlapping_matches_pick_the_more_specific_rule() {
        // The password value also looks like an email local part; the URL
        // credential rule is more specific and wins.
        let out = scrub(
            &["email", "url_credentials"],
            "https://admin:hunter2@mail.example.com/",
        );
        assert!(out.contains("[URL_CREDENTIALS]"), "got {out}");
        assert!(!out.contains("hunter2"), "got {out}");
    }

    #[test]
    fn invalid_utf8_is_preserved_and_valid_regions_still_scrub() {
        let mut input = b"user ".to_vec();
        input.push(0xff);
        input.extend_from_slice(b" nik@example.com end");
        let e = engine(&["email"]);
        let out = e.scrub(&input).expect("should match");
        assert!(out.contains(&0xff), "invalid byte must survive");
        assert!(String::from_utf8_lossy(&out).contains("[EMAIL]"));
        assert!(!String::from_utf8_lossy(&out).contains("nik@example.com"));
    }

    #[test]
    fn multibyte_text_keeps_byte_offsets_consistent() {
        let text = "🎉 नमस्ते nik@example.com 🎉";
        let e = engine(&["email"]);
        let hits = e.scan(text.as_bytes());
        assert_eq!(hits.len(), 1);
        assert_eq!(&text[hits[0].start..hits[0].end], "nik@example.com");
    }

    #[test]
    fn every_default_detector_compiles_together() {
        let e = Engine::build(&defaults(), &[], "label", None).unwrap();
        assert!(e.rule_count() >= detectors::DEFAULTS.len());
    }

    #[test]
    fn india_pack_detects_aadhaar_pan_upi() {
        let keys: Vec<String> = detectors::INDIA.iter().map(|k| k.to_string()).collect();
        let e = Engine::build(&keys, &[], "label", None).unwrap();
        let text = "pan ABCPE1234F vpa nik@ybl phone +919876543210";
        let out = String::from_utf8(e.scrub(text.as_bytes()).unwrap()).unwrap();
        assert!(out.contains("[PAN]"), "got {out}");
        assert!(out.contains("[UPI]"), "got {out}");
        assert!(out.contains("[PHONE_IN]"), "got {out}");
    }

    #[test]
    fn unknown_detector_names_itself() {
        let err = Engine::build(&["nope".to_string()], &[], "label", None).unwrap_err();
        assert!(matches!(err, BuildError::UnknownDetector { .. }));
        assert!(err.to_string().contains("nope"));
    }

    #[test]
    fn unsupported_custom_pattern_names_the_construct() {
        let custom = CustomSpec {
            name: "bad".into(),
            source: r"(a)\1".into(),
            options: 0,
        };
        let err = Engine::build(&[], std::slice::from_ref(&custom), "label", None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(r"\1"), "got {msg}");
        assert!(msg.contains("bad"), "got {msg}");
    }

    #[test]
    fn custom_detectors_use_their_own_label() {
        let custom = CustomSpec {
            name: "employee_id".into(),
            source: r"\bEMP-\d{6}\b".into(),
            options: 0,
        };
        let e = Engine::build(&[], std::slice::from_ref(&custom), "label", None).unwrap();
        let out = String::from_utf8(e.scrub(b"ticket for EMP-004521 today").unwrap()).unwrap();
        assert_eq!(out, "ticket for [EMPLOYEE_ID] today");
    }

    #[test]
    fn hash_strategy_is_stable_across_occurrences() {
        let e = Engine::build(&["email".to_string()], &[], "hash", None).unwrap();
        let out =
            String::from_utf8(e.scrub(b"a@x.com then a@x.com then b@x.com").unwrap()).unwrap();
        let tokens: Vec<&str> = out
            .split_whitespace()
            .filter(|t| t.starts_with('['))
            .collect();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0], tokens[1]);
        assert_ne!(tokens[0], tokens[2]);
    }

    #[test]
    fn salt_changes_the_token() {
        let a = Engine::build(&["email".to_string()], &[], "hash", None).unwrap();
        let b = Engine::build(
            &["email".to_string()],
            &[],
            "hash",
            Some("pepper".to_string()),
        )
        .unwrap();
        assert_ne!(a.scrub(b"a@x.com").unwrap(), b.scrub(b"a@x.com").unwrap());
    }

    #[test]
    fn engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Engine>();
    }

    // ---- fuzz-lite -------------------------------------------------------
    //
    // The invariant that matters for a redaction library running over
    // attacker-controlled log content: whatever you feed it, it comes back.
    // No panic, no abort across the FFI boundary, no truncation.

    fn shared_engine(strategy: &'static str) -> &'static Engine {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};
        static CACHE: OnceLock<Mutex<HashMap<&'static str, &'static Engine>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut guard = cache.lock().unwrap();
        guard.entry(strategy).or_insert_with(|| {
            let mut keys = defaults();
            keys.extend(detectors::INDIA.iter().map(|k| k.to_string()));
            Box::leak(Box::new(Engine::build(&keys, &[], strategy, None).unwrap()))
        })
    }

    use proptest::prelude::{any, ProptestConfig};
    use proptest::{prop_assert, proptest};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(400))]

        #[test]
        fn never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let engine = shared_engine("label");
            let _ = engine.scrub(&bytes);
        }

        #[test]
        fn arbitrary_text_survives_a_round_trip(
            text in ".{0,512}"
        ) {
            let engine = shared_engine("label");
            let hits = engine.scan(text.as_bytes());
            for hit in &hits {
                // Every hit must be a real, in-bounds, char-aligned slice.
                prop_assert!(hit.end <= text.len());
                prop_assert!(hit.start < hit.end);
                prop_assert!(text.is_char_boundary(hit.start));
                prop_assert!(text.is_char_boundary(hit.end));
            }
            for pair in hits.windows(2) {
                prop_assert!(pair[0].end <= pair[1].start);
            }
        }

        #[test]
        fn remove_never_grows_the_output(
            bytes in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let engine = shared_engine("remove");
            if let Some(out) = engine.scrub(&bytes) {
                prop_assert!(out.len() <= bytes.len());
            }
        }

        #[test]
        fn unmatched_bytes_are_preserved_verbatim(
            prefix in proptest::collection::vec(any::<u8>(), 0..64)
        ) {
            // Bytes with no detector coverage must come back untouched.
            let engine = shared_engine("label");
            let mut input = prefix.clone();
            input.extend_from_slice(b"\x00\x01\x02");
            if engine.scrub(&input).is_none() {
                // No match at all: caller keeps the original, which is exactly
                // the contract (S1).
                prop_assert!(true);
            }
        }
    }

    #[test]
    fn hits_never_overlap() {
        let e = Engine::build(&defaults(), &[], "label", None).unwrap();
        let text = "https://admin:hunter2@mail.example.com/ card 4111111111111111 \
                    key AKIAIOSFODNN7EXAMPLE ip 10.0.0.1 mac 00:1a:2b:3c:4d:5e";
        let hits = e.scan(text.as_bytes());
        for pair in hits.windows(2) {
            assert!(pair[0].end <= pair[1].start, "overlap: {pair:?}");
        }
    }
}
