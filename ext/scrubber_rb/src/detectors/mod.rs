//! The detector registry.
//!
//! A *detector* is a public key the user enables (`:email`, `:credit_card`).
//! A *rule* is one compiled regex. Most detectors are a single rule; a few
//! (`:api_key`, `:phone`, `:password_pair`) are a family of rules that all
//! report the same type, because expressing them as one alternation would make
//! capture-group bookkeeping unreadable.

pub mod checksum;
pub mod upi;
pub mod validate;

pub use validate::{Candidate, Validator};

use crate::replace::MaskKind;

/// One compiled-at-startup pattern.
pub struct Rule {
    /// Detector key this rule reports as, e.g. `"credit_card"`.
    pub kind: &'static str,
    /// The Rust `regex` source.
    pub pattern: &'static str,
    /// Literal substrings, any one of which must be present for this rule to
    /// have a chance of matching. Empty means "always run this rule".
    /// Used to build the stage-1 Aho-Corasick prefilter.
    pub anchors: &'static [&'static str],
    /// Which capture group to redact. 0 is the whole match; `password_pair` and
    /// `url_credentials` redact only group 1 so the surrounding key stays
    /// readable in logs.
    pub capture: usize,
    pub validator: Option<Validator>,
    /// Lower wins when two matches overlap.
    pub priority: u8,
    pub mask: MaskKind,
}

/// Plain rule: redact the whole match, no post-validation.
const fn rule(
    kind: &'static str,
    pattern: &'static str,
    anchors: &'static [&'static str],
    priority: u8,
    mask: MaskKind,
) -> Rule {
    Rule {
        kind,
        pattern,
        anchors,
        capture: 0,
        validator: None,
        priority,
        mask,
    }
}

/// Rule with a checksum or context validator.
const fn checked(
    kind: &'static str,
    pattern: &'static str,
    anchors: &'static [&'static str],
    priority: u8,
    mask: MaskKind,
    validator: Validator,
) -> Rule {
    Rule {
        kind,
        pattern,
        anchors,
        capture: 0,
        validator: Some(validator),
        priority,
        mask,
    }
}

/// Rule that redacts only capture group 1, leaving the surrounding key visible.
const fn captured(
    kind: &'static str,
    pattern: &'static str,
    anchors: &'static [&'static str],
    priority: u8,
) -> Rule {
    Rule {
        kind,
        pattern,
        anchors,
        capture: 1,
        validator: None,
        priority,
        mask: MaskKind::Full,
    }
}

/// Capture-group rule with a validator that sees the captured span.
const fn captured_checked(
    kind: &'static str,
    pattern: &'static str,
    anchors: &'static [&'static str],
    priority: u8,
    validator: Validator,
) -> Rule {
    Rule {
        kind,
        pattern,
        anchors,
        capture: 1,
        validator: Some(validator),
        priority,
        mask: MaskKind::Full,
    }
}

// Priorities. Secrets beat structured IDs beat loose numeric shapes, so that
// when spans overlap the more specific reading wins (behaviour contract S2).
// A provider-specific secret rule and the generic `key = value` rule usually
// match the same span. Ranking the specific one first means you get
// `[API_KEY]` rather than `[PASSWORD_PAIR]` — same redaction, better forensics.
const P_PRIVATE_KEY: u8 = 1;
const P_AWS: u8 = 2;
const P_API_KEY: u8 = 3;
const P_JWT: u8 = 4;
const P_URL_CREDS: u8 = 5;
const P_PASSWORD: u8 = 6;
pub const P_CUSTOM: u8 = 8;
const P_CARD: u8 = 20;
const P_IBAN: u8 = 21;
const P_AADHAAR: u8 = 22;
const P_SSN: u8 = 23;
const P_PAN: u8 = 24;
const P_UPI: u8 = 25;
const P_EMAIL: u8 = 26;
const P_MAC: u8 = 40;
const P_IPV6: u8 = 41;
const P_IPV4: u8 = 42;
const P_PHONE_IN: u8 = 50;
const P_PHONE: u8 = 51;

/// Every rule in the library, grouped by the detector key that enables it.
pub static REGISTRY: &[(&str, &[Rule])] = &[
    (
        "email",
        &[checked(
            "email",
            r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?\.[A-Za-z]{2,24}\b",
            &[],
            P_EMAIL,
            MaskKind::Email,
            validate::email,
        )],
    ),
    (
        "phone",
        &[
            // +country (space/dot/dash) NNN NNN NNNN
            rule(
                "phone",
                r"\+[1-9]\d{0,2}[ .\-]?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}\b",
                &[],
                P_PHONE,
                MaskKind::Tail4,
            ),
            // Bare E.164
            rule("phone", r"\+[1-9]\d{7,14}\b", &[], P_PHONE, MaskKind::Tail4),
            // NNN-NNN-NNNN / NNN.NNN.NNNN / NNN NNN NNNN
            checked(
                "phone",
                r"\b\d{3}[ .\-]\d{3}[ .\-]\d{4}\b",
                &[],
                P_PHONE,
                MaskKind::Tail4,
                validate::word_start,
            ),
            // (NNN) NNN-NNNN
            rule(
                "phone",
                r"\(\d{3}\)[ .\-]?\d{3}[ .\-]?\d{4}\b",
                &[],
                P_PHONE,
                MaskKind::Tail4,
            ),
        ],
    ),
    (
        "phone_in",
        &[
            rule(
                "phone_in",
                r"\+91[ .\-]?[6-9]\d{9}\b",
                &["+91"],
                P_PHONE_IN,
                MaskKind::Tail4,
            ),
            checked(
                "phone_in",
                r"\b0?[6-9]\d{9}\b",
                &[],
                P_PHONE_IN,
                MaskKind::Tail4,
                validate::word_start,
            ),
        ],
    ),
    (
        "credit_card",
        &[checked(
            "credit_card",
            r"\b\d(?:[ \-]?\d){12,18}\b",
            &[],
            P_CARD,
            MaskKind::Tail4,
            validate::credit_card,
        )],
    ),
    (
        "aadhaar",
        &[checked(
            "aadhaar",
            r"\b[2-9]\d{3}[ \-]?\d{4}[ \-]?\d{4}\b",
            &[],
            P_AADHAAR,
            MaskKind::Tail4,
            validate::aadhaar,
        )],
    ),
    (
        "pan",
        &[checked(
            "pan",
            r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
            &[],
            P_PAN,
            MaskKind::Tail4,
            validate::pan,
        )],
    ),
    (
        "upi",
        &[checked(
            "upi",
            r"\b[A-Za-z0-9][A-Za-z0-9.\-_]{1,60}@[A-Za-z]{2,64}\b",
            &[],
            P_UPI,
            MaskKind::Full,
            validate::upi_vpa,
        )],
    ),
    (
        "ssn",
        &[
            checked(
                "ssn",
                r"\b\d{3}-\d{2}-\d{4}\b",
                &[],
                P_SSN,
                MaskKind::Tail4,
                validate::ssn,
            ),
            checked(
                "ssn",
                r"\b\d{3} \d{2} \d{4}\b",
                &[],
                P_SSN,
                MaskKind::Tail4,
                validate::ssn,
            ),
        ],
    ),
    (
        "iban",
        &[checked(
            "iban",
            r"\b[A-Z]{2}\d{2}(?:[ \-]?[A-Z0-9]){11,30}\b",
            &[],
            P_IBAN,
            MaskKind::Tail4,
            validate::iban,
        )],
    ),
    (
        "ip",
        &[checked(
            "ip",
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            &[],
            P_IPV4,
            MaskKind::Tail4,
            validate::ipv4,
        )],
    ),
    (
        "ipv6",
        &[checked(
            "ipv6",
            r"(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f]{0,4})",
            &[],
            P_IPV6,
            MaskKind::Full,
            validate::ipv6,
        )],
    ),
    (
        "mac",
        &[
            rule(
                "mac",
                r"\b[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}\b",
                &[],
                P_MAC,
                MaskKind::Tail4,
            ),
            // Cisco three-group form.
            rule(
                "mac",
                r"\b[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}\b",
                &[],
                P_MAC,
                MaskKind::Tail4,
            ),
        ],
    ),
    (
        "jwt",
        &[rule(
            "jwt",
            r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*",
            &["eyJ"],
            P_JWT,
            MaskKind::Full,
        )],
    ),
    (
        "aws_key",
        &[rule(
            "aws_key",
            r"\bA(?:KIA|SIA|IDA|ROA|GPA|NPA|NVA|PKA|IPA)[0-9A-Z]{16}\b",
            &[
                "AKIA", "ASIA", "AIDA", "AROA", "AGPA", "ANPA", "ANVA", "APKA", "AIPA",
            ],
            P_AWS,
            MaskKind::Full,
        )],
    ),
    (
        "private_key",
        &[rule(
            "private_key",
            r"(?s)-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----.*?-----END[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----",
            &["-----BEGIN"],
            P_PRIVATE_KEY,
            MaskKind::Full,
        )],
    ),
    ("api_key", API_KEY_RULES),
    (
        "password_pair",
        &[
            captured_checked(
                "password_pair",
                r#"(?i)(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|token)["']?\s*[:=]\s*"([^"\n]{1,256})""#,
                PASSWORD_ANCHORS,
                P_PASSWORD,
                validate::not_redaction_token,
            ),
            captured_checked(
                "password_pair",
                r#"(?i)(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|token)["']?\s*[:=]\s*'([^'\n]{1,256})'"#,
                PASSWORD_ANCHORS,
                P_PASSWORD,
                validate::not_redaction_token,
            ),
            captured_checked(
                "password_pair",
                r#"(?i)(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|token)["']?\s*[:=]\s*([^\s,;&"'}\]]{1,256})"#,
                PASSWORD_ANCHORS,
                P_PASSWORD + 1,
                validate::not_redaction_token,
            ),
        ],
    ),
    (
        "url_credentials",
        &[captured(
            "url_credentials",
            r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@]+:([^\s/@]+)@",
            &["://"],
            P_URL_CREDS,
        )],
    ),
];

const PASSWORD_ANCHORS: &[&str] = &[
    "password", "passwd", "pwd", "secret", "apikey", "api_key", "api-key", "token",
];

/// A curated subset of gitleaks-style provider rules. Every entry here is a
/// vendor-documented, structurally unambiguous credential format — no
/// entropy heuristics, because those false-positive on hashes and UUIDs.
static API_KEY_RULES: &[Rule] = &[
    // GitHub classic PAT / OAuth / user-to-server / server-to-server / refresh
    rule(
        "api_key",
        r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // GitHub fine-grained PAT
    rule(
        "api_key",
        r"\bgithub_pat_[A-Za-z0-9_]{60,120}\b",
        &["github_pat_"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // GitLab PAT
    rule(
        "api_key",
        r"\bglpat-[A-Za-z0-9_\-]{20,64}\b",
        &["glpat-"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // Slack tokens
    rule(
        "api_key",
        r"\bxox[baprse]-[A-Za-z0-9\-]{10,72}\b",
        &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxe-"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // Slack incoming webhook
    rule(
        "api_key",
        r"https://hooks\.slack\.com/services/[A-Za-z0-9_/\-]{20,}",
        &["hooks.slack.com"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // Stripe secret / restricted / publishable
    rule(
        "api_key",
        r"\b[srp]k_(?:live|test)_[A-Za-z0-9]{16,247}\b",
        &[
            "sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_",
        ],
        P_API_KEY,
        MaskKind::Full,
    ),
    // Anthropic
    rule(
        "api_key",
        r"\bsk-ant-[A-Za-z0-9_\-]{20,120}\b",
        &["sk-ant-"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // OpenAI (classic and project-scoped)
    rule(
        "api_key",
        r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,160}\b",
        &["sk-"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // Google API key
    rule(
        "api_key",
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
        &["AIza"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // SendGrid
    rule(
        "api_key",
        r"\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b",
        &["SG."],
        P_API_KEY,
        MaskKind::Full,
    ),
    // Twilio API key / account SID
    rule(
        "api_key",
        r"\b(?:SK|AC)[0-9a-fA-F]{32}\b",
        &[],
        P_API_KEY,
        MaskKind::Full,
    ),
    // npm
    rule(
        "api_key",
        r"\bnpm_[A-Za-z0-9]{36}\b",
        &["npm_"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // PyPI upload token
    rule(
        "api_key",
        r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}",
        &["pypi-AgEIcHlwaS5vcmc"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // Shopify access tokens
    rule(
        "api_key",
        r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b",
        &["shpat_", "shpca_", "shppa_", "shpss_"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // Square
    rule(
        "api_key",
        r"\bsq0(?:atp|csp|idp)-[A-Za-z0-9_\-]{22,64}\b",
        &["sq0atp-", "sq0csp-", "sq0idp-"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // Mailgun
    rule(
        "api_key",
        r"\bkey-[0-9a-f]{32}\b",
        &["key-"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // DigitalOcean
    rule(
        "api_key",
        r"\bdop_v1_[a-f0-9]{64}\b",
        &["dop_v1_"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // Telegram bot token
    rule(
        "api_key",
        r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b",
        &[":AA"],
        P_API_KEY,
        MaskKind::Full,
    ),
    // AWS secret access key, which only has shape in context
    captured(
        "api_key",
        r#"(?i)aws[_\-]?(?:secret[_\-]?)?access[_\-]?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})"#,
        &["aws"],
        P_API_KEY,
    ),
];

/// Detector keys enabled by default: everything except the region packs.
pub const DEFAULTS: &[&str] = &[
    "email",
    "phone",
    "credit_card",
    "ssn",
    "iban",
    "ip",
    "ipv6",
    "mac",
    "jwt",
    "aws_key",
    "api_key",
    "private_key",
    "password_pair",
    "url_credentials",
];

/// The opt-in India pack (DPDP Act shaped).
pub const INDIA: &[&str] = &["phone_in", "aadhaar", "pan", "upi"];

/// Rules for a detector key, or `None` if the key is unknown.
pub fn rules_for(key: &str) -> Option<&'static [Rule]> {
    REGISTRY
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, rules)| *rules)
}

/// Every detector key, for error messages and `Scrubber.detectors`.
pub fn all_keys() -> Vec<&'static str> {
    REGISTRY.iter().map(|(k, _)| *k).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registry_pattern_compiles() {
        for (key, rules) in REGISTRY {
            for (i, r) in rules.iter().enumerate() {
                regex::Regex::new(r.pattern)
                    .unwrap_or_else(|e| panic!("{key} rule {i} failed to compile: {e}"));
            }
        }
    }

    #[test]
    fn capture_groups_exist_where_declared() {
        for (key, rules) in REGISTRY {
            for (i, r) in rules.iter().enumerate() {
                let re = regex::Regex::new(r.pattern).unwrap();
                assert!(
                    re.captures_len() > r.capture,
                    "{key} rule {i} declares capture {} but has {} groups",
                    r.capture,
                    re.captures_len() - 1
                );
            }
        }
    }

    #[test]
    fn defaults_and_india_are_registered_and_disjoint() {
        for key in DEFAULTS.iter().chain(INDIA.iter()) {
            assert!(rules_for(key).is_some(), "{key} is not in the registry");
        }
        for key in INDIA {
            assert!(!DEFAULTS.contains(key), "{key} must be opt-in");
        }
        assert_eq!(DEFAULTS.len() + INDIA.len(), REGISTRY.len());
    }

    #[test]
    fn rule_kinds_match_their_registry_key() {
        for (key, rules) in REGISTRY {
            for r in rules.iter() {
                assert_eq!(r.kind, *key);
            }
        }
    }
}
