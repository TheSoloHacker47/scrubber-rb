//! Per-detector validators.
//!
//! A validator runs *after* a regex matches and gets the full surrounding text,
//! so it can do things the (deliberately) backtracking-free regex engine
//! cannot: run a checksum, check the character just past the match, or parse
//! the candidate with a real parser.

use std::net::Ipv6Addr;
use std::str::FromStr;

use super::checksum::{iban_mod97, luhn, verhoeff};
use super::upi;

/// What a validator sees: the matched slice plus its position in the haystack.
pub struct Candidate<'a> {
    pub text: &'a str,
    pub matched: &'a str,
    pub start: usize,
    pub end: usize,
}

impl Candidate<'_> {
    /// The byte immediately before the match, if any.
    pub fn prev_byte(&self) -> Option<u8> {
        self.text
            .as_bytes()
            .get(self.start.wrapping_sub(1))
            .copied()
    }

    /// The byte immediately after the match, if any.
    pub fn next_byte(&self) -> Option<u8> {
        self.text.as_bytes().get(self.end).copied()
    }

    fn digits(&self) -> Vec<u8> {
        self.matched
            .bytes()
            .filter(u8::is_ascii_digit)
            .map(|b| b - b'0')
            .collect()
    }
}

pub type Validator = fn(&Candidate) -> bool;

/// Credit card: 13-19 digits that pass Luhn.
pub fn credit_card(c: &Candidate) -> bool {
    let digits = c.digits();
    (13..=19).contains(&digits.len()) && luhn(&digits)
}

/// Aadhaar: exactly 12 digits, first digit 2-9, passing Verhoeff.
pub fn aadhaar(c: &Candidate) -> bool {
    let digits = c.digits();
    digits.len() == 12 && digits[0] >= 2 && verhoeff(&digits)
}

/// IBAN: registered country code, then ISO 7064 mod-97-10.
pub fn iban(c: &Candidate) -> bool {
    let compact: Vec<u8> = c
        .matched
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if compact.len() < 15 {
        return false;
    }
    let country = std::str::from_utf8(&compact[..2]).unwrap_or("");
    if !IBAN_COUNTRIES.contains(&country) {
        return false;
    }
    iban_mod97(&compact)
}

/// US SSN, rejecting the ranges the SSA never issues.
pub fn ssn(c: &Candidate) -> bool {
    let digits = c.digits();
    if digits.len() != 9 {
        return false;
    }
    let area = u16::from(digits[0]) * 100 + u16::from(digits[1]) * 10 + u16::from(digits[2]);
    let group = digits[3] * 10 + digits[4];
    let serial = u16::from(digits[5]) * 1000
        + u16::from(digits[6]) * 100
        + u16::from(digits[7]) * 10
        + u16::from(digits[8]);
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// IPv4: four octets, each 0-255, not embedded in a longer dotted run.
pub fn ipv4(c: &Candidate) -> bool {
    if matches!(c.prev_byte(), Some(b'.') | Some(b'-')) {
        return false;
    }
    if matches!(c.next_byte(), Some(b'.')) {
        return false;
    }
    let mut octets = 0;
    for part in c.matched.split('.') {
        if part.is_empty() || part.len() > 3 {
            return false;
        }
        match part.parse::<u16>() {
            Ok(v) if v <= 255 => octets += 1,
            _ => return false,
        }
    }
    octets == 4
}

/// IPv6: hand the candidate to the standard-library parser and believe it.
pub fn ipv6(c: &Candidate) -> bool {
    // The address has to be a standalone token. Without this, the `::C` in
    // `PG::ConnectionBad` parses as a perfectly valid IPv6 address, and every
    // Ruby or C++ namespace separator in your logs becomes an "address".
    if matches!(c.prev_byte(), Some(b) if b.is_ascii_alphanumeric() || b == b':') {
        return false;
    }
    if matches!(c.next_byte(), Some(b) if b.is_ascii_alphanumeric() || b == b':') {
        return false;
    }
    Ipv6Addr::from_str(c.matched).is_ok()
}

/// Reject a value that is already one of our own redaction tokens.
///
/// Scrubbing an already-scrubbed line is normal — nested middleware, a log
/// formatter running over a pre-redacted message — and it has to be a no-op.
/// Without this, `password=[PASSWORD_PAIR]` re-redacts to
/// `password=[PASSWORD_PAIR]]`, corrupting the line a little more on every pass.
///
/// The check is deliberately narrow: `[secret]` is a real value and still gets
/// redacted. Only `[UPPER_CASE]` and `[UPPER_CASE:0badc0de]` are treated as ours.
pub fn not_redaction_token(c: &Candidate) -> bool {
    let Some(body) = c
        .matched
        .strip_prefix('[')
        .map(|rest| rest.strip_suffix(']').unwrap_or(rest))
    else {
        return true;
    };

    let (label, digest) = match body.split_once(':') {
        Some((label, digest)) => (label, Some(digest)),
        None => (body, None),
    };
    let labelish = !label.is_empty()
        && label
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    let digestish = match digest {
        None => true,
        Some(d) => !d.is_empty() && d.bytes().all(|b| b.is_ascii_hexdigit()),
    };

    !(labelish && digestish)
}

/// Indian PAN: the 4th character encodes the holder type.
pub fn pan(c: &Candidate) -> bool {
    // A=AOP, B=BOI, C=Company, F=Firm, G=Government, H=HUF, J=Artificial
    // juridical person, L=Local authority, P=Individual, T=Trust, E=LLP,
    // K=Krish (trust variant).
    const ENTITY_TYPES: &[u8] = b"ABCFGHJLPTEK";
    c.matched
        .as_bytes()
        .get(3)
        .is_some_and(|b| ENTITY_TYPES.contains(b))
}

/// UPI VPA: the handle after `@` must be a known PSP, and the match must not be
/// the front half of an email address (`nik@upi.example.com`).
pub fn upi_vpa(c: &Candidate) -> bool {
    if matches!(c.next_byte(), Some(b) if b == b'.' || b == b'-' || b == b'_' || b.is_ascii_alphanumeric())
    {
        return false;
    }
    match c.matched.rsplit_once('@') {
        Some((local, handle)) => !local.is_empty() && upi::is_psp(handle),
        None => false,
    }
}

/// Email: reject the domain shapes the (deliberately loose) regex lets through.
pub fn email(c: &Candidate) -> bool {
    let Some((local, domain)) = c.matched.rsplit_once('@') else {
        return false;
    };
    if local.is_empty() || local.len() > 64 || local.starts_with('.') || local.ends_with('.') {
        return false;
    }
    if domain.contains("..") || domain.starts_with('.') || domain.starts_with('-') {
        return false;
    }
    // Don't fire on the tail of something already handled as a UPI VPA or on a
    // match that starts mid-token.
    !matches!(c.prev_byte(), Some(b) if b.is_ascii_alphanumeric() || b == b'@')
}

/// Generic guard: the match must not start in the middle of a word.
pub fn word_start(c: &Candidate) -> bool {
    !matches!(c.prev_byte(), Some(b) if b.is_ascii_alphanumeric())
}

/// Countries that have joined the IBAN registry. Checking this before mod-97
/// takes the false-positive rate on random uppercase tokens from ~1% to ~0.
const IBAN_COUNTRIES: &[&str] = &[
    "AD", "AE", "AL", "AT", "AZ", "BA", "BE", "BG", "BH", "BI", "BR", "BY", "CH", "CR", "CY", "CZ",
    "DE", "DJ", "DK", "DO", "EE", "EG", "ES", "FI", "FK", "FO", "FR", "GB", "GE", "GI", "GL", "GR",
    "GT", "HN", "HR", "HU", "IE", "IL", "IQ", "IS", "IT", "JO", "KW", "KZ", "LB", "LC", "LI", "LT",
    "LU", "LV", "LY", "MC", "MD", "ME", "MK", "MN", "MR", "MT", "MU", "NI", "NL", "NO", "OM", "PK",
    "PL", "PS", "PT", "QA", "RO", "RS", "RU", "SA", "SC", "SD", "SE", "SI", "SK", "SM", "SO", "ST",
    "SV", "TL", "TN", "TR", "UA", "VA", "VG", "XK", "YE",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn cand<'a>(text: &'a str, matched: &'a str) -> Candidate<'a> {
        let start = text.find(matched).expect("matched must occur in text");
        Candidate {
            text,
            matched,
            start,
            end: start + matched.len(),
        }
    }

    #[test]
    fn credit_card_needs_luhn_and_length() {
        assert!(credit_card(&cand(
            "x 4111 1111 1111 1111 y",
            "4111 1111 1111 1111"
        )));
        assert!(credit_card(&cand("x 378282246310005 y", "378282246310005")));
        // Right shape, wrong checksum (S3).
        assert!(!credit_card(&cand(
            "x 1234567890123456 y",
            "1234567890123456"
        )));
        // Passes Luhn but too short to be a PAN.
        assert!(!credit_card(&cand("x 000000000000 y", "000000000000")));
    }

    #[test]
    fn ssn_rejects_unissued_ranges() {
        assert!(ssn(&cand("a 123-45-6789 b", "123-45-6789")));
        assert!(!ssn(&cand("a 000-45-6789 b", "000-45-6789")));
        assert!(!ssn(&cand("a 666-45-6789 b", "666-45-6789")));
        assert!(!ssn(&cand("a 900-45-6789 b", "900-45-6789")));
        assert!(!ssn(&cand("a 123-00-6789 b", "123-00-6789")));
        assert!(!ssn(&cand("a 123-45-0000 b", "123-45-0000")));
    }

    #[test]
    fn ipv4_validates_octets_and_boundaries() {
        assert!(ipv4(&cand("from 192.168.1.10 ok", "192.168.1.10")));
        assert!(!ipv4(&cand("v 999.1.1.1 x", "999.1.1.1")));
        assert!(!ipv4(&cand("v 1.2.3.4.5 x", "1.2.3.4")));
    }

    #[test]
    fn ipv6_uses_the_real_parser() {
        assert!(ipv6(&cand(
            "src 2001:0db8:85a3:0000:0000:8a2e:0370:7334 dst",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        )));
        assert!(ipv6(&cand("host ::1 port", "::1")));
        assert!(ipv6(&cand("host fe80::1 port", "fe80::1")));
        // A timestamp is not an address.
        assert!(!ipv6(&cand("at 12:34:56 done", "12:34:56")));
        // Neither is a MAC.
        assert!(!ipv6(&cand(
            "mac 00:1a:2b:3c:4d:5e up",
            "00:1a:2b:3c:4d:5e"
        )));
        // Nor is a Ruby constant path, even though `::C` parses as an address.
        assert!(!ipv6(&cand("PG::ConnectionBad raised", "::C")));
        assert!(!ipv6(&cand("Foo::Bar::Baz", "::Ba")));
    }

    #[test]
    fn redaction_tokens_are_not_re_redacted() {
        for token in [
            "[PASSWORD_PAIR",
            "[PASSWORD_PAIR]",
            "[EMAIL:9f86d081]",
            "[API_KEY]",
        ] {
            let text = format!("password={token}");
            assert!(
                !not_redaction_token(&cand(&text, token)),
                "{token} should be recognised as ours"
            );
        }
    }

    #[test]
    fn real_bracketed_values_are_still_redacted() {
        for value in ["[secret]", "[hunter2", "[MiXeD]", "[EMAIL:zzz]"] {
            let text = format!("password={value}");
            assert!(
                not_redaction_token(&cand(&text, value)),
                "{value} is a real value, not a token"
            );
        }
    }

    #[test]
    fn pan_checks_entity_character() {
        assert!(pan(&cand("pan ABCPE1234F now", "ABCPE1234F")));
        assert!(pan(&cand("pan ABCCE1234F now", "ABCCE1234F")));
        // 'X' is not a valid holder type.
        assert!(!pan(&cand("pan ABCXE1234F now", "ABCXE1234F")));
    }

    #[test]
    fn upi_requires_known_psp_and_clean_boundary() {
        assert!(upi_vpa(&cand("pay nik@ybl now", "nik@ybl")));
        assert!(!upi_vpa(&cand("mail nik@gmail.com now", "nik@gmail")));
        // `nik@upi.example.com` is an email, not a VPA.
        assert!(!upi_vpa(&cand("mail nik@upi.example.com x", "nik@upi")));
    }

    #[test]
    fn iban_requires_registered_country() {
        assert!(iban(&cand(
            "acct GB82 WEST 1234 5698 7654 32 ok",
            "GB82 WEST 1234 5698 7654 32"
        )));
        assert!(!iban(&cand(
            "acct ZZ82WEST12345698765432 ok",
            "ZZ82WEST12345698765432"
        )));
    }
}
