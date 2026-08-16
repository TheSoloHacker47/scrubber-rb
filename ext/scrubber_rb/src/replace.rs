//! Replacement strategies: what actually goes into the output where a match was.

use sha2::{Digest, Sha256};

/// How `:mask` should partially reveal a value. Secrets get `Full` — showing
/// the last four characters of an API key is a leak, not a convenience.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaskKind {
    /// `nik@example.com` -> `n***@e***.com`
    Email,
    /// Keep the last four alphanumerics, star the rest, preserve separators.
    Tail4,
    /// Star every non-space character.
    Full,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Strategy {
    Label,
    Mask,
    Hash { salt: String },
    Remove,
}

impl Strategy {
    pub fn from_name(name: &str, salt: Option<String>) -> Option<Self> {
        match name {
            "label" => Some(Strategy::Label),
            "mask" => Some(Strategy::Mask),
            "hash" => Some(Strategy::Hash {
                salt: salt.unwrap_or_default(),
            }),
            "remove" => Some(Strategy::Remove),
            _ => None,
        }
    }
}

/// Render the replacement text for one match.
pub fn render(strategy: &Strategy, kind: &str, matched: &str, mask: MaskKind, out: &mut String) {
    match strategy {
        Strategy::Remove => {}
        Strategy::Label => {
            out.push('[');
            push_label(kind, out);
            out.push(']');
        }
        Strategy::Hash { salt } => {
            out.push('[');
            push_label(kind, out);
            out.push(':');
            out.push_str(&hash_token(salt, matched));
            out.push(']');
        }
        Strategy::Mask => match mask {
            MaskKind::Email => mask_email(matched, out),
            MaskKind::Tail4 => mask_tail(matched, 4, out),
            MaskKind::Full => mask_tail(matched, 0, out),
        },
    }
}

fn push_label(kind: &str, out: &mut String) {
    for ch in kind.chars() {
        out.extend(ch.to_uppercase());
    }
}

/// sha256(salt || value), first 8 hex characters. Deterministic, so the same
/// value produces the same token across processes and days — logs stay
/// correlatable without holding the value.
pub fn hash_token(salt: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut s = String::with_capacity(8);
    for byte in &digest[..4] {
        s.push(char::from_digit(u32::from(byte >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap());
    }
    s
}

/// `nikhil@example.co.uk` -> `n*****@e******.co.uk`
fn mask_email(value: &str, out: &mut String) {
    let Some((local, domain)) = value.rsplit_once('@') else {
        mask_tail(value, 0, out);
        return;
    };
    push_first_then_stars(local, out);
    out.push('@');
    match domain.split_once('.') {
        Some((host, rest)) => {
            push_first_then_stars(host, out);
            out.push('.');
            out.push_str(rest);
        }
        None => push_first_then_stars(domain, out),
    }
}

fn push_first_then_stars(s: &str, out: &mut String) {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => {
            out.push(first);
            for _ in chars {
                out.push('*');
            }
        }
        None => out.push('*'),
    }
}

/// Star every alphanumeric except the last `keep`, preserving separators so
/// `4111 1111 1111 1111` stays visually a card: `**** **** **** 1111`.
fn mask_tail(value: &str, keep: usize, out: &mut String) {
    let total = value.chars().filter(|c| c.is_alphanumeric()).count();
    let reveal_from = total.saturating_sub(keep);
    let mut seen = 0;
    for ch in value.chars() {
        if ch.is_alphanumeric() {
            if seen >= reveal_from {
                out.push(ch);
            } else {
                out.push('*');
            }
            seen += 1;
        } else {
            out.push(ch);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(strategy: &Strategy, kind: &str, value: &str, mask: MaskKind) -> String {
        let mut s = String::new();
        render(strategy, kind, value, mask, &mut s);
        s
    }

    #[test]
    fn label_uppercases_the_detector_key() {
        assert_eq!(
            rendered(&Strategy::Label, "credit_card", "x", MaskKind::Tail4),
            "[CREDIT_CARD]"
        );
        assert_eq!(
            rendered(&Strategy::Label, "email", "x", MaskKind::Email),
            "[EMAIL]"
        );
    }

    #[test]
    fn remove_emits_nothing() {
        assert_eq!(
            rendered(&Strategy::Remove, "email", "a@b.com", MaskKind::Email),
            ""
        );
    }

    #[test]
    fn hash_is_deterministic_and_salt_sensitive() {
        let a = Strategy::Hash {
            salt: String::new(),
        };
        let b = Strategy::Hash {
            salt: "pepper".into(),
        };
        let first = rendered(&a, "email", "nik@example.com", MaskKind::Email);
        let second = rendered(&a, "email", "nik@example.com", MaskKind::Email);
        assert_eq!(first, second);
        assert_ne!(
            first,
            rendered(&b, "email", "nik@example.com", MaskKind::Email)
        );
        assert!(first.starts_with("[EMAIL:") && first.ends_with(']'));
        assert_eq!(first.len(), "[EMAIL:".len() + 8 + 1);
    }

    #[test]
    fn mask_email_keeps_shape() {
        assert_eq!(
            rendered(&Strategy::Mask, "email", "nik@example.com", MaskKind::Email),
            "n**@e******.com"
        );
        assert_eq!(
            rendered(&Strategy::Mask, "email", "a@b.co.uk", MaskKind::Email),
            "a@b.co.uk"
        );
    }

    #[test]
    fn mask_card_preserves_grouping() {
        assert_eq!(
            rendered(
                &Strategy::Mask,
                "credit_card",
                "4111 1111 1111 1111",
                MaskKind::Tail4
            ),
            "**** **** **** 1111"
        );
        assert_eq!(
            rendered(
                &Strategy::Mask,
                "credit_card",
                "4111111111111111",
                MaskKind::Tail4
            ),
            "************1111"
        );
    }

    #[test]
    fn mask_full_hides_everything() {
        assert_eq!(
            rendered(&Strategy::Mask, "api_key", "ghp_abc123", MaskKind::Full),
            "***_******"
        );
    }

    #[test]
    fn strategy_names_round_trip() {
        assert!(Strategy::from_name("label", None).is_some());
        assert!(Strategy::from_name("mask", None).is_some());
        assert!(Strategy::from_name("remove", None).is_some());
        assert_eq!(
            Strategy::from_name("hash", Some("s".into())),
            Some(Strategy::Hash { salt: "s".into() })
        );
        assert!(Strategy::from_name("nope", None).is_none());
    }
}
