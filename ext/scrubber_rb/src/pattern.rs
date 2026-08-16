//! Translating user-supplied Ruby `Regexp`s into Rust `regex` syntax.
//!
//! The two dialects overlap a lot but not completely. Where Ruby has something
//! Rust's linear-time engine deliberately cannot do — backreferences, lookaround
//! — we refuse at construction time with the name of the offending construct.
//! Silently dropping a custom detector would be the worst possible failure mode
//! for a redaction library: you would ship, see no errors, and leak.

/// Why a Ruby pattern could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    /// The literal construct we found, e.g. `"(?<=" (lookbehind)`.
    pub construct: String,
    /// Why the Rust engine cannot express it.
    pub reason: &'static str,
}

/// Ruby `Regexp` option bits, as returned by `Regexp#options`.
pub const IGNORECASE: i32 = 1;
pub const EXTENDED: i32 = 2;
/// Ruby's `/m` means "dot matches newline", which Rust spells `(?s)`.
pub const MULTILINE: i32 = 4;

/// Translate a Ruby pattern source plus option bits into Rust `regex` syntax.
pub fn translate(source: &str, options: i32) -> Result<String, Unsupported> {
    reject_unsupported(source)?;

    let mut flags = String::new();
    if options & IGNORECASE != 0 {
        flags.push('i');
    }
    if options & EXTENDED != 0 {
        flags.push('x');
    }
    if options & MULTILINE != 0 {
        flags.push('s');
    }
    // Ruby's `^` and `$` are always line anchors; Rust's are text anchors
    // unless `m` is set. Setting it unconditionally preserves Ruby semantics.
    flags.push('m');

    let body = rewrite(source);
    Ok(format!("(?{flags}){body}"))
}

/// Constructs Rust's `regex` crate cannot express, in scan order.
fn reject_unsupported(source: &str) -> Result<(), Unsupported> {
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut in_class = false;

    while i < bytes.len() {
        let b = bytes[i];

        if b == b'\\' {
            if let Some(next) = bytes.get(i + 1) {
                if let Some(u) = escape_problem(*next) {
                    return Err(u);
                }
                // `\H` expands to a negated class, which cannot be nested
                // inside another character class without changing meaning.
                if *next == b'H' && in_class {
                    return Err(Unsupported {
                        construct: r"[\H]".to_string(),
                        reason: "\\H inside a character class has no Rust equivalent; \
                                 write the negation explicitly",
                    });
                }
                if (*next == b'k' || *next == b'g')
                    && matches!(bytes.get(i + 2), Some(b'<') | Some(b'\''))
                {
                    return Err(Unsupported {
                        construct: format!("\\{}<...>", *next as char),
                        reason: if *next == b'k' {
                            "named backreferences require backtracking"
                        } else {
                            "subexpression calls require backtracking"
                        },
                    });
                }
            }
            i += 2;
            continue;
        }

        if in_class {
            if b == b']' {
                in_class = false;
            }
            i += 1;
            continue;
        }

        match b {
            b'[' => in_class = true,
            b'(' => {
                let rest = &source[i..];
                if let Some(u) = group_problem(rest) {
                    return Err(u);
                }
            }
            b'*' | b'+' | b'?' | b'}' => {
                if bytes.get(i + 1) == Some(&b'+') && b != b'+' {
                    return Err(Unsupported {
                        construct: format!("{}+", b as char),
                        reason: "possessive quantifiers require backtracking",
                    });
                }
                // `++` is possessive; `+?` is lazy and fine.
                if b == b'+' && bytes.get(i + 1) == Some(&b'+') {
                    return Err(Unsupported {
                        construct: "++".to_string(),
                        reason: "possessive quantifiers require backtracking",
                    });
                }
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

fn escape_problem(next: u8) -> Option<Unsupported> {
    match next {
        b'1'..=b'9' => Some(Unsupported {
            construct: format!("\\{}", next as char),
            reason: "backreferences require backtracking",
        }),
        b'G' => Some(Unsupported {
            construct: "\\G".to_string(),
            reason: "the \\G anchor has no equivalent in a one-pass engine",
        }),
        b'K' => Some(Unsupported {
            construct: "\\K".to_string(),
            reason: "\\K is a backtracking-only match reset",
        }),
        _ => None,
    }
}

fn group_problem(rest: &str) -> Option<Unsupported> {
    const CASES: &[(&str, &str, &str)] = &[
        ("(?<=", "(?<=", "lookbehind requires backtracking"),
        ("(?<!", "(?<!", "negative lookbehind requires backtracking"),
        ("(?=", "(?=", "lookahead requires backtracking"),
        ("(?!", "(?!", "negative lookahead requires backtracking"),
        ("(?>", "(?>", "atomic groups require backtracking"),
        ("(?(", "(?(", "conditional groups require backtracking"),
        ("(?~", "(?~", "absence operators are Onigmo-only"),
    ];
    CASES.iter().find_map(|(prefix, construct, reason)| {
        rest.starts_with(prefix).then(|| Unsupported {
            construct: (*construct).to_string(),
            reason,
        })
    })
}

/// Rewrite the Ruby-only escapes that do have a Rust equivalent.
fn rewrite(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len() + 16);
    let mut i = 0;
    let mut in_class = false;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            match bytes.get(i + 1) {
                // `\h` / `\H` are Onigmo hex-digit shorthands.
                Some(b'h') => {
                    out.push_str(if in_class { "0-9a-fA-F" } else { "[0-9a-fA-F]" });
                    i += 2;
                    continue;
                }
                Some(b'H') => {
                    out.push_str(if in_class {
                        "^0-9a-fA-F"
                    } else {
                        "[^0-9a-fA-F]"
                    });
                    i += 2;
                    continue;
                }
                // `\Z` is "end of string, ignoring one trailing newline".
                Some(b'Z') if !in_class => {
                    out.push_str(r"(?:\n?\z)");
                    i += 2;
                    continue;
                }
                Some(next) => {
                    out.push('\\');
                    out.push(*next as char);
                    i += 2;
                    continue;
                }
                None => {
                    out.push('\\');
                    i += 1;
                    continue;
                }
            }
        }

        if !in_class && b == b'[' {
            in_class = true;
        } else if in_class && b == b']' {
            in_class = false;
        }

        // Copy the whole UTF-8 character, not just this byte.
        let len = utf8_len(b);
        out.push_str(&source[i..(i + len).min(source.len())]);
        i += len;
    }
    out
}

fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_patterns_pass_through_with_multiline_flag() {
        let out = translate(r"\bEMP-\d{6}\b", 0).unwrap();
        assert_eq!(out, r"(?m)\bEMP-\d{6}\b");
        assert!(regex::Regex::new(&out).is_ok());
    }

    #[test]
    fn ruby_option_bits_become_inline_flags() {
        assert!(translate("abc", IGNORECASE).unwrap().starts_with("(?im)"));
        assert!(translate("abc", MULTILINE).unwrap().starts_with("(?sm)"));
        assert!(translate("abc", EXTENDED).unwrap().starts_with("(?xm)"));
        assert!(translate("abc", IGNORECASE | MULTILINE | EXTENDED)
            .unwrap()
            .starts_with("(?ixsm)"));
    }

    #[test]
    fn hex_shorthand_is_expanded_inside_and_outside_classes() {
        assert_eq!(translate(r"\h{6}", 0).unwrap(), r"(?m)[0-9a-fA-F]{6}");
        assert_eq!(translate(r"[\h_]{6}", 0).unwrap(), r"(?m)[0-9a-fA-F_]{6}");
        assert!(regex::Regex::new(&translate(r"[\h_]{6}", 0).unwrap()).is_ok());
    }

    #[test]
    fn trailing_newline_anchor_is_translated() {
        let out = translate(r"end\Z", 0).unwrap();
        assert_eq!(out, r"(?m)end(?:\n?\z)");
        assert!(regex::Regex::new(&out).is_ok());
    }

    #[test]
    fn backreferences_are_rejected_by_name() {
        let err = translate(r"(a)\1", 0).unwrap_err();
        assert_eq!(err.construct, r"\1");
        assert!(err.reason.contains("backreference"));
    }

    #[test]
    fn lookaround_is_rejected_by_name() {
        for (src, construct) in [
            (r"(?<=x)y", "(?<="),
            (r"(?<!x)y", "(?<!"),
            (r"x(?=y)", "(?="),
            (r"x(?!y)", "(?!"),
        ] {
            let err = translate(src, 0).unwrap_err();
            assert_eq!(err.construct, construct, "for {src}");
        }
    }

    #[test]
    fn atomic_groups_and_possessive_quantifiers_are_rejected() {
        assert_eq!(translate(r"(?>a+)b", 0).unwrap_err().construct, "(?>");
        assert_eq!(translate(r"a*+b", 0).unwrap_err().construct, "*+");
        assert_eq!(translate(r"a++b", 0).unwrap_err().construct, "++");
        assert_eq!(translate(r"a?+b", 0).unwrap_err().construct, "?+");
    }

    #[test]
    fn lazy_quantifiers_are_fine() {
        assert!(translate(r"a+?b", 0).is_ok());
        assert!(translate(r"a*?b", 0).is_ok());
    }

    #[test]
    fn named_groups_are_not_mistaken_for_lookbehind() {
        let out = translate(r"(?<id>\d+)", 0).unwrap();
        assert!(regex::Regex::new(&out).is_ok());
    }

    #[test]
    fn brackets_inside_classes_do_not_confuse_the_scanner() {
        // `(` inside a character class is a literal, not a group.
        assert!(translate(r"[(?=]+", 0).is_ok());
        // An escaped bracket does not open a class.
        assert!(translate(r"\[(?=x)", 0).is_err());
    }

    #[test]
    fn multibyte_sources_survive_the_rewrite() {
        let out = translate("नमस्ते|🎉", 0).unwrap();
        assert!(out.ends_with("नमस्ते|🎉"));
        assert!(regex::Regex::new(&out).is_ok());
    }
}
