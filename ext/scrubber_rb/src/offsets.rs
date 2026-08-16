//! Byte offset -> character offset mapping.
//!
//! Rust works in bytes; `Scrubber#detect` promises offsets that index the Ruby
//! string. For UTF-8 those differ the moment anyone writes an emoji or a word
//! in Devanagari, so we convert here rather than making callers guess
//! (behaviour contract S11).

/// Convert byte offsets to character offsets in one pass over `bytes`.
///
/// `bytes` may contain invalid UTF-8; each invalid byte counts as one
/// character, which is exactly how Ruby counts them in a UTF-8 string.
/// `wanted` must be sorted ascending. Offsets past the end map to the total
/// character count.
pub fn to_char_offsets(bytes: &[u8], wanted: &[usize]) -> Vec<usize> {
    let mut out = Vec::with_capacity(wanted.len());
    if wanted.is_empty() {
        return out;
    }

    let mut next = 0usize;
    let mut byte_idx = 0usize;
    let mut char_idx = 0usize;

    while byte_idx <= bytes.len() {
        while next < wanted.len() && wanted[next] <= byte_idx {
            // `<=` rather than `==` so an offset landing inside a multi-byte
            // sequence (only reachable via a caller bug) degrades to the
            // character that contains it instead of running off the end.
            out.push(char_idx);
            next += 1;
        }
        if next == wanted.len() || byte_idx == bytes.len() {
            break;
        }
        byte_idx += char_len_at(bytes, byte_idx);
        char_idx += 1;
    }

    // Anything past the end of the string clamps to the character count.
    while out.len() < wanted.len() {
        out.push(char_idx);
    }
    out
}

/// Length in bytes of the character starting at `i`, treating an invalid
/// sequence as a single one-byte character.
fn char_len_at(bytes: &[u8], i: usize) -> usize {
    let b = bytes[i];
    let expected = match b {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return 1, // continuation byte or invalid lead: one "character"
    };
    if expected == 1 {
        return 1;
    }
    // Verify the continuation bytes are actually there; if not, the lead byte
    // stands alone.
    for k in 1..expected {
        match bytes.get(i + k) {
            Some(c) if (0x80..=0xbf).contains(c) => {}
            _ => return 1,
        }
    }
    expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_offsets_are_identity() {
        let s = "hello world";
        assert_eq!(to_char_offsets(s.as_bytes(), &[0, 6, 11]), vec![0, 6, 11]);
    }

    #[test]
    fn multibyte_offsets_count_characters() {
        // "🎉 नमस्ते nik@example.com"
        let s = "🎉 नमस्ते nik@example.com";
        let byte_start = s.find("nik@").unwrap();
        let char_start = s.chars().take_while(|c| *c != 'n').count();
        assert_eq!(
            to_char_offsets(s.as_bytes(), &[byte_start]),
            vec![char_start]
        );
    }

    #[test]
    fn handles_invalid_bytes_as_single_characters() {
        let mut bytes = b"ab".to_vec();
        bytes.push(0xff);
        bytes.extend_from_slice("cd".as_bytes());
        // a=0, b=1, 0xff=2, c=3, d=4
        assert_eq!(to_char_offsets(&bytes, &[0, 2, 3, 5]), vec![0, 2, 3, 5]);
    }

    #[test]
    fn truncated_sequence_does_not_run_off_the_end() {
        let bytes = vec![0xe0, 0xa4]; // start of a 3-byte sequence, truncated
        assert_eq!(to_char_offsets(&bytes, &[0, 1, 2]), vec![0, 1, 2]);
    }

    #[test]
    fn offsets_past_the_end_clamp() {
        let s = "abc";
        assert_eq!(to_char_offsets(s.as_bytes(), &[1, 99]), vec![1, 3]);
    }

    #[test]
    fn empty_request_is_empty() {
        assert!(to_char_offsets(b"abc", &[]).is_empty());
    }
}
