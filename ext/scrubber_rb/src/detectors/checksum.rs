//! Checksum validators.
//!
//! These are what separate `scrubber_rb` from a pile of regexes: a 16-digit
//! number is only redacted as a credit card if it actually passes Luhn, and a
//! 12-digit number is only an Aadhaar if it passes Verhoeff. Shapes lie;
//! checksums do not.

/// Luhn (mod-10) checksum, used by credit / debit card PANs.
///
/// Accepts an iterator of ASCII digit characters; non-digits must already be
/// stripped by the caller.
pub fn luhn(digits: &[u8]) -> bool {
    if digits.len() < 12 {
        return false;
    }
    let mut sum: u32 = 0;
    // Double every second digit counting from the right.
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = u32::from(*d);
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

// Verhoeff tables. `D` is the dihedral group D5 multiplication table, `P` the
// permutation table, `INV` the multiplicative inverse table.
#[rustfmt::skip]
const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

#[rustfmt::skip]
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Verhoeff checksum, used by the Indian Aadhaar number.
pub fn verhoeff(digits: &[u8]) -> bool {
    let mut c: u8 = 0;
    for (i, d) in digits.iter().rev().enumerate() {
        if *d > 9 {
            return false;
        }
        c = VERHOEFF_D[c as usize][VERHOEFF_P[i % 8][*d as usize] as usize];
    }
    c == 0
}

/// ISO 7064 mod-97-10, used by IBAN account numbers.
///
/// `s` is the raw IBAN with separators already stripped and letters uppercased.
pub fn iban_mod97(s: &[u8]) -> bool {
    if s.len() < 15 || s.len() > 34 {
        return false;
    }
    // Move the first four characters to the end, then map A-Z to 10-35 and take
    // the whole thing mod 97 incrementally (the number is far too big for u128).
    let rotated = s[4..].iter().chain(s[..4].iter());
    let mut rem: u32 = 0;
    for ch in rotated {
        let val = match ch {
            b'0'..=b'9' => u32::from(ch - b'0'),
            b'A'..=b'Z' => u32::from(ch - b'A') + 10,
            _ => return false,
        };
        // Feed one or two decimal digits depending on the mapped value.
        if val >= 10 {
            rem = (rem * 100 + val) % 97;
        } else {
            rem = (rem * 10 + val) % 97;
        }
    }
    rem == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Vec<u8> {
        s.bytes()
            .filter(u8::is_ascii_digit)
            .map(|b| b - b'0')
            .collect()
    }

    #[test]
    fn luhn_known_good_vectors() {
        // Publicly published test card numbers.
        for good in [
            "4111111111111111", // Visa
            "4012888888881881", // Visa
            "5500005555555559", // Mastercard
            "5105105105105100", // Mastercard
            "378282246310005",  // Amex
            "371449635398431",  // Amex
            "6011111111111117", // Discover
            "3530111333300000", // JCB
        ] {
            assert!(luhn(&d(good)), "{good} should pass Luhn");
        }
    }

    #[test]
    fn luhn_rejects_bad_check_digits() {
        for bad in [
            "4111111111111112",
            "1234567890123456",
            "0000000000000001",
            "5500005555555558",
        ] {
            assert!(!luhn(&d(bad)), "{bad} should fail Luhn");
        }
    }

    #[test]
    fn luhn_rejects_short_input() {
        assert!(!luhn(&d("12345678901")));
    }

    // Multiplicative inverse table for D5, used only to *generate* valid test
    // vectors so the tests don't depend on hand-copied numbers.
    const INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

    fn with_check_digit(payload: &str) -> Vec<u8> {
        let mut digits = d(payload);
        let mut c: u8 = 0;
        for (i, dg) in digits.iter().rev().enumerate() {
            c = VERHOEFF_D[c as usize][VERHOEFF_P[(i + 1) % 8][*dg as usize] as usize];
        }
        digits.push(INV[c as usize]);
        digits
    }

    #[test]
    fn verhoeff_known_vectors() {
        // Verhoeff's own published example: the check digit for 236 is 3.
        assert!(verhoeff(&d("2363")));
        assert!(!verhoeff(&d("2364")));
    }

    #[test]
    fn verhoeff_accepts_generated_check_digits() {
        for payload in ["23678901234", "99988877766", "20000000000", "61234567890"] {
            let full = with_check_digit(payload);
            assert_eq!(full.len(), 12);
            assert!(verhoeff(&full), "{payload} + check digit should validate");
        }
    }

    #[test]
    fn verhoeff_rejects_transpositions_and_single_digit_errors() {
        // Verhoeff catches all single-digit errors and all adjacent transpositions.
        let base = with_check_digit("23678901234");
        assert!(verhoeff(&base));
        for i in 0..base.len() - 1 {
            if base[i] == base[i + 1] {
                continue;
            }
            let mut swapped = base.clone();
            swapped.swap(i, i + 1);
            assert!(!verhoeff(&swapped), "transposition at {i} should fail");
        }
        for i in 0..base.len() {
            let mut bumped = base.clone();
            bumped[i] = (bumped[i] + 1) % 10;
            assert!(!verhoeff(&bumped), "single-digit error at {i} should fail");
        }
    }

    #[test]
    fn iban_known_vectors() {
        for good in [
            "GB82WEST12345698765432",
            "DE89370400440532013000",
            "FR1420041010050500013M02606",
            "NL91ABNA0417164300",
            "CH9300762011623852957",
        ] {
            assert!(iban_mod97(good.as_bytes()), "{good} should pass mod-97");
        }
    }

    #[test]
    fn iban_rejects_bad_checksums() {
        for bad in [
            "GB82WEST12345698765431",
            "DE89370400440532013001",
            "XX00NOTANIBANATALL0000",
        ] {
            assert!(!iban_mod97(bad.as_bytes()), "{bad} should fail mod-97");
        }
    }

    #[test]
    fn iban_rejects_out_of_range_lengths() {
        assert!(!iban_mod97(b"GB82WEST"));
        assert!(!iban_mod97(&[b'A'; 40]));
    }
}
