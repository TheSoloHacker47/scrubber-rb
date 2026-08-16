//! Known UPI payment service provider (PSP) handles.
//!
//! A UPI VPA looks like `name@psp`. Matching `\w+@\w+` alone would redact half
//! of every log line, so we require the suffix to be a real PSP handle. This
//! list is deliberately a plain constant: adding a handle is a one-line PR.
//!
//! Source: NPCI's published list of live UPI members plus the handles used by
//! the major third-party apps (GPay/PhonePe/Paytm/Amazon Pay/CRED).

pub const PSP_HANDLES: &[&str] = &[
    // Third-party apps
    "ybl",         // PhonePe (Yes Bank)
    "ibl",         // PhonePe (ICICI)
    "axl",         // PhonePe (Axis)
    "okaxis",      // Google Pay
    "okhdfcbank",  // Google Pay
    "okicici",     // Google Pay
    "oksbi",       // Google Pay
    "paytm",       // Paytm
    "ptaxis",      // Paytm
    "ptyes",       // Paytm
    "ptsbi",       // Paytm
    "pthdfc",      // Paytm
    "apl",         // Amazon Pay
    "yapl",        // Amazon Pay
    "rapl",        // Amazon Pay
    "abfspay",     // Aditya Birla
    "freecharge",  // Freecharge
    "jupiteraxis", // Jupiter
    "naviaxis",    // Navi
    "fam",         // FamPay
    "goaxb",       // Google/Axis
    "superyes",    // Super.money
    "slice",       // Slice
    "timecosmos",  // CRED
    "waaxis",      // WhatsApp Pay
    "wahdfcbank",  // WhatsApp Pay
    "waicici",     // WhatsApp Pay
    "wasbi",       // WhatsApp Pay
    "mbk",         // MobiKwik
    "ikwik",       // MobiKwik
    "yesg",        // Groww
    // Banks
    "sbi",
    "hdfcbank",
    "icici",
    "axisbank",
    "kotak",
    "kmb",
    "kmbl",
    "yesbank",
    "yesbankltd",
    "idfcbank",
    "idfcfirst",
    "indus",
    "indianbank",
    "iob",
    "federal",
    "fbl",
    "pnb",
    "uboi",
    "unionbank",
    "unionbankofindia",
    "ucobank",
    "barodampay",
    "barodapay",
    "cnrb",
    "cbin",
    "citi",
    "citigold",
    "dbs",
    "dlb",
    "equitas",
    "hsbc",
    "idbi",
    "jkb",
    "jsb",
    "kbl",
    "karb",
    "lvb",
    "mahb",
    "psb",
    "rbl",
    "sc",
    "scb",
    "scbl",
    "sib",
    "srcb",
    "tjsb",
    "utbi",
    "uco",
    "aubank",
    "bandhan",
    "dcb",
    "finobank",
    "airtel",
    "aubankltd",
    "postbank",
    "allbank",
    "andb",
    "upi",
];

/// True if `suffix` (the part after `@`, case-insensitive) is a known PSP.
pub fn is_psp(suffix: &str) -> bool {
    let lowered = suffix.to_ascii_lowercase();
    PSP_HANDLES.iter().any(|h| *h == lowered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_common_handles() {
        assert!(is_psp("ybl"));
        assert!(is_psp("okaxis"));
        assert!(is_psp("PAYTM"));
        assert!(is_psp("OkHdfcBank"));
    }

    #[test]
    fn rejects_lookalikes() {
        assert!(!is_psp("gmail"));
        assert!(!is_psp("example"));
        assert!(!is_psp("yblx"));
        assert!(!is_psp(""));
    }

    #[test]
    fn handle_list_is_lowercase_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for h in PSP_HANDLES {
            assert_eq!(*h, &h.to_ascii_lowercase(), "{h} must be lowercase");
            assert!(seen.insert(*h), "{h} is duplicated");
        }
    }
}
