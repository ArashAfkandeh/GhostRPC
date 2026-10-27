//! Reads the validity period (`notBefore` / `notAfter`) of an X.509 certificate from its DER
//! encoding. Only the few ASN.1 elements in front of the validity field are walked, which avoids
//! pulling a full X.509 parser into the binary just for the panel's certificate page.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// Unix seconds.
    pub not_before: i64,
    /// Unix seconds.
    pub not_after: i64,
}

/// Splits one DER TLV: `(tag, value, rest)`.
fn read_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)?;
    let (len, hdr) = if l0 & 0x80 == 0 {
        (l0 as usize, 2usize)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | *b.get(2 + i)? as usize;
        }
        (l, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if b.len() < end {
        return None;
    }
    Some((tag, &b[hdr..end], &b[end..]))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn num(b: &[u8]) -> Option<i64> {
    let mut v = 0i64;
    for c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as i64;
    }
    Some(v)
}

/// UTCTime (`YYMMDDHHMMSSZ`, tag 0x17) or GeneralizedTime (`YYYYMMDDHHMMSSZ`, tag 0x18).
fn parse_time(tag: u8, v: &[u8]) -> Option<i64> {
    let (year, rest) = match tag {
        0x17 if v.len() >= 12 => {
            let yy = num(&v[0..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &v[2..])
        }
        0x18 if v.len() >= 14 => (num(&v[0..4])?, &v[4..]),
        _ => return None,
    };
    let (mo, d, h, mi, s) = (
        num(&rest[0..2])?,
        num(&rest[2..4])?,
        num(&rest[4..6])?,
        num(&rest[6..8])?,
        num(&rest[8..10])?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    Some(days_from_civil(year, mo, d) * 86400 + h * 3600 + mi * 60 + s)
}

/// Extracts the validity period from a DER certificate.
pub fn validity(der: &[u8]) -> Option<Validity> {
    let (t, cert, _) = read_tlv(der)?;
    if t != 0x30 {
        return None;
    }
    let (t, tbs, _) = read_tlv(cert)?;
    if t != 0x30 {
        return None;
    }
    let mut rest = tbs;
    // Optional explicit [0] version.
    let (t0, _, after) = read_tlv(rest)?;
    if t0 == 0xA0 {
        rest = after;
    }
    // serialNumber, signature AlgorithmIdentifier, issuer
    for _ in 0..3 {
        let (_, _, after) = read_tlv(rest)?;
        rest = after;
    }
    let (t, val, _) = read_tlv(rest)?;
    if t != 0x30 {
        return None;
    }
    let (t1, nb, r) = read_tlv(val)?;
    let (t2, na, _) = read_tlv(r)?;
    Some(Validity {
        not_before: parse_time(t1, nb)?,
        not_after: parse_time(t2, na)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(days_from_civil(2026, 10, 25), 20751);
    }

    #[test]
    fn time_formats() {
        // 2030-06-15 12:30:45Z
        assert_eq!(parse_time(0x17, b"300615123045Z"), Some(1_907_757_045));
        assert_eq!(parse_time(0x18, b"20300615123045Z"), Some(1_907_757_045));
        // two-digit years >= 50 are 19xx
        assert_eq!(parse_time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(parse_time(0x17, b"13"), None);
        assert_eq!(parse_time(0x05, b"300615123045Z"), None);
    }

    #[test]
    fn reads_generated_certificate() {
        let mut params = rcgen::CertificateParams::new(vec!["example.test".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2024, 1, 2);
        params.not_after = rcgen::date_time_ymd(2030, 6, 15);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let v = validity(cert.der()).expect("validity");
        assert_eq!(v.not_before, days_from_civil(2024, 1, 2) * 86400);
        assert_eq!(v.not_after, days_from_civil(2030, 6, 15) * 86400);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(validity(&[]).is_none());
        assert!(validity(&[0x30, 0x03, 0x01, 0x02, 0x03]).is_none());
        assert!(validity(b"not a certificate").is_none());
    }
}
