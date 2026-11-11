//! Just enough DNS wire format for a filtering sinkhole: read the one question of a query and build the
//! answer for a blocked name. Everything else is forwarded untouched, so nothing here interprets answers.

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;

#[derive(Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    /// Byte length of header plus the question section, used to echo the question back.
    pub end: usize,
}

/// The single question of a standard query; `None` for responses, odd opcodes, multi-question packets,
/// compressed names in the question (never legal there) or anything truncated.
#[must_use]
pub fn parse_query(pkt: &[u8]) -> Option<Question> {
    if pkt.len() < 12 || pkt[2] & 0x80 != 0 || (pkt[2] >> 3) & 0x0f != 0 {
        return None;
    }
    if u16::from_be_bytes([pkt[4], pkt[5]]) != 1 {
        return None;
    }
    let (mut i, mut name) = (12, String::new());
    loop {
        let len = usize::from(*pkt.get(i)?);
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 || name.len() + len > 253 {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(pkt.get(i..i + len)?));
        i += len;
    }
    let qtype = u16::from_be_bytes([*pkt.get(i)?, *pkt.get(i + 1)?]);
    Some(Question {
        name,
        qtype,
        end: i + 4,
    })
}

/// The reply for a blocked name: `0.0.0.0` / `::` for address queries, NXDOMAIN for everything else
/// (so HTTPS/SVCB hints cannot route around the block).
#[must_use]
pub fn blocked_reply(query: &[u8], q: &Question) -> Vec<u8> {
    let mut out = query[..q.end].to_vec();
    out[2] = 0x80 | (query[2] & 0x01); // QR, keep RD
    let rdata_len: u16 = match q.qtype {
        TYPE_A => 4,
        TYPE_AAAA => 16,
        _ => 0,
    };
    out[3] = 0x80 | if rdata_len > 0 { 0 } else { 3 }; // RA, RCODE
    out[6..12].fill(0);
    if rdata_len > 0 {
        out[7] = 1;
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        out.extend_from_slice(&rdata_len.to_be_bytes());
        out.resize(out.len() + usize::from(rdata_len), 0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut p = vec![0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            p.push(u8::try_from(l.len()).unwrap());
            p.extend_from_slice(l.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&[0, 1]);
        p
    }

    #[test]
    fn parses_the_question_and_rejects_bad_packets() {
        let p = query("Ads.Example.com", TYPE_A);
        let q = parse_query(&p).unwrap();
        assert_eq!(
            (q.name.as_str(), q.qtype, q.end),
            ("Ads.Example.com", 1, p.len())
        );
        assert!(parse_query(&p[..15]).is_none());
        let mut resp = p.clone();
        resp[2] |= 0x80;
        assert!(parse_query(&resp).is_none());
        let mut two = p;
        two[5] = 2;
        assert!(parse_query(&two).is_none());
    }

    #[test]
    fn blocked_a_gets_zero_address_and_other_types_nxdomain() {
        let p = query("evil.example", TYPE_A);
        let q = parse_query(&p).unwrap();
        let r = blocked_reply(&p, &q);
        assert_eq!(&r[..2], &p[..2], "same id");
        assert_eq!((r[2] & 0x80, r[3] & 0x0f, r[7]), (0x80, 0, 1));
        assert_eq!(&r[r.len() - 4..], &[0, 0, 0, 0]);
        let p = query("evil.example", 65);
        let q = parse_query(&p).unwrap();
        let r = blocked_reply(&p, &q);
        assert_eq!((r[3] & 0x0f, r[7]), (3, 0));
        assert_eq!(r.len(), p.len());
    }
}
