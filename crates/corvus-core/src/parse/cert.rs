// ©AngelaMos | 2026
// cert.rs

use smallvec::SmallVec;

use crate::error::Result;
use crate::parse::reader::Reader;

/// The DER certificates carried by one TLS Certificate handshake message.
pub type CertificateList<'pkt> = SmallVec<[&'pkt [u8]; 4]>;

/// Extracts the DER encoded certificates from a Certificate message body.
///
/// The body is a three byte total length followed by entries that are each a
/// three byte length and the raw DER bytes. This is the TLS 1.2 framing; it is
/// the only framing a passive observer ever parses, because TLS 1.3 moved the
/// Certificate message inside the encrypted part of the handshake. The
/// certificates come back in wire order, leaf first, which is the order JA4X
/// reports them in.
pub fn certificate_der_list(body: &[u8]) -> Result<CertificateList<'_>> {
    let mut r = Reader::new(body);
    let mut list = r.sub_u24_vec()?;
    let mut certs = CertificateList::new();
    while !list.is_empty() {
        certs.push(list.take_u24_vec()?);
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::certificate_der_list;
    use crate::error::ParseError;

    fn message(certs: &[&[u8]]) -> Vec<u8> {
        let total: usize = certs.iter().map(|c| c.len() + 3).sum();
        let mut v = Vec::new();
        v.extend_from_slice(&u32::try_from(total).unwrap().to_be_bytes()[1..]);
        for cert in certs {
            v.extend_from_slice(&u32::try_from(cert.len()).unwrap().to_be_bytes()[1..]);
            v.extend_from_slice(cert);
        }
        v
    }

    #[test]
    fn splits_a_two_certificate_chain() {
        let body = message(&[&[0x30, 0x01, 0xaa], &[0x30, 0x02, 0xbb, 0xcc]]);
        let certs = certificate_der_list(&body).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], &[0x30, 0x01, 0xaa]);
        assert_eq!(certs[1], &[0x30, 0x02, 0xbb, 0xcc]);
    }

    #[test]
    fn truncated_entry_is_an_error_not_a_panic() {
        let mut body = message(&[&[0x30, 0x01, 0xaa]]);
        body.truncate(body.len() - 1);
        assert!(matches!(
            certificate_der_list(&body),
            Err(ParseError::Truncated { .. })
        ));
    }

    #[test]
    fn empty_chain_is_empty() {
        let certs = certificate_der_list(&[0, 0, 0]).unwrap();
        assert!(certs.is_empty());
    }
}
