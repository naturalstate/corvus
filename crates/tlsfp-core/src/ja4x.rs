// ©AngelaMos | 2026
// ja4x.rs

use smallvec::SmallVec;

use crate::der::{Der, tag};
use crate::error::{ParseError, Result};
use crate::hash::sha256_hex12;

/// Computes the JA4X fingerprint of one DER encoded X.509 certificate.
///
/// JA4X does not fingerprint the contents of a certificate. It fingerprints how
/// the certificate was built: which object identifiers appear in the issuer
/// name, which appear in the subject name, and which appear among the
/// extensions, each in the order they were written. Two certificates minted by
/// the same software with the same template share a JA4X even when every name
/// and serial differs, which is what makes it useful for clustering certificates
/// from one toolchain or one malware family.
///
/// Passively this only works on TLS 1.2 and earlier, where the certificate
/// travels in the clear. TLS 1.3 encrypts the certificate message, so a passive
/// observer never sees it.
pub fn ja4x(cert_der: &[u8]) -> Result<String> {
    let (issuer_oids, subject_oids, ext_oids) = certificate_oids(cert_der)?;

    let issuer_hash = sha256_hex12(issuer_oids.join(",").as_bytes());
    let subject_hash = sha256_hex12(subject_oids.join(",").as_bytes());
    let ext_hash = sha256_hex12(ext_oids.join(",").as_bytes());

    Ok(format!("{issuer_hash}_{subject_hash}_{ext_hash}"))
}

type OidList = SmallVec<[String; 8]>;

/// Walks a certificate down to the issuer Name, the subject Name, and the
/// extension block, the three field groups JA4X reads.
///
/// The TBSCertificate fields sit in a fixed order (RFC 5280): an optional
/// explicit version tagged context zero, then the serial number, signature
/// algorithm, issuer, validity, subject, and public key, with the extensions
/// tagged context three at the end. The walk names every field it steps over and
/// bounds checks each one, so a certificate truncated before the public key or
/// the extensions is an error rather than a panic.
fn certificate_oids(cert_der: &[u8]) -> Result<(OidList, OidList, OidList)> {
    let mut outer = Der::new(cert_der);
    let (_, certificate) = outer.read_tlv()?;
    let mut cert = Der::new(certificate);
    let (_, tbs) = cert.read_tlv()?;

    let mut fields: SmallVec<[(u8, &[u8]); 10]> = SmallVec::new();
    let mut walker = Der::new(tbs);
    while !walker.is_empty() {
        fields.push(walker.read_tlv()?);
    }

    let mut cursor = 0usize;
    if fields.first().is_some_and(|(t, _)| *t == tag::CONTEXT_0) {
        cursor += 1;
    }
    let _serial = field_content(&fields, cursor)?;
    cursor += 1;
    let _signature = field_content(&fields, cursor)?;
    cursor += 1;
    let issuer = field_content(&fields, cursor)?;
    cursor += 1;
    let _validity = field_content(&fields, cursor)?;
    cursor += 1;
    let subject = field_content(&fields, cursor)?;
    cursor += 1;

    let extensions = fields
        .get(cursor..)
        .unwrap_or(&[])
        .iter()
        .find(|(t, _)| *t == tag::CONTEXT_3)
        .map(|(_, c)| *c);

    let issuer_oids = name_oids(issuer)?;
    let subject_oids = name_oids(subject)?;
    let ext_oids = match extensions {
        Some(content) => extension_oids(content)?,
        None => OidList::new(),
    };

    Ok((issuer_oids, subject_oids, ext_oids))
}

fn field_content<'a>(fields: &[(u8, &'a [u8])], idx: usize) -> Result<&'a [u8]> {
    fields
        .get(idx)
        .map(|(_, c)| *c)
        .ok_or(ParseError::Truncated { needed: 1, have: 0 })
}

/// Collects the attribute type object identifiers from a Name, in order.
///
/// A Name is a sequence of relative distinguished names, each a set of attribute
/// type and value pairs. The fingerprint reads only the attribute type, the
/// leading object identifier of each pair, and renders it as the hex of its DER
/// content bytes, which is exactly the form JA4X hashes.
fn name_oids(name: &[u8]) -> Result<OidList> {
    let mut oids = OidList::new();
    let mut rdns = Der::new(name);
    while !rdns.is_empty() {
        let (_, rdn) = rdns.read_tlv()?;
        let mut set = Der::new(rdn);
        while !set.is_empty() {
            let (_, atv) = set.read_tlv()?;
            let mut pair = Der::new(atv);
            let (oid_tag, oid) = pair.read_tlv()?;
            if oid_tag == tag::OBJECT_IDENTIFIER {
                oids.push(hex::encode(oid));
            }
        }
    }
    Ok(oids)
}

/// Collects the extension object identifiers, in order.
fn extension_oids(context: &[u8]) -> Result<OidList> {
    let mut oids = OidList::new();
    let mut wrapper = Der::new(context);
    let (_, sequence) = wrapper.read_tlv()?;
    let mut exts = Der::new(sequence);
    while !exts.is_empty() {
        let (_, ext) = exts.read_tlv()?;
        let mut fields = Der::new(ext);
        let (oid_tag, oid) = fields.read_tlv()?;
        if oid_tag == tag::OBJECT_IDENTIFIER {
            oids.push(hex::encode(oid));
        }
    }
    Ok(oids)
}

#[cfg(test)]
mod tests {
    use super::{extension_oids, name_oids};

    fn oid(content: &[u8]) -> Vec<u8> {
        let mut v = vec![0x06, u8::try_from(content.len()).unwrap()];
        v.extend_from_slice(content);
        v
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, u8::try_from(content.len()).unwrap()];
        v.extend_from_slice(content);
        v
    }

    #[test]
    fn extracts_issuer_oids_in_order() {
        let mut name = Vec::new();
        for content in [
            &[0x55u8, 0x04, 0x06][..],
            &[0x55, 0x04, 0x0a],
            &[0x55, 0x04, 0x0b],
            &[0x55, 0x04, 0x03],
        ] {
            let atv = tlv(0x30, &{
                let mut a = oid(content);
                a.extend(tlv(0x13, b"x"));
                a
            });
            name.extend(tlv(0x31, &atv));
        }

        let oids = name_oids(&name).unwrap();
        assert_eq!(oids.as_slice(), &["550406", "55040a", "55040b", "550403"]);
    }

    #[test]
    fn certificate_ending_after_subject_is_handled_without_panic() {
        let rdn = tlv(
            0x31,
            &tlv(0x30, &{
                let mut atv = oid(&[0x55, 0x04, 0x03]);
                atv.extend(tlv(0x13, b"x"));
                atv
            }),
        );
        let tbs = tlv(
            0x30,
            &[
                tlv(0x02, &[0x01]),
                tlv(0x30, &[]),
                tlv(0x30, &rdn),
                tlv(0x30, &[]),
                tlv(0x30, &rdn),
            ]
            .concat(),
        );
        let cert = tlv(0x30, &tbs);
        assert!(super::ja4x(&cert).is_ok());
    }

    #[test]
    fn extracts_extension_oids() {
        let mut sequence = Vec::new();
        for content in [&[0x55u8, 0x1d, 0x23][..], &[0x55, 0x1d, 0x0e]] {
            let ext = tlv(0x30, &{
                let mut e = oid(content);
                e.extend(tlv(0x04, b"v"));
                e
            });
            sequence.extend(ext);
        }
        let context = tlv(0x30, &sequence);

        let oids = extension_oids(&context).unwrap();
        assert_eq!(oids.as_slice(), &["551d23", "551d0e"]);
    }
}
