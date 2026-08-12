// ©AngelaMos | 2026
// der.rs

use crate::error::{ParseError, Result};

/// DER tag bytes that the certificate walk needs to recognize.
pub mod tag {
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
    pub const CONTEXT_0: u8 = 0xa0;
    pub const CONTEXT_3: u8 = 0xa3;
}

/// A minimal reader for the subset of DER that X.509 certificates use.
///
/// It decodes one tag length value triple at a time and hands back the content
/// as a borrowed slice. It deliberately does not understand the meaning of any
/// structure; the JA4X walk drives it, deciding which fields to descend into and
/// which to skip. Keeping the reader this small keeps it auditable, which
/// matters because certificate parsers are a classic source of memory safety
/// bugs and this one has no `unsafe` and cannot read out of bounds.
pub struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn byte(&mut self) -> Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(ParseError::Truncated { needed: 1, have: 0 });
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Reads one tag length value triple and returns the tag and the content
    /// slice, advancing past the whole triple.
    pub fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = self.byte()?;
        let len = self.read_length()?;
        if self.buf.len() - self.pos < len {
            return Err(ParseError::LengthOverrun {
                field: "der",
                declared: len,
                available: self.buf.len() - self.pos,
            });
        }
        let content = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, content))
    }

    fn read_length(&mut self) -> Result<usize> {
        let first = self.byte()?;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let count = (first & 0x7f) as usize;
        if count == 0 || count > core::mem::size_of::<usize>() {
            return Err(ParseError::Misaligned(count));
        }
        let mut len = 0usize;
        for _ in 0..count {
            len = (len << 8) | self.byte()? as usize;
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::{Der, tag};

    #[test]
    fn reads_short_form_sequence() {
        let data = [0x30, 0x03, 0x06, 0x01, 0x55];
        let mut der = Der::new(&data);
        let (t, content) = der.read_tlv().unwrap();
        assert_eq!(t, tag::SEQUENCE);
        assert_eq!(content, &[0x06, 0x01, 0x55]);
        assert!(der.is_empty());
    }

    #[test]
    fn reads_long_form_length() {
        let mut data = vec![0x04, 0x82, 0x01, 0x00];
        data.extend(std::iter::repeat_n(0xaa, 256));
        let mut der = Der::new(&data);
        let (_t, content) = der.read_tlv().unwrap();
        assert_eq!(content.len(), 256);
    }

    #[test]
    fn rejects_length_overrun() {
        let data = [0x06, 0x05, 0x55, 0x04];
        let mut der = Der::new(&data);
        assert!(der.read_tlv().is_err());
    }
}
