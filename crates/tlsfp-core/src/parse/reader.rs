// ©AngelaMos | 2026
// reader.rs

use crate::error::{ParseError, Result};

/// A forward only cursor over a borrowed byte slice with bounds checked reads.
///
/// Every read advances the cursor and returns an error rather than panicking
/// when the buffer is too short. This is the foundation the whole parser stands
/// on: because the cursor can never read past the end of the slice, the parser
/// has no `unsafe`, cannot index out of bounds, and treats a truncated or
/// hostile packet as an ordinary error instead of a crash. The slices it hands
/// back borrow from the original packet buffer, so parsing copies nothing.
pub struct Reader<'pkt> {
    buf: &'pkt [u8],
    pos: usize,
}

impl<'pkt> Reader<'pkt> {
    #[must_use]
    pub const fn new(buf: &'pkt [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            return Err(ParseError::Truncated {
                needed: n,
                have: self.remaining(),
            });
        }
        Ok(())
    }

    pub fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn u16(&mut self) -> Result<u16> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Reads a 24 bit big endian length, the width TLS uses for handshake
    /// message bodies and certificate entries.
    pub fn u24(&mut self) -> Result<u32> {
        self.need(3)?;
        let v = u32::from_be_bytes([
            0,
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
        ]);
        self.pos += 3;
        Ok(v)
    }

    pub fn u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Borrows the next `n` bytes and advances past them.
    pub fn take(&mut self, n: usize) -> Result<&'pkt [u8]> {
        self.need(n)?;
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Reads a one byte length prefix, then borrows that many bytes.
    pub fn take_u8_vec(&mut self) -> Result<&'pkt [u8]> {
        let len = self.u8()? as usize;
        self.take(len)
    }

    /// Reads a two byte length prefix, then borrows that many bytes.
    pub fn take_u16_vec(&mut self) -> Result<&'pkt [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }

    /// Reads a three byte length prefix, then borrows that many bytes.
    pub fn take_u24_vec(&mut self) -> Result<&'pkt [u8]> {
        let len = self.u24()? as usize;
        self.take(len)
    }

    /// Returns a sub reader over a two byte length prefixed region.
    ///
    /// This is the workhorse for nested vectors such as the extensions block,
    /// where an outer length governs a region that itself contains a sequence of
    /// length prefixed elements.
    pub fn sub_u16_vec(&mut self) -> Result<Reader<'pkt>> {
        let len = self.u16()? as usize;
        let slice = self.take(len)?;
        Ok(Reader::new(slice))
    }

    /// Returns a sub reader over a three byte length prefixed region, the width
    /// the Certificate message uses for its certificate list.
    pub fn sub_u24_vec(&mut self) -> Result<Reader<'pkt>> {
        let len = self.u24()? as usize;
        let slice = self.take(len)?;
        Ok(Reader::new(slice))
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;
    use crate::error::ParseError;

    #[test]
    fn reads_widths_in_order() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mut r = Reader::new(&data);
        assert_eq!(r.u8().unwrap(), 0x01);
        assert_eq!(r.u16().unwrap(), 0x0203);
        assert_eq!(r.u24().unwrap(), 0x0004_0506);
        assert!(r.is_empty());
    }

    #[test]
    fn short_read_is_an_error_not_a_panic() {
        let data = [0x01];
        let mut r = Reader::new(&data);
        assert_eq!(
            r.u16().unwrap_err(),
            ParseError::Truncated { needed: 2, have: 1 }
        );
    }

    #[test]
    fn length_prefixed_take_respects_bounds() {
        let data = [0x03, 0xaa, 0xbb, 0xcc, 0xff];
        let mut r = Reader::new(&data);
        assert_eq!(r.take_u8_vec().unwrap(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(r.u8().unwrap(), 0xff);
    }

    #[test]
    fn sub_vector_isolates_a_region() {
        let data = [0x00, 0x02, 0x11, 0x22, 0x33];
        let mut r = Reader::new(&data);
        let mut sub = r.sub_u16_vec().unwrap();
        assert_eq!(sub.remaining(), 2);
        assert_eq!(sub.u16().unwrap(), 0x1122);
        assert_eq!(r.u8().unwrap(), 0x33);
    }
}
