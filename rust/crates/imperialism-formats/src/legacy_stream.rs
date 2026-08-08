#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum StreamError {
    #[error(
        "legacy stream ended at offset {offset:#x}: requested {requested} bytes, {remaining} remain"
    )]
    Truncated {
        offset: usize,
        requested: usize,
        remaining: usize,
    },
    #[error("MFC Unicode CString marker at offset {offset:#x} is not supported")]
    UnsupportedUnicodeString { offset: usize },
    #[error("{context}: count {value} exceeds maximum {maximum}")]
    InvalidCount {
        context: &'static str,
        value: i64,
        maximum: usize,
    },
}

pub(crate) struct LegacyStream<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> LegacyStream<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(crate) const fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], StreamError> {
        let remaining = self.bytes.len().saturating_sub(self.position);
        if length > remaining {
            return Err(StreamError::Truncated {
                offset: self.position,
                requested: length,
                remaining,
            });
        }
        let start = self.position;
        self.position += length;
        Ok(&self.bytes[start..self.position])
    }

    pub(crate) fn skip(&mut self, length: usize) -> Result<(), StreamError> {
        self.read_bytes(length).map(|_| ())
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, StreamError> {
        Ok(self.read_bytes(1)?[0])
    }

    pub(crate) fn read_i8(&mut self) -> Result<i8, StreamError> {
        Ok(self.read_u8()? as i8)
    }

    pub(crate) fn read_le_u16(&mut self) -> Result<u16, StreamError> {
        Ok(u16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }

    pub(crate) fn read_le_i16(&mut self) -> Result<i16, StreamError> {
        Ok(i16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }

    pub(crate) fn read_le_u32(&mut self) -> Result<u32, StreamError> {
        Ok(u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    pub(crate) fn read_le_i32(&mut self) -> Result<i32, StreamError> {
        Ok(i32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    pub(crate) fn read_be_i16(&mut self) -> Result<i16, StreamError> {
        Ok(i16::from_be_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }

    pub(crate) fn read_be_i32(&mut self) -> Result<i32, StreamError> {
        Ok(i32::from_be_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    /// Reads the compact length used by MFC `CArchive` for serialized ANSI `CString`s.
    ///
    /// Unicode MFC archives encode a `0xff` length escape followed by the `0xfffe`
    /// Unicode marker; that form is rejected rather than being treated as a huge
    /// ANSI byte count.
    pub(crate) fn read_mfc_string(&mut self) -> Result<Vec<u8>, StreamError> {
        let length_start = self.position;
        let byte_length = self.read_u8()?;
        let length = if byte_length != u8::MAX {
            usize::from(byte_length)
        } else {
            let word_length = self.read_le_u16()?;
            // MFC Unicode string marker (not the 0xffff extended-length escape).
            if word_length == 0xfffe {
                return Err(StreamError::UnsupportedUnicodeString {
                    offset: length_start,
                });
            }
            if word_length != u16::MAX {
                usize::from(word_length)
            } else {
                self.read_le_u32()? as usize
            }
        };
        Ok(self.read_bytes(length)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_native_and_swapped_integer_shapes() {
        let bytes = [0x34, 0x12, 0x12, 0x34, 0x78, 0x56, 0x34, 0x12];
        let mut stream = LegacyStream::new(&bytes);
        assert_eq!(stream.read_le_i16().unwrap(), 0x1234);
        assert_eq!(stream.read_be_i16().unwrap(), 0x1234);
        assert_eq!(stream.read_le_i32().unwrap(), 0x1234_5678);
    }

    #[test]
    fn reports_the_exact_truncation_offset() {
        let mut stream = LegacyStream::new(&[1, 2]);
        stream.read_u8().unwrap();
        assert_eq!(
            stream.read_le_u16().unwrap_err(),
            StreamError::Truncated {
                offset: 1,
                requested: 2,
                remaining: 1
            }
        );
    }

    #[test]
    fn reads_all_mfc_string_length_forms() {
        let bytes = [
            3, b'o', b'n', b'e', 0xff, 4, 0, b't', b'e', b's', b't', 0xff, 0xff, 0xff, 2, 0, 0, 0,
            b'o', b'k',
        ];
        let mut stream = LegacyStream::new(&bytes);
        assert_eq!(stream.read_mfc_string().unwrap(), b"one");
        assert_eq!(stream.read_mfc_string().unwrap(), b"test");
        assert_eq!(stream.read_mfc_string().unwrap(), b"ok");
    }

    #[test]
    fn rejects_mfc_unicode_string_marker() {
        let bytes = [0xff, 0xfe, 0xff, 0x01, 0x00, b'A', 0x00];
        let mut stream = LegacyStream::new(&bytes);
        assert_eq!(
            stream.read_mfc_string().unwrap_err(),
            StreamError::UnsupportedUnicodeString { offset: 0 }
        );
    }

    #[test]
    fn reads_big_endian_longs() {
        let mut stream = LegacyStream::new(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(stream.read_be_i32().unwrap(), 0x1234_5678);
    }
}
