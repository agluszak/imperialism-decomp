pub(crate) struct LegacyStream<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> LegacyStream<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    #[cfg(test)]
    pub(crate) const fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn read_bytes(&mut self, length: usize) -> &'a [u8] {
        let start = self.position;
        self.position += length;
        &self.bytes[start..self.position]
    }

    pub(crate) fn read_array<const N: usize>(&mut self) -> [u8; N] {
        self.read_bytes(N).try_into().unwrap()
    }

    pub(crate) fn skip(&mut self, length: usize) {
        self.read_bytes(length);
    }

    pub(crate) fn read_u8(&mut self) -> u8 {
        self.read_bytes(1)[0]
    }

    pub(crate) fn read_i8(&mut self) -> i8 {
        self.read_u8() as i8
    }

    pub(crate) fn read_le_u16(&mut self) -> u16 {
        u16::from_le_bytes(self.read_array())
    }

    pub(crate) fn read_le_i16(&mut self) -> i16 {
        i16::from_le_bytes(self.read_array())
    }

    pub(crate) fn read_le_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.read_array())
    }

    pub(crate) fn read_le_i32(&mut self) -> i32 {
        i32::from_le_bytes(self.read_array())
    }

    pub(crate) fn read_be_i16(&mut self) -> i16 {
        i16::from_be_bytes(self.read_array())
    }

    pub(crate) fn read_be_i32(&mut self) -> i32 {
        i32::from_be_bytes(self.read_array())
    }

    /// Reads the compact length used by MFC `CArchive` for serialized ANSI `CString`s.
    pub(crate) fn read_mfc_string(&mut self) -> String {
        let byte_length = self.read_u8();
        let length = if byte_length != u8::MAX {
            usize::from(byte_length)
        } else {
            let word_length = self.read_le_u16();
            if word_length != u16::MAX {
                usize::from(word_length)
            } else {
                self.read_le_u32() as usize
            }
        };
        String::from_utf8_lossy(self.read_bytes(length)).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_all_mfc_string_length_forms() {
        let bytes = [
            3, b'o', b'n', b'e', 0xff, 4, 0, b't', b'e', b's', b't', 0xff, 0xff, 0xff, 2, 0, 0, 0,
            b'o', b'k',
        ];
        let mut stream = LegacyStream::new(&bytes);
        assert_eq!(stream.read_mfc_string(), "one");
        assert_eq!(stream.read_mfc_string(), "test");
        assert_eq!(stream.read_mfc_string(), "ok");
    }
}
