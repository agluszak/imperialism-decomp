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

pub(crate) struct LegacyWriter {
    bytes: Vec<u8>,
}

impl LegacyWriter {
    pub(crate) fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub(crate) fn write_zeros(&mut self, length: usize) {
        self.bytes.resize(self.bytes.len() + length, 0);
    }

    pub(crate) fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn write_i8(&mut self, value: i8) {
        self.write_u8(value as u8);
    }

    pub(crate) fn write_le_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub(crate) fn write_le_i16(&mut self, value: i16) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub(crate) fn write_le_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub(crate) fn write_le_i32(&mut self, value: i32) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub(crate) fn write_be_i16(&mut self, value: i16) {
        self.write_bytes(&value.to_be_bytes());
    }

    pub(crate) fn write_be_i32(&mut self, value: i32) {
        self.write_bytes(&value.to_be_bytes());
    }

    pub(crate) fn write_be_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_be_bytes());
    }

    pub(crate) fn write_f64_le(&mut self, value: f64) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub(crate) fn write_fixed_text(&mut self, text: &str, length: usize) {
        let mut bytes = vec![0; length];
        let encoded = text.as_bytes();
        let copy = encoded.len().min(length);
        bytes[..copy].copy_from_slice(&encoded[..copy]);
        self.write_bytes(&bytes);
    }

    pub(crate) fn write_mfc_string(&mut self, text: &str) {
        let bytes = text.as_bytes();
        if bytes.len() < usize::from(u8::MAX) {
            self.write_u8(bytes.len() as u8);
        } else if bytes.len() < usize::from(u16::MAX) {
            self.write_u8(u8::MAX);
            self.write_le_u16(bytes.len() as u16);
        } else {
            self.write_u8(u8::MAX);
            self.write_le_u16(u16::MAX);
            self.write_le_u32(bytes.len() as u32);
        }
        self.write_bytes(bytes);
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

    #[test]
    fn writes_all_mfc_string_length_forms() {
        let mut writer = LegacyWriter::new();
        writer.write_mfc_string("one");
        writer.write_mfc_string("test");
        writer.write_mfc_string("ok");
        let bytes = writer.into_bytes();
        let mut stream = LegacyStream::new(&bytes);
        assert_eq!(stream.read_mfc_string(), "one");
        assert_eq!(stream.read_mfc_string(), "test");
        assert_eq!(stream.read_mfc_string(), "ok");
    }
}
