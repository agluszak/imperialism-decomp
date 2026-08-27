use std::fmt;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PictureId(i16);

impl PictureId {
    pub const fn new(value: i16) -> Self {
        Self(value)
    }

    pub const fn offset(self, offset: i16) -> Self {
        Self(self.0 + offset)
    }

    pub const fn get(self) -> i16 {
        self.0
    }
}

impl fmt::Display for PictureId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Final Windows `LoadStringA` / `RT_STRING` identifier.
///
/// Retail builds this as `group * 100 + direct_index` with full-width integer
/// arithmetic. Win32 then selects the `RT_STRING` block from `LOWORD(id)`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StringResourceId(u32);

impl StringResourceId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for StringResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Retail string-table family used to construct [`StringResourceId`] values.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StringGroup(u16);

impl StringGroup {
    pub const fn new(group: u16) -> Self {
        Self(group)
    }

    /// Direct retail index `n` (`LoadUiStringResourceByGroupAndIndex`).
    pub const fn entry(self, direct_index: u16) -> StringResourceId {
        StringResourceId::new(self.0 as u32 * 100 + direct_index as u32)
    }

    /// Zero-based `TSimMgr::GetString` offset (adds one before the direct lookup).
    pub const fn offset(self, zero_based: u16) -> StringResourceId {
        self.entry(zero_based + 1)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FourCc([u8; 4]);

pub const OKAY: FourCc = FourCc(*b"okay");
pub const TRADE: FourCc = FourCc(*b"trad");

impl FourCc {
    pub const fn new(value: &str) -> Self {
        assert!(
            value.len() == 4,
            "FourCc tags must be exactly four characters"
        );
        let bytes = value.as_bytes();
        Self([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    pub const fn as_bytes(self) -> [u8; 4] {
        self.0
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("FourCc must be UTF-8")
    }
}

impl fmt::Debug for FourCc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FourCc").field(&self.as_str()).finish()
    }
}

impl fmt::Display for FourCc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[macro_export]
macro_rules! fourcc {
    ($lit:literal) => {{
        const TAG: $crate::FourCc = $crate::FourCc::new($lit);
        TAG
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_group_builds_full_width_resource_ids() {
        assert_eq!(StringGroup::new(0x2752).entry(1).get(), 0x2752 * 100 + 1);
        assert_eq!(StringGroup::new(0x2719).offset(6).get(), 0x2719 * 100 + 7);
        // High groups exceed 16 bits; the typed ID must retain the full value.
        assert!(StringGroup::new(0x2752).entry(1).get() > u32::from(u16::MAX));
    }

    #[test]
    fn picture_id_offset_keeps_resource_family_arithmetic() {
        assert_eq!(PictureId::new(0x266a).offset(3).get(), 0x266a + 3);
    }
}
