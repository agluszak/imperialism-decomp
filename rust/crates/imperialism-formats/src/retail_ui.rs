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

/// Effective Windows `LoadStringA` / `RT_STRING` identifier (`LOWORD(uID)`).
///
/// Retail builds the value as `group * 100 + direct_index` with wrapping 16-bit
/// arithmetic — the same effective ID Win32 uses to select the string block.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StringResourceId(u16);

impl StringResourceId {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u16 {
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
        StringResourceId(self.0.wrapping_mul(100).wrapping_add(direct_index))
    }

    /// Zero-based `TSimMgr::GetString` offset (adds one before the direct lookup).
    pub const fn offset(self, zero_based: u16) -> StringResourceId {
        self.entry(zero_based.wrapping_add(1))
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
    fn string_group_builds_wrapping_u16_resource_ids() {
        assert_eq!(
            StringGroup::new(0x2719).offset(6).get(),
            0x2719u16.wrapping_mul(100).wrapping_add(7)
        );
        // High groups wrap to the same LOWORD Win32 LoadString uses.
        assert_eq!(
            StringGroup::new(0x2752).entry(1).get(),
            0x2752u16.wrapping_mul(100).wrapping_add(1)
        );
    }
}
