use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};

/// TCivUnit specialization of `TUnit::orderType` (retail string group `0x2718`).
#[derive(Clone, Copy, Debug, Enum, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CivilianUnitKind {
    Miner = 0,
    Prospector = 1,
    Farmer = 2,
    Forester = 3,
    Engineer = 4,
    Rancher = 5,
    Fisherman = 6,
    Developer = 7,
    Driller = 8,
}

pub type CivilianUnitTable<T> = EnumMap<CivilianUnitKind, T>;

impl CivilianUnitKind {
    pub fn from_retail_index(value: i16) -> Option<Self> {
        let index = usize::try_from(value).ok()?;
        (index < Self::LENGTH).then(|| Self::from_usize(index))
    }

    pub const fn retail_index(self) -> i16 {
        self as i16
    }
}

impl Serialize for CivilianUnitKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.retail_index().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CivilianUnitKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        let Ok(index) = i16::try_from(value) else {
            return Err(serde::de::Error::custom(format_args!(
                "civilian unit kind {value} is outside the retail range 0..=8"
            )));
        };
        Self::from_retail_index(index).ok_or_else(|| {
            serde::de::Error::custom(format_args!(
                "civilian unit kind {index} is outside the retail range 0..=8"
            ))
        })
    }
}

/// TMilitaryUnit specialization of `TUnit::orderType` (string group `0x2717` for
/// `0..26`; picture names identify generals `27..29`).
#[derive(Clone, Copy, Debug, Enum, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MilitaryUnitKind {
    Minutemen = 0,
    Skirmishers = 1,
    Regulars = 2,
    Grenadiers = 3,
    Hussars = 4,
    Cuirassiers = 5,
    LightArtillery = 6,
    Artillery = 7,
    Militia = 8,
    Sharpshooters = 9,
    RifleInfantry = 10,
    Guards = 11,
    Scouts = 12,
    CarbineCavalry = 13,
    FieldArtillery = 14,
    SiegeArtillery = 15,
    Conscripts = 16,
    Rangers = 17,
    Infantry = 18,
    MachineGunners = 19,
    MechanizedInfantry = 20,
    Armor = 21,
    MobileArtillery = 22,
    RailroadGuns = 23,
    Sappers = 24,
    CombatEngineers = 25,
    Saboteurs = 26,
    GeneralEra1 = 27,
    GeneralEra2 = 28,
    GeneralEra3 = 29,
}

pub type MilitaryUnitTable<T> = EnumMap<MilitaryUnitKind, T>;

impl MilitaryUnitKind {
    pub fn from_retail_index(value: i16) -> Option<Self> {
        let index = usize::try_from(value).ok()?;
        (index < Self::LENGTH).then(|| Self::from_usize(index))
    }

    pub const fn retail_index(self) -> i16 {
        self as i16
    }

    /// Retail era bucket used when spawning specialists (`entry_id / 8`).
    pub const fn spawn_era(self) -> i16 {
        self as i16 / 8
    }
}

impl Serialize for MilitaryUnitKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.retail_index().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MilitaryUnitKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        let Ok(index) = i16::try_from(value) else {
            return Err(serde::de::Error::custom(format_args!(
                "military unit kind {value} is outside the retail range 0..=29"
            )));
        };
        Self::from_retail_index(index).ok_or_else(|| {
            serde::de::Error::custom(format_args!(
                "military unit kind {index} is outside the retail range 0..=29"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_the_retail_civilian_unit_order() {
        assert_eq!(CivilianUnitKind::Miner.into_usize(), 0);
        assert_eq!(CivilianUnitKind::Engineer.into_usize(), 4);
        assert_eq!(CivilianUnitKind::Driller.into_usize(), 8);
        assert_eq!(CivilianUnitKind::LENGTH, 9);
    }

    #[test]
    fn preserves_the_retail_military_unit_order() {
        assert_eq!(MilitaryUnitKind::Minutemen.into_usize(), 0);
        assert_eq!(MilitaryUnitKind::Sappers.into_usize(), 24);
        assert_eq!(MilitaryUnitKind::GeneralEra3.into_usize(), 29);
        assert_eq!(MilitaryUnitKind::LENGTH, 30);
        assert_eq!(MilitaryUnitKind::Sappers.spawn_era(), 3);
    }

    #[test]
    fn unit_kinds_round_trip_as_retail_indices() {
        let json = serde_json::to_string(&MilitaryUnitKind::Sappers).unwrap();
        assert_eq!(json, "24");
        assert_eq!(
            serde_json::from_str::<MilitaryUnitKind>("24").unwrap(),
            MilitaryUnitKind::Sappers
        );
        assert_eq!(
            serde_json::from_str::<CivilianUnitKind>("4").unwrap(),
            CivilianUnitKind::Engineer
        );
    }
}
