use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};

/// TCivUnit specialization of `TUnit::orderType`.
#[derive(
    Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum CivilianUnitKind {
    Miner,
    Prospector,
    Farmer,
    Forester,
    Engineer,
    Rancher,
    Fisherman,
    Developer,
    Driller,
}

pub type CivilianUnitTable<T> = EnumMap<CivilianUnitKind, T>;

/// Dense retail-index array form used by the C++ `game_state` capture.
pub fn serialize_civilian_unit_table<T, S>(
    table: &CivilianUnitTable<T>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: serde::Serializer,
{
    use serde::ser::SerializeTuple;
    let mut tuple = serializer.serialize_tuple(CivilianUnitKind::LENGTH)?;
    for value in table.values() {
        tuple.serialize_element(value)?;
    }
    tuple.end()
}

pub fn deserialize_civilian_unit_table<'de, T, D>(
    deserializer: D,
) -> Result<CivilianUnitTable<T>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let values = <[T; CivilianUnitKind::LENGTH]>::deserialize(deserializer)?;
    Ok(EnumMap::from_array(values))
}

impl CivilianUnitKind {
    pub fn from_index(index: u8) -> Option<Self> {
        (usize::from(index) < Self::LENGTH).then(|| Self::from_usize(usize::from(index)))
    }
}

/// TMilitaryUnit specialization of `TUnit::orderType`.
#[derive(
    Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum MilitaryUnitKind {
    Minutemen,
    Skirmishers,
    Regulars,
    Grenadiers,
    Hussars,
    Cuirassiers,
    LightArtillery,
    Artillery,
    Militia,
    Sharpshooters,
    RifleInfantry,
    Guards,
    Scouts,
    CarbineCavalry,
    FieldArtillery,
    SiegeArtillery,
    Conscripts,
    Rangers,
    Infantry,
    MachineGunners,
    MechanizedInfantry,
    Armor,
    MobileArtillery,
    RailroadGuns,
    Sappers,
    CombatEngineers,
    Saboteurs,
    GeneralEra1,
    GeneralEra2,
    GeneralEra3,
}

pub type MilitaryUnitTable<T> = EnumMap<MilitaryUnitKind, T>;

const ARMS_BY_MILITARY_UNIT: MilitaryUnitTable<i32> = MilitaryUnitTable::from_array([
    0, 1, 1, 1, 1, 1, 2, 2, 0, 2, 2, 2, 2, 2, 4, 4, 0, 4, 4, 4, 4, 10, 6, 8, 2, 2, 3, 0, 0, 0,
]);

/// Dense retail-index array form used by the C++ `game_state` capture.
pub fn serialize_military_unit_table<T, S>(
    table: &MilitaryUnitTable<T>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: serde::Serializer,
{
    use serde::ser::SerializeTuple;
    let mut tuple = serializer.serialize_tuple(MilitaryUnitKind::LENGTH)?;
    for value in table.values() {
        tuple.serialize_element(value)?;
    }
    tuple.end()
}

pub fn deserialize_military_unit_table<'de, T, D>(
    deserializer: D,
) -> Result<MilitaryUnitTable<T>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let values = <[T; MilitaryUnitKind::LENGTH]>::deserialize(deserializer)?;
    Ok(EnumMap::from_array(values))
}

impl MilitaryUnitKind {
    pub fn from_index(index: u8) -> Option<Self> {
        (usize::from(index) < Self::LENGTH).then(|| Self::from_usize(usize::from(index)))
    }

    pub const fn index(self) -> u8 {
        self as u8
    }

    pub fn spawn_era(self) -> i16 {
        (self.index() / 8) as i16
    }

    pub(crate) fn arms_required(self) -> i32 {
        ARMS_BY_MILITARY_UNIT[self]
    }


}
