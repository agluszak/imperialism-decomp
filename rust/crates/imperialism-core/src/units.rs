use crate::*;
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

impl CivilianUnitKind {
    pub const LENGTH: usize = enum_map::enum_len::<Self>();
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
        let index = usize::from(index);
        (index < Self::LENGTH).then(|| Self::from_usize(index))
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

/// The five tactical AI composition classes used by land-battle scoring.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
pub enum TacticalCombatClass {
    Infantry,
    Cavalry,
    Artillery,
    Armor,
    Support,
}

pub type TacticalCombatClassTable<T> = EnumMap<TacticalCombatClass, T>;

/// Retail's ten land-unit toolbar and tactical groups.
#[derive(
    Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[repr(u8)]
pub enum ArmyUnitCategory {
    Garrison,
    LightInfantry,
    LineInfantry,
    EliteInfantry,
    LightCavalry,
    HeavyCavalry,
    FieldArtillery,
    SiegeArtillery,
    Engineers,
    Generals,
}

pub type ArmyCategoryTable<T> = EnumMap<ArmyUnitCategory, T>;

/// Dense retail-index array form used by the C++ army-toolbar capture.
pub fn deserialize_army_category_table<'de, T, D>(
    deserializer: D,
) -> Result<ArmyCategoryTable<T>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let values = <[T; ArmyUnitCategory::LENGTH]>::deserialize(deserializer)?;
    Ok(EnumMap::from_array(values))
}

/// Retail tactical category ordinal used only by native-capture JSON.
pub fn deserialize_army_unit_category<'de, D>(deserializer: D) -> Result<ArmyUnitCategory, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ordinal = u8::deserialize(deserializer)?;
    ArmyUnitCategory::from_index(ordinal)
        .ok_or_else(|| serde::de::Error::custom("unknown retail army category"))
}

impl ArmyUnitCategory {
    pub const LENGTH: usize = enum_map::enum_len::<Self>();

    pub fn from_index(index: u8) -> Option<Self> {
        let index = usize::from(index);
        (index < Self::LENGTH).then(|| Self::from_usize(index))
    }

    pub fn all() -> impl DoubleEndedIterator<Item = Self> + ExactSizeIterator {
        (0..Self::LENGTH).map(Self::from_usize)
    }
}

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
    pub const LENGTH: usize = enum_map::enum_len::<Self>();

    pub fn from_index(index: u8) -> Option<Self> {
        let index = usize::from(index);
        (index < Self::LENGTH).then(|| Self::from_usize(index))
    }

    pub(crate) fn spawn_era(self) -> i16 {
        (self as i16) / 8
    }

    pub(crate) const fn roster_name(self) -> Option<&'static str> {
        match self {
            Self::Minutemen => Some("Minutemen"),
            Self::Skirmishers => Some("Skirmishers"),
            Self::Regulars => Some("Regulars"),
            Self::Grenadiers => Some("Grenadiers"),
            Self::Hussars => Some("Hussars"),
            Self::Cuirassiers => Some("Cuirassiers"),
            Self::LightArtillery => Some("Light Artillery"),
            Self::Artillery => Some("Artillery"),
            _ => None,
        }
    }

    pub(crate) const fn upgrade_successor(self) -> Option<Self> {
        match self {
            Self::Minutemen => Some(Self::Militia),
            Self::Skirmishers => Some(Self::Sharpshooters),
            Self::Regulars => Some(Self::RifleInfantry),
            Self::Grenadiers => Some(Self::Guards),
            Self::Hussars => Some(Self::Scouts),
            Self::Cuirassiers => Some(Self::CarbineCavalry),
            Self::LightArtillery => Some(Self::FieldArtillery),
            Self::Artillery => Some(Self::SiegeArtillery),
            Self::Militia => Some(Self::Conscripts),
            Self::Sharpshooters => Some(Self::Rangers),
            Self::RifleInfantry => Some(Self::Infantry),
            Self::Guards => Some(Self::MachineGunners),
            Self::Scouts => Some(Self::MechanizedInfantry),
            Self::CarbineCavalry => Some(Self::Armor),
            Self::FieldArtillery => Some(Self::MobileArtillery),
            Self::SiegeArtillery => Some(Self::RailroadGuns),
            Self::Sappers => Some(Self::CombatEngineers),
            Self::CombatEngineers => Some(Self::Saboteurs),
            Self::GeneralEra1 => Some(Self::GeneralEra2),
            Self::GeneralEra2 => Some(Self::GeneralEra3),
            Self::Conscripts
            | Self::Rangers
            | Self::Infantry
            | Self::MachineGunners
            | Self::MechanizedInfantry
            | Self::Armor
            | Self::MobileArtillery
            | Self::RailroadGuns
            | Self::Saboteurs
            | Self::GeneralEra3 => None,
        }
    }

    pub(crate) fn army_placard_picture_id(self) -> i16 {
        const PICTURES: MilitaryUnitTable<i16> = MilitaryUnitTable::from_array([
            0x4c4, 0x4c5, 0x4c6, 0x4c7, 0x4c8, 0x4c9, 0x4ca, 0x4cb, 0x4cc, 0x4cd, 0x4ce, 0x4cf,
            0x4d0, 0x4d1, 0x4d2, 0x4d3, 0x4d4, 0x4d5, 0x4d6, 0x4d7, 0x4d8, 0x4d9, 0x4da, 0x4db,
            0x4dc, 0x4dd, 0x4de, 0x4df, 0x4e0, 0x4e1,
        ]);
        PICTURES[self]
    }

    pub(crate) fn arms_required(self) -> i32 {
        ARMS_BY_MILITARY_UNIT[self]
    }

    pub(crate) fn tactical_category(self) -> ArmyUnitCategory {
        const CATEGORY: MilitaryUnitTable<ArmyUnitCategory> = MilitaryUnitTable::from_array([
            ArmyUnitCategory::Garrison,
            ArmyUnitCategory::LightInfantry,
            ArmyUnitCategory::LineInfantry,
            ArmyUnitCategory::EliteInfantry,
            ArmyUnitCategory::LightCavalry,
            ArmyUnitCategory::HeavyCavalry,
            ArmyUnitCategory::FieldArtillery,
            ArmyUnitCategory::SiegeArtillery,
            ArmyUnitCategory::Garrison,
            ArmyUnitCategory::LightInfantry,
            ArmyUnitCategory::LineInfantry,
            ArmyUnitCategory::EliteInfantry,
            ArmyUnitCategory::LightCavalry,
            ArmyUnitCategory::HeavyCavalry,
            ArmyUnitCategory::FieldArtillery,
            ArmyUnitCategory::SiegeArtillery,
            ArmyUnitCategory::Garrison,
            ArmyUnitCategory::LightInfantry,
            ArmyUnitCategory::LineInfantry,
            ArmyUnitCategory::EliteInfantry,
            ArmyUnitCategory::LightCavalry,
            ArmyUnitCategory::HeavyCavalry,
            ArmyUnitCategory::FieldArtillery,
            ArmyUnitCategory::SiegeArtillery,
            ArmyUnitCategory::Engineers,
            ArmyUnitCategory::Engineers,
            ArmyUnitCategory::Engineers,
            ArmyUnitCategory::Generals,
            ArmyUnitCategory::Generals,
            ArmyUnitCategory::Generals,
        ]);
        CATEGORY[self]
    }

    pub(crate) fn is_militia_category(self) -> bool {
        matches!(self, Self::Minutemen | Self::Militia | Self::Conscripts)
    }

    pub(crate) fn arms_carried(self) -> i32 {
        match self {
            Self::GeneralEra1 | Self::GeneralEra2 | Self::GeneralEra3 => 1,
            other => other.arms_required(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UnitIdAllocator(i32);
impl UnitIdAllocator {
    pub const fn from_retail(value: i32) -> Self {
        Self(value)
    }
    pub const fn current(self) -> i32 {
        self.0
    }
    pub(crate) fn next_civilian(&mut self) -> CivilianUnitId {
        self.0 += 1;
        CivilianUnitId::new(self.0)
    }
    pub(crate) fn next_military(&mut self) -> MilitaryUnitId {
        self.0 += 1;
        MilitaryUnitId::new(self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MilitaryUnitState {
    pub(crate) nation: NationId,
    pub(crate) unit_type: MilitaryUnitKind,
    pub(crate) stationed_province: Option<ProvinceId>,
    pub(crate) order: MilitaryOrder,
    pub(crate) owner_nation: NationId,
    pub(crate) roster_id: i16,
    pub(crate) registered: bool,
    pub(crate) name: String,
    pub(crate) strength: i16,
    pub(crate) era: i16,
    pub(crate) experience: i16,
    pub(crate) battle_flags: i16,
}

impl MilitaryUnitState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nation: NationId,
        unit_type: MilitaryUnitKind,
        stationed_province: Option<ProvinceId>,
        order: MilitaryOrder,
        owner_nation: NationId,
        roster_id: i16,
        registered: bool,
        name: String,
        strength: i16,
        era: i16,
        experience: i16,
        battle_flags: i16,
    ) -> Self {
        Self {
            nation,
            unit_type,
            stationed_province,
            order,
            owner_nation,
            roster_id,
            registered,
            name,
            strength,
            era,
            experience,
            battle_flags,
        }
    }

    pub const fn nation(&self) -> NationId {
        self.nation
    }

    pub const fn unit_type(&self) -> MilitaryUnitKind {
        self.unit_type
    }

    pub const fn order(&self) -> &MilitaryOrder {
        &self.order
    }

    pub const fn stationed_province(&self) -> Option<ProvinceId> {
        self.stationed_province
    }

    pub const fn owner_nation(&self) -> NationId {
        self.owner_nation
    }

    pub const fn roster_id(&self) -> i16 {
        self.roster_id
    }

    pub const fn registered(&self) -> bool {
        self.registered
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn strength(&self) -> i16 {
        self.strength
    }

    pub const fn era(&self) -> i16 {
        self.era
    }

    pub const fn experience(&self) -> i16 {
        self.experience
    }

    pub const fn battle_flags(&self) -> i16 {
        self.battle_flags
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MilitaryOrder {
    Idle {
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    },
    Retail {
        code: MilitaryOrderCode,
        target: Option<ProvinceId>,
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    },
}

impl MilitaryOrder {
    pub const fn idle(
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    ) -> Self {
        Self::Idle {
            targets,
            target_mirrors,
        }
    }

    pub const fn retail(
        code: MilitaryOrderCode,
        target: Option<ProvinceId>,
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    ) -> Self {
        Self::Retail {
            code,
            target,
            targets,
            target_mirrors,
        }
    }

    pub const fn targets(&self) -> &[Option<ProvinceId>; 3] {
        match self {
            Self::Idle { targets, .. } | Self::Retail { targets, .. } => targets,
        }
    }

    pub const fn target_mirrors(&self) -> &[Option<ProvinceId>; 3] {
        match self {
            Self::Idle { target_mirrors, .. } | Self::Retail { target_mirrors, .. } => {
                target_mirrors
            }
        }
    }

    pub const fn target(&self) -> Option<ProvinceId> {
        match *self {
            Self::Idle { .. } => None,
            Self::Retail { target, .. } => target,
        }
    }

    pub const fn code(&self) -> MilitaryOrderCode {
        match *self {
            Self::Idle { .. } => MilitaryOrderCode::Idle,
            Self::Retail { code, .. } => code,
        }
    }
}

/// Land-unit order discriminator recovered from retail `UnitOrder`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum MilitaryOrderCode {
    Idle = 0,
    Redeploy = 1,
    Sleep = 2,
    Latr = 3,
    Done = 4,
}

impl MilitaryOrderCode {
    pub fn from_retail(value: i32) -> Self {
        match value {
            0 => Self::Idle,
            1 => Self::Redeploy,
            2 => Self::Sleep,
            3 => Self::Latr,
            4 => Self::Done,
            _ => panic!("unrecovered military order code {value}"),
        }
    }

    pub const fn get(self) -> i32 {
        self as i32
    }
}

impl From<MilitaryOrderCode> for i32 {
    fn from(code: MilitaryOrderCode) -> Self {
        code.get()
    }
}

impl From<i32> for MilitaryOrderCode {
    fn from(value: i32) -> Self {
        Self::from_retail(value)
    }
}

impl Serialize for MilitaryOrderCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.get().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MilitaryOrderCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        i32::deserialize(deserializer).map(Self::from_retail)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CivilianUnitState {
    pub(crate) nation: NationId,
    pub(crate) unit_type: CivilianUnitKind,
    pub(crate) location: CivilianLocation,
    pub(crate) order: CivilianWorkOrder,
    pub(crate) owner_nation: NationId,
    pub(crate) roster_id: i16,
    pub(crate) registered: bool,
    /// Per-tile prepend chain (`nextAtLocation14`). Tracked-list order stays in `civilian_units`.
    #[serde(skip)]
    pub(crate) next_on_tile: Option<CivilianUnitId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CivilianLocation {
    OnMap(TileId),
    OffMap,
}
impl CivilianLocation {
    pub const fn tile(self) -> Option<TileId> {
        match self {
            Self::OnMap(tile) => Some(tile),
            Self::OffMap => None,
        }
    }
}

impl CivilianUnitState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nation: NationId,
        unit_type: CivilianUnitKind,
        location: CivilianLocation,
        order: CivilianWorkOrder,
        owner_nation: NationId,
        roster_id: i16,
        registered: bool,
    ) -> Option<Self> {
        let valid_location = match order {
            CivilianWorkOrder::Idle
            | CivilianWorkOrder::Sleep
            | CivilianWorkOrder::Redeploy { .. } => true,
            CivilianWorkOrder::LayRail { segment, .. } => {
                location.tile() == Some(segment.destination())
            }
            _ => location.tile().is_some(),
        };
        valid_location.then_some(Self {
            nation,
            unit_type,
            location,
            order,
            owner_nation,
            roster_id,
            registered,
            next_on_tile: None,
        })
    }
    pub const fn nation(&self) -> NationId {
        self.nation
    }
    pub const fn location(&self) -> CivilianLocation {
        self.location
    }
    pub const fn unit_type(&self) -> CivilianUnitKind {
        self.unit_type
    }

    pub const fn order(&self) -> &CivilianWorkOrder {
        &self.order
    }

    pub const fn owner_nation(&self) -> NationId {
        self.owner_nation
    }

    pub const fn roster_id(&self) -> i16 {
        self.roster_id
    }

    pub const fn registered(&self) -> bool {
        self.registered
    }
}
