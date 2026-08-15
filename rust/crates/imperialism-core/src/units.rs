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
    pub const ALL: [Self; 9] = [
        Self::Miner,
        Self::Prospector,
        Self::Farmer,
        Self::Forester,
        Self::Engineer,
        Self::Rancher,
        Self::Fisherman,
        Self::Developer,
        Self::Driller,
    ];
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

    pub(crate) fn arms_required(self) -> i32 {
        ARMS_BY_MILITARY_UNIT[self]
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
    pub(crate) id: MilitaryUnitId,
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
        id: MilitaryUnitId,
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
            id,
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

    pub const fn id(&self) -> MilitaryUnitId {
        self.id
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
}

impl MilitaryOrderCode {
    pub fn from_retail(value: i32) -> Self {
        match value {
            0 => Self::Idle,
            1 => Self::Redeploy,
            2 => Self::Sleep,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CivilianUnitState {
    pub(crate) id: CivilianUnitId,
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

impl<'de> Deserialize<'de> for CivilianUnitState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedCivilianUnit {
            id: CivilianUnitId,
            nation: NationId,
            unit_type: CivilianUnitKind,
            location: CivilianLocation,
            order: CivilianWorkOrder,
            owner_nation: NationId,
            roster_id: i16,
            registered: bool,
        }

        let unit = SerializedCivilianUnit::deserialize(deserializer)?;
        Self::new(
            unit.id,
            unit.nation,
            unit.unit_type,
            unit.location,
            unit.order,
            unit.owner_nation,
            unit.roster_id,
            unit.registered,
        )
        .ok_or_else(|| serde::de::Error::custom("civilian order is inconsistent with location"))
    }
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
        id: CivilianUnitId,
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
            id,
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
    pub const fn id(&self) -> CivilianUnitId {
        self.id
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
