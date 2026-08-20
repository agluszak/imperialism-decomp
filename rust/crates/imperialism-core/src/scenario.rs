use crate::*;

/// One semantic operation from a retail `Scenario/sN.scn` startup script.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScenarioInstruction {
    SetLabor {
        nation: MajorNationId,
        unskilled: i16,
        skilled: i16,
        professionals: i16,
    },
    SetProductionCapacity {
        nation: MajorNationId,
        slot: u16,
        value: i16,
    },
    SetStockpile {
        nation: MajorNationId,
        resource: ResourceKind,
        value: i16,
    },
    CreateArmy {
        province: ProvinceId,
        kind: MilitaryUnitKind,
        count: u32,
    },
    CreateCivilian {
        kind: CivilianUnitKind,
        tile: TileId,
    },
    CreateShips {
        nation: MajorNationId,
        kind: ShipType,
        zone: u16,
        count: u32,
    },
    SetTransportCapacity {
        nation: MajorNationId,
        value: i16,
    },
    SetDevelopment {
        tile: TileId,
        value: u8,
    },
    BuildDepot {
        tile: TileId,
    },
    BuildPort {
        tile: TileId,
    },
    UnlockTechnology {
        nation: MajorNationId,
        technology: Technology,
    },
    SetMarketPrice {
        commodity: TradeCommodity,
        value: i16,
    },
    SetMissionLevel {
        source: NationId,
        target: NationId,
        level: DiplomaticMissionLevel,
    },
    SetTradePolicy {
        owner: MajorNationId,
        target: NationId,
        score: TradePolicyScore,
    },
    SetTreaty {
        source: NationId,
        target: NationId,
        relationship: DiplomaticRelationship,
    },
    SetYear(i16),
    SetProvinceOwner {
        province: ProvinceId,
        nation: NationId,
    },
    SetZoneName {
        zone: u16,
        name: String,
    },
    SetCountryName {
        nation: NationId,
        name: String,
    },
    SetStanding {
        source: NationId,
        target: NationId,
        value: i16,
    },
    SetProvinceName {
        tile: TileId,
        name: String,
    },
    SetCash {
        nation: MajorNationId,
        value: i32,
    },
    SetFlag(u16),
    SetCapabilityTier {
        technology: Technology,
        value: i32,
    },
    SetNeedTarget {
        nation: MajorNationId,
        resource: ResourceKind,
        value: i16,
    },
    ClearNeedTargets {
        nation: MajorNationId,
    },
    SetCouncilState {
        decade: u8,
        state: u8,
    },
}
