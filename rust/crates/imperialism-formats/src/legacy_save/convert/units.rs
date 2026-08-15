use super::*;
use imperialism_core::*;

fn civilian_work_order(
    value: i32,
    tile: Option<TileId>,
    target: Option<TileId>,
    remaining: i16,
    topology: MapTopology,
) -> CivilianWorkOrder {
    let turns =
        || TurnsRemaining::try_new(remaining).expect("retail work order has turns remaining");
    let required_tile = || tile.expect("retail work order has a tile");
    match value {
        0 => CivilianWorkOrder::Idle,
        1 => CivilianWorkOrder::Redeploy {
            destination: target.expect("retail redeploy order has a destination"),
            turns: turns(),
        },
        2 => CivilianWorkOrder::Sleep,
        5 => CivilianWorkOrder::LayRail {
            segment: RailSegment::between(
                topology,
                target.expect("retail rail order has a source"),
                required_tile(),
            )
            .expect("retail rail order tiles are adjacent"),
            turns: turns(),
        },
        6 => {
            required_tile();
            CivilianWorkOrder::BuildDepot { turns: turns() }
        }
        7 => {
            required_tile();
            CivilianWorkOrder::BuildPort { turns: turns() }
        }
        8 => {
            required_tile();
            CivilianWorkOrder::Prospect { turns: turns() }
        }
        10 => {
            required_tile();
            CivilianWorkOrder::DevelopResource { turns: turns() }
        }
        12 => {
            required_tile();
            CivilianWorkOrder::BuildFort { turns: turns() }
        }
        13 => {
            required_tile();
            CivilianWorkOrder::PurchaseLand { turns: turns() }
        }
        _ => panic!("unrecovered civilian work order {value}"),
    }
}

impl LegacyGreatPowerPostCity {
    pub(super) fn civilian_unit_states(
        &self,
        nation: NationId,
        topology: MapTopology,
    ) -> Vec<CivilianUnitState> {
        self.civilian_units
            .iter()
            .map(|unit| {
                let unit_type = CivilianUnitKind::from_index(unit.unit_type as u8)
                    .expect("retail civilian unit type");
                let tile = optional_tile_id(i32::from(unit.tile_index));
                let target = optional_tile_id(i32::from(unit.order_target));
                CivilianUnitState::new(
                    CivilianUnitId::from_serialized(unit.persistent_id),
                    nation,
                    unit_type,
                    tile.map_or(CivilianLocation::OffMap, CivilianLocation::OnMap),
                    civilian_work_order(unit.order, tile, target, unit.remaining_turns, topology),
                    nation_id_from_retail_i16(unit.owner_nation),
                    unit.roster_id,
                    unit.registered != 0,
                )
                .expect("retail civilian order agrees with its location")
            })
            .collect()
    }
}

pub(super) fn civilian_unit_dto(
    unit: &CivilianUnitState,
    topology: MapTopology,
) -> LegacyCivilianUnit {
    let tile = option_i16(unit.location().tile().map(TileId::get));
    let (order, target, remaining) = match unit.order() {
        CivilianWorkOrder::Idle => (0, -1, 0),
        CivilianWorkOrder::Redeploy { destination, turns } => {
            (1, destination.get() as i16, turns.get())
        }
        CivilianWorkOrder::Sleep => (2, -1, 0),
        CivilianWorkOrder::LayRail { segment, turns } => {
            let _ = topology;
            (5, segment.origin().get() as i16, turns.get())
        }
        CivilianWorkOrder::BuildDepot { turns } => (6, -1, turns.get()),
        CivilianWorkOrder::BuildPort { turns } => (7, -1, turns.get()),
        CivilianWorkOrder::Prospect { turns } => (8, -1, turns.get()),
        CivilianWorkOrder::DevelopResource { turns } => (10, -1, turns.get()),
        CivilianWorkOrder::BuildFort { turns } => (12, -1, turns.get()),
        CivilianWorkOrder::PurchaseLand { turns } => (13, -1, turns.get()),
    };
    LegacyCivilianUnit {
        unit_type: i16::from(unit.unit_type() as u8),
        tile_index: tile,
        order_target: target,
        owner_nation: i16::from(unit.owner_nation().get()),
        roster_id: unit.roster_id(),
        registered: u8::from(unit.registered()),
        order,
        persistent_id: unit.id().get(),
        remaining_turns: remaining,
    }
}

pub(super) fn military_unit_dto(unit: &MilitaryUnitState) -> LegacyMilitaryUnit {
    LegacyMilitaryUnit {
        unit_type: i16::from(unit.unit_type() as u8),
        stationed_province: option_i16(unit.stationed_province().map(ProvinceId::get)),
        order_target: option_i16(unit.order().target().map(ProvinceId::get)),
        owner_nation: i16::from(unit.owner_nation().get()),
        roster_id: unit.roster_id(),
        registered: u8::from(unit.registered()),
        order: unit.order().code().get(),
        persistent_id: unit.id().get(),
        name: unit.name().to_owned(),
        order_target_tiles: unit
            .order()
            .targets()
            .map(|province| option_i16(province.map(ProvinceId::get))),
        order_target_mirrors: unit
            .order()
            .target_mirrors()
            .map(|province| option_i16(province.map(ProvinceId::get))),
        strength: unit.strength(),
        era: unit.era(),
        experience: unit.experience(),
        battle_flags: unit.battle_flags(),
    }
}

pub(super) fn ship_states(navy: &LegacyNavyState) -> Vec<ShipState> {
    navy.ships
        .iter()
        .map(|ship| ShipState {
            ship_type: ShipType::from_index(ship.ship_type as u8)
                .expect("retail ship type is in the descriptor table"),
            location: OceanZoneId::new(
                u16::try_from(ship.zone_ordinal).expect("retail ship zone ordinal is non-negative"),
            ),
            task_force: None,
            aggression: ship.aggression,
            nation: nation_id_from_retail_i16(ship.nation),
            name: ship.name.clone(),
            strength: ship.strength,
            experience: ship.experience,
            selection: ship.selection,
        })
        .collect()
}

pub(super) fn admiral_states(navy: &LegacyNavyState, ship_count: usize) -> Vec<AdmiralState> {
    navy.admirals
        .iter()
        .map(|admiral| AdmiralState {
            nation: nation_id_from_retail_i16(admiral.nation),
            name: admiral.name.clone(),
            experience: admiral.experience,
            ship: (admiral.ship_index >= 0 && (admiral.ship_index as usize) < ship_count)
                .then(|| ShipIndex::new(admiral.ship_index as usize)),
        })
        .collect()
}

pub(super) fn navy_dto(state: &GameState) -> LegacyNavyState {
    let ships: Vec<LegacyShip> = state
        .ships()
        .iter()
        .map(|ship| LegacyShip {
            ship_type: ship.ship_type as i16,
            aggression: ship.aggression,
            nation: i16::from(ship.nation.get()),
            name: ship.name.clone(),
            strength: ship.strength,
            selection: ship.selection,
            experience: ship.experience,
            zone_ordinal: i16::try_from(ship.location.get())
                .expect("ship zone ordinal fits a save short"),
        })
        .collect();
    let ship_count = i16::try_from(ships.len()).expect("ship count fits a save short");
    let admirals = state
        .admirals()
        .iter()
        .map(|admiral| LegacyAdmiral {
            nation: i16::from(admiral.nation.get()),
            name: admiral.name.clone(),
            experience: admiral.experience,
            ship_index: admiral
                .ship
                .map(|id| i16::try_from(id.get()).expect("admiral ship index fits a save short"))
                .unwrap_or(ship_count),
        })
        .collect();
    LegacyNavyState {
        ships,
        admirals,
        task_forces: Vec::new(),
    }
}

pub(super) fn navy_mission_dto(navy: &NavyMissionState) -> LegacyNavyMission {
    LegacyNavyMission {
        target_zone: option_i16(navy.target_zone.map(OceanZoneId::get)),
        resolved_port_zone: option_i16(navy.resolved_port_zone.map(OceanZoneId::get)),
        required_equipage_bits: navy.required_equipage_bits,
        ship_ordinals: Vec::new(),
        state: navy.state,
    }
}

pub(super) fn empty_navy_mission() -> LegacyNavyMission {
    LegacyNavyMission {
        target_zone: -1,
        resolved_port_zone: -1,
        required_equipage_bits: [0; 4],
        ship_ordinals: Vec::new(),
        state: 0,
    }
}

pub(super) fn ship_type_from_retail(value: i16) -> ShipType {
    match value {
        0 => ShipType::NoShip,
        1 => ShipType::Trader,
        2 => ShipType::Indiaman,
        3 => ShipType::Frigate,
        4 => ShipType::ShipOfTheLine,
        5 => ShipType::Paddlewheeler,
        6 => ShipType::Clipper,
        7 => ShipType::Raider,
        8 => ShipType::Ironclad,
        9 => ShipType::AdvancedIronclad,
        10 => ShipType::Freighter,
        11 => ShipType::ArmoredCruiser,
        12 => ShipType::Dreadnought,
        13 => ShipType::Battlecruiser,
        _ => panic!("unrecovered ship type {value}"),
    }
}
