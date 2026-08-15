use super::*;
use imperialism_core::*;

impl LegacyMission {
    pub(super) fn mission_state(
        &self,
        nation: NationId,
        military_units: &[LegacyMilitaryUnit],
    ) -> MissionState {
        let (common, data) = match self {
            Self::DefendProvince { common, army } => {
                let (province, army) = army_mission_state(army, military_units);
                (
                    common,
                    MissionData::DefendProvince {
                        province: province.expect("retail defend mission has a province"),
                        army,
                    },
                )
            }
            Self::AttackProvince {
                common,
                army,
                target_province,
                amassing_province,
            } => (
                common,
                MissionData::AttackProvince(attack_mission_state(
                    army,
                    *target_province,
                    *amassing_province,
                    military_units,
                )),
            ),
            Self::Invade {
                common,
                army,
                target_province,
                amassing_province,
                beachhead,
            } => (
                common,
                MissionData::Invade {
                    attack: attack_mission_state(
                        army,
                        *target_province,
                        *amassing_province,
                        military_units,
                    ),
                    beachhead: Some(navy_mission_state(beachhead)),
                },
            ),
            Self::ControlSeaZone { common, navy } => (
                common,
                MissionData::ControlSeaZone(navy_mission_state(navy)),
            ),
            Self::Escort { common, navy } => {
                (common, MissionData::Escort(navy_mission_state(navy)))
            }
            Self::ScatteredShips { common, navy } => (
                common,
                MissionData::ScatteredShips(navy_mission_state(navy)),
            ),
            Self::Beachhead { common, navy } => {
                (common, MissionData::Beachhead(navy_mission_state(navy)))
            }
            Self::BlockadePort {
                common,
                navy,
                blockade_port_zone,
            } => (
                common,
                MissionData::BlockadePort {
                    navy: navy_mission_state(navy),
                    port_zone: optional_ocean_zone_id(*blockade_port_zone)
                        .expect("retail blockade mission has a port zone"),
                },
            ),
        };
        MissionState {
            nation,
            data,
            path_nation: optional_nation_id(common.path_marker),
            state: common.state,
            importance_bits: common.importance_bits,
            held: common.flag != 0,
            marker: common.marker,
        }
    }
}

fn army_mission_state(
    mission: &LegacyArmyMission,
    military_units: &[LegacyMilitaryUnit],
) -> (Option<ProvinceId>, ArmyMissionState) {
    let units = mission
        .unit_ordinals
        .iter()
        .map(|ordinal| {
            let unit = &military_units[(*ordinal - 1) as usize];
            MilitaryUnitId::from_serialized(unit.persistent_id)
        })
        .collect();
    (
        optional_province_id(mission.present_location),
        ArmyMissionState {
            required_equipage_bits: mission.required_equipage_bits,
            units,
        },
    )
}

fn attack_mission_state(
    mission: &LegacyArmyMission,
    target_province: i16,
    amassing_province: i16,
    military_units: &[LegacyMilitaryUnit],
) -> AttackMissionState {
    let (present_province, army) = army_mission_state(mission, military_units);
    AttackMissionState {
        army,
        present_province,
        target_province: optional_province_id(target_province)
            .expect("retail attack mission has a target province"),
        amassing_province: optional_province_id(amassing_province),
    }
}

fn navy_mission_state(mission: &LegacyNavyMission) -> NavyMissionState {
    assert!(
        mission.ship_ordinals.is_empty(),
        "semantic projection of navy mission ship references is not implemented"
    );
    NavyMissionState {
        target_zone: optional_ocean_zone_id(mission.target_zone),
        resolved_port_zone: optional_ocean_zone_id(mission.resolved_port_zone),
        // TNavyMission::ReadFrom rebuilds these runtime-only links as null.
        selected_ship: None,
        task_force: None,
        state: mission.state,
        required_equipage_bits: mission.required_equipage_bits,
        ships: Vec::new(),
    }
}

pub(super) fn mission_dto(mission: &MissionState, military: &[MilitaryUnitState]) -> LegacyMission {
    let common = LegacyMissionCommon {
        source_nation: i16::from(mission.nation.get()),
        state: mission.state,
        importance_bits: mission.importance_bits,
        flag: u8::from(mission.held),
        path_marker: option_i16(mission.path_nation.map(|id| u16::from(id.get()))),
        marker: mission.marker,
    };
    match &mission.data {
        MissionData::DefendProvince { province, army } => LegacyMission::DefendProvince {
            common,
            army: army_dto(army, Some(*province), military),
        },
        MissionData::AttackProvince(attack) => LegacyMission::AttackProvince {
            common,
            army: army_dto(&attack.army, attack.present_province, military),
            target_province: attack.target_province.get() as i16,
            amassing_province: option_i16(attack.amassing_province.map(ProvinceId::get)),
        },
        MissionData::Invade { attack, beachhead } => LegacyMission::Invade {
            common,
            army: army_dto(&attack.army, attack.present_province, military),
            target_province: attack.target_province.get() as i16,
            amassing_province: option_i16(attack.amassing_province.map(ProvinceId::get)),
            beachhead: beachhead
                .as_ref()
                .map(super::units::navy_mission_dto)
                .unwrap_or_else(super::units::empty_navy_mission),
        },
        MissionData::ControlSeaZone(navy) => LegacyMission::ControlSeaZone {
            common,
            navy: super::units::navy_mission_dto(navy),
        },
        MissionData::Escort(navy) => LegacyMission::Escort {
            common,
            navy: super::units::navy_mission_dto(navy),
        },
        MissionData::ScatteredShips(navy) => LegacyMission::ScatteredShips {
            common,
            navy: super::units::navy_mission_dto(navy),
        },
        MissionData::Beachhead(navy) => LegacyMission::Beachhead {
            common,
            navy: super::units::navy_mission_dto(navy),
        },
        MissionData::BlockadePort { navy, port_zone } => LegacyMission::BlockadePort {
            common,
            navy: super::units::navy_mission_dto(navy),
            blockade_port_zone: port_zone.get() as i16,
        },
    }
}

fn army_dto(
    army: &ArmyMissionState,
    present: Option<ProvinceId>,
    military: &[MilitaryUnitState],
) -> LegacyArmyMission {
    let unit_ordinals = army
        .units
        .iter()
        .map(|id| {
            let index = military
                .iter()
                .position(|unit| unit.id() == *id)
                .expect("mission unit belongs to the owning nation");
            (index + 1) as i16
        })
        .collect();
    LegacyArmyMission {
        present_location: option_i16(present.map(ProvinceId::get)),
        required_equipage_bits: army.required_equipage_bits,
        unit_ordinals,
    }
}

pub(super) fn military_capability_kind(value: i16) -> MilitaryUnitKind {
    MilitaryUnitKind::from_index(
        u8::try_from(value).expect("retail nationCapRows slot is a military unit kind"),
    )
    .expect("retail nationCapRows slot is a military unit kind")
}
