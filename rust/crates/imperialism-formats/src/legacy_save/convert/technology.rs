use super::*;
use imperialism_core::*;

fn technology_research_status(value: u8) -> TechnologyResearchStatus {
    match value {
        0 => TechnologyResearchStatus::NotStarted,
        1 => TechnologyResearchStatus::Pending,
        2 => TechnologyResearchStatus::Researched,
        _ => panic!("unrecovered technology research status {value}"),
    }
}

pub(super) fn technology_state(legacy: &LegacyTechnologyState) -> TechnologyState {
    let status =
        |nation: usize, tech: Technology| legacy.research_status_by_nation[nation][tech as usize];
    let researched = |nation: usize, tech: Technology| status(nation, tech) == 2;
    let city_capabilities_by_nation = std::array::from_fn(|nation| CityTechnologyCapabilities {
        advanced_iron_working: researched(nation, Technology::AdvancedIronWorking),
        oil_drilling: researched(nation, Technology::OilDrilling),
        university: UniversityTechnologyState {
            available: CivilianUnitTable::from_array(
                legacy.university_recruitment_availability[nation].map(|value| value != 0),
            ),
            requirement_levels: ResourceTable::from_array(
                legacy.capability_value_by_nation_and_resource[nation].map(|value| value as u8),
            ),
        },
        primary_civilian_distance_terrain: CivilianTerrainAccess {
            hills: researched(nation, Technology::CompoundSteamEngine),
            mountain: researched(nation, Technology::Dynamite),
            swamp: researched(nation, Technology::IronRailroadBridge),
        },
        secondary_civilian_hills: researched(nation, Technology::BessemerConverter),
        secondary_civilian_swamp: researched(nation, Technology::SquareSetTimbering),
        fort_level_cap: if status(nation, Technology::LargeArtillery) != 0 {
            FortLevelCap::THREE
        } else if status(nation, Technology::BessemerConverter) != 0 {
            FortLevelCap::TWO
        } else {
            FortLevelCap::ONE
        },
    });

    TechnologyState {
        advanced_iron_working: legacy.resource_type_enabled[CityFacilitySlot::Armory as usize] != 0,
        marine_engineering: legacy.resource_type_enabled[CityFacilitySlot::PowerPlant as usize]
            != 0,
        scheduled_unlock_turn_by_technology: TechnologyTable::from_array(legacy.priority_slots),
        global_unlocks_by_technology: TechnologyTable::from_array(
            legacy.per_technology_unlock_flags.map(|value| value != 0),
        ),
        research_status_by_nation: MajorNationTable::from_array(
            legacy
                .research_status_by_nation
                .map(|row| TechnologyTable::from_array(row.map(technology_research_status))),
        ),
        industry_enabled_by_slot: legacy.resource_type_enabled.map(|value| value != 0),
        military_unit_ability_active_by_nation: MajorNationTable::from_array(
            legacy
                .ability_active_by_nation
                .map(|row| MilitaryUnitTable::from_array(row.map(|value| value != 0))),
        ),
        selected_capability_slots: MajorNationTable::from_array(
            legacy
                .nation_capability_slots
                .map(|row| row.map(super::military::military_capability_kind)),
        ),
        city_capabilities_by_nation: MajorNationTable::from_array(city_capabilities_by_nation),
        navy_growth_ship_type: ShipType::from_index(legacy.active_zone_index as u8)
            .expect("retail activeZoneIndex1d4 is a ship type"),
    }
}

pub(super) fn technology_dto(technology: &TechnologyState) -> LegacyTechnologyState {
    let mut research_status_by_nation = [[0_u8; Technology::LENGTH]; MAJOR_NATION_COUNT];
    let mut ability_active_by_nation = [[0_u8; 30]; MAJOR_NATION_COUNT];
    let mut university_recruitment_availability = [[0_u8; 9]; MAJOR_NATION_COUNT];
    let mut capability_value_by_nation_and_resource =
        [[0_i16; RESOURCE_KIND_COUNT]; MAJOR_NATION_COUNT];
    for slot in 0..MAJOR_NATION_COUNT {
        let nation = MajorNationId::new(slot as u8);
        research_status_by_nation[slot] =
            (*technology.research_status_by_nation[nation].as_array()).map(|status| match status {
                TechnologyResearchStatus::NotStarted => 0,
                TechnologyResearchStatus::Pending => 1,
                TechnologyResearchStatus::Researched => 2,
            });
        ability_active_by_nation[slot] =
            enum_u8(&technology.military_unit_ability_active_by_nation[nation]);
        let capabilities = &technology.city_capabilities_by_nation[nation];
        university_recruitment_availability[slot] = enum_u8(&capabilities.university.available);
        capability_value_by_nation_and_resource[slot] =
            resource_i16(&capabilities.university.requirement_levels);
    }
    LegacyTechnologyState {
        priority_slots: *technology.scheduled_unlock_turn_by_technology.as_array(),
        initial_capability_value_by_nation_and_resource: [[0; RESOURCE_KIND_COUNT];
            MAJOR_NATION_COUNT],
        tech_selector: 0,
        active_zone_index: technology.navy_growth_ship_type as i16,
        per_technology_unlock_flags: (*technology.global_unlocks_by_technology.as_array())
            .map(u8::from),
        resource_type_enabled: technology.industry_enabled_by_slot.map(u8::from),
        init_flags_1ab: [0; 30],
        init_flags_1c9: [0; 9],
        active_prerequisite_pair: [0; 2],
        nation_capability_slots: std::array::from_fn(|slot| {
            technology.selected_capability_slots[MajorNationId::new(slot as u8)]
                .map(|kind| kind as i16)
        }),
        research_status_by_nation,
        selected_resource_type_by_nation: [[0; 14]; MAJOR_NATION_COUNT],
        ability_active_by_nation,
        university_recruitment_availability,
        completion_year_offsets: [[0; Technology::LENGTH]; MAJOR_NATION_COUNT],
        capability_value_by_nation_and_resource,
        marker: 0,
    }
}
