use super::*;

pub(in crate::ui::city) const CITY_BUILDING_STRING_GROUP: i16 = 0x2719;
pub(in crate::ui::city) const CITY_TEXT_STRING_GROUP: i16 = 0x2738;

pub(in crate::ui::city) const UNIVERSITY_KINDS: [CivilianUnitKind; 7] = [
    CivilianUnitKind::Miner,
    CivilianUnitKind::Prospector,
    CivilianUnitKind::Farmer,
    CivilianUnitKind::Forester,
    CivilianUnitKind::Engineer,
    CivilianUnitKind::Rancher,
    CivilianUnitKind::Driller,
];

pub(in crate::ui::city) const SHIPYARD_SLOTS: [(ShipOrderSlot, f32); 8] = [
    (ShipOrderSlot::MerchantEarlyPrimary, 4.0),
    (ShipOrderSlot::MerchantEarlySecondary, 4.0),
    (ShipOrderSlot::MerchantAdvancedPrimary, 3.0),
    (ShipOrderSlot::MerchantAdvancedSecondary, 2.0),
    (ShipOrderSlot::WarshipEarlyPrimary, 4.0),
    (ShipOrderSlot::WarshipEarlySecondary, 4.0),
    (ShipOrderSlot::WarshipAdvancedPrimary, 3.0),
    (ShipOrderSlot::WarshipAdvancedSecondary, 2.0),
];

pub(in crate::ui::city) const SHIPYARD_MATERIALS: [ResourceKind; 6] = [
    ResourceKind::Fabric,
    ResourceKind::Lumber,
    ResourceKind::Arms,
    ResourceKind::Steel,
    ResourceKind::Coal,
    ResourceKind::Fuel,
];

#[derive(Clone, Copy)]
pub(in crate::ui::city) enum CityDialogKind {
    Industry(CityFacilitySlot),
    Training,
    Armory,
    University,
    Shipyard,
    Warehouse,
    FoodProcessing,
    PowerPlant,
    Transport,
    Population,
}

pub(in crate::ui::city) fn city_dialog_kind(slot: CityFacilitySlot) -> CityDialogKind {
    match slot {
        CityFacilitySlot::TextileMill
        | CityFacilitySlot::ClothingFactory
        | CityFacilitySlot::SteelMill
        | CityFacilitySlot::Metalworks
        | CityFacilitySlot::LumberMill
        | CityFacilitySlot::FurnitureFactory
        | CityFacilitySlot::OilRefinery => CityDialogKind::Industry(slot),
        CityFacilitySlot::TradeSchool => CityDialogKind::Training,
        CityFacilitySlot::Armory => CityDialogKind::Armory,
        CityFacilitySlot::University => CityDialogKind::University,
        CityFacilitySlot::Shipyard => CityDialogKind::Shipyard,
        CityFacilitySlot::Warehouse => CityDialogKind::Warehouse,
        CityFacilitySlot::FoodProcessing => CityDialogKind::FoodProcessing,
        CityFacilitySlot::PowerPlant => CityDialogKind::PowerPlant,
        CityFacilitySlot::Transport => CityDialogKind::Transport,
        CityFacilitySlot::RegionalPopulation => CityDialogKind::Population,
    }
}

pub(in crate::ui::city) fn city_oil_industry_unlocked(
    state: &GameState,
    nation: MajorNationId,
    slot: CityFacilitySlot,
) -> bool {
    city_oil_industry_unlocked_for(
        slot,
        state.technology().city_capabilities_by_nation[nation].oil_drilling,
    )
}

fn city_oil_industry_unlocked_for(slot: CityFacilitySlot, oil_drilling: bool) -> bool {
    !matches!(
        slot,
        CityFacilitySlot::OilRefinery | CityFacilitySlot::PowerPlant
    ) || oil_drilling
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::ui::city) enum CityBuildingClick {
    Construction,
    Production,
}

pub(in crate::ui::city) fn city_building_click(
    state: &GameState,
    nation: MajorNationId,
    slot: CityFacilitySlot,
) -> Option<CityBuildingClick> {
    let major = state.nations().major(nation);
    city_building_click_action(
        slot,
        major
            .city
            .building_type(slot, &major.economy, major.common.owned_region_count()),
        state.technology().city_capabilities_by_nation[nation].oil_drilling,
    )
}

fn city_building_click_action(
    slot: CityFacilitySlot,
    building_type: i16,
    oil_drilling: bool,
) -> Option<CityBuildingClick> {
    if slot.is_capacity_center() && building_type == 0 {
        return city_oil_industry_unlocked_for(slot, oil_drilling)
            .then_some(CityBuildingClick::Construction);
    }
    Some(CityBuildingClick::Production)
}

pub(in crate::ui::city) fn city_building_level(
    state: &GameState,
    nation: MajorNationId,
    slot: CityFacilitySlot,
) -> i16 {
    let major = state.nations().major(nation);
    major.city.next_building_type(
        slot,
        &major.economy,
        major.common.owned_region_count(),
        state.technology().city_capabilities_by_nation[nation].advanced_iron_working,
    )
}

pub(in crate::ui::city) fn city_is_expanding(city: &CityState, slot: CityFacilitySlot) -> bool {
    ExpandableFacility::try_from_slot(slot)
        .is_some_and(|facility| city.orders.expansions[facility].progress.quantity > 0)
}

pub(in crate::ui::city) fn city_building_picture(
    city: &CityState,
    slot: CityFacilitySlot,
    level: i16,
) -> Option<PictureId> {
    let expanding = city_is_expanding(city, slot);
    let should_draw = level >= 1
        || (ExpandableFacility::try_from_slot(slot).is_some() && expanding)
        || (slot == CityFacilitySlot::PowerPlant && city.power_plant_upgrade_queued);
    if !should_draw {
        return None;
    }
    if slot == CityFacilitySlot::PowerPlant {
        return Some(PictureId::new(if city.power_plant_upgrade_queued {
            7011
        } else {
            7027
        }));
    }
    let offset = i16::from(slot.retail());
    let normal = level == 0 || offset > 5 || !expanding || !slot.is_capacity_center();
    Some(PictureId::new(
        (if normal { 7000 } else { 7300 }) + level * 16 + offset,
    ))
}

pub(in crate::ui::city) fn city_string(
    assets: &RetailUiAssets,
    group: i16,
    zero_based_index: i16,
) -> String {
    assets
        .string(group, city_string_index(zero_based_index))
        .expect("retail English City string")
}

pub(in crate::ui::city) const fn city_string_index(zero_based_index: i16) -> i16 {
    zero_based_index + 1
}

pub(in crate::ui::city) fn format_retail_number(template: &str, value: i16) -> String {
    fill_brackets(template, &[&value.to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbuilt_oil_and_power_stay_closed_without_oil_drilling() {
        for slot in [CityFacilitySlot::OilRefinery, CityFacilitySlot::PowerPlant] {
            assert_eq!(city_building_click_action(slot, 0, false), None);
            assert!(!city_oil_industry_unlocked_for(slot, false));
        }
    }

    #[test]
    fn unbuilt_oil_and_power_open_construction_after_oil_drilling() {
        for slot in [CityFacilitySlot::OilRefinery, CityFacilitySlot::PowerPlant] {
            assert_eq!(
                city_building_click_action(slot, 0, true),
                Some(CityBuildingClick::Construction)
            );
            assert!(city_oil_industry_unlocked_for(slot, true));
        }
    }

    #[test]
    fn built_oil_and_power_open_production_even_without_oil_drilling() {
        for slot in [CityFacilitySlot::OilRefinery, CityFacilitySlot::PowerPlant] {
            assert_eq!(
                city_building_click_action(slot, 1, false),
                Some(CityBuildingClick::Production)
            );
        }
    }

    #[test]
    fn other_unbuilt_capacity_centers_open_construction() {
        assert_eq!(
            city_building_click_action(CityFacilitySlot::TextileMill, 0, false),
            Some(CityBuildingClick::Construction)
        );
        assert_eq!(
            city_building_click_action(CityFacilitySlot::Shipyard, 0, false),
            Some(CityBuildingClick::Production)
        );
    }

    #[test]
    fn beginning_of_game_does_not_open_unbuilt_oil_or_power() {
        let state = crate::ui::test_support::beginning_of_game();
        let nation = MajorNationId::from_nation(state.turn().active_nation).unwrap();
        assert_eq!(
            city_building_click(&state, nation, CityFacilitySlot::OilRefinery),
            None
        );
        assert_eq!(
            city_building_click(&state, nation, CityFacilitySlot::PowerPlant),
            None
        );
        assert!(!city_oil_industry_unlocked(
            &state,
            nation,
            CityFacilitySlot::OilRefinery
        ));
        assert_eq!(
            city_building_click(&state, nation, CityFacilitySlot::TextileMill),
            Some(CityBuildingClick::Production)
        );
    }
}
