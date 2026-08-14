use super::*;

pub(in crate::ui::city) const CITY_BUILDING_STRING_GROUP: i16 = 0x2719;
pub(in crate::ui::city) const CITY_TEXT_STRING_GROUP: i16 = 0x2738;

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct CityOrderBinding {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) tag: FourCc,
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct IndustryPage {
    pub(in crate::ui::city) slot: CityFacilitySlot,
    pub(in crate::ui::city) orders: &'static [CityOrderBinding],
    pub(in crate::ui::city) stocks: &'static [(ResourceKind, FourCc, i16)],
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct ArmoryRow {
    pub(in crate::ui::city) category: MilitaryRecruitmentCategory,
    pub(in crate::ui::city) order_tag: FourCc,
    pub(in crate::ui::city) button_tag: FourCc,
}

impl ArmoryRow {
    pub(in crate::ui::city) const fn binding(self) -> CityOrderBinding {
        CityOrderBinding {
            order: CityOrderId::MilitaryRecruit(self.category),
            tag: self.order_tag,
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct UniversityRow {
    pub(in crate::ui::city) kind: CivilianUnitKind,
    pub(in crate::ui::city) order_tag: FourCc,
    pub(in crate::ui::city) button_tag: FourCc,
}

impl UniversityRow {
    pub(in crate::ui::city) const fn binding(self) -> CityOrderBinding {
        CityOrderBinding {
            order: CityOrderId::CivilianRecruit(self.kind),
            tag: self.order_tag,
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct ShipyardRow {
    pub(in crate::ui::city) slot: ShipOrderSlot,
    pub(in crate::ui::city) order_tag: FourCc,
    pub(in crate::ui::city) button_tag: FourCc,
    pub(in crate::ui::city) overlay_left: f32,
}

impl ShipyardRow {
    pub(in crate::ui::city) const fn binding(self) -> CityOrderBinding {
        CityOrderBinding {
            order: CityOrderId::Ship(self.slot),
            tag: self.order_tag,
        }
    }
}

pub(in crate::ui::city) const TRAINING_ORDERS: [CityOrderBinding; 2] = [
    CityOrderBinding {
        order: CityOrderId::Training(TrainingLevel::Medium),
        tag: fourcc!("trai"),
    },
    CityOrderBinding {
        order: CityOrderId::Training(TrainingLevel::High),
        tag: fourcc!("prof"),
    },
];
pub(in crate::ui::city) const ARMORY_ROWS: [ArmoryRow; 8] = [
    ArmoryRow {
        category: MilitaryRecruitmentCategory::LightInfantry,
        order_tag: fourcc!("clu0"),
        button_tag: fourcc!("civ0"),
    },
    ArmoryRow {
        category: MilitaryRecruitmentCategory::RegularInfantry,
        order_tag: fourcc!("clu1"),
        button_tag: fourcc!("civ1"),
    },
    ArmoryRow {
        category: MilitaryRecruitmentCategory::HeavyInfantry,
        order_tag: fourcc!("clu2"),
        button_tag: fourcc!("civ2"),
    },
    ArmoryRow {
        category: MilitaryRecruitmentCategory::LightCavalry,
        order_tag: fourcc!("clu3"),
        button_tag: fourcc!("civ3"),
    },
    ArmoryRow {
        category: MilitaryRecruitmentCategory::HeavyCavalry,
        order_tag: fourcc!("clu4"),
        button_tag: fourcc!("civ4"),
    },
    ArmoryRow {
        category: MilitaryRecruitmentCategory::LightArtillery,
        order_tag: fourcc!("clu5"),
        button_tag: fourcc!("civ5"),
    },
    ArmoryRow {
        category: MilitaryRecruitmentCategory::HeavyArtillery,
        order_tag: fourcc!("clu6"),
        button_tag: fourcc!("civ6"),
    },
    ArmoryRow {
        category: MilitaryRecruitmentCategory::Demolitionist,
        order_tag: fourcc!("clu7"),
        button_tag: fourcc!("civ7"),
    },
];
pub(in crate::ui::city) const UNIVERSITY_ROWS: [UniversityRow; 7] = [
    UniversityRow {
        kind: CivilianUnitKind::Miner,
        order_tag: fourcc!("clu0"),
        button_tag: fourcc!("civ0"),
    },
    UniversityRow {
        kind: CivilianUnitKind::Prospector,
        order_tag: fourcc!("clu1"),
        button_tag: fourcc!("civ1"),
    },
    UniversityRow {
        kind: CivilianUnitKind::Farmer,
        order_tag: fourcc!("clu2"),
        button_tag: fourcc!("civ2"),
    },
    UniversityRow {
        kind: CivilianUnitKind::Forester,
        order_tag: fourcc!("clu3"),
        button_tag: fourcc!("civ3"),
    },
    UniversityRow {
        kind: CivilianUnitKind::Engineer,
        order_tag: fourcc!("clu4"),
        button_tag: fourcc!("civ4"),
    },
    UniversityRow {
        kind: CivilianUnitKind::Rancher,
        order_tag: fourcc!("clu5"),
        button_tag: fourcc!("civ5"),
    },
    UniversityRow {
        kind: CivilianUnitKind::Driller,
        order_tag: fourcc!("clu8"),
        button_tag: fourcc!("civ8"),
    },
];
pub(in crate::ui::city) const SHIPYARD_ROWS: [ShipyardRow; 8] = [
    ShipyardRow {
        slot: ShipOrderSlot::MerchantEarlyPrimary,
        order_tag: fourcc!("clu0"),
        button_tag: fourcc!("but0"),
        overlay_left: 4.0,
    },
    ShipyardRow {
        slot: ShipOrderSlot::MerchantEarlySecondary,
        order_tag: fourcc!("clu1"),
        button_tag: fourcc!("but1"),
        overlay_left: 4.0,
    },
    ShipyardRow {
        slot: ShipOrderSlot::MerchantAdvancedPrimary,
        order_tag: fourcc!("clu2"),
        button_tag: fourcc!("but2"),
        overlay_left: 3.0,
    },
    ShipyardRow {
        slot: ShipOrderSlot::MerchantAdvancedSecondary,
        order_tag: fourcc!("clu3"),
        button_tag: fourcc!("but3"),
        overlay_left: 2.0,
    },
    ShipyardRow {
        slot: ShipOrderSlot::WarshipEarlyPrimary,
        order_tag: fourcc!("clu4"),
        button_tag: fourcc!("but4"),
        overlay_left: 4.0,
    },
    ShipyardRow {
        slot: ShipOrderSlot::WarshipEarlySecondary,
        order_tag: fourcc!("clu5"),
        button_tag: fourcc!("but5"),
        overlay_left: 4.0,
    },
    ShipyardRow {
        slot: ShipOrderSlot::WarshipAdvancedPrimary,
        order_tag: fourcc!("clu6"),
        button_tag: fourcc!("but6"),
        overlay_left: 3.0,
    },
    ShipyardRow {
        slot: ShipOrderSlot::WarshipAdvancedSecondary,
        order_tag: fourcc!("clu7"),
        button_tag: fourcc!("but7"),
        overlay_left: 2.0,
    },
];
const INDUSTRY_PAGES: [IndustryPage; 7] = [
    IndustryPage {
        slot: CityFacilitySlot::TextileMill,
        orders: &[CityOrderBinding {
            order: CityOrderId::Item(ManufacturedItem::Fabric),
            tag: fourcc!("fabr"),
        }],
        stocks: &[
            (ResourceKind::Cotton, fourcc!("cott"), 1),
            (ResourceKind::Wool, fourcc!("wool"), 1),
        ],
    },
    IndustryPage {
        slot: CityFacilitySlot::ClothingFactory,
        orders: &[CityOrderBinding {
            order: CityOrderId::Item(ManufacturedItem::Clothing),
            tag: fourcc!("clot"),
        }],
        stocks: &[(ResourceKind::Fabric, fourcc!("fabr"), 2)],
    },
    IndustryPage {
        slot: CityFacilitySlot::SteelMill,
        orders: &[CityOrderBinding {
            order: CityOrderId::Item(ManufacturedItem::Steel),
            tag: fourcc!("stee"),
        }],
        stocks: &[
            (ResourceKind::Coal, fourcc!("coal"), 1),
            (ResourceKind::Iron, fourcc!("iron"), 1),
        ],
    },
    IndustryPage {
        slot: CityFacilitySlot::Metalworks,
        orders: &[
            CityOrderBinding {
                order: CityOrderId::Item(ManufacturedItem::Hardware),
                tag: fourcc!("hard"),
            },
            CityOrderBinding {
                order: CityOrderId::Item(ManufacturedItem::Arms),
                tag: fourcc!("arma"),
            },
        ],
        stocks: &[(ResourceKind::Steel, fourcc!("stee"), 2)],
    },
    IndustryPage {
        slot: CityFacilitySlot::LumberMill,
        orders: &[
            CityOrderBinding {
                order: CityOrderId::Item(ManufacturedItem::Lumber),
                tag: fourcc!("lumb"),
            },
            CityOrderBinding {
                order: CityOrderId::Item(ManufacturedItem::Paper),
                tag: fourcc!("pape"),
            },
        ],
        stocks: &[(ResourceKind::Timber, fourcc!("timb"), 2)],
    },
    IndustryPage {
        slot: CityFacilitySlot::FurnitureFactory,
        orders: &[CityOrderBinding {
            order: CityOrderId::Item(ManufacturedItem::Furniture),
            tag: fourcc!("furn"),
        }],
        stocks: &[(ResourceKind::Lumber, fourcc!("lumb"), 2)],
    },
    IndustryPage {
        slot: CityFacilitySlot::OilRefinery,
        orders: &[CityOrderBinding {
            order: CityOrderId::Item(ManufacturedItem::Fuel),
            tag: fourcc!("fuel"),
        }],
        stocks: &[(ResourceKind::Oil, fourcc!("oil "), 2)],
    },
];
pub(in crate::ui::city) const SHIPYARD_MATERIALS: [ResourceKind; 6] = [
    ResourceKind::Fabric,
    ResourceKind::Lumber,
    ResourceKind::Arms,
    ResourceKind::Steel,
    ResourceKind::Coal,
    ResourceKind::Fuel,
];
pub(in crate::ui::city) const SHIPYARD_STAT_ORIGINS: [(f32, f32); 6] = [
    (28.0, 86.0),
    (28.0, 102.0),
    (28.0, 118.0),
    (120.0, 86.0),
    (120.0, 102.0),
    (120.0, 118.0),
];
pub(in crate::ui::city) const FOOD_ORDER: CityOrderBinding = CityOrderBinding {
    order: CityOrderId::FoodProcessing,
    tag: fourcc!("food"),
};
pub(in crate::ui::city) const POWER_ORDER: CityOrderBinding = CityOrderBinding {
    order: CityOrderId::PowerPlant,
    tag: fourcc!("powe"),
};
pub(in crate::ui::city) const TRANSPORT_CAPACITY_ORDER: CityOrderBinding = CityOrderBinding {
    order: CityOrderId::TransportCapacity,
    tag: fourcc!("rail"),
};
pub(in crate::ui::city) const POPULATION_ORDER: CityOrderBinding = CityOrderBinding {
    order: CityOrderId::PopulationGrowth,
    tag: fourcc!("popu"),
};
pub(in crate::ui::city) const WAREHOUSE_STOCKS: [(ResourceKind, FourCc); 20] = [
    (ResourceKind::Cotton, fourcc!("cott")),
    (ResourceKind::Wool, fourcc!("wool")),
    (ResourceKind::Timber, fourcc!("timb")),
    (ResourceKind::Coal, fourcc!("coal")),
    (ResourceKind::Iron, fourcc!("iron")),
    (ResourceKind::Horses, fourcc!("hors")),
    (ResourceKind::Oil, fourcc!("oil ")),
    (ResourceKind::Food, fourcc!("food")),
    (ResourceKind::Fabric, fourcc!("fabr")),
    (ResourceKind::Lumber, fourcc!("lumb")),
    (ResourceKind::Paper, fourcc!("pape")),
    (ResourceKind::Steel, fourcc!("stee")),
    (ResourceKind::Fuel, fourcc!("fuel")),
    (ResourceKind::Clothing, fourcc!("clot")),
    (ResourceKind::Furniture, fourcc!("furn")),
    (ResourceKind::Hardware, fourcc!("hard")),
    (ResourceKind::Arms, fourcc!("arma")),
    (ResourceKind::Grain, fourcc!("grai")),
    (ResourceKind::Fruit, fourcc!("prod")),
    (ResourceKind::Livestock, fourcc!("live")),
];

pub(in crate::ui::city) fn industry_page(slot: CityFacilitySlot) -> Option<IndustryPage> {
    INDUSTRY_PAGES
        .iter()
        .copied()
        .find(|page| page.slot == slot)
}

pub(in crate::ui::city) fn city_active_nation(session: &GameSession) -> MajorNationId {
    MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("City active nation is a major nation")
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
    let offset = i16::from(slot as u8);
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

pub(in crate::ui::city) fn format_retail_value(template: &str, value: &str) -> String {
    if template.contains("[1: number]") {
        template.replace("[1: number]", value)
    } else if template.contains("[1:number]") {
        template.replace("[1:number]", value)
    } else {
        panic!("retail City number template has no first-number token");
    }
}

pub(in crate::ui::city) fn format_retail_number(template: &str, value: i16) -> String {
    format_retail_value(template, &value.to_string())
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

    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../../fixtures/retail/beginning_of_game.imp");

    #[test]
    fn beginning_of_game_does_not_open_unbuilt_oil_or_power() {
        let selected_nation = peek_save_header(BEGINNING_OF_GAME)
            .and_then(|header| NationId::try_new(header.active_nation))
            .unwrap();
        let state = LegacySaveV62::parse(BEGINNING_OF_GAME).game_state(LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 0,
            selected_nation,
        });
        let nation = MajorNationId::from_nation(selected_nation).unwrap();
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
