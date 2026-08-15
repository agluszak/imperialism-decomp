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
pub(in crate::ui::city) struct CityChoiceRow {
    pub(in crate::ui::city) binding: CityOrderBinding,
    pub(in crate::ui::city) button_tag: FourCc,
}

impl CityChoiceRow {
    const fn military(
        category: MilitaryRecruitmentCategory,
        order_tag: FourCc,
        button_tag: FourCc,
    ) -> Self {
        Self {
            binding: CityOrderBinding {
                order: CityOrderId::MilitaryRecruit(category),
                tag: order_tag,
            },
            button_tag,
        }
    }

    const fn civilian(kind: CivilianUnitKind, order_tag: FourCc, button_tag: FourCc) -> Self {
        Self {
            binding: CityOrderBinding {
                order: CityOrderId::CivilianRecruit(kind),
                tag: order_tag,
            },
            button_tag,
        }
    }

    pub(in crate::ui::city) fn military_category(self) -> MilitaryRecruitmentCategory {
        match self.binding.order {
            CityOrderId::MilitaryRecruit(category) => category,
            other => panic!("Armory row is a military recruit order, got {other:?}"),
        }
    }

    pub(in crate::ui::city) fn civilian_kind(self) -> CivilianUnitKind {
        match self.binding.order {
            CityOrderId::CivilianRecruit(kind) => kind,
            other => panic!("University row is a civilian recruit order, got {other:?}"),
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct ShipyardRow {
    pub(in crate::ui::city) binding: CityOrderBinding,
    pub(in crate::ui::city) button_tag: FourCc,
    pub(in crate::ui::city) overlay_left: f32,
}

impl ShipyardRow {
    const fn new(
        slot: ShipOrderSlot,
        order_tag: FourCc,
        button_tag: FourCc,
        overlay_left: f32,
    ) -> Self {
        Self {
            binding: CityOrderBinding {
                order: CityOrderId::Ship(slot),
                tag: order_tag,
            },
            button_tag,
            overlay_left,
        }
    }

    pub(in crate::ui::city) fn slot(self) -> ShipOrderSlot {
        match self.binding.order {
            CityOrderId::Ship(slot) => slot,
            other => panic!("Shipyard row is a ship order, got {other:?}"),
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
pub(in crate::ui::city) const ARMORY_ROWS: [CityChoiceRow; 8] = [
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::LightInfantry,
        fourcc!("clu0"),
        fourcc!("civ0"),
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::RegularInfantry,
        fourcc!("clu1"),
        fourcc!("civ1"),
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::HeavyInfantry,
        fourcc!("clu2"),
        fourcc!("civ2"),
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::LightCavalry,
        fourcc!("clu3"),
        fourcc!("civ3"),
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::HeavyCavalry,
        fourcc!("clu4"),
        fourcc!("civ4"),
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::LightArtillery,
        fourcc!("clu5"),
        fourcc!("civ5"),
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::HeavyArtillery,
        fourcc!("clu6"),
        fourcc!("civ6"),
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::Demolitionist,
        fourcc!("clu7"),
        fourcc!("civ7"),
    ),
];
pub(in crate::ui::city) const UNIVERSITY_ROWS: [CityChoiceRow; 7] = [
    CityChoiceRow::civilian(CivilianUnitKind::Miner, fourcc!("clu0"), fourcc!("civ0")),
    CityChoiceRow::civilian(
        CivilianUnitKind::Prospector,
        fourcc!("clu1"),
        fourcc!("civ1"),
    ),
    CityChoiceRow::civilian(CivilianUnitKind::Farmer, fourcc!("clu2"), fourcc!("civ2")),
    CityChoiceRow::civilian(CivilianUnitKind::Forester, fourcc!("clu3"), fourcc!("civ3")),
    CityChoiceRow::civilian(CivilianUnitKind::Engineer, fourcc!("clu4"), fourcc!("civ4")),
    CityChoiceRow::civilian(CivilianUnitKind::Rancher, fourcc!("clu5"), fourcc!("civ5")),
    CityChoiceRow::civilian(CivilianUnitKind::Driller, fourcc!("clu8"), fourcc!("civ8")),
];
pub(in crate::ui::city) const SHIPYARD_ROWS: [ShipyardRow; 8] = [
    ShipyardRow::new(
        ShipOrderSlot::MerchantEarlyPrimary,
        fourcc!("clu0"),
        fourcc!("but0"),
        4.0,
    ),
    ShipyardRow::new(
        ShipOrderSlot::MerchantEarlySecondary,
        fourcc!("clu1"),
        fourcc!("but1"),
        4.0,
    ),
    ShipyardRow::new(
        ShipOrderSlot::MerchantAdvancedPrimary,
        fourcc!("clu2"),
        fourcc!("but2"),
        3.0,
    ),
    ShipyardRow::new(
        ShipOrderSlot::MerchantAdvancedSecondary,
        fourcc!("clu3"),
        fourcc!("but3"),
        2.0,
    ),
    ShipyardRow::new(
        ShipOrderSlot::WarshipEarlyPrimary,
        fourcc!("clu4"),
        fourcc!("but4"),
        4.0,
    ),
    ShipyardRow::new(
        ShipOrderSlot::WarshipEarlySecondary,
        fourcc!("clu5"),
        fourcc!("but5"),
        4.0,
    ),
    ShipyardRow::new(
        ShipOrderSlot::WarshipAdvancedPrimary,
        fourcc!("clu6"),
        fourcc!("but6"),
        3.0,
    ),
    ShipyardRow::new(
        ShipOrderSlot::WarshipAdvancedSecondary,
        fourcc!("clu7"),
        fourcc!("but7"),
        2.0,
    ),
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

fn industry_page(slot: CityFacilitySlot) -> Option<IndustryPage> {
    INDUSTRY_PAGES
        .iter()
        .copied()
        .find(|page| page.slot == slot)
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) enum CityDialogKind {
    Industry(IndustryPage),
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
    if let Some(page) = industry_page(slot) {
        return CityDialogKind::Industry(page);
    }
    match slot {
        CityFacilitySlot::TradeSchool => CityDialogKind::Training,
        CityFacilitySlot::Armory => CityDialogKind::Armory,
        CityFacilitySlot::University => CityDialogKind::University,
        CityFacilitySlot::Shipyard => CityDialogKind::Shipyard,
        CityFacilitySlot::Warehouse => CityDialogKind::Warehouse,
        CityFacilitySlot::FoodProcessing => CityDialogKind::FoodProcessing,
        CityFacilitySlot::PowerPlant => CityDialogKind::PowerPlant,
        CityFacilitySlot::Transport => CityDialogKind::Transport,
        CityFacilitySlot::RegionalPopulation => CityDialogKind::Population,
        _ => unreachable!("ordinary industry is classified by INDUSTRY_PAGES"),
    }
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

    #[test]
    fn beginning_of_game_does_not_open_unbuilt_oil_or_power() {
        let state = crate::ui::test_support::beginning_of_game();
        let nation = MajorNationId::from_nation(state.turn().selected_nation).unwrap();
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
