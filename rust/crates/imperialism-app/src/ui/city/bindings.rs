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
        (order_tag, button_tag): (FourCc, FourCc),
    ) -> Self {
        Self {
            binding: CityOrderBinding {
                order: CityOrderId::MilitaryRecruit(category),
                tag: order_tag,
            },
            button_tag,
        }
    }

    const fn civilian(kind: CivilianUnitKind, (order_tag, button_tag): (FourCc, FourCc)) -> Self {
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
        (order_tag, button_tag, overlay_left): (FourCc, FourCc, f32),
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

const fn item_binding(item: ManufacturedItem, page: usize, order: usize) -> CityOrderBinding {
    CityOrderBinding {
        order: CityOrderId::Item(item),
        tag: generated::INDUSTRY_PAGE_CONTROLS[page].order_tags[order],
    }
}

const fn stock_binding(
    resource: ResourceKind,
    page: usize,
    stock: usize,
) -> (ResourceKind, FourCc, i16) {
    (
        resource,
        generated::INDUSTRY_PAGE_CONTROLS[page].stocks[stock].0,
        generated::INDUSTRY_PAGE_CONTROLS[page].stocks[stock].1,
    )
}

pub(in crate::ui::city) const TRAINING_ORDERS: [CityOrderBinding; 2] = [
    CityOrderBinding {
        order: CityOrderId::Training(TrainingLevel::Medium),
        tag: generated::TRAINING_ORDER_TAGS[0],
    },
    CityOrderBinding {
        order: CityOrderId::Training(TrainingLevel::High),
        tag: generated::TRAINING_ORDER_TAGS[1],
    },
];
pub(in crate::ui::city) const ARMORY_ROWS: [CityChoiceRow; 8] = [
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::LightInfantry,
        generated::ARMORY_ROW_CONTROLS[0],
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::RegularInfantry,
        generated::ARMORY_ROW_CONTROLS[1],
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::HeavyInfantry,
        generated::ARMORY_ROW_CONTROLS[2],
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::LightCavalry,
        generated::ARMORY_ROW_CONTROLS[3],
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::HeavyCavalry,
        generated::ARMORY_ROW_CONTROLS[4],
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::LightArtillery,
        generated::ARMORY_ROW_CONTROLS[5],
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::HeavyArtillery,
        generated::ARMORY_ROW_CONTROLS[6],
    ),
    CityChoiceRow::military(
        MilitaryRecruitmentCategory::Demolitionist,
        generated::ARMORY_ROW_CONTROLS[7],
    ),
];
pub(in crate::ui::city) const UNIVERSITY_ROWS: [CityChoiceRow; 7] = [
    CityChoiceRow::civilian(
        CivilianUnitKind::Miner,
        generated::UNIVERSITY_ROW_CONTROLS[0],
    ),
    CityChoiceRow::civilian(
        CivilianUnitKind::Prospector,
        generated::UNIVERSITY_ROW_CONTROLS[1],
    ),
    CityChoiceRow::civilian(
        CivilianUnitKind::Farmer,
        generated::UNIVERSITY_ROW_CONTROLS[2],
    ),
    CityChoiceRow::civilian(
        CivilianUnitKind::Forester,
        generated::UNIVERSITY_ROW_CONTROLS[3],
    ),
    CityChoiceRow::civilian(
        CivilianUnitKind::Engineer,
        generated::UNIVERSITY_ROW_CONTROLS[4],
    ),
    CityChoiceRow::civilian(
        CivilianUnitKind::Rancher,
        generated::UNIVERSITY_ROW_CONTROLS[5],
    ),
    CityChoiceRow::civilian(
        CivilianUnitKind::Driller,
        generated::UNIVERSITY_ROW_CONTROLS[6],
    ),
];
pub(in crate::ui::city) const SHIPYARD_ROWS: [ShipyardRow; 8] = [
    ShipyardRow::new(
        ShipOrderSlot::MerchantEarlyPrimary,
        generated::SHIPYARD_ROW_CONTROLS[0],
    ),
    ShipyardRow::new(
        ShipOrderSlot::MerchantEarlySecondary,
        generated::SHIPYARD_ROW_CONTROLS[1],
    ),
    ShipyardRow::new(
        ShipOrderSlot::MerchantAdvancedPrimary,
        generated::SHIPYARD_ROW_CONTROLS[2],
    ),
    ShipyardRow::new(
        ShipOrderSlot::MerchantAdvancedSecondary,
        generated::SHIPYARD_ROW_CONTROLS[3],
    ),
    ShipyardRow::new(
        ShipOrderSlot::WarshipEarlyPrimary,
        generated::SHIPYARD_ROW_CONTROLS[4],
    ),
    ShipyardRow::new(
        ShipOrderSlot::WarshipEarlySecondary,
        generated::SHIPYARD_ROW_CONTROLS[5],
    ),
    ShipyardRow::new(
        ShipOrderSlot::WarshipAdvancedPrimary,
        generated::SHIPYARD_ROW_CONTROLS[6],
    ),
    ShipyardRow::new(
        ShipOrderSlot::WarshipAdvancedSecondary,
        generated::SHIPYARD_ROW_CONTROLS[7],
    ),
];
const INDUSTRY_PAGES: [IndustryPage; 7] = [
    IndustryPage {
        slot: CityFacilitySlot::TextileMill,
        orders: &[item_binding(ManufacturedItem::Fabric, 0, 0)],
        stocks: &[
            stock_binding(ResourceKind::Cotton, 0, 0),
            stock_binding(ResourceKind::Wool, 0, 1),
        ],
    },
    IndustryPage {
        slot: CityFacilitySlot::ClothingFactory,
        orders: &[item_binding(ManufacturedItem::Clothing, 1, 0)],
        stocks: &[stock_binding(ResourceKind::Fabric, 1, 0)],
    },
    IndustryPage {
        slot: CityFacilitySlot::SteelMill,
        orders: &[item_binding(ManufacturedItem::Steel, 2, 0)],
        stocks: &[
            stock_binding(ResourceKind::Coal, 2, 0),
            stock_binding(ResourceKind::Iron, 2, 1),
        ],
    },
    IndustryPage {
        slot: CityFacilitySlot::Metalworks,
        orders: &[
            item_binding(ManufacturedItem::Hardware, 3, 0),
            item_binding(ManufacturedItem::Arms, 3, 1),
        ],
        stocks: &[stock_binding(ResourceKind::Steel, 3, 0)],
    },
    IndustryPage {
        slot: CityFacilitySlot::LumberMill,
        orders: &[
            item_binding(ManufacturedItem::Lumber, 4, 0),
            item_binding(ManufacturedItem::Paper, 4, 1),
        ],
        stocks: &[stock_binding(ResourceKind::Timber, 4, 0)],
    },
    IndustryPage {
        slot: CityFacilitySlot::FurnitureFactory,
        orders: &[item_binding(ManufacturedItem::Furniture, 5, 0)],
        stocks: &[stock_binding(ResourceKind::Lumber, 5, 0)],
    },
    IndustryPage {
        slot: CityFacilitySlot::OilRefinery,
        orders: &[item_binding(ManufacturedItem::Fuel, 6, 0)],
        stocks: &[stock_binding(ResourceKind::Oil, 6, 0)],
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
pub(in crate::ui::city) const FOOD_ORDER: CityOrderBinding = CityOrderBinding {
    order: CityOrderId::FoodProcessing,
    tag: generated::FOOD_ORDER_TAG,
};
pub(in crate::ui::city) const POWER_ORDER: CityOrderBinding = CityOrderBinding {
    order: CityOrderId::PowerPlant,
    tag: generated::POWER_ORDER_TAG,
};
pub(in crate::ui::city) const TRANSPORT_CAPACITY_ORDER: CityOrderBinding = CityOrderBinding {
    order: CityOrderId::TransportCapacity,
    tag: generated::TRANSPORT_ORDER_TAG,
};
pub(in crate::ui::city) const POPULATION_ORDER: CityOrderBinding = CityOrderBinding {
    order: CityOrderId::PopulationGrowth,
    tag: generated::POPULATION_ORDER_TAG,
};
pub(in crate::ui::city) const WAREHOUSE_STOCKS: [(ResourceKind, FourCc); 20] = [
    (ResourceKind::Cotton, generated::WAREHOUSE_STOCK_TAGS[0]),
    (ResourceKind::Wool, generated::WAREHOUSE_STOCK_TAGS[1]),
    (ResourceKind::Timber, generated::WAREHOUSE_STOCK_TAGS[2]),
    (ResourceKind::Coal, generated::WAREHOUSE_STOCK_TAGS[3]),
    (ResourceKind::Iron, generated::WAREHOUSE_STOCK_TAGS[4]),
    (ResourceKind::Horses, generated::WAREHOUSE_STOCK_TAGS[5]),
    (ResourceKind::Oil, generated::WAREHOUSE_STOCK_TAGS[6]),
    (ResourceKind::Food, generated::WAREHOUSE_STOCK_TAGS[7]),
    (ResourceKind::Fabric, generated::WAREHOUSE_STOCK_TAGS[8]),
    (ResourceKind::Lumber, generated::WAREHOUSE_STOCK_TAGS[9]),
    (ResourceKind::Paper, generated::WAREHOUSE_STOCK_TAGS[10]),
    (ResourceKind::Steel, generated::WAREHOUSE_STOCK_TAGS[11]),
    (ResourceKind::Fuel, generated::WAREHOUSE_STOCK_TAGS[12]),
    (ResourceKind::Clothing, generated::WAREHOUSE_STOCK_TAGS[13]),
    (ResourceKind::Furniture, generated::WAREHOUSE_STOCK_TAGS[14]),
    (ResourceKind::Hardware, generated::WAREHOUSE_STOCK_TAGS[15]),
    (ResourceKind::Arms, generated::WAREHOUSE_STOCK_TAGS[16]),
    (ResourceKind::Grain, generated::WAREHOUSE_STOCK_TAGS[17]),
    (ResourceKind::Fruit, generated::WAREHOUSE_STOCK_TAGS[18]),
    (ResourceKind::Livestock, generated::WAREHOUSE_STOCK_TAGS[19]),
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
