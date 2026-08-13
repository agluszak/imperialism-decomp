use super::*;

pub(in crate::ui::city) const CITY_BUILDING_STRING_GROUP: i16 = 0x2719;
pub(in crate::ui::city) const CITY_TEXT_STRING_GROUP: i16 = 0x2738;

pub(in crate::ui::city) const TEXTILE_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::Item(ManufacturedItem::Fabric),
    tag: fourcc!("fabr"),
}];
pub(in crate::ui::city) const CLOTHING_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::Item(ManufacturedItem::Clothing),
    tag: fourcc!("clot"),
}];
pub(in crate::ui::city) const STEEL_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::Item(ManufacturedItem::Steel),
    tag: fourcc!("stee"),
}];
pub(in crate::ui::city) const METALWORKS_ORDERS: [CityOrderBinding; 2] = [
    CityOrderBinding {
        order: CityOrderId::Item(ManufacturedItem::Hardware),
        tag: fourcc!("hard"),
    },
    CityOrderBinding {
        order: CityOrderId::Item(ManufacturedItem::Arms),
        tag: fourcc!("arma"),
    },
];
pub(in crate::ui::city) const LUMBER_ORDERS: [CityOrderBinding; 2] = [
    CityOrderBinding {
        order: CityOrderId::Item(ManufacturedItem::Lumber),
        tag: fourcc!("lumb"),
    },
    CityOrderBinding {
        order: CityOrderId::Item(ManufacturedItem::Paper),
        tag: fourcc!("pape"),
    },
];
pub(in crate::ui::city) const FURNITURE_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::Item(ManufacturedItem::Furniture),
    tag: fourcc!("furn"),
}];
pub(in crate::ui::city) const OIL_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::Item(ManufacturedItem::Fuel),
    tag: fourcc!("fuel"),
}];
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
pub(in crate::ui::city) const UNIVERSITY_ORDERS: [CityOrderBinding; 7] = [
    CityOrderBinding {
        order: CityOrderId::CivilianRecruit(CivilianUnitKind::Miner),
        tag: fourcc!("clu0"),
    },
    CityOrderBinding {
        order: CityOrderId::CivilianRecruit(CivilianUnitKind::Prospector),
        tag: fourcc!("clu1"),
    },
    CityOrderBinding {
        order: CityOrderId::CivilianRecruit(CivilianUnitKind::Farmer),
        tag: fourcc!("clu2"),
    },
    CityOrderBinding {
        order: CityOrderId::CivilianRecruit(CivilianUnitKind::Forester),
        tag: fourcc!("clu3"),
    },
    CityOrderBinding {
        order: CityOrderId::CivilianRecruit(CivilianUnitKind::Engineer),
        tag: fourcc!("clu4"),
    },
    CityOrderBinding {
        order: CityOrderId::CivilianRecruit(CivilianUnitKind::Rancher),
        tag: fourcc!("clu5"),
    },
    CityOrderBinding {
        order: CityOrderId::CivilianRecruit(CivilianUnitKind::Driller),
        tag: fourcc!("clu8"),
    },
];
pub(in crate::ui::city) const SHIP_ORDERS: [CityOrderBinding; 8] = [
    CityOrderBinding {
        order: CityOrderId::Ship(ShipOrderSlot::MerchantEarlyPrimary),
        tag: fourcc!("clu0"),
    },
    CityOrderBinding {
        order: CityOrderId::Ship(ShipOrderSlot::MerchantEarlySecondary),
        tag: fourcc!("clu1"),
    },
    CityOrderBinding {
        order: CityOrderId::Ship(ShipOrderSlot::MerchantAdvancedPrimary),
        tag: fourcc!("clu2"),
    },
    CityOrderBinding {
        order: CityOrderId::Ship(ShipOrderSlot::MerchantAdvancedSecondary),
        tag: fourcc!("clu3"),
    },
    CityOrderBinding {
        order: CityOrderId::Ship(ShipOrderSlot::WarshipEarlyPrimary),
        tag: fourcc!("clu4"),
    },
    CityOrderBinding {
        order: CityOrderId::Ship(ShipOrderSlot::WarshipEarlySecondary),
        tag: fourcc!("clu5"),
    },
    CityOrderBinding {
        order: CityOrderId::Ship(ShipOrderSlot::WarshipAdvancedPrimary),
        tag: fourcc!("clu6"),
    },
    CityOrderBinding {
        order: CityOrderId::Ship(ShipOrderSlot::WarshipAdvancedSecondary),
        tag: fourcc!("clu7"),
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
pub(in crate::ui::city) const SHIPYARD_OVERLAY_LEFT: [f32; 8] =
    [4.0, 4.0, 3.0, 2.0, 4.0, 4.0, 3.0, 2.0];
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
pub(in crate::ui::city) const ARMORY_ORDERS: [CityOrderBinding; 8] = [
    CityOrderBinding {
        order: CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::LightInfantry),
        tag: fourcc!("clu0"),
    },
    CityOrderBinding {
        order: CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::RegularInfantry),
        tag: fourcc!("clu1"),
    },
    CityOrderBinding {
        order: CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::HeavyInfantry),
        tag: fourcc!("clu2"),
    },
    CityOrderBinding {
        order: CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::LightCavalry),
        tag: fourcc!("clu3"),
    },
    CityOrderBinding {
        order: CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::HeavyCavalry),
        tag: fourcc!("clu4"),
    },
    CityOrderBinding {
        order: CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::LightArtillery),
        tag: fourcc!("clu5"),
    },
    CityOrderBinding {
        order: CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::HeavyArtillery),
        tag: fourcc!("clu6"),
    },
    CityOrderBinding {
        order: CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::Demolitionist),
        tag: fourcc!("clu7"),
    },
];

pub(in crate::ui::city) const TEXTILE_STOCKS: [(ResourceKind, FourCc, i16); 2] = [
    (ResourceKind::Cotton, fourcc!("cott"), 1),
    (ResourceKind::Wool, fourcc!("wool"), 1),
];
pub(in crate::ui::city) const CLOTHING_STOCKS: [(ResourceKind, FourCc, i16); 1] =
    [(ResourceKind::Fabric, fourcc!("fabr"), 2)];
pub(in crate::ui::city) const STEEL_STOCKS: [(ResourceKind, FourCc, i16); 2] = [
    (ResourceKind::Coal, fourcc!("coal"), 1),
    (ResourceKind::Iron, fourcc!("iron"), 1),
];
pub(in crate::ui::city) const METALWORKS_STOCKS: [(ResourceKind, FourCc, i16); 1] =
    [(ResourceKind::Steel, fourcc!("stee"), 2)];
pub(in crate::ui::city) const LUMBER_STOCKS: [(ResourceKind, FourCc, i16); 1] =
    [(ResourceKind::Timber, fourcc!("timb"), 2)];
pub(in crate::ui::city) const FURNITURE_STOCKS: [(ResourceKind, FourCc, i16); 1] =
    [(ResourceKind::Lumber, fourcc!("lumb"), 2)];
pub(in crate::ui::city) const OIL_STOCKS: [(ResourceKind, FourCc, i16); 1] =
    [(ResourceKind::Oil, fourcc!("oil "), 2)];
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

pub(in crate::ui::city) fn industry_page(slot: CityFacilitySlot) -> Option<IndustryPage> {
    let page = match slot {
        CityFacilitySlot::TextileMill => IndustryPage {
            slot,
            orders: &TEXTILE_ORDERS,
            stocks: &TEXTILE_STOCKS,
        },
        CityFacilitySlot::ClothingFactory => IndustryPage {
            slot,
            orders: &CLOTHING_ORDERS,
            stocks: &CLOTHING_STOCKS,
        },
        CityFacilitySlot::SteelMill => IndustryPage {
            slot,
            orders: &STEEL_ORDERS,
            stocks: &STEEL_STOCKS,
        },
        CityFacilitySlot::Metalworks => IndustryPage {
            slot,
            orders: &METALWORKS_ORDERS,
            stocks: &METALWORKS_STOCKS,
        },
        CityFacilitySlot::LumberMill => IndustryPage {
            slot,
            orders: &LUMBER_ORDERS,
            stocks: &LUMBER_STOCKS,
        },
        CityFacilitySlot::FurnitureFactory => IndustryPage {
            slot,
            orders: &FURNITURE_ORDERS,
            stocks: &FURNITURE_STOCKS,
        },
        CityFacilitySlot::OilRefinery => IndustryPage {
            slot,
            orders: &OIL_ORDERS,
            stocks: &OIL_STOCKS,
        },
        _ => return None,
    };
    Some(page)
}

pub(in crate::ui::city) const fn armory_button_tag(
    category: MilitaryRecruitmentCategory,
) -> FourCc {
    match category {
        MilitaryRecruitmentCategory::LightInfantry => fourcc!("civ0"),
        MilitaryRecruitmentCategory::RegularInfantry => fourcc!("civ1"),
        MilitaryRecruitmentCategory::HeavyInfantry => fourcc!("civ2"),
        MilitaryRecruitmentCategory::LightCavalry => fourcc!("civ3"),
        MilitaryRecruitmentCategory::HeavyCavalry => fourcc!("civ4"),
        MilitaryRecruitmentCategory::LightArtillery => fourcc!("civ5"),
        MilitaryRecruitmentCategory::HeavyArtillery => fourcc!("civ6"),
        MilitaryRecruitmentCategory::Demolitionist => fourcc!("civ7"),
    }
}

pub(in crate::ui::city) const fn university_button_tag(kind: CivilianUnitKind) -> FourCc {
    match kind {
        CivilianUnitKind::Miner => fourcc!("civ0"),
        CivilianUnitKind::Prospector => fourcc!("civ1"),
        CivilianUnitKind::Farmer => fourcc!("civ2"),
        CivilianUnitKind::Forester => fourcc!("civ3"),
        CivilianUnitKind::Engineer => fourcc!("civ4"),
        CivilianUnitKind::Rancher => fourcc!("civ5"),
        CivilianUnitKind::Driller => fourcc!("civ8"),
        CivilianUnitKind::Fisherman | CivilianUnitKind::Developer => {
            panic!("retail University skips civilian rows 6 and 7")
        }
    }
}

pub(in crate::ui::city) const fn shipyard_button_tag(slot: ShipOrderSlot) -> FourCc {
    match slot {
        ShipOrderSlot::MerchantEarlyPrimary => fourcc!("but0"),
        ShipOrderSlot::MerchantEarlySecondary => fourcc!("but1"),
        ShipOrderSlot::MerchantAdvancedPrimary => fourcc!("but2"),
        ShipOrderSlot::MerchantAdvancedSecondary => fourcc!("but3"),
        ShipOrderSlot::WarshipEarlyPrimary => fourcc!("but4"),
        ShipOrderSlot::WarshipEarlySecondary => fourcc!("but5"),
        ShipOrderSlot::WarshipAdvancedPrimary => fourcc!("but6"),
        ShipOrderSlot::WarshipAdvancedSecondary => fourcc!("but7"),
    }
}

pub(in crate::ui::city) fn city_active_nation(session: &GameSession) -> MajorNationId {
    MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation")
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
        major.common.owned_region_count() as i32,
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
    let normal = level == 0 || offset > 5 || !expanding || !CityState::is_capacity_center(slot);
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
