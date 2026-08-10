use super::catalog::*;
use super::game_shell::*;
use super::random_setup::GameSession;
use crate::*;
use bevy::log::warn;
use bevy::picking::events::{Click, Drag, Pointer, Press};
use bevy::prelude::*;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, Button as UiButton, ValueChange};
use imperialism_core::*;
use imperialism_formats::*;
use std::time::Duration;

const CITY_WIDTH: f32 = 640.0;
const CITY_HEIGHT: f32 = 480.0;
const INDUSTRY_BAR_WIDTH: i16 = 150;
const INDUSTRY_BAR_X: f32 = 62.0;
const INDUSTRY_BAR_Y: f32 = 8.0;
const CITY_DIALOG_CAPTION_HEIGHT: f32 = 18.0;
const CITY_DIALOG_CLOSE_SIZE: f32 = 14.0;
const CITY_BUILDING_STRING_GROUP: i16 = 0x2719;
const CITY_TEXT_STRING_GROUP: i16 = 0x2738;

fn construction_dialog_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Citydlog.rsrc".to_owned(),
        resource_id: 9220,
    }
}

fn expansion_dialog_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Citydlog.rsrc".to_owned(),
        resource_id: 9221,
    }
}

const TEXTILE_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::Item(ResourceKind::Fabric),
    tag: fourcc!("fabr"),
}];
const CLOTHING_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::Item(ResourceKind::Clothing),
    tag: fourcc!("clot"),
}];
const STEEL_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::Item(ResourceKind::Steel),
    tag: fourcc!("stee"),
}];
const METALWORKS_ORDERS: [CityOrderBinding; 2] = [
    CityOrderBinding {
        order: CityOrderId::Item(ResourceKind::Hardware),
        tag: fourcc!("hard"),
    },
    CityOrderBinding {
        order: CityOrderId::Item(ResourceKind::Arms),
        tag: fourcc!("arma"),
    },
];
const LUMBER_ORDERS: [CityOrderBinding; 2] = [
    CityOrderBinding {
        order: CityOrderId::Item(ResourceKind::Lumber),
        tag: fourcc!("lumb"),
    },
    CityOrderBinding {
        order: CityOrderId::Item(ResourceKind::Paper),
        tag: fourcc!("pape"),
    },
];
const FURNITURE_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::Item(ResourceKind::Furniture),
    tag: fourcc!("furn"),
}];
const OIL_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::Item(ResourceKind::Fuel),
    tag: fourcc!("fuel"),
}];
const TRAINING_ORDERS: [CityOrderBinding; 2] = [
    CityOrderBinding {
        order: CityOrderId::Training(TrainingLevel::Medium),
        tag: fourcc!("trai"),
    },
    CityOrderBinding {
        order: CityOrderId::Training(TrainingLevel::High),
        tag: fourcc!("prof"),
    },
];
const UNIVERSITY_ORDERS: [CityOrderBinding; 7] = [
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
const SHIP_ORDERS: [CityOrderBinding; 8] = [
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
const FOOD_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::FoodProcessing,
    tag: fourcc!("food"),
}];
const POWER_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::PowerPlant,
    tag: fourcc!("powe"),
}];
const TRANSPORT_CAPACITY_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::TransportCapacity,
    tag: fourcc!("rail"),
}];
const POPULATION_ORDERS: [CityOrderBinding; 1] = [CityOrderBinding {
    order: CityOrderId::PopulationGrowth,
    tag: fourcc!("popu"),
}];
const ARMORY_ORDERS: [CityOrderBinding; 8] = [
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

const TEXTILE_STOCKS: [(ResourceKind, FourCc, i16); 2] = [
    (ResourceKind::Cotton, fourcc!("cott"), 1),
    (ResourceKind::Wool, fourcc!("wool"), 1),
];
const CLOTHING_STOCKS: [(ResourceKind, FourCc, i16); 1] =
    [(ResourceKind::Fabric, fourcc!("fabr"), 2)];
const STEEL_STOCKS: [(ResourceKind, FourCc, i16); 2] = [
    (ResourceKind::Coal, fourcc!("coal"), 1),
    (ResourceKind::Iron, fourcc!("iron"), 1),
];
const METALWORKS_STOCKS: [(ResourceKind, FourCc, i16); 1] =
    [(ResourceKind::Steel, fourcc!("stee"), 2)];
const LUMBER_STOCKS: [(ResourceKind, FourCc, i16); 1] =
    [(ResourceKind::Timber, fourcc!("timb"), 2)];
const FURNITURE_STOCKS: [(ResourceKind, FourCc, i16); 1] =
    [(ResourceKind::Lumber, fourcc!("lumb"), 2)];
const OIL_STOCKS: [(ResourceKind, FourCc, i16); 1] = [(ResourceKind::Oil, fourcc!("oil "), 2)];

#[derive(Clone, Copy)]
struct CityOrderBinding {
    order: CityOrderId,
    tag: FourCc,
}

struct UniversityRowText {
    unit_name: String,
    description: String,
}

struct UniversityDialogData {
    available: CivilianUnitTable<bool>,
    rows: [UniversityRowText; UNIVERSITY_ORDERS.len()],
}

struct ShipyardRowData {
    ship_name: String,
    description: String,
    picture: Handle<Image>,
}

struct ShipyardDialogData {
    rows: [Option<ShipyardRowData>; SHIP_ORDERS.len()],
}

#[derive(Clone, Copy)]
struct IndustryPage {
    slot: ProductionSlot,
    orders: &'static [CityOrderBinding],
    stocks: &'static [(ResourceKind, FourCc, i16)],
}

fn industry_page(slot: ProductionSlot) -> Option<IndustryPage> {
    let page = match slot {
        ProductionSlot::TextileMill => IndustryPage {
            slot,
            orders: &TEXTILE_ORDERS,
            stocks: &TEXTILE_STOCKS,
        },
        ProductionSlot::ClothingFactory => IndustryPage {
            slot,
            orders: &CLOTHING_ORDERS,
            stocks: &CLOTHING_STOCKS,
        },
        ProductionSlot::SteelMill => IndustryPage {
            slot,
            orders: &STEEL_ORDERS,
            stocks: &STEEL_STOCKS,
        },
        ProductionSlot::Metalworks => IndustryPage {
            slot,
            orders: &METALWORKS_ORDERS,
            stocks: &METALWORKS_STOCKS,
        },
        ProductionSlot::LumberMill => IndustryPage {
            slot,
            orders: &LUMBER_ORDERS,
            stocks: &LUMBER_STOCKS,
        },
        ProductionSlot::FurnitureFactory => IndustryPage {
            slot,
            orders: &FURNITURE_ORDERS,
            stocks: &FURNITURE_STOCKS,
        },
        ProductionSlot::OilRefinery => IndustryPage {
            slot,
            orders: &OIL_ORDERS,
            stocks: &OIL_STOCKS,
        },
        _ => return None,
    };
    Some(page)
}

fn dialog_orders(slot: ProductionSlot) -> &'static [CityOrderBinding] {
    if let Some(page) = industry_page(slot) {
        page.orders
    } else if slot == ProductionSlot::TradeSchool {
        &TRAINING_ORDERS
    } else if slot == ProductionSlot::University {
        &UNIVERSITY_ORDERS
    } else if slot == ProductionSlot::Shipyard {
        &SHIP_ORDERS
    } else if slot == ProductionSlot::FoodProcessing {
        &FOOD_ORDERS
    } else if slot == ProductionSlot::PowerPlant {
        &POWER_ORDERS
    } else if slot == ProductionSlot::Transport {
        &TRANSPORT_CAPACITY_ORDERS
    } else if slot == ProductionSlot::RegionalPopulation {
        &POPULATION_ORDERS
    } else if slot == ProductionSlot::Armory {
        &ARMORY_ORDERS
    } else {
        &[]
    }
}

const fn armory_button_tag(category: MilitaryRecruitmentCategory) -> FourCc {
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

const fn university_button_tag(kind: CivilianUnitKind) -> FourCc {
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

const fn shipyard_button_tag(slot: ShipOrderSlot) -> FourCc {
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

const fn is_ordinary_industry(slot: ProductionSlot) -> bool {
    matches!(
        slot,
        ProductionSlot::TextileMill
            | ProductionSlot::ClothingFactory
            | ProductionSlot::SteelMill
            | ProductionSlot::Metalworks
            | ProductionSlot::LumberMill
            | ProductionSlot::FurnitureFactory
            | ProductionSlot::OilRefinery
    )
}

fn city_building_level(
    state: &GameState,
    nation: MajorNationId,
    slot: ProductionSlot,
) -> Option<i16> {
    let major = state.nations.major(nation);
    Some(major.city().next_building_type(
        slot,
        major.economy(),
        major.common().owned_regions.len() as i32,
        state.technology.city_capabilities_by_nation[nation].advanced_iron_working,
    ))
}

fn city_is_expanding(city: &CityState, slot: ProductionSlot) -> bool {
    city.orders.expansions[slot]
        .as_ref()
        .is_some_and(|state| state.progress.quantity > 0)
}

fn city_building_picture(city: &CityState, slot: ProductionSlot, level: i16) -> Option<PictureId> {
    let expanding = city_is_expanding(city, slot);
    let should_draw = level >= 1
        || (is_ordinary_industry(slot) && expanding)
        || (slot == ProductionSlot::PowerPlant && city.power_plant_upgrade_queued);
    if !should_draw {
        return None;
    }
    if slot == ProductionSlot::PowerPlant {
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

pub(crate) fn validate_application_bindings(catalog: &UiCatalogResource) -> Result<(), String> {
    catalog.require_unique_bindings(
        &city_view_id(),
        &[
            fourcc!("main"),
            fourcc!("labP"),
            fourcc!("untr"),
            fourcc!("trai"),
            fourcc!("prof"),
            fourcc!("powe"),
            fourcc!("grai"),
            fourcc!("prod"),
            fourcc!("meat"),
            fourcc!("hard"),
            fourcc!("clot"),
            fourcc!("furn"),
            fourcc!("trea"),
        ],
    )?;
    let city = catalog
        .view(&city_view_id())
        .expect("city view was validated above");
    if city.city_buildings.len() != ProductionSlot::COUNT {
        return Err(format!(
            "Citymain.rsrc:2011 has {} dynamic buildings; expected {}",
            city.city_buildings.len(),
            ProductionSlot::COUNT
        ));
    }
    let dialog = |slot| {
        city.city_buildings
            .iter()
            .find(|building| building.slot == slot)
            .map(|building| &building.dialog)
            .ok_or_else(|| format!("Citymain.rsrc:2011 is missing {slot:?}"))
    };
    for slot in [
        ProductionSlot::TextileMill,
        ProductionSlot::ClothingFactory,
        ProductionSlot::SteelMill,
        ProductionSlot::Metalworks,
        ProductionSlot::LumberMill,
        ProductionSlot::FurnitureFactory,
        ProductionSlot::OilRefinery,
    ] {
        let page = industry_page(slot).expect("ordinary industry has a page");
        let view_id = dialog(slot)?;
        catalog.require_unique_bindings(
            view_id,
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("labV"),
                fourcc!("name"),
                fourcc!("capT"),
                fourcc!("expa"),
                fourcc!("flag"),
            ],
        )?;
        for binding in page.orders {
            for tag in [
                fourcc!("left"),
                fourcc!("rght"),
                fourcc!("move"),
                fourcc!("bar "),
            ] {
                catalog.require_control_under(view_id, tag, &[binding.tag])?;
            }
        }
        for &(_, tag, _) in page.stocks {
            catalog.require_unique_bindings(view_id, &[tag])?;
        }
    }
    for (slot, bindings, unique_tags) in [
        (
            ProductionSlot::TradeSchool,
            TRAINING_ORDERS.as_slice(),
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("name"),
                fourcc!("cos1"),
                fourcc!("cos2"),
                fourcc!("pap1"),
                fourcc!("pap2"),
                fourcc!("mon1"),
                fourcc!("mon2"),
                fourcc!("untV"),
                fourcc!("traV"),
            ][..],
        ),
        (
            ProductionSlot::FoodProcessing,
            FOOD_ORDERS.as_slice(),
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("name"),
                fourcc!("labV"),
                fourcc!("grai"),
                fourcc!("prod"),
                fourcc!("fish"),
            ],
        ),
        (
            ProductionSlot::PowerPlant,
            POWER_ORDERS.as_slice(),
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("name"),
                fourcc!("fuel"),
            ],
        ),
        (
            ProductionSlot::Transport,
            TRANSPORT_CAPACITY_ORDERS.as_slice(),
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("name"),
                fourcc!("labV"),
                fourcc!("lumb"),
                fourcc!("stee"),
            ],
        ),
        (
            ProductionSlot::RegionalPopulation,
            POPULATION_ORDERS.as_slice(),
            &[
                fourcc!("WIND"),
                fourcc!("DLOG"),
                fourcc!("name"),
                fourcc!("food"),
                fourcc!("clot"),
                fourcc!("furn"),
                fourcc!("capT"),
                fourcc!("prov"),
            ],
        ),
    ] {
        let view_id = dialog(slot)?;
        catalog.require_unique_bindings(view_id, unique_tags)?;
        for binding in bindings {
            for tag in [
                fourcc!("left"),
                fourcc!("rght"),
                fourcc!("move"),
                fourcc!("bar "),
            ] {
                catalog.require_control_under(view_id, tag, &[binding.tag])?;
            }
        }
    }
    let armory = dialog(ProductionSlot::Armory)?;
    catalog.require_unique_bindings(
        armory,
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("sele"),
            fourcc!("unit"),
            fourcc!("cos0"),
            fourcc!("cos1"),
            fourcc!("cos2"),
            fourcc!("cos3"),
            fourcc!("ava0"),
            fourcc!("ava1"),
            fourcc!("ava2"),
            fourcc!("ava3"),
        ],
    )?;
    for binding in &ARMORY_ORDERS {
        let CityOrderId::MilitaryRecruit(category) = binding.order else {
            unreachable!("armory binding has a military recruitment order");
        };
        catalog.require_unique_bindings(armory, &[armory_button_tag(category)])?;
        for tag in [fourcc!("minu"), fourcc!("plus"), fourcc!("numb")] {
            catalog.require_control_under(armory, tag, &[binding.tag])?;
        }
    }
    let shipyard = dialog(ProductionSlot::Shipyard)?;
    catalog.require_unique_bindings(
        shipyard,
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("sele"),
            fourcc!("titl"),
            fourcc!("snam"),
            fourcc!("desc"),
            fourcc!("spic"),
        ],
    )?;
    for binding in &SHIP_ORDERS {
        let CityOrderId::Ship(slot) = binding.order else {
            unreachable!("Shipyard binding has a ship order");
        };
        catalog.require_unique_bindings(shipyard, &[shipyard_button_tag(slot)])?;
        for tag in [fourcc!("minu"), fourcc!("plus"), fourcc!("numb")] {
            catalog.require_control_under(shipyard, tag, &[binding.tag])?;
        }
    }
    let university = dialog(ProductionSlot::University)?;
    catalog.require_unique_bindings(
        university,
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("sele"),
            fourcc!("titl"),
            fourcc!("unit"),
            fourcc!("desc"),
            fourcc!("fix0"),
            fourcc!("fix1"),
            fourcc!("fix2"),
            fourcc!("fix3"),
            fourcc!("fix4"),
            fourcc!("cexp"),
            fourcc!("cpap"),
            fourcc!("cash"),
            fourcc!("aexp"),
            fourcc!("apap"),
            fourcc!("trea"),
        ],
    )?;
    for binding in &UNIVERSITY_ORDERS {
        let CityOrderId::CivilianRecruit(kind) = binding.order else {
            unreachable!("University binding has a civilian recruitment order");
        };
        catalog.require_unique_bindings(university, &[university_button_tag(kind)])?;
        for tag in [fourcc!("minu"), fourcc!("plus"), fourcc!("numb")] {
            catalog.require_control_under(university, tag, &[binding.tag])?;
        }
    }
    catalog.require_unique_bindings(
        &construction_dialog_view_id(),
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("okay"),
            fourcc!("cncl"),
            fourcc!("tex1"),
            fourcc!("tex2"),
            fourcc!("warn"),
            fourcc!("name"),
            fourcc!("cost"),
            fourcc!("capT"),
            fourcc!("or  "),
            fourcc!("buck"),
        ],
    )?;
    catalog.require_unique_bindings(
        &expansion_dialog_view_id(),
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("okay"),
            fourcc!("cncl"),
            fourcc!("name"),
            fourcc!("capT"),
            fourcc!("cost"),
            fourcc!("warn"),
        ],
    )?;
    Ok(())
}

#[derive(Clone)]
struct CityBuildingHitMask {
    width: i32,
    height: i32,
    polygon: Vec<IVec2>,
}

impl CityBuildingHitMask {
    fn from_indexed_picture(image: &IndexedPicture) -> Option<Self> {
        let width = image.width as usize;
        let height = image.height as usize;
        if width == 0 || height == 0 || image.pixels.len() != width * height {
            return None;
        }
        let transparent = image.pixels[(height - 1) * width];

        let mut edges = Vec::new();
        for y in (0..height).rev().step_by(2) {
            let row = &image.pixels[y * width..(y + 1) * width];
            let left = row.iter().position(|&pixel| pixel != transparent);
            let right = row.iter().rposition(|&pixel| pixel != transparent);
            if let (Some(left), Some(right)) = (left, right) {
                edges.push((y as i32, left as i32, right as i32));
            }
        }
        if edges.is_empty() {
            return None;
        }
        let mut polygon = Vec::with_capacity(edges.len() * 2);
        polygon.extend(edges.iter().map(|&(y, left, _)| IVec2::new(left, y)));
        polygon.extend(
            edges
                .iter()
                .rev()
                .map(|&(y, _, right)| IVec2::new(right, y)),
        );
        Some(Self {
            width: width as i32,
            height: height as i32,
            polygon,
        })
    }

    fn contains(&self, point: IVec2) -> bool {
        if point.x < 0 || point.y < 0 || point.x >= self.width || point.y >= self.height {
            return false;
        }
        let mut winding = 0_i32;
        let mut previous = self.polygon[self.polygon.len() - 1];
        for &current in &self.polygon {
            let side = i64::from(current.x - previous.x) * i64::from(point.y - previous.y)
                - i64::from(point.x - previous.x) * i64::from(current.y - previous.y);
            if previous.y <= point.y {
                if current.y > point.y && side > 0 {
                    winding += 1;
                }
            } else if current.y <= point.y && side < 0 {
                winding -= 1;
            }
            previous = current;
        }
        winding != 0
    }
}

fn apply_city_picture_transparency(image: &mut Image, indexed: &IndexedPicture) {
    let width = image.width() as usize;
    let height = image.height() as usize;
    let Some(pixels) = image.data.as_mut() else {
        return;
    };
    if width == 0
        || height == 0
        || indexed.width as usize != width
        || indexed.height as usize != height
        || pixels.len() != width * height * 4
        || indexed.pixels.len() != width * height
    {
        return;
    }
    let transparent = indexed.pixels[(height - 1) * width];
    for (pixel, &palette_index) in pixels.chunks_exact_mut(4).zip(&indexed.pixels) {
        if palette_index == transparent {
            pixel[3] = 0;
        }
    }
}

#[derive(Clone)]
struct CityBuildingHitRegion {
    origin: IVec2,
    draw_order: u8,
    slot: ProductionSlot,
    dialog: ScopedViewId,
    mask: CityBuildingHitMask,
}

#[derive(Component)]
struct CityCanvas {
    buildings: Vec<CityBuildingHitRegion>,
}

#[derive(Component)]
struct CityScreenRoot;

#[derive(Component)]
struct CityScreenNeedsSync;

#[derive(Component)]
struct CityDialogsNeedRestore;

#[derive(Component, Clone, Copy)]
struct CityBuildingPicture {
    nation: MajorNationId,
    slot: ProductionSlot,
}

#[derive(Component)]
struct CityBuildingActionAnimation {
    nation: MajorNationId,
    slot: ProductionSlot,
    frame_count: u8,
    frame_size: [i32; 2],
    frame: u8,
    timer: Timer,
}

#[derive(Component, Clone, Copy)]
struct CityBuildingDialog {
    nation: MajorNationId,
    slot: ProductionSlot,
    window: Entity,
}

#[derive(Component, Clone, Copy)]
struct CityDialogWindow {
    dialog: Entity,
}

#[derive(Component, Clone, Copy)]
struct CityDialogCaption {
    window: Entity,
}

#[derive(Component, Clone, Copy)]
struct CityDialogClose {
    dialog: Entity,
}

#[derive(Component)]
struct CityDialogNeedsSync;

#[derive(Component, Clone, Copy)]
struct CityExpansionOpen {
    dialog: Entity,
    nation: MajorNationId,
    slot: ProductionSlot,
}

#[derive(Component, Clone, Copy)]
struct CityBuildingChangeDialog;

#[derive(Component, Clone, Copy)]
struct CityBuildingChangeChoice {
    dialog: Entity,
    nation: MajorNationId,
    slot: ProductionSlot,
    accept: bool,
}

#[derive(Component, Clone, Copy)]
struct CityOrderAdjust {
    dialog: Entity,
    nation: MajorNationId,
    order: CityOrderId,
    delta: i16,
}

#[derive(Component, Clone, Copy)]
struct CityIndustryAmountBar {
    dialog: Entity,
    nation: MajorNationId,
    order: CityOrderId,
    slot: ProductionSlot,
    quantity: Entity,
    fill: Entity,
    maximum: Entity,
}

#[derive(Component, Clone, Copy)]
struct ArmorySelection {
    category: MilitaryRecruitmentCategory,
}

#[derive(Component, Clone, Copy)]
struct ArmoryRowChoice {
    dialog: Entity,
    category: MilitaryRecruitmentCategory,
}

#[derive(Component, Clone, Copy)]
struct UniversitySelection {
    kind: CivilianUnitKind,
}

#[derive(Component)]
struct UniversityRowChoice {
    dialog: Entity,
    kind: CivilianUnitKind,
    unit_name: String,
    description: String,
}

#[derive(Component, Clone, Copy)]
struct ShipyardSelection {
    slot: ShipOrderSlot,
}

#[derive(Component)]
struct ShipyardRowChoice {
    dialog: Entity,
    slot: ShipOrderSlot,
    ship_name: String,
    description: String,
    picture: Handle<Image>,
}

#[derive(Component, Clone, Copy)]
struct ShipyardDetailPicture {
    dialog: Entity,
}

#[derive(Component, Clone, Copy)]
enum CityValue {
    LaborLow,
    LaborMedium,
    LaborHigh,
    LaborAvailable,
    PowerAvailable,
    Treasury,
    PredictedNeed(ResourceKind),
    OrderQuantity(CityOrderId),
    ArmoryOrderQuantity(MilitaryRecruitmentCategory),
    UniversityOrderQuantity(CivilianUnitKind),
    ShipyardOrderQuantity(ShipOrderSlot),
    LaborIndicator,
    StockIndicator(ResourceKind, i16),
    AvailableStockIndicator(ResourceKind, i16),
    AvailableCombinedStockIndicator(ResourceKind, ResourceKind, i16),
    AvailableBudgetIndicator(i32),
    TrainingLaborIndicator(TrainingLevel),
    BuildingCapacity(ProductionSlot),
    RegionalCapacity,
    OwnedRegionCount,
    ArmoryUnitKind,
    ArmoryWorkforceCost,
    ArmoryPrimaryCost,
    ArmorySecondaryCost,
    ArmoryCashCost,
    ArmoryWorkforceAvailable,
    ArmoryPrimaryAvailable,
    ArmorySecondaryAvailable,
    ArmoryTreasuryAvailable,
    UniversityUnitName,
    UniversityDescription,
    UniversityWorkforceCost,
    UniversityPaperCost,
    UniversityCashCost,
    UniversityWorkforceAvailable,
    UniversityPaperAvailable,
    ShipyardName,
    ShipyardDescription,
}

#[derive(Component, Clone, Copy)]
struct CityValueBinding {
    dialog: Option<Entity>,
    value: CityValue,
}

#[derive(Component)]
struct RetailNumberTemplate(String);

#[derive(Component, Clone, Copy)]
struct CityExpansionIndicator {
    dialog: Entity,
    slot: ProductionSlot,
}

pub(crate) struct CityPlugin;

impl Plugin for CityPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::City), enter_city_screen)
            .add_systems(OnExit(AppState::City), leave_city_screen)
            .add_systems(
                Update,
                animate_city_building_actions.run_if(in_state(AppState::City)),
            )
            .add_systems(
                Update,
                (
                    restore_city_dialogs,
                    sync_city_building_pictures,
                    sync_city_values,
                )
                    .chain()
                    .run_if(in_state(AppState::City)),
            )
            .add_observer(on_city_dialog_pressed)
            .add_observer(on_city_dialog_dragged)
            .add_observer(on_city_dialog_close)
            .add_observer(on_city_canvas_click)
            .add_observer(on_armory_row_selected)
            .add_observer(on_university_row_selected)
            .add_observer(on_shipyard_row_selected)
            .add_observer(on_city_amount_bar_click)
            .add_observer(on_city_expansion_open)
            .add_observer(on_city_building_change_choice)
            .add_observer(on_city_order_adjust);
    }
}

fn enter_city_screen(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
    session: Option<Res<GameSession>>,
) {
    let view_id = city_view_id();
    let view = catalog
        .view(&view_id)
        .expect("validated city-screen catalog view");
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_game_screen_nav(&mut commands, &catalog, &spawned);
    let mut root = commands.entity(spawned.root);
    root.insert((
        GameScreenRoot(view_id),
        CityScreenRoot,
        CityScreenNeedsSync,
        CityDialogsNeedRestore,
        DespawnOnExit(AppState::City),
    ));

    let Some(session) = session else {
        warn!("city screen opened without an authoritative game session");
        return;
    };
    let Some(nation) = MajorNationId::from_nation(session.0.turn.active_nation) else {
        warn!("city screen active nation is not a major nation");
        return;
    };
    bind_city_summary_values(&mut commands, &spawned, &mut assets);
    spawn_city_buildings(
        &mut commands,
        &spawned,
        &view.city_buildings,
        &view.city_building_actions,
        &session.0,
        nation,
        &mut assets,
    );
}

fn bind_city_summary_values(
    commands: &mut Commands,
    spawned: &super::catalog::SpawnedView,
    assets: &mut UiAssetResources,
) {
    let (font, layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 9,
            alignment: 1,
        })
        .expect("retail city placard text style");
    for (tag, value) in [
        (fourcc!("untr"), CityValue::LaborLow),
        (fourcc!("trai"), CityValue::LaborMedium),
        (fourcc!("prof"), CityValue::LaborHigh),
        (fourcc!("labP"), CityValue::LaborAvailable),
        (fourcc!("powe"), CityValue::PowerAvailable),
        (
            fourcc!("grai"),
            CityValue::PredictedNeed(ResourceKind::Grain),
        ),
        (
            fourcc!("prod"),
            CityValue::PredictedNeed(ResourceKind::Fruit),
        ),
        (
            fourcc!("meat"),
            CityValue::PredictedNeed(ResourceKind::Livestock),
        ),
        (
            fourcc!("hard"),
            CityValue::PredictedNeed(ResourceKind::Hardware),
        ),
        (
            fourcc!("clot"),
            CityValue::PredictedNeed(ResourceKind::Clothing),
        ),
        (
            fourcc!("furn"),
            CityValue::PredictedNeed(ResourceKind::Furniture),
        ),
    ] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated city summary binding");
        commands.entity(entity).insert((
            CityValueBinding {
                dialog: None,
                value,
            },
            Text::new(""),
            font.clone(),
            layout,
            TextColor(Color::BLACK),
        ));
    }
    let treasury = spawned
        .require_unique(fourcc!("trea"))
        .expect("validated city treasury binding");
    commands.entity(treasury).insert(CityValueBinding {
        dialog: None,
        value: CityValue::Treasury,
    });
}

fn spawn_city_buildings(
    commands: &mut Commands,
    spawned: &SpawnedView,
    visuals: &[CityBuildingVisual],
    actions: &[CityBuildingActionVisual],
    state: &GameState,
    nation: MajorNationId,
    assets: &mut UiAssetResources,
) {
    let main = spawned
        .require_unique(fourcc!("main"))
        .expect("validated city canvas binding");
    let city = state.nations.major(nation).city();
    let mut buildings = Vec::new();
    for visual in visuals {
        let Some(level) = city_building_level(state, nation, visual.slot) else {
            continue;
        };
        let offset = i16::from(visual.slot as u8);
        let mask_picture = PictureId::new(7100 + level * 16 + offset);
        let mask = match assets.indexed_picture(mask_picture) {
            Ok(indexed) => match CityBuildingHitMask::from_indexed_picture(&indexed) {
                Some(mask) => mask,
                None => {
                    warn!("city building mask {mask_picture} has no usable silhouette");
                    continue;
                }
            },
            Err(error) => {
                warn!("could not decode city building mask {mask_picture}: {error}");
                continue;
            }
        };
        let mut image = ImageNode::default();
        let mut visibility = Visibility::Hidden;
        if let Some(picture) = city_building_picture(city, visual.slot, level) {
            match assets.indexed_picture(picture) {
                Ok(indexed_picture) => {
                    if let Err(error) = assets.with_picture_image_mut(picture, |image| {
                        apply_city_picture_transparency(image, &indexed_picture);
                    }) {
                        warn!("could not decode city building picture {picture}: {error}");
                    } else {
                        match assets.picture(picture) {
                            Ok(handle) => {
                                image.image = handle;
                                visibility = Visibility::Visible;
                            }
                            Err(error) => {
                                warn!("could not load city building picture {picture}: {error}");
                            }
                        }
                    }
                }
                Err(error) => {
                    warn!("could not decode indexed city building picture {picture}: {error}");
                }
            }
        }
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(visual.origin[0] as f32),
                top: Val::Px(visual.origin[1] as f32),
                width: Val::Px(mask.width as f32),
                height: Val::Px(mask.height as f32),
                ..default()
            },
            image,
            visibility,
            CityBuildingPicture {
                nation,
                slot: visual.slot,
            },
            ZIndex(visual.draw_order as i32),
            Pickable::IGNORE,
            ChildOf(main),
            Name::new(format!("city-building:{:?}", visual.slot)),
        ));
        buildings.push(CityBuildingHitRegion {
            origin: IVec2::from_array(visual.origin),
            draw_order: visual.draw_order,
            slot: visual.slot,
            dialog: visual.dialog.clone(),
            mask,
        });
    }
    buildings.sort_by_key(|building| building.draw_order);
    commands
        .entity(main)
        .insert((CityCanvas { buildings }, RelativeCursorPosition::default()));
    spawn_city_building_actions(commands, main, actions, state, nation, assets);
}

fn apply_city_action_transparency(
    image: &mut Image,
    indexed: &IndexedPicture,
    frame_size: [i32; 2],
    frame_count: u8,
    occlusions: &[[i32; 4]],
) {
    let width = image.width() as usize;
    let height = image.height() as usize;
    let Some(pixels) = image.data.as_mut() else {
        return;
    };
    if width == 0
        || height == 0
        || indexed.width as usize != width
        || indexed.height as usize != height
        || pixels.len() != width * height * 4
        || indexed.pixels.len() != width * height
    {
        return;
    }
    for (pixel, &palette_index) in pixels.chunks_exact_mut(4).zip(&indexed.pixels) {
        if palette_index == 0x10 {
            pixel[3] = 0;
        }
    }
    let frame_width = frame_size[0] as usize;
    for &[left, top, right, bottom] in occlusions {
        for frame in 0..usize::from(frame_count) {
            for y in top as usize..bottom as usize {
                for x in left as usize..right as usize {
                    let alpha = ((y * width + frame * frame_width + x) * 4) + 3;
                    pixels[alpha] = 0;
                }
            }
        }
    }
}

fn city_building_action_enabled(city: &CityState, slot: ProductionSlot) -> bool {
    if slot == ProductionSlot::PowerPlant {
        !city.power_plant_upgrade_queued && city.orders.power_plant.progress.quantity > 0
    } else {
        assert!(
            is_ordinary_industry(slot),
            "generated city action belongs to a supported retail building"
        );
        !city_is_expanding(city, slot) && city.production_accum[slot] < city.production_orders[slot]
    }
}

fn spawn_city_building_actions(
    commands: &mut Commands,
    main: Entity,
    actions: &[CityBuildingActionVisual],
    state: &GameState,
    nation: MajorNationId,
    assets: &mut UiAssetResources,
) {
    let active_actions: Vec<_> = actions
        .iter()
        .filter(|action| {
            city_building_level(state, nation, action.slot) == Some(i16::from(action.level))
        })
        .collect();
    for (draw_order, action) in active_actions.iter().enumerate() {
        let indexed = match assets.indexed_picture(action.picture_id) {
            Ok(indexed) => indexed,
            Err(error) => {
                warn!(
                    "could not decode city action strip {}: {error}",
                    action.picture_id
                );
                continue;
            }
        };
        let strip_width = u32::try_from(action.frame_size[0] * i32::from(action.frame_count))
            .expect("generated city action strip has a positive width");
        let frame_height = u32::try_from(action.frame_size[1])
            .expect("generated city action strip has a positive height");
        if indexed.width < strip_width || indexed.height < frame_height {
            warn!(
                "city action strip {} is smaller than its recovered frame table",
                action.picture_id
            );
            continue;
        }
        let mut occlusions = Vec::new();
        let action_right = action.origin[0] + action.frame_size[0];
        let action_bottom = action.origin[1] + action.frame_size[1];
        for later in &active_actions[draw_order + 1..] {
            let left = action.origin[0].max(later.origin[0]);
            let top = action.origin[1].max(later.origin[1]);
            let right = action_right.min(later.origin[0] + later.frame_size[0]);
            let bottom = action_bottom.min(later.origin[1] + later.frame_size[1]);
            if left < right && top < bottom {
                occlusions.push([
                    left - action.origin[0],
                    top - action.origin[1],
                    right - action.origin[0],
                    bottom - action.origin[1],
                ]);
            }
        }
        let handle = match assets.transformed_picture(action.picture_id, |image| {
            apply_city_action_transparency(
                image,
                &indexed,
                action.frame_size,
                action.frame_count,
                &occlusions,
            );
        }) {
            Ok(handle) => handle,
            Err(error) => {
                warn!(
                    "could not prepare city action strip {}: {error}",
                    action.picture_id
                );
                continue;
            }
        };
        let frame_width = action.frame_size[0] as f32;
        let frame_height = action.frame_size[1] as f32;
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(action.origin[0] as f32),
                top: Val::Px(action.origin[1] as f32),
                width: Val::Px(frame_width),
                height: Val::Px(frame_height),
                ..default()
            },
            ImageNode {
                image: handle,
                rect: Some(Rect::new(0.0, 0.0, frame_width, frame_height)),
                ..default()
            },
            CityBuildingActionAnimation {
                nation,
                slot: action.slot,
                frame_count: action.frame_count,
                frame_size: action.frame_size,
                frame: 0,
                timer: Timer::new(
                    Duration::from_millis(if action.slot == ProductionSlot::PowerPlant {
                        160
                    } else {
                        224
                    }),
                    TimerMode::Repeating,
                ),
            },
            Visibility::Hidden,
            ZIndex(16 + draw_order as i32),
            Pickable::IGNORE,
            ChildOf(main),
            Name::new(format!("city-action:{}", action.picture_id)),
        ));
    }
}

fn animate_city_building_actions(
    time: Res<Time>,
    session: Res<GameSession>,
    mut actions: Query<(
        &mut CityBuildingActionAnimation,
        &mut ImageNode,
        &mut Visibility,
    )>,
) {
    for (mut action, mut image, mut visibility) in &mut actions {
        action.timer.tick(time.delta());
        let advanced = action.timer.times_finished_this_tick();
        if advanced > 0 {
            let frame_count = u32::from(action.frame_count);
            let shown_frame = (u32::from(action.frame) + advanced - 1) % frame_count;
            action.frame = ((shown_frame + 1) % frame_count) as u8;
            let left = shown_frame as f32 * action.frame_size[0] as f32;
            image.rect = Some(Rect::new(
                left,
                0.0,
                left + action.frame_size[0] as f32,
                action.frame_size[1] as f32,
            ));
            let city = session.0.nations.major(action.nation).city();
            *visibility = if city_building_action_enabled(city, action.slot) {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn on_city_canvas_click(
    click: On<Pointer<Click>>,
    canvases: Query<(&RelativeCursorPosition, &CityCanvas)>,
    dialogs: Query<(Entity, &CityBuildingDialog, &GlobalZIndex)>,
    screen_roots: Query<Entity, With<CityScreenRoot>>,
    modal_dialogs: Query<(), With<ModalDialog>>,
    mut session: ResMut<GameSession>,
    catalog: Res<UiCatalogResource>,
    mut ui: UiSpawner,
) {
    if !modal_dialogs.is_empty() {
        return;
    }
    let Ok((cursor, canvas)) = canvases.get(click.entity) else {
        return;
    };
    let Some(normalized) = cursor.normalized.filter(|_| cursor.cursor_over()) else {
        return;
    };
    let point = IVec2::new(
        ((normalized.x + 0.5) * CITY_WIDTH).floor() as i32,
        ((normalized.y + 0.5) * CITY_HEIGHT).floor() as i32,
    );
    let Some(building) = canvas
        .buildings
        .iter()
        .rev()
        .find(|building| building.mask.contains(point - building.origin))
    else {
        return;
    };
    let Some(nation) = MajorNationId::from_nation(session.0.turn.active_nation) else {
        return;
    };
    if dialogs
        .iter()
        .any(|(_, dialog, _)| dialog.nation == nation && dialog.slot == building.slot)
    {
        return;
    }
    let unbuilt_capacity_center = {
        let major = session.0.nations.major(nation);
        CityState::is_capacity_center(building.slot)
            && major.city().building_type(
                building.slot,
                major.economy(),
                major.common().owned_regions.len() as i32,
            ) == 0
    };
    if unbuilt_capacity_center {
        let available = !matches!(
            building.slot,
            ProductionSlot::OilRefinery | ProductionSlot::PowerPlant
        ) || session.0.technology.city_capabilities_by_nation[nation].oil_drilling;
        if available {
            open_city_construction_dialog(&mut ui, &mut session, nation, building.slot);
            for (entity, _, _) in &dialogs {
                ui.commands.entity(entity).insert(CityDialogNeedsSync);
            }
            for root in &screen_roots {
                ui.commands.entity(root).insert(CityScreenNeedsSync);
            }
            return;
        }
    }
    let z_index = dialogs.iter().map(|(_, _, z)| z.0).max().unwrap_or(0) + 1;
    assert!(z_index < 20, "modeless City dialogs remain below modals");
    open_city_dialog(
        &mut ui,
        &catalog,
        &session.0,
        nation,
        building.slot,
        building.dialog.clone(),
        None,
        z_index,
    );
}

fn supports_city_dialog(slot: ProductionSlot) -> bool {
    industry_page(slot).is_some()
        || matches!(
            slot,
            ProductionSlot::TradeSchool
                | ProductionSlot::Armory
                | ProductionSlot::University
                | ProductionSlot::Shipyard
                | ProductionSlot::FoodProcessing
                | ProductionSlot::PowerPlant
                | ProductionSlot::Transport
                | ProductionSlot::RegionalPopulation
        )
}

fn city_string(ui: &UiSpawner, group: i16, zero_based_index: i16) -> String {
    ui.string(group, zero_based_index + 1)
        .expect("validated English retail City string")
}

fn format_retail_value(template: &str, value: &str) -> String {
    if template.contains("[1: number]") {
        template.replace("[1: number]", value)
    } else if template.contains("[1:number]") {
        template.replace("[1:number]", value)
    } else {
        panic!("retail City number template has no first-number token");
    }
}

fn format_retail_number(template: &str, value: i16) -> String {
    format_retail_value(template, &value.to_string())
}

fn format_currency(value: i32) -> String {
    let negative = value < 0;
    let digits = i64::from(value).abs().to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    if negative {
        format!("-${grouped}")
    } else {
        format!("${grouped}")
    }
}

#[allow(clippy::too_many_arguments)]
fn open_city_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    state: &GameState,
    nation: MajorNationId,
    slot: ProductionSlot,
    view_id: ScopedViewId,
    saved_position: Option<IVec2>,
    z_index: i32,
) {
    if !supports_city_dialog(slot) {
        return;
    }
    let bar_color = ui.palette_color(0x16);
    let building_name = city_string(ui, CITY_BUILDING_STRING_GROUP, slot as i16);
    let capacity_template = city_string(ui, CITY_TEXT_STRING_GROUP, 0x10);
    let province_template = city_string(ui, CITY_TEXT_STRING_GROUP, 0x1d);
    let armory_title = (slot == ProductionSlot::Armory).then(|| {
        ui.string(0x271c, 0x20)
            .expect("validated English retail Armory title")
    });
    let university_data = (slot == ProductionSlot::University).then(|| UniversityDialogData {
        available: state.technology.city_capabilities_by_nation[nation]
            .university
            .available,
        rows: UNIVERSITY_ORDERS.map(|binding| {
            let CityOrderId::CivilianRecruit(kind) = binding.order else {
                unreachable!("University binding has a civilian recruitment order");
            };
            UniversityRowText {
                unit_name: ui
                    .string(0x2718, i16::from(kind as u8) + 1)
                    .expect("validated English retail civilian name"),
                description: ui
                    .string(0x2751, i16::from(kind as u8))
                    .expect("validated English retail civilian description"),
            }
        }),
    });
    let shipyard_data = (slot == ProductionSlot::Shipyard).then(|| {
        let city = state.nations.major(nation).city();
        ShipyardDialogData {
            rows: SHIP_ORDERS.map(|binding| {
                let CityOrderId::Ship(slot) = binding.order else {
                    unreachable!("Shipyard binding has a ship order");
                };
                let ship_type = city.orders.ships[slot].ship_type;
                if ship_type == ShipType::NoShip {
                    return None;
                }
                Some(ShipyardRowData {
                    ship_name: ui
                        .string(0x2716, ship_type as i16 + 1)
                        .expect("validated English retail ship name"),
                    description: ui
                        .string(0x2752, ship_type as i16)
                        .expect("validated English retail ship description"),
                    picture: ui
                        .picture(PictureId::new(9834 + ship_type as i16))
                        .expect("validated retail Shipyard detail picture"),
                })
            }),
        }
    });
    let spawned = ui.spawn(view_id);
    if let Some(page) = industry_page(slot) {
        bind_industry_dialog(
            &mut ui.commands,
            catalog,
            &spawned,
            nation,
            page,
            building_name,
            capacity_template,
            bar_color,
        );
    } else {
        match slot {
            ProductionSlot::TradeSchool => {
                bind_training_dialog(&mut ui.commands, catalog, &spawned, nation, building_name)
            }
            ProductionSlot::Armory => bind_armory_dialog(
                &mut ui.commands,
                catalog,
                &spawned,
                nation,
                armory_title.expect("Armory branch has its retail title"),
            ),
            ProductionSlot::University => bind_university_dialog(
                &mut ui.commands,
                catalog,
                &spawned,
                nation,
                university_data.expect("University branch has retail text and technology"),
            ),
            ProductionSlot::Shipyard => bind_shipyard_dialog(
                &mut ui.commands,
                catalog,
                &spawned,
                nation,
                shipyard_data.expect("Shipyard branch has retail ship data"),
            ),
            ProductionSlot::FoodProcessing => {
                bind_food_dialog(&mut ui.commands, catalog, &spawned, nation, building_name)
            }
            ProductionSlot::PowerPlant => {
                bind_power_dialog(&mut ui.commands, catalog, &spawned, nation, building_name)
            }
            ProductionSlot::Transport => bind_transport_capacity_dialog(
                &mut ui.commands,
                catalog,
                &spawned,
                nation,
                building_name,
            ),
            ProductionSlot::RegionalPopulation => bind_population_dialog(
                &mut ui.commands,
                catalog,
                &spawned,
                nation,
                building_name,
                capacity_template,
                province_template,
            ),
            _ => unreachable!("supported ordinary city dialog handled above"),
        }
    }
    if let Some(position) = saved_position {
        let window = spawned
            .require_unique(fourcc!("WIND"))
            .expect("validated city window binding");
        ui.commands
            .entity(window)
            .entry::<Node>()
            .and_modify(move |mut node| {
                node.left = px(position.x as f32);
                node.top = px(position.y as f32);
            });
    }
    ui.commands
        .entity(spawned.root)
        .insert(GlobalZIndex(z_index));
}

fn bind_city_dialog_root(
    commands: &mut Commands,
    spawned: &SpawnedView,
    nation: MajorNationId,
    slot: ProductionSlot,
) -> Entity {
    let root = spawned.root;
    let window = spawned
        .require_unique(fourcc!("WIND"))
        .expect("validated city window binding");
    commands.entity(root).insert((
        CityBuildingDialog {
            nation,
            slot,
            window,
        },
        CityDialogNeedsSync,
        GlobalZIndex(19),
        Pickable::IGNORE,
    ));
    commands
        .entity(window)
        .insert((CityDialogWindow { dialog: root }, Pickable::default()));
    commands.entity(window).with_children(|parent| {
        parent.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(0),
                top: px(-CITY_DIALOG_CAPTION_HEIGHT),
                width: percent(100),
                height: px(CITY_DIALOG_CAPTION_HEIGHT),
                ..default()
            },
            BackgroundColor(Color::srgb_u8(0, 0, 128)),
            CityDialogCaption { window },
            Pickable::default(),
            Name::new("city-dialog-caption"),
        ));
        parent
            .spawn((
                UiButton,
                Node {
                    position_type: PositionType::Absolute,
                    right: px(2),
                    top: px(-CITY_DIALOG_CAPTION_HEIGHT + 2.0),
                    width: px(CITY_DIALOG_CLOSE_SIZE),
                    height: px(CITY_DIALOG_CLOSE_SIZE),
                    align_items: AlignItems::Center,
                    justify_content: JustifyContent::Center,
                    ..default()
                },
                BackgroundColor(Color::srgb_u8(192, 192, 192)),
                CityDialogClose { dialog: root },
                ZIndex(1),
                Name::new("city-dialog-close"),
            ))
            .with_child((
                Text::new("×"),
                TextFont {
                    font_size: FontSize::Px(12.0),
                    ..default()
                },
                TextColor(Color::BLACK),
                Pickable::IGNORE,
            ));
    });
    root
}

fn restore_city_dialogs(
    roots: Query<Entity, With<CityDialogsNeedRestore>>,
    session: Option<Res<GameSession>>,
    catalog: Res<UiCatalogResource>,
    dialogs: Query<(&CityBuildingDialog, &GlobalZIndex)>,
    mut ui: UiSpawner,
) {
    if roots.is_empty() {
        return;
    }
    let Some(session) = session else {
        for root in &roots {
            ui.commands.entity(root).remove::<CityDialogsNeedRestore>();
        }
        return;
    };
    let nation = MajorNationId::from_nation(session.0.turn.active_nation)
        .expect("City screen requires an active major nation");
    let buildings = catalog
        .view(&city_view_id())
        .expect("validated City screen catalog view")
        .city_buildings
        .clone();
    let city = session.0.nations.major(nation).city();
    let mut next_z = dialogs.iter().map(|(_, z)| z.0).max().unwrap_or(0) + 1;
    for building in buildings {
        if !supports_city_dialog(building.slot) {
            continue;
        }
        if dialogs
            .iter()
            .any(|(dialog, _)| dialog.nation == nation && dialog.slot == building.slot)
        {
            continue;
        }
        let state = city.building_window_state(building.slot);
        if state.flag == 0 {
            continue;
        }
        open_city_dialog(
            &mut ui,
            &catalog,
            &session.0,
            nation,
            building.slot,
            building.dialog,
            Some(IVec2::new(
                i32::from(state.current),
                i32::from(state.accumulated),
            )),
            next_z,
        );
        next_z += 1;
    }
    assert!(next_z <= 20, "modeless City dialogs remain below modals");
    for root in &roots {
        ui.commands.entity(root).remove::<CityDialogsNeedRestore>();
    }
}

fn node_position(node: &Node) -> (f32, f32) {
    let Val::Px(left) = node.left else {
        panic!("generated City window has a non-pixel left position");
    };
    let Val::Px(top) = node.top else {
        panic!("generated City window has a non-pixel top position");
    };
    (left, top)
}

fn saved_window_coordinate(value: f32) -> i16 {
    i16::try_from(value.round() as i32).expect("City window coordinate fits retail short storage")
}

fn leave_city_screen(
    mut commands: Commands,
    mut session: Option<ResMut<GameSession>>,
    catalog: Res<UiCatalogResource>,
    dialogs: Query<(Entity, &CityBuildingDialog)>,
    windows: Query<&Node, With<CityDialogWindow>>,
) {
    if let Some(session) = session.as_mut() {
        let nation = MajorNationId::from_nation(session.0.turn.active_nation)
            .expect("City screen requires an active major nation");
        let slots = catalog
            .view(&city_view_id())
            .expect("validated City screen catalog view")
            .city_buildings
            .iter()
            .map(|building| building.slot)
            .filter(|slot| supports_city_dialog(*slot))
            .collect::<Vec<_>>();
        for slot in slots {
            let open = dialogs
                .iter()
                .find(|(_, dialog)| dialog.nation == nation && dialog.slot == slot);
            let state = if let Some((_, dialog)) = open {
                let (left, top) = node_position(
                    windows
                        .get(dialog.window)
                        .expect("open City dialog has its generated window"),
                );
                BuildingWindowState {
                    flag: 1,
                    current: saved_window_coordinate(left),
                    accumulated: saved_window_coordinate(top),
                }
            } else {
                BuildingWindowState {
                    flag: 0,
                    current: 0,
                    accumulated: 0,
                }
            };
            session
                .0
                .set_city_building_window_state(nation, slot, state);
        }
    }
    for (root, _) in &dialogs {
        commands.entity(root).despawn();
    }
}

fn on_city_dialog_pressed(
    press: On<Pointer<Press>>,
    windows: Query<&CityDialogWindow>,
    parents: Query<&ChildOf>,
    mut dialogs: Query<(Entity, &mut GlobalZIndex), With<CityBuildingDialog>>,
    modals: Query<(), With<ModalDialog>>,
) {
    if press.event.button != PointerButton::Primary || !modals.is_empty() {
        return;
    }
    let mut target = press.original_event_target();
    let dialog = loop {
        if let Ok(window) = windows.get(target) {
            break window.dialog;
        }
        let Ok(parent) = parents.get(target) else {
            return;
        };
        target = parent.parent();
    };
    if dialogs.get(dialog).is_err() {
        return;
    }
    let mut order = dialogs
        .iter()
        .map(|(entity, z)| (entity, z.0))
        .collect::<Vec<_>>();
    order.sort_by_key(|(entity, z)| (*entity == dialog, *z, entity.to_bits()));
    for (index, (entity, _)) in order.into_iter().enumerate() {
        dialogs
            .get_mut(entity)
            .expect("City dialog remained present while raising it")
            .1
            .0 = i32::try_from(index + 1).expect("City dialog count fits z order");
    }
}

fn on_city_dialog_dragged(
    drag: On<Pointer<Drag>>,
    captions: Query<&CityDialogCaption>,
    mut windows: Query<&mut Node, With<CityDialogWindow>>,
    modals: Query<(), With<ModalDialog>>,
) {
    if drag.event.button != PointerButton::Primary || !modals.is_empty() {
        return;
    }
    let Ok(caption) = captions.get(drag.entity) else {
        return;
    };
    let mut node = windows
        .get_mut(caption.window)
        .expect("City dialog caption owns its generated window");
    let (left, top) = node_position(&node);
    node.left = px(left + drag.event.delta.x);
    node.top = px(top + drag.event.delta.y);
}

fn on_city_dialog_close(
    activate: On<Activate>,
    closes: Query<&CityDialogClose>,
    modals: Query<(), With<ModalDialog>>,
    mut commands: Commands,
) {
    if !modals.is_empty() {
        return;
    }
    let Ok(close) = closes.get(activate.entity) else {
        return;
    };
    commands.entity(close.dialog).despawn();
}

#[allow(clippy::too_many_arguments)]
fn bind_city_order_controls(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    root: Entity,
    nation: MajorNationId,
    bindings: &[CityOrderBinding],
    decrease_tag: FourCc,
    increase_tag: FourCc,
    quantity_tag: FourCc,
    step: i16,
) {
    for binding in bindings {
        let left = spawned
            .require_under(catalog, binding.tag, decrease_tag)
            .expect("validated city order decrease binding");
        let right = spawned
            .require_under(catalog, binding.tag, increase_tag)
            .expect("validated city order increase binding");
        let quantity = spawned
            .require_under(catalog, binding.tag, quantity_tag)
            .expect("validated city order quantity binding");
        commands.entity(left).insert(CityOrderAdjust {
            dialog: root,
            nation,
            order: binding.order,
            delta: -step,
        });
        commands.entity(right).insert(CityOrderAdjust {
            dialog: root,
            nation,
            order: binding.order,
            delta: step,
        });
        commands.entity(quantity).insert((
            Text::new(""),
            CityValueBinding {
                dialog: Some(root),
                value: CityValue::OrderQuantity(binding.order),
            },
        ));
    }
}

fn bind_industry_amount_bars(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    root: Entity,
    nation: MajorNationId,
    page: IndustryPage,
    bar_color: Color,
) {
    for binding in page.orders {
        let bar = spawned
            .require_under(catalog, binding.tag, fourcc!("bar "))
            .expect("validated industry amount-bar binding");
        let quantity = spawned
            .require_under(catalog, binding.tag, fourcc!("move"))
            .expect("validated industry quantity binding");
        let fill = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(0.0),
                    top: Val::Px(1.0),
                    width: Val::Px(0.0),
                    height: Val::Px(4.0),
                    ..default()
                },
                BackgroundColor(bar_color),
                Pickable::IGNORE,
                ChildOf(bar),
                Name::new("city-industry-amount"),
            ))
            .id();
        let maximum = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(0.0),
                    top: Val::Px(0.0),
                    width: Val::Px(1.0),
                    height: Val::Px(5.0),
                    ..default()
                },
                BackgroundColor(Color::BLACK),
                Pickable::IGNORE,
                ChildOf(bar),
                Name::new("city-industry-maximum"),
            ))
            .id();
        commands.entity(bar).insert((
            RelativeCursorPosition::default(),
            CityIndustryAmountBar {
                dialog: root,
                nation,
                order: binding.order,
                slot: page.slot,
                quantity,
                fill,
                maximum,
            },
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn bind_industry_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    page: IndustryPage,
    building_name: String,
    capacity_template: String,
    bar_color: Color,
) {
    let root = bind_city_dialog_root(commands, spawned, nation, page.slot);

    let name = spawned
        .require_unique(fourcc!("name"))
        .expect("validated industry name binding");
    commands.entity(name).insert(Text::new(building_name));
    let capacity = spawned
        .require_unique(fourcc!("capT"))
        .expect("validated industry capacity binding");
    commands.entity(capacity).insert((
        Text::new(""),
        CityValueBinding {
            dialog: Some(root),
            value: CityValue::BuildingCapacity(page.slot),
        },
        RetailNumberTemplate(capacity_template),
    ));
    let labor = spawned
        .require_unique(fourcc!("labV"))
        .expect("validated industry labor binding");
    commands.entity(labor).insert((
        Text::new("X"),
        CityValueBinding {
            dialog: Some(root),
            value: CityValue::LaborIndicator,
        },
    ));
    for &(resource, tag, minimum) in page.stocks {
        let entity = spawned
            .require_unique(tag)
            .expect("validated industry stock binding");
        commands.entity(entity).insert((
            Text::new("X"),
            CityValueBinding {
                dialog: Some(root),
                value: CityValue::StockIndicator(resource, minimum),
            },
        ));
    }
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        page.orders,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        1,
    );
    bind_industry_amount_bars(commands, catalog, spawned, root, nation, page, bar_color);
    let expansion = spawned
        .require_unique(fourcc!("expa"))
        .expect("validated industry expansion binding");
    commands.entity(expansion).insert(CityExpansionOpen {
        dialog: root,
        nation,
        slot: page.slot,
    });
    let expansion_indicator = spawned
        .require_unique(fourcc!("flag"))
        .expect("validated industry expansion binding");
    commands
        .entity(expansion_indicator)
        .insert(CityExpansionIndicator {
            dialog: root,
            slot: page.slot,
        });
}

fn bind_training_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
) {
    let root = bind_city_dialog_root(commands, spawned, nation, ProductionSlot::TradeSchool);
    let name = spawned
        .require_unique(fourcc!("name"))
        .expect("validated trade-school name binding");
    commands.entity(name).insert(Text::new(building_name));
    for (tag, text) in [(fourcc!("cos1"), "$100"), (fourcc!("cos2"), "$1,000")] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated trade-school cost binding");
        commands.entity(entity).insert(Text::new(text));
    }
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        &TRAINING_ORDERS,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        1,
    );
    for (tag, value) in [
        (
            fourcc!("pap1"),
            CityValue::AvailableStockIndicator(ResourceKind::Paper, 1),
        ),
        (
            fourcc!("pap2"),
            CityValue::AvailableStockIndicator(ResourceKind::Paper, 2),
        ),
        (fourcc!("mon1"), CityValue::AvailableBudgetIndicator(100)),
        (fourcc!("mon2"), CityValue::AvailableBudgetIndicator(1_000)),
        (
            fourcc!("untV"),
            CityValue::TrainingLaborIndicator(TrainingLevel::Medium),
        ),
        (
            fourcc!("traV"),
            CityValue::TrainingLaborIndicator(TrainingLevel::High),
        ),
    ] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated trade-school availability binding");
        commands.entity(entity).insert((
            Text::new("X"),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
}

fn bind_armory_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    title: String,
) {
    let root = bind_city_dialog_root(commands, spawned, nation, ProductionSlot::Armory);
    let title_control = spawned
        .require_unique(fourcc!("titl"))
        .expect("validated Armory title binding");
    commands.entity(title_control).insert(Text::new(title));
    commands.entity(root).insert(ArmorySelection {
        category: MilitaryRecruitmentCategory::LightInfantry,
    });
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        &ARMORY_ORDERS,
        fourcc!("minu"),
        fourcc!("plus"),
        fourcc!("numb"),
        1,
    );
    for binding in &ARMORY_ORDERS {
        let CityOrderId::MilitaryRecruit(category) = binding.order else {
            unreachable!("armory binding has a military recruitment order");
        };
        let button = spawned
            .require_unique(armory_button_tag(category))
            .expect("validated armory row button binding");
        let mut button_commands = commands.entity(button);
        button_commands.insert(ArmoryRowChoice {
            dialog: root,
            category,
        });
        if category == MilitaryRecruitmentCategory::LightInfantry {
            button_commands.insert(Checked);
        } else {
            button_commands.remove::<Checked>();
        }
        let quantity = spawned
            .require_under(catalog, binding.tag, fourcc!("numb"))
            .expect("validated armory quantity binding");
        commands.entity(quantity).insert((
            InteractionDisabled,
            CityValueBinding {
                dialog: Some(root),
                value: CityValue::ArmoryOrderQuantity(category),
            },
        ));
    }
    for (tag, value) in [
        (fourcc!("unit"), CityValue::ArmoryUnitKind),
        (fourcc!("cos0"), CityValue::ArmoryWorkforceCost),
        (fourcc!("cos1"), CityValue::ArmoryPrimaryCost),
        (fourcc!("cos2"), CityValue::ArmorySecondaryCost),
        (fourcc!("cos3"), CityValue::ArmoryCashCost),
        (fourcc!("ava0"), CityValue::ArmoryWorkforceAvailable),
        (fourcc!("ava1"), CityValue::ArmoryPrimaryAvailable),
        (fourcc!("ava2"), CityValue::ArmorySecondaryAvailable),
        (fourcc!("ava3"), CityValue::ArmoryTreasuryAvailable),
    ] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated armory detail binding");
        commands.entity(entity).insert((
            Text::new(""),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
}

fn bind_university_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    data: UniversityDialogData,
) {
    let root = bind_city_dialog_root(commands, spawned, nation, ProductionSlot::University);
    commands.entity(root).insert(UniversitySelection {
        kind: CivilianUnitKind::Miner,
    });
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        &UNIVERSITY_ORDERS,
        fourcc!("minu"),
        fourcc!("plus"),
        fourcc!("numb"),
        1,
    );
    for (binding, row_text) in UNIVERSITY_ORDERS.iter().zip(data.rows) {
        let CityOrderId::CivilianRecruit(kind) = binding.order else {
            unreachable!("University binding has a civilian recruitment order");
        };
        let button = spawned
            .require_unique(university_button_tag(kind))
            .expect("validated University row button binding");
        let row = spawned
            .require_unique(binding.tag)
            .expect("validated University quantity-row binding");
        let minus = spawned
            .require_under(catalog, binding.tag, fourcc!("minu"))
            .expect("validated University decrease binding");
        let plus = spawned
            .require_under(catalog, binding.tag, fourcc!("plus"))
            .expect("validated University increase binding");
        let quantity = spawned
            .require_under(catalog, binding.tag, fourcc!("numb"))
            .expect("validated University quantity binding");
        let available = data.available[kind];
        let visibility = if available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        {
            let mut button_commands = commands.entity(button);
            button_commands.insert((
                UniversityRowChoice {
                    dialog: root,
                    kind,
                    unit_name: row_text.unit_name,
                    description: row_text.description,
                },
                visibility,
            ));
            if kind == CivilianUnitKind::Miner {
                button_commands.insert(Checked);
            } else {
                button_commands.remove::<Checked>();
            }
            if available {
                button_commands.remove::<InteractionDisabled>();
            } else {
                button_commands.insert(InteractionDisabled);
            }
        }
        commands.entity(row).insert(visibility);
        for control in [minus, plus] {
            if available {
                commands.entity(control).remove::<InteractionDisabled>();
            } else {
                commands.entity(control).insert(InteractionDisabled);
            }
        }
        commands.entity(quantity).insert((
            InteractionDisabled,
            CityValueBinding {
                dialog: Some(root),
                value: CityValue::UniversityOrderQuantity(kind),
            },
        ));
    }
    for tag in [fourcc!("fix2"), fourcc!("fix3"), fourcc!("fix4")] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated University requirement-label binding");
        commands.entity(entity).insert(Visibility::Hidden);
    }
    for (tag, value) in [
        (fourcc!("unit"), CityValue::UniversityUnitName),
        (fourcc!("desc"), CityValue::UniversityDescription),
        (fourcc!("cexp"), CityValue::UniversityWorkforceCost),
        (fourcc!("cpap"), CityValue::UniversityPaperCost),
        (fourcc!("cash"), CityValue::UniversityCashCost),
        (fourcc!("aexp"), CityValue::UniversityWorkforceAvailable),
        (fourcc!("apap"), CityValue::UniversityPaperAvailable),
        (fourcc!("trea"), CityValue::Treasury),
    ] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated University detail binding");
        commands.entity(entity).insert((
            Text::new(""),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
}

fn bind_shipyard_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    data: ShipyardDialogData,
) {
    assert!(
        data.rows[0].is_some(),
        "retail Shipyard row zero always has a current ship"
    );
    let root = bind_city_dialog_root(commands, spawned, nation, ProductionSlot::Shipyard);
    commands.entity(root).insert(ShipyardSelection {
        slot: ShipOrderSlot::MerchantEarlyPrimary,
    });
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        &SHIP_ORDERS,
        fourcc!("minu"),
        fourcc!("plus"),
        fourcc!("numb"),
        1,
    );
    for (binding, row_data) in SHIP_ORDERS.iter().zip(data.rows) {
        let CityOrderId::Ship(slot) = binding.order else {
            unreachable!("Shipyard binding has a ship order");
        };
        let button = spawned
            .require_unique(shipyard_button_tag(slot))
            .expect("validated Shipyard row button binding");
        let row = spawned
            .require_unique(binding.tag)
            .expect("validated Shipyard quantity-row binding");
        let minus = spawned
            .require_under(catalog, binding.tag, fourcc!("minu"))
            .expect("validated Shipyard decrease binding");
        let plus = spawned
            .require_under(catalog, binding.tag, fourcc!("plus"))
            .expect("validated Shipyard increase binding");
        let quantity = spawned
            .require_under(catalog, binding.tag, fourcc!("numb"))
            .expect("validated Shipyard quantity binding");
        let visibility = if row_data.is_some() {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        {
            let mut button_commands = commands.entity(button);
            button_commands.insert(visibility);
            if slot == ShipOrderSlot::MerchantEarlyPrimary {
                button_commands.insert(Checked);
            } else {
                button_commands.remove::<Checked>();
            }
            if let Some(row_data) = row_data {
                button_commands.insert(ShipyardRowChoice {
                    dialog: root,
                    slot,
                    ship_name: row_data.ship_name,
                    description: row_data.description,
                    picture: row_data.picture,
                });
                button_commands.remove::<InteractionDisabled>();
            } else {
                button_commands.insert(InteractionDisabled);
            }
        }
        commands.entity(row).insert(visibility);
        for control in [minus, plus] {
            if visibility == Visibility::Visible {
                commands.entity(control).remove::<InteractionDisabled>();
            } else {
                commands.entity(control).insert(InteractionDisabled);
            }
        }
        commands.entity(quantity).insert((
            InteractionDisabled,
            CityValueBinding {
                dialog: Some(root),
                value: CityValue::ShipyardOrderQuantity(slot),
            },
        ));
    }
    for (tag, value) in [
        (fourcc!("snam"), CityValue::ShipyardName),
        (fourcc!("desc"), CityValue::ShipyardDescription),
    ] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated Shipyard detail binding");
        commands.entity(entity).insert((
            Text::new(""),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
    let picture = spawned
        .require_unique(fourcc!("spic"))
        .expect("validated Shipyard detail-picture binding");
    commands
        .entity(picture)
        .insert(ShipyardDetailPicture { dialog: root });
}

#[allow(clippy::too_many_arguments)]
fn bind_rail_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    slot: ProductionSlot,
    building_name: String,
    bindings: &[CityOrderBinding],
    step: i16,
) -> Entity {
    let root = bind_city_dialog_root(commands, spawned, nation, slot);
    let name_control = spawned
        .require_unique(fourcc!("name"))
        .expect("validated city dialog name binding");
    commands
        .entity(name_control)
        .insert(Text::new(building_name));
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        bindings,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        step,
    );
    root
}

fn bind_food_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
) {
    let root = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        ProductionSlot::FoodProcessing,
        building_name,
        &FOOD_ORDERS,
        2,
    );
    for (tag, value) in [
        (fourcc!("labV"), CityValue::LaborIndicator),
        (
            fourcc!("grai"),
            CityValue::AvailableStockIndicator(ResourceKind::Grain, 2),
        ),
        (
            fourcc!("prod"),
            CityValue::AvailableStockIndicator(ResourceKind::Fruit, 1),
        ),
        (
            fourcc!("fish"),
            CityValue::AvailableCombinedStockIndicator(
                ResourceKind::Fish,
                ResourceKind::Livestock,
                1,
            ),
        ),
    ] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated food-processing availability binding");
        commands.entity(entity).insert((
            Text::new("X"),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
}

fn bind_power_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
) {
    bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        ProductionSlot::PowerPlant,
        building_name,
        &POWER_ORDERS,
        6,
    );
    let fuel = spawned
        .require_unique(fourcc!("fuel"))
        .expect("validated power-plant fuel binding");
    commands
        .entity(fuel)
        .insert((Text::new("X"), Visibility::Hidden));
}

fn bind_transport_capacity_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
) {
    let root = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        ProductionSlot::Transport,
        building_name,
        &TRANSPORT_CAPACITY_ORDERS,
        1,
    );
    for (tag, value) in [
        (fourcc!("labV"), CityValue::LaborIndicator),
        (
            fourcc!("lumb"),
            CityValue::StockIndicator(ResourceKind::Lumber, 1),
        ),
        (
            fourcc!("stee"),
            CityValue::StockIndicator(ResourceKind::Steel, 1),
        ),
    ] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated transport-capacity availability binding");
        commands.entity(entity).insert((
            Text::new("X"),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
}

fn bind_population_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    building_name: String,
    capacity_template: String,
    province_template: String,
) {
    let root = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        ProductionSlot::RegionalPopulation,
        building_name,
        &POPULATION_ORDERS,
        1,
    );
    for (tag, value) in [
        (
            fourcc!("food"),
            CityValue::AvailableStockIndicator(ResourceKind::Food, 1),
        ),
        (
            fourcc!("clot"),
            CityValue::AvailableStockIndicator(ResourceKind::Clothing, 1),
        ),
        (
            fourcc!("furn"),
            CityValue::AvailableStockIndicator(ResourceKind::Furniture, 1),
        ),
        (fourcc!("capT"), CityValue::RegionalCapacity),
        (fourcc!("prov"), CityValue::OwnedRegionCount),
    ] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated population-growth binding");
        commands.entity(entity).insert((
            Text::new(""),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
    }
    let capacity = spawned
        .require_unique(fourcc!("capT"))
        .expect("validated population capacity binding");
    commands
        .entity(capacity)
        .insert(RetailNumberTemplate(capacity_template));
    let provinces = spawned
        .require_unique(fourcc!("prov"))
        .expect("validated population province-count binding");
    commands
        .entity(provinces)
        .insert(RetailNumberTemplate(province_template));
}

fn open_city_construction_dialog(
    ui: &mut UiSpawner,
    session: &mut GameSession,
    nation: MajorNationId,
    slot: ProductionSlot,
) {
    assert!(
        CityState::is_capacity_center(slot),
        "retail construction dialog belongs to a City capacity center"
    );
    let (capacity_value, can_reserve) = match slot {
        ProductionSlot::PowerPlant => {
            session.0.set_power_plant_upgrade(nation, false);
            let major = session.0.nations.major(nation);
            let can_reserve = major
                .economy()
                .available_diplomacy_budget(major.common().treasury)
                >= 5_000;
            (city_string(ui, CITY_TEXT_STRING_GROUP, 0x15), can_reserve)
        }
        _ => {
            assert!(
                is_ordinary_industry(slot),
                "non-power capacity center has a retail expansion order"
            );
            let (next_capacity, needed, original_quantity) = {
                let major = session.0.nations.major(nation);
                let city = major.city();
                let owned_regions = major.common().owned_regions.len() as i32;
                let current = city.building_type(slot, major.economy(), owned_regions);
                let next_capacity =
                    city.max_building_capacity(slot, major.economy(), owned_regions);
                let original_quantity = city.orders.expansions[slot]
                    .as_ref()
                    .expect("ordinary capacity center has a retail expansion order")
                    .progress
                    .quantity;
                (next_capacity, next_capacity - current, original_quantity)
            };
            let order = CityOrderId::Expansion(slot);
            let can_reserve = session.0.set_city_order_quantity(nation, order, needed);
            assert!(
                session
                    .0
                    .set_city_order_quantity(nation, order, original_quantity),
                "retail construction probe must restore its original quantity"
            );
            (next_capacity.to_string(), can_reserve)
        }
    };
    let spawned = ui.spawn_modal(construction_dialog_view_id());
    bind_construction_dialog(ui, &spawned, nation, slot, &capacity_value, can_reserve);
}

fn bind_construction_dialog(
    ui: &mut UiSpawner,
    spawned: &SpawnedView,
    nation: MajorNationId,
    slot: ProductionSlot,
    capacity_value: &str,
    can_reserve: bool,
) {
    let root = spawned.root;
    ui.commands
        .entity(root)
        .insert((CityBuildingChangeDialog, DespawnOnExit(AppState::City)));

    let picture = PictureId::new(9250 + i16::from(slot as u8) * 5);
    match ui.picture(picture) {
        Ok(handle) => {
            let dialog = spawned
                .require_unique(fourcc!("DLOG"))
                .expect("validated construction-dialog picture binding");
            ui.commands.entity(dialog).insert(ImageNode::new(handle));
        }
        Err(error) => warn!("could not load construction-dialog picture {picture}: {error}"),
    }

    let capacity = format_retail_value(
        &city_string(ui, CITY_TEXT_STRING_GROUP, 0x10),
        capacity_value,
    );
    let text_group = 0x2422 + i16::from(slot as u8);
    let text = [
        (
            fourcc!("tex1"),
            ui.string(text_group, 1)
                .expect("validated English retail construction headline"),
        ),
        (
            fourcc!("name"),
            city_string(ui, CITY_BUILDING_STRING_GROUP, slot as i16),
        ),
        (fourcc!("capT"), capacity),
        (
            fourcc!("cost"),
            city_string(ui, CITY_TEXT_STRING_GROUP, 0x14),
        ),
    ];
    for (tag, value) in text {
        let entity = spawned
            .require_unique(tag)
            .expect("validated construction-dialog text binding");
        ui.commands.entity(entity).insert(Text::new(value));
    }

    let text2 = spawned
        .require_unique(fourcc!("tex2"))
        .expect("validated construction detail binding");
    if slot == ProductionSlot::PowerPlant {
        ui.commands
            .entity(text2)
            .entry::<Node>()
            .and_modify(|mut node| {
                let Val::Px(top) = node.top else {
                    panic!("catalog construction detail has fixed retail coordinates");
                };
                node.top = px(top + 5.0);
            });
    }

    let connective = spawned
        .require_unique(fourcc!("or  "))
        .expect("validated construction connective binding");
    let connective_left = match slot {
        ProductionSlot::TextileMill => Some(0x98),
        ProductionSlot::Metalworks => Some(0xcd),
        ProductionSlot::LumberMill => Some(0xd0),
        _ => None,
    };
    if let Some(left) = connective_left {
        let connective_text = city_string(ui, CITY_TEXT_STRING_GROUP, 0x11);
        let mut connective_commands = ui.commands.entity(connective);
        connective_commands.insert((Text::new(connective_text), Visibility::Visible));
        connective_commands
            .entry::<Node>()
            .and_modify(move |mut node| node.left = px(left as f32));
    } else {
        ui.commands.entity(connective).insert(Visibility::Hidden);
    }

    let buck = spawned
        .require_unique(fourcc!("buck"))
        .expect("validated construction cash binding");
    ui.commands.entity(buck).insert((
        Text::new(if slot == ProductionSlot::PowerPlant {
            format_currency(5_000)
        } else {
            String::new()
        }),
        if slot == ProductionSlot::PowerPlant {
            Visibility::Visible
        } else {
            Visibility::Hidden
        },
    ));

    let warning = spawned
        .require_unique(fourcc!("warn"))
        .expect("validated construction warning binding");
    let warning_text = city_string(
        ui,
        CITY_TEXT_STRING_GROUP,
        if slot == ProductionSlot::PowerPlant {
            0x16
        } else {
            0x17
        },
    );
    let warning_color = ui.palette_color(0xcb);
    ui.commands.entity(warning).insert((
        Text::new(warning_text),
        TextColor(warning_color),
        if can_reserve {
            Visibility::Hidden
        } else {
            Visibility::Visible
        },
    ));

    let okay = spawned
        .require_unique(fourcc!("okay"))
        .expect("validated construction OK binding");
    let mut okay_commands = ui.commands.entity(okay);
    okay_commands.insert(CityBuildingChangeChoice {
        dialog: root,
        nation,
        slot,
        accept: true,
    });
    if !can_reserve {
        okay_commands.insert((InteractionDisabled, Visibility::Hidden));
    }

    let cancel = spawned
        .require_unique(fourcc!("cncl"))
        .expect("validated construction cancel binding");
    ui.commands.entity(cancel).insert(CityBuildingChangeChoice {
        dialog: root,
        nation,
        slot,
        accept: false,
    });
}

#[allow(clippy::too_many_arguments)]
fn bind_expansion_dialog(
    ui: &mut UiSpawner,
    spawned: &SpawnedView,
    nation: MajorNationId,
    slot: ProductionSlot,
    building_name: String,
    next_capacity: i16,
    next_level: u8,
    can_reserve: bool,
) {
    let root = spawned.root;
    ui.commands
        .entity(root)
        .insert((CityBuildingChangeDialog, DespawnOnExit(AppState::City)));

    let picture = PictureId::new(9250 + i16::from(slot as u8) * 5 + i16::from(next_level));
    match ui.picture(picture) {
        Ok(handle) => {
            let dialog = spawned
                .require_unique(fourcc!("DLOG"))
                .expect("validated expansion-dialog picture binding");
            ui.commands.entity(dialog).insert(ImageNode::new(handle));
        }
        Err(error) => warn!("could not load expansion-dialog picture {picture}: {error}"),
    }

    let capacity = format_retail_number(
        &city_string(ui, CITY_TEXT_STRING_GROUP, 0x10),
        next_capacity,
    );
    let cost = city_string(ui, CITY_TEXT_STRING_GROUP, 0x14);
    for (tag, text) in [
        (fourcc!("name"), building_name),
        (fourcc!("capT"), capacity),
        (fourcc!("cost"), cost),
    ] {
        let entity = spawned
            .require_unique(tag)
            .expect("validated expansion-dialog text binding");
        ui.commands.entity(entity).insert(Text::new(text));
    }

    let warning = spawned
        .require_unique(fourcc!("warn"))
        .expect("validated expansion warning binding");
    let warning_color = ui.palette_color(0xcb);
    let warning_text = city_string(ui, CITY_TEXT_STRING_GROUP, 0x17);
    ui.commands.entity(warning).insert((
        Text::new(warning_text),
        TextColor(warning_color),
        if can_reserve {
            Visibility::Hidden
        } else {
            Visibility::Visible
        },
    ));

    let okay = spawned
        .require_unique(fourcc!("okay"))
        .expect("validated expansion OK binding");
    let mut okay_commands = ui.commands.entity(okay);
    okay_commands.insert(CityBuildingChangeChoice {
        dialog: root,
        nation,
        slot,
        accept: true,
    });
    if !can_reserve {
        okay_commands.insert((InteractionDisabled, Visibility::Hidden));
    }

    let cancel = spawned
        .require_unique(fourcc!("cncl"))
        .expect("validated expansion cancel binding");
    ui.commands.entity(cancel).insert(CityBuildingChangeChoice {
        dialog: root,
        nation,
        slot,
        accept: false,
    });
}

fn on_city_expansion_open(
    activate: On<Activate>,
    openers: Query<&CityExpansionOpen>,
    dialogs: Query<Entity, With<CityBuildingDialog>>,
    screen_roots: Query<Entity, With<CityScreenRoot>>,
    modals: Query<(), With<ModalDialog>>,
    mut session: ResMut<GameSession>,
    mut ui: UiSpawner,
) {
    let Ok(open) = openers.get(activate.entity) else {
        return;
    };
    if dialogs.get(open.dialog).is_err() || !modals.is_empty() {
        return;
    }
    assert!(
        industry_page(open.slot).is_some(),
        "expansion hotspot belongs to an ordinary industry"
    );
    let (next_capacity, needed, next_level) = {
        let major = session.0.nations.major(open.nation);
        let city = major.city();
        let owned_regions = major.common().owned_regions.len() as i32;
        let current = city.building_type(open.slot, major.economy(), owned_regions);
        let next_capacity = city.max_building_capacity(open.slot, major.economy(), owned_regions);
        (
            next_capacity,
            next_capacity - current,
            city.next_building_level(open.slot, major.economy(), owned_regions),
        )
    };
    let order = CityOrderId::Expansion(open.slot);
    let original_quantity = session
        .0
        .nations
        .major(open.nation)
        .city()
        .orders
        .expansions[open.slot]
        .as_ref()
        .expect("ordinary industry has an expansion order")
        .progress
        .quantity;
    let can_reserve = session
        .0
        .set_city_order_quantity(open.nation, order, needed);
    assert!(
        session
            .0
            .set_city_order_quantity(open.nation, order, original_quantity),
        "retail expansion probe must restore its original quantity"
    );
    let spawned = ui.spawn_modal(expansion_dialog_view_id());
    let building_name = city_string(&ui, CITY_BUILDING_STRING_GROUP, open.slot as i16);
    bind_expansion_dialog(
        &mut ui,
        &spawned,
        open.nation,
        open.slot,
        building_name,
        next_capacity,
        next_level,
        can_reserve,
    );
    for dialog in &dialogs {
        ui.commands.entity(dialog).insert(CityDialogNeedsSync);
    }
    for root in &screen_roots {
        ui.commands.entity(root).insert(CityScreenNeedsSync);
    }
}

#[allow(clippy::too_many_arguments)]
fn on_city_building_change_choice(
    activate: On<Activate>,
    choices: Query<&CityBuildingChangeChoice>,
    change_dialogs: Query<(), With<CityBuildingChangeDialog>>,
    dialogs: Query<Entity, With<CityBuildingDialog>>,
    screen_roots: Query<Entity, With<CityScreenRoot>>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    let Ok(choice) = choices.get(activate.entity) else {
        return;
    };
    if change_dialogs.get(choice.dialog).is_err() {
        return;
    }
    if choice.slot == ProductionSlot::PowerPlant {
        if choice.accept {
            session.0.set_power_plant_upgrade(choice.nation, true);
        }
    } else {
        let order = CityOrderId::Expansion(choice.slot);
        if choice.accept {
            let needed = {
                let major = session.0.nations.major(choice.nation);
                let city = major.city();
                let owned_regions = major.common().owned_regions.len() as i32;
                city.max_building_capacity(choice.slot, major.economy(), owned_regions)
                    - city.building_type(choice.slot, major.economy(), owned_regions)
            };
            let _ = session
                .0
                .set_city_order_quantity(choice.nation, order, needed);
        } else {
            let quantity = session
                .0
                .nations
                .major(choice.nation)
                .city()
                .orders
                .expansions[choice.slot]
                .as_ref()
                .expect("ordinary industry has an expansion order")
                .progress
                .quantity;
            if quantity > 0 {
                let _ = session.0.set_city_order_quantity(choice.nation, order, 0);
            }
        }
    }

    commands.entity(choice.dialog).despawn();
    for dialog in &dialogs {
        commands.entity(dialog).insert(CityDialogNeedsSync);
    }
    for root in &screen_roots {
        commands.entity(root).insert(CityScreenNeedsSync);
    }
}

fn sync_city_building_pictures(
    screens: Query<(), With<CityScreenNeedsSync>>,
    session: Res<GameSession>,
    mut assets: UiAssetResources,
    mut buildings: Query<(&CityBuildingPicture, &mut ImageNode, &mut Visibility)>,
) {
    if screens.is_empty() {
        return;
    }
    for (building, mut image, mut visibility) in &mut buildings {
        let Some(level) = city_building_level(&session.0, building.nation, building.slot) else {
            *visibility = Visibility::Hidden;
            continue;
        };
        let city = session.0.nations.major(building.nation).city();
        let Some(picture) = city_building_picture(city, building.slot, level) else {
            *visibility = Visibility::Hidden;
            continue;
        };
        let indexed = match assets.indexed_picture(picture) {
            Ok(indexed) => indexed,
            Err(error) => {
                warn!("could not decode indexed city building picture {picture}: {error}");
                continue;
            }
        };
        if let Err(error) = assets.with_picture_image_mut(picture, |picture_image| {
            apply_city_picture_transparency(picture_image, &indexed);
        }) {
            warn!("could not decode city building picture {picture}: {error}");
            continue;
        }
        match assets.picture(picture) {
            Ok(handle) => {
                image.image = handle;
                *visibility = Visibility::Visible;
            }
            Err(error) => warn!("could not load city building picture {picture}: {error}"),
        }
    }
}

fn on_city_amount_bar_click(
    mut click: On<Pointer<Click>>,
    bars: Query<(&RelativeCursorPosition, &CityIndustryAmountBar)>,
    modals: Query<(), With<ModalDialog>>,
    dialogs: Query<Entity, With<CityBuildingDialog>>,
    screen_roots: Query<Entity, With<CityScreenRoot>>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    if !modals.is_empty() {
        return;
    }
    let Ok((cursor, bar)) = bars.get(click.entity) else {
        return;
    };
    let Some(normalized) = cursor.normalized.filter(|_| cursor.cursor_over()) else {
        return;
    };
    if dialogs.get(bar.dialog).is_err() {
        return;
    }
    click.propagate(false);
    let x = (((normalized.x + 0.5) * f32::from(INDUSTRY_BAR_WIDTH)).floor() as i16)
        .clamp(0, INDUSTRY_BAR_WIDTH - 1);
    let city = session.0.nations.major(bar.nation).city();
    let capacity = city.production_orders[bar.slot];
    let previous = match bar.order {
        CityOrderId::Item(output) => {
            city.orders.items[output]
                .as_ref()
                .expect("industry amount bar has a retail item order")
                .progress
                .quantity
        }
        _ => unreachable!("industry amount bar has an item order"),
    };
    let mut quantity = if capacity > 0
        && i32::from(x) < i32::from(INDUSTRY_BAR_WIDTH) / (i32::from(capacity) * 2)
    {
        0
    } else if capacity > 0 {
        (i32::from(x) * i32::from(capacity) / i32::from(INDUSTRY_BAR_WIDTH) + 1) as i16
    } else {
        1
    };
    if quantity == 0 && x != 0 && previous == 0 {
        quantity = 1;
    }
    if !session
        .0
        .set_city_order_quantity(bar.nation, bar.order, quantity)
        || quantity == previous
    {
        return;
    }
    for dialog in &dialogs {
        commands.entity(dialog).insert(CityDialogNeedsSync);
    }
    for root in &screen_roots {
        commands.entity(root).insert(CityScreenNeedsSync);
    }
}

fn on_armory_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<(Entity, &ArmoryRowChoice, Has<Checked>)>,
    modals: Query<(), With<ModalDialog>>,
    mut selections: Query<&mut ArmorySelection>,
    mut commands: Commands,
) {
    if !modals.is_empty() {
        return;
    }
    if !change.value {
        return;
    }
    let Ok((_, row, _)) = rows.get(change.source) else {
        return;
    };
    let Ok(mut selection) = selections.get_mut(row.dialog) else {
        return;
    };
    selection.category = row.category;
    for (entity, candidate, checked) in &rows {
        if candidate.dialog != row.dialog {
            continue;
        }
        let should_check = candidate.category == row.category;
        if should_check && !checked {
            commands.entity(entity).insert(Checked);
        } else if !should_check && checked {
            commands.entity(entity).remove::<Checked>();
        }
    }
    commands.entity(row.dialog).insert(CityDialogNeedsSync);
}

fn select_university_row(
    dialog: Entity,
    kind: CivilianUnitKind,
    selections: &mut Query<&mut UniversitySelection>,
    rows: &Query<(Entity, &UniversityRowChoice, Has<Checked>)>,
    commands: &mut Commands,
) {
    let Ok(mut selection) = selections.get_mut(dialog) else {
        return;
    };
    selection.kind = kind;
    for (entity, candidate, checked) in rows.iter() {
        if candidate.dialog != dialog {
            continue;
        }
        let should_check = candidate.kind == kind;
        if should_check && !checked {
            commands.entity(entity).insert(Checked);
        } else if !should_check && checked {
            commands.entity(entity).remove::<Checked>();
        }
    }
    commands.entity(dialog).insert(CityDialogNeedsSync);
}

fn on_university_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<(Entity, &UniversityRowChoice, Has<Checked>)>,
    modals: Query<(), With<ModalDialog>>,
    mut selections: Query<&mut UniversitySelection>,
    mut commands: Commands,
) {
    if !modals.is_empty() || !change.value {
        return;
    }
    let Ok((_, row, _)) = rows.get(change.source) else {
        return;
    };
    select_university_row(row.dialog, row.kind, &mut selections, &rows, &mut commands);
}

fn select_shipyard_row(
    dialog: Entity,
    slot: ShipOrderSlot,
    selections: &mut Query<&mut ShipyardSelection>,
    rows: &Query<(Entity, &ShipyardRowChoice, Has<Checked>)>,
    commands: &mut Commands,
) {
    if !rows
        .iter()
        .any(|(_, row, _)| row.dialog == dialog && row.slot == slot)
    {
        return;
    }
    let Ok(mut selection) = selections.get_mut(dialog) else {
        return;
    };
    selection.slot = slot;
    for (entity, candidate, checked) in rows.iter() {
        if candidate.dialog != dialog {
            continue;
        }
        let should_check = candidate.slot == slot;
        if should_check && !checked {
            commands.entity(entity).insert(Checked);
        } else if !should_check && checked {
            commands.entity(entity).remove::<Checked>();
        }
    }
    commands.entity(dialog).insert(CityDialogNeedsSync);
}

fn on_shipyard_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<(Entity, &ShipyardRowChoice, Has<Checked>)>,
    modals: Query<(), With<ModalDialog>>,
    mut selections: Query<&mut ShipyardSelection>,
    mut commands: Commands,
) {
    if !modals.is_empty() || !change.value {
        return;
    }
    let Ok((_, row, _)) = rows.get(change.source) else {
        return;
    };
    select_shipyard_row(row.dialog, row.slot, &mut selections, &rows, &mut commands);
}

#[allow(clippy::too_many_arguments)]
fn on_city_order_adjust(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    modals: Query<(), With<ModalDialog>>,
    dialogs: Query<Entity, With<CityBuildingDialog>>,
    mut armory_selections: Query<&mut ArmorySelection>,
    armory_rows: Query<(Entity, &ArmoryRowChoice, Has<Checked>)>,
    mut university_selections: Query<&mut UniversitySelection>,
    university_rows: Query<(Entity, &UniversityRowChoice, Has<Checked>)>,
    mut shipyard_selections: Query<&mut ShipyardSelection>,
    shipyard_rows: Query<(Entity, &ShipyardRowChoice, Has<Checked>)>,
    screen_roots: Query<Entity, With<CityScreenRoot>>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    if !modals.is_empty() {
        return;
    }
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    if dialogs.get(action.dialog).is_err() {
        return;
    }
    if let CityOrderId::MilitaryRecruit(category) = action.order
        && let Ok(mut selection) = armory_selections.get_mut(action.dialog)
    {
        selection.category = category;
        commands.entity(action.dialog).insert(CityDialogNeedsSync);
        for (entity, row, checked) in &armory_rows {
            if row.dialog != action.dialog {
                continue;
            }
            let should_check = row.category == category;
            if should_check && !checked {
                commands.entity(entity).insert(Checked);
            } else if !should_check && checked {
                commands.entity(entity).remove::<Checked>();
            }
        }
    }
    if let CityOrderId::CivilianRecruit(kind) = action.order {
        select_university_row(
            action.dialog,
            kind,
            &mut university_selections,
            &university_rows,
            &mut commands,
        );
    }
    if let CityOrderId::Ship(slot) = action.order {
        select_shipyard_row(
            action.dialog,
            slot,
            &mut shipyard_selections,
            &shipyard_rows,
            &mut commands,
        );
    }
    if !session
        .0
        .adjust_city_order(action.nation, action.order, action.delta)
    {
        return;
    }
    for dialog in &dialogs {
        commands.entity(dialog).insert(CityDialogNeedsSync);
    }
    for root in &screen_roots {
        commands.entity(root).insert(CityScreenNeedsSync);
    }
}

#[allow(clippy::too_many_arguments)]
fn sync_city_values(
    mut commands: Commands,
    mut session: ResMut<GameSession>,
    screens: Query<Entity, With<CityScreenNeedsSync>>,
    dialogs: Query<
        (Entity, &CityBuildingDialog, Option<&ArmorySelection>),
        With<CityDialogNeedsSync>,
    >,
    university_selections: Query<&UniversitySelection>,
    university_rows: Query<&UniversityRowChoice>,
    shipyard_selections: Query<&ShipyardSelection>,
    shipyard_rows: Query<&ShipyardRowChoice>,
    mut values: Query<
        (
            &CityValueBinding,
            Option<&RetailNumberTemplate>,
            &mut Text,
            &mut Visibility,
        ),
        Without<CityExpansionIndicator>,
    >,
    amount_bars: Query<&CityIndustryAmountBar>,
    mut amount_nodes: Query<&mut Node>,
    mut indicators: Query<(&CityExpansionIndicator, &mut Visibility), Without<CityValueBinding>>,
    mut shipyard_pictures: Query<(&ShipyardDetailPicture, &mut ImageNode)>,
) {
    if screens.is_empty() && dialogs.is_empty() {
        return;
    }

    let screen_nation = MajorNationId::from_nation(session.0.turn.active_nation);
    let mut dialog_states = Vec::new();
    for (root, dialog, armory_selection) in &dialogs {
        let mut order_views = Vec::new();
        let bindings = dialog_orders(dialog.slot);
        assert!(!bindings.is_empty(), "open city dialog has order bindings");
        if !matches!(
            dialog.slot,
            ProductionSlot::Armory | ProductionSlot::University | ProductionSlot::Shipyard
        ) {
            for binding in bindings {
                let view = session.0.refresh_city_order(dialog.nation, binding.order);
                order_views.push((binding.order, view));
            }
        }
        dialog_states.push((
            root,
            dialog.nation,
            order_views,
            armory_selection.map(|selection| selection.category),
        ));
    }

    for (binding, number_template, mut text, mut visibility) in &mut values {
        let (nation, order_views, armory_selection): (
            MajorNationId,
            &[(CityOrderId, CityOrderView)],
            Option<MilitaryRecruitmentCategory>,
        ) = match binding.dialog {
            Some(root) => {
                let Some((_, nation, order_views, armory_selection)) = dialog_states
                    .iter()
                    .find(|(candidate, _, _, _)| *candidate == root)
                else {
                    continue;
                };
                (*nation, order_views, *armory_selection)
            }
            None => {
                let Some(nation) = screen_nation else {
                    continue;
                };
                (nation, &[], None)
            }
        };
        let major = session.0.nations.major(nation);
        let city = major.city();
        let labor = city.population.baseline_labor();
        let labor_available = city.population.strength();
        let armory_order =
            armory_selection.map(|category| &city.orders.military_recruitment[category]);
        let armory_spec = armory_order.map(|order| {
            military_recruitment_spec(order.unit_kind)
                .expect("armory row has a recruitable retail unit recipe")
        });
        let university_selection = binding
            .dialog
            .and_then(|root| university_selections.get(root).ok());
        let university_row = binding.dialog.and_then(|root| {
            let selection = university_selection?;
            university_rows
                .iter()
                .find(|row| row.dialog == root && row.kind == selection.kind)
        });
        let university_spec =
            university_selection.map(|selection| civilian_recruitment_spec(selection.kind));
        let shipyard_selection = binding
            .dialog
            .and_then(|root| shipyard_selections.get(root).ok());
        let shipyard_row = binding.dialog.and_then(|root| {
            let selection = shipyard_selection?;
            shipyard_rows
                .iter()
                .find(|row| row.dialog == root && row.slot == selection.slot)
        });
        let value = match binding.value {
            CityValue::LaborLow => labor.low,
            CityValue::LaborMedium => labor.medium,
            CityValue::LaborHigh => labor.high,
            CityValue::LaborAvailable => labor_available,
            CityValue::PowerAvailable => city.power_available,
            CityValue::PredictedNeed(resource) => city.population.predicted_need(resource),
            CityValue::Treasury => {
                text.0 = format_currency(major.common().treasury);
                continue;
            }
            CityValue::OrderQuantity(order) => {
                let Some((_, view)) = order_views
                    .iter()
                    .find(|(candidate, _)| *candidate == order)
                else {
                    continue;
                };
                view.quantity
            }
            CityValue::ArmoryOrderQuantity(category) => {
                city.orders.military_recruitment[category].progress.quantity
            }
            CityValue::UniversityOrderQuantity(kind) => {
                city.orders.civilian_recruitment[kind].quantity
            }
            CityValue::ShipyardOrderQuantity(slot) => city.orders.ships[slot].progress.quantity,
            CityValue::LaborIndicator => {
                text.0 = "X".to_owned();
                *visibility = if labor_available >= 2 {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::StockIndicator(resource, minimum) => {
                text.0 = "X".to_owned();
                *visibility = if city.stockpile[resource] < minimum {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::AvailableStockIndicator(resource, minimum) => {
                text.0 = "X".to_owned();
                *visibility = if city.stockpile[resource] >= minimum {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::AvailableCombinedStockIndicator(first, second, minimum) => {
                text.0 = "X".to_owned();
                *visibility = if city.stockpile[first] + city.stockpile[second] >= minimum {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::AvailableBudgetIndicator(minimum) => {
                text.0 = "X".to_owned();
                *visibility = if major
                    .economy()
                    .available_diplomacy_budget(major.common().treasury)
                    >= minimum
                {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::TrainingLaborIndicator(level) => {
                let production = city.population.production_labor();
                let available = match level {
                    TrainingLevel::Medium => production.low.min(labor_available),
                    TrainingLevel::High => production.medium.min(labor_available / 2),
                };
                text.0 = "X".to_owned();
                *visibility = if available != 0 {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::BuildingCapacity(slot) => city.production_orders[slot],
            CityValue::RegionalCapacity => city.building_type(
                ProductionSlot::RegionalPopulation,
                major.economy(),
                major.common().owned_regions.len() as i32,
            ),
            CityValue::OwnedRegionCount => major.common().owned_regions.len() as i16,
            CityValue::ArmoryUnitKind => {
                let Some(order) = armory_order else {
                    continue;
                };
                text.0 = format!("{:?}", order.unit_kind);
                continue;
            }
            CityValue::ArmoryWorkforceCost => 1,
            CityValue::ArmoryPrimaryCost => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                spec.primary.per_unit()
            }
            CityValue::ArmorySecondaryCost => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                let Some(secondary) = spec.secondary else {
                    text.0.clear();
                    *visibility = Visibility::Hidden;
                    continue;
                };
                *visibility = Visibility::Visible;
                secondary.per_unit()
            }
            CityValue::ArmoryCashCost => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                text.0 = format_currency(i32::from(spec.cash_per_unit));
                continue;
            }
            CityValue::ArmoryWorkforceAvailable => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                let production = city.population.production_labor();
                let (available, strength_divisor) = match spec.workforce {
                    SkillBand::Low => (production.low, 1),
                    SkillBand::Medium => (production.medium, 2),
                    SkillBand::High => (production.high, 4),
                };
                available.min(labor_available / strength_divisor)
            }
            CityValue::ArmoryPrimaryAvailable => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                city.stockpile[spec.primary.resource]
            }
            CityValue::ArmorySecondaryAvailable => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                let Some(secondary) = spec.secondary else {
                    text.0.clear();
                    *visibility = Visibility::Hidden;
                    continue;
                };
                *visibility = Visibility::Visible;
                city.stockpile[secondary.resource]
            }
            CityValue::ArmoryTreasuryAvailable => {
                text.0 = format_currency(major.common().treasury);
                continue;
            }
            CityValue::UniversityUnitName => {
                let Some(row) = university_row else {
                    continue;
                };
                text.0.clone_from(&row.unit_name);
                continue;
            }
            CityValue::UniversityDescription => {
                let Some(row) = university_row else {
                    continue;
                };
                text.0.clone_from(&row.description);
                continue;
            }
            CityValue::UniversityWorkforceCost => 1,
            CityValue::UniversityPaperCost => {
                let Some(spec) = university_spec else {
                    continue;
                };
                spec.primary.per_unit()
            }
            CityValue::UniversityCashCost => {
                let Some(spec) = university_spec else {
                    continue;
                };
                text.0 = format_currency(i32::from(spec.cash_per_unit));
                continue;
            }
            CityValue::UniversityWorkforceAvailable => {
                let production = city.population.production_labor();
                production.high.min(labor_available / 4)
            }
            CityValue::UniversityPaperAvailable => {
                let Some(spec) = university_spec else {
                    continue;
                };
                city.stockpile[spec.primary.resource]
            }
            CityValue::ShipyardName => {
                let Some(row) = shipyard_row else {
                    continue;
                };
                text.0.clone_from(&row.ship_name);
                continue;
            }
            CityValue::ShipyardDescription => {
                let Some(row) = shipyard_row else {
                    continue;
                };
                text.0.clone_from(&row.description);
                continue;
            }
        };
        text.0 = if let Some(template) = number_template {
            format_retail_number(&template.0, value)
        } else {
            value.to_string()
        };
    }
    for (binding, mut image) in &mut shipyard_pictures {
        let Ok(selection) = shipyard_selections.get(binding.dialog) else {
            continue;
        };
        let Some(row) = shipyard_rows
            .iter()
            .find(|row| row.dialog == binding.dialog && row.slot == selection.slot)
        else {
            continue;
        };
        image.image.clone_from(&row.picture);
    }
    for bar in &amount_bars {
        let Some((_, nation, order_views, _)) = dialog_states
            .iter()
            .find(|(root, _, _, _)| *root == bar.dialog)
        else {
            continue;
        };
        let Some((_, view)) = order_views.iter().find(|(order, _)| *order == bar.order) else {
            continue;
        };
        let capacity = session.0.nations.major(*nation).city().production_orders[bar.slot];
        let scale = |quantity: i16| {
            if capacity > 0 {
                (i32::from(quantity) * i32::from(INDUSTRY_BAR_WIDTH) / i32::from(capacity))
                    .clamp(0, i32::from(INDUSTRY_BAR_WIDTH)) as i16
            } else {
                0
            }
        };
        let current = scale(view.quantity);
        let maximum = scale(view.maximum);
        let Ok([mut fill, mut maximum_marker, mut quantity]) =
            amount_nodes.get_many_mut([bar.fill, bar.maximum, bar.quantity])
        else {
            continue;
        };
        fill.width = Val::Px(f32::from(current));
        maximum_marker.left = Val::Px(f32::from(maximum));
        quantity.left = Val::Px(INDUSTRY_BAR_X + f32::from(current) - 2.0);
        quantity.top = Val::Px(INDUSTRY_BAR_Y + 6.0);
    }
    for (indicator, mut visibility) in &mut indicators {
        let Some((_, nation, _, _)) = dialog_states
            .iter()
            .find(|(root, _, _, _)| *root == indicator.dialog)
        else {
            continue;
        };
        let city = session.0.nations.major(*nation).city();
        *visibility = if city_is_expanding(city, indicator.slot) {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
    for root in &screens {
        commands.entity(root).remove::<CityScreenNeedsSync>();
    }
    for (root, _, _) in &dialogs {
        commands.entity(root).remove::<CityDialogNeedsSync>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::catalog::spawn_view_nodes;
    use bevy::ecs::system::RunSystemOnce;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");
    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

    #[derive(Clone, Copy)]
    struct TestDialog {
        root: Entity,
        window: Entity,
        decrease: Entity,
        increase: Entity,
        quantity: Entity,
        fabric: Entity,
        labor: Entity,
        capacity: Entity,
        expansion: Entity,
    }

    #[derive(Clone, Copy)]
    struct TestTrainingDialog {
        root: Entity,
        medium_decrease: Entity,
        medium_increase: Entity,
        medium_quantity: Entity,
        high_decrease: Entity,
        high_increase: Entity,
        high_quantity: Entity,
    }

    #[derive(Clone, Copy)]
    struct TestUniversityDialog {
        root: Entity,
        miner_button: Entity,
        forester_button: Entity,
        forester_increase: Entity,
        forester_decrease: Entity,
        forester_quantity: Entity,
        engineer_button: Entity,
        engineer_increase: Entity,
        engineer_quantity: Entity,
        driller_button: Entity,
        driller_increase: Entity,
    }

    fn fixture_session() -> GameSession {
        let save = LegacySaveV62::parse(BEGINNING_OF_GAME).unwrap();
        let state = save
            .game_state(LegacyGameStateContext {
                crt_rand_state: 1,
                map_generation_lcg: 0,
                zone_status_lcg: 3_916_827_792,
                selected_nation: NationId::new(6),
            })
            .unwrap();
        GameSession(state)
    }

    fn spawn_clothing_dialog(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
    ) -> TestDialog {
        let city = catalog.view(&city_view_id()).unwrap();
        let view_id = city
            .city_buildings
            .iter()
            .find(|building| building.slot == ProductionSlot::ClothingFactory)
            .unwrap()
            .dialog
            .clone();
        let view = catalog.view(&view_id).unwrap();
        let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
        let page = industry_page(ProductionSlot::ClothingFactory).unwrap();
        bind_industry_dialog(
            &mut commands,
            &catalog,
            &spawned,
            MajorNationId::new(6),
            page,
            "Clothing Factory".to_owned(),
            "Capacity: [1: number]".to_owned(),
            Color::WHITE,
        );
        TestDialog {
            root: spawned.root,
            window: spawned.require_unique(fourcc!("WIND")).unwrap(),
            decrease: spawned
                .require_under(&catalog, fourcc!("clot"), fourcc!("left"))
                .unwrap(),
            increase: spawned
                .require_under(&catalog, fourcc!("clot"), fourcc!("rght"))
                .unwrap(),
            quantity: spawned
                .require_under(&catalog, fourcc!("clot"), fourcc!("move"))
                .unwrap(),
            fabric: spawned.require_unique(fourcc!("fabr")).unwrap(),
            labor: spawned.require_unique(fourcc!("labV")).unwrap(),
            capacity: spawned.require_unique(fourcc!("capT")).unwrap(),
            expansion: spawned.require_unique(fourcc!("flag")).unwrap(),
        }
    }

    fn spawn_training_dialog(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
    ) -> TestTrainingDialog {
        let city = catalog.view(&city_view_id()).unwrap();
        let view_id = city
            .city_buildings
            .iter()
            .find(|building| building.slot == ProductionSlot::TradeSchool)
            .unwrap()
            .dialog
            .clone();
        let view = catalog.view(&view_id).unwrap();
        let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
        bind_training_dialog(
            &mut commands,
            &catalog,
            &spawned,
            MajorNationId::new(6),
            "Trade School".to_owned(),
        );
        TestTrainingDialog {
            root: spawned.root,
            medium_decrease: spawned
                .require_under(&catalog, fourcc!("trai"), fourcc!("left"))
                .unwrap(),
            medium_increase: spawned
                .require_under(&catalog, fourcc!("trai"), fourcc!("rght"))
                .unwrap(),
            medium_quantity: spawned
                .require_under(&catalog, fourcc!("trai"), fourcc!("move"))
                .unwrap(),
            high_decrease: spawned
                .require_under(&catalog, fourcc!("prof"), fourcc!("left"))
                .unwrap(),
            high_increase: spawned
                .require_under(&catalog, fourcc!("prof"), fourcc!("rght"))
                .unwrap(),
            high_quantity: spawned
                .require_under(&catalog, fourcc!("prof"), fourcc!("move"))
                .unwrap(),
        }
    }

    fn spawn_university_dialog(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
        session: Res<GameSession>,
    ) -> TestUniversityDialog {
        let city = catalog.view(&city_view_id()).unwrap();
        let view_id = city
            .city_buildings
            .iter()
            .find(|building| building.slot == ProductionSlot::University)
            .unwrap()
            .dialog
            .clone();
        let view = catalog.view(&view_id).unwrap();
        let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
        let technology =
            session.0.technology.city_capabilities_by_nation[MajorNationId::new(6)].university;
        bind_university_dialog(
            &mut commands,
            &catalog,
            &spawned,
            MajorNationId::new(6),
            UniversityDialogData {
                available: technology.available,
                rows: UNIVERSITY_ORDERS.map(|binding| {
                    let CityOrderId::CivilianRecruit(kind) = binding.order else {
                        unreachable!("University binding has a civilian recruitment order");
                    };
                    UniversityRowText {
                        unit_name: format!("{kind:?}"),
                        description: format!("{kind:?} description"),
                    }
                }),
            },
        );
        TestUniversityDialog {
            root: spawned.root,
            miner_button: spawned.require_unique(fourcc!("civ0")).unwrap(),
            forester_button: spawned.require_unique(fourcc!("civ3")).unwrap(),
            forester_increase: spawned
                .require_under(&catalog, fourcc!("clu3"), fourcc!("plus"))
                .unwrap(),
            forester_decrease: spawned
                .require_under(&catalog, fourcc!("clu3"), fourcc!("minu"))
                .unwrap(),
            forester_quantity: spawned
                .require_under(&catalog, fourcc!("clu3"), fourcc!("numb"))
                .unwrap(),
            engineer_button: spawned.require_unique(fourcc!("civ4")).unwrap(),
            engineer_increase: spawned
                .require_under(&catalog, fourcc!("clu4"), fourcc!("plus"))
                .unwrap(),
            engineer_quantity: spawned
                .require_under(&catalog, fourcc!("clu4"), fourcc!("numb"))
                .unwrap(),
            driller_button: spawned.require_unique(fourcc!("civ8")).unwrap(),
            driller_increase: spawned
                .require_under(&catalog, fourcc!("clu8"), fourcc!("plus"))
                .unwrap(),
        }
    }

    fn order_quantity(app: &mut App, order: CityOrderId) -> i16 {
        app.world_mut()
            .resource_mut::<GameSession>()
            .0
            .refresh_city_order(MajorNationId::new(6), order)
            .quantity
    }

    fn activate(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
    }

    #[test]
    fn clothing_order_round_trips_through_generated_controls_and_reopen() {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog).unwrap())
            .insert_resource(fixture_session())
            .add_observer(on_city_order_adjust)
            .add_systems(Update, sync_city_values);

        let first = app
            .world_mut()
            .run_system_once(spawn_clothing_dialog)
            .unwrap();
        app.update();
        assert_eq!(
            order_quantity(&mut app, CityOrderId::Item(ResourceKind::Clothing)),
            0
        );
        assert_eq!(
            *app.world().get::<Visibility>(first.fabric).unwrap(),
            Visibility::Hidden
        );
        assert_eq!(
            *app.world().get::<Visibility>(first.labor).unwrap(),
            Visibility::Visible
        );
        assert_eq!(
            app.world().get::<Text>(first.capacity).unwrap().0,
            "Capacity: 1"
        );
        assert_eq!(
            *app.world().get::<Visibility>(first.expansion).unwrap(),
            Visibility::Hidden
        );
        activate(&mut app, first.increase);
        assert_eq!(
            order_quantity(&mut app, CityOrderId::Item(ResourceKind::Clothing)),
            1
        );
        assert_eq!(app.world().get::<Text>(first.quantity).unwrap().0, "1");
        assert_eq!(
            *app.world().get::<Visibility>(first.fabric).unwrap(),
            Visibility::Hidden
        );
        {
            let session = app.world().resource::<GameSession>();
            let city = session.0.nations.major(MajorNationId::new(6)).city();
            assert_eq!(city.stockpile[ResourceKind::Fabric], 8);
            assert_eq!(city.population.strength(), 10);
            assert_eq!(city.production_accum[ProductionSlot::ClothingFactory], 0);
        }

        app.world_mut().commands().entity(first.root).despawn();
        app.world_mut().flush();
        let reopened = app
            .world_mut()
            .run_system_once(spawn_clothing_dialog)
            .unwrap();
        app.update();
        assert_eq!(app.world().get::<Text>(reopened.quantity).unwrap().0, "1");

        activate(&mut app, reopened.decrease);
        assert_eq!(
            order_quantity(&mut app, CityOrderId::Item(ResourceKind::Clothing)),
            0
        );
        assert_eq!(app.world().get::<Text>(reopened.quantity).unwrap().0, "0");
        assert_eq!(
            *app.world().get::<Visibility>(reopened.fabric).unwrap(),
            Visibility::Hidden
        );
        {
            let session = app.world().resource::<GameSession>();
            let city = session.0.nations.major(MajorNationId::new(6)).city();
            assert_eq!(city.stockpile[ResourceKind::Fabric], 10);
            assert_eq!(city.population.strength(), 12);
            assert_eq!(city.production_accum[ProductionSlot::ClothingFactory], 1);
        }

        {
            let mut window = app.world_mut().get_mut::<Node>(reopened.window).unwrap();
            window.left = px(123);
            window.top = px(87);
        }
        app.world_mut().run_system_once(leave_city_screen).unwrap();
        app.world_mut().flush();
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .0
                .nations
                .major(MajorNationId::new(6))
                .city()
                .building_window_state(ProductionSlot::ClothingFactory),
            BuildingWindowState {
                flag: 1,
                current: 123,
                accumulated: 87,
            }
        );
    }

    #[test]
    fn training_orders_round_trip_through_both_generated_rows() {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog).unwrap())
            .insert_resource(fixture_session())
            .add_observer(on_city_order_adjust)
            .add_systems(Update, sync_city_values);

        let first = app
            .world_mut()
            .run_system_once(spawn_training_dialog)
            .unwrap();
        app.update();
        activate(&mut app, first.medium_increase);
        activate(&mut app, first.high_increase);
        assert_eq!(
            app.world().get::<Text>(first.medium_quantity).unwrap().0,
            "1"
        );
        assert_eq!(app.world().get::<Text>(first.high_quantity).unwrap().0, "1");
        {
            let session = app.world().resource::<GameSession>();
            let major = session.0.nations.major(MajorNationId::new(6));
            let city = major.city();
            assert_eq!(city.stockpile[ResourceKind::Paper], 5);
            assert_eq!(major.common().treasury, 8_900);
            assert_eq!(city.population.production_labor(), LaborPool::new(3, 1, 1));
            assert_eq!(city.population.strength(), 9);
        }

        app.world_mut().commands().entity(first.root).despawn();
        app.world_mut().flush();
        let reopened = app
            .world_mut()
            .run_system_once(spawn_training_dialog)
            .unwrap();
        app.update();
        assert_eq!(
            app.world().get::<Text>(reopened.medium_quantity).unwrap().0,
            "1"
        );
        assert_eq!(
            app.world().get::<Text>(reopened.high_quantity).unwrap().0,
            "1"
        );

        activate(&mut app, reopened.medium_decrease);
        activate(&mut app, reopened.high_decrease);
        {
            let session = app.world().resource::<GameSession>();
            let major = session.0.nations.major(MajorNationId::new(6));
            let city = major.city();
            assert_eq!(city.stockpile[ResourceKind::Paper], 8);
            assert_eq!(major.common().treasury, 10_000);
            assert_eq!(city.population.production_labor(), LaborPool::new(4, 2, 1));
            assert_eq!(city.population.strength(), 12);
        }
    }

    #[test]
    fn university_availability_and_orders_round_trip_through_generated_rows() {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let nation = MajorNationId::new(6);
        let mut session = fixture_session();
        let university = &mut session.0.technology.city_capabilities_by_nation[nation].university;
        university.available[CivilianUnitKind::Forester] = true;
        university.available[CivilianUnitKind::Engineer] = true;
        university.available[CivilianUnitKind::Driller] = false;

        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog).unwrap())
            .insert_resource(session)
            .add_observer(on_city_order_adjust)
            .add_observer(on_university_row_selected)
            .add_systems(Update, sync_city_values);

        let first = app
            .world_mut()
            .run_system_once(spawn_university_dialog)
            .unwrap();
        app.update();
        assert_eq!(
            *app.world()
                .get::<Visibility>(first.forester_button)
                .unwrap(),
            Visibility::Visible
        );
        assert!(
            app.world()
                .get::<InteractionDisabled>(first.forester_increase)
                .is_none()
        );
        assert_eq!(
            *app.world().get::<Visibility>(first.driller_button).unwrap(),
            Visibility::Hidden
        );
        assert!(
            app.world()
                .get::<InteractionDisabled>(first.driller_increase)
                .is_some()
        );
        assert!(app.world().get::<Checked>(first.miner_button).is_some());

        activate(&mut app, first.forester_increase);
        assert_eq!(
            app.world()
                .get::<UniversitySelection>(first.root)
                .unwrap()
                .kind,
            CivilianUnitKind::Forester
        );
        assert!(app.world().get::<Checked>(first.forester_button).is_some());
        assert_eq!(
            app.world().get::<Text>(first.forester_quantity).unwrap().0,
            "1"
        );
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .0
                .nations
                .major(nation)
                .city()
                .orders
                .civilian_recruitment[CivilianUnitKind::Forester]
                .quantity,
            1
        );

        activate(&mut app, first.engineer_increase);
        assert_eq!(
            app.world()
                .get::<UniversitySelection>(first.root)
                .unwrap()
                .kind,
            CivilianUnitKind::Engineer,
            "a rejected adjustment still selects its University row"
        );
        assert!(app.world().get::<Checked>(first.engineer_button).is_some());
        assert!(app.world().get::<Checked>(first.forester_button).is_none());
        assert_eq!(
            app.world().get::<Text>(first.engineer_quantity).unwrap().0,
            "0"
        );

        activate(&mut app, first.forester_decrease);
        assert_eq!(
            app.world()
                .get::<UniversitySelection>(first.root)
                .unwrap()
                .kind,
            CivilianUnitKind::Forester
        );
        assert_eq!(
            app.world().get::<Text>(first.forester_quantity).unwrap().0,
            "0"
        );
    }
}
