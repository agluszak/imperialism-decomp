use super::catalog::{
    ModalDialog, SpawnedView, UiAssetResources, UiCatalogResource, UiSpawner, spawn_view,
};
use super::game_shell::{GameScreenRoot, bind_game_screen_nav, city_view_id, disable_control};
use super::random_setup::GameSession;
use crate::AppState;
use bevy::log::warn;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ValueChange};
use imperialism_core::*;
use imperialism_formats::*;

const CITY_WIDTH: f32 = 640.0;
const CITY_HEIGHT: f32 = 480.0;
const INDUSTRY_BAR_WIDTH: i16 = 150;
const INDUSTRY_BAR_X: f32 = 62.0;
const INDUSTRY_BAR_Y: f32 = 8.0;

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

#[derive(Clone, Copy)]
struct IndustryPage {
    slot: ProductionSlot,
    name: &'static str,
    orders: &'static [CityOrderBinding],
    stocks: &'static [(ResourceKind, FourCc, i16)],
}

fn industry_page(slot: ProductionSlot) -> Option<IndustryPage> {
    let page = match slot {
        ProductionSlot::TextileMill => IndustryPage {
            slot,
            name: "Textile Mill",
            orders: &TEXTILE_ORDERS,
            stocks: &TEXTILE_STOCKS,
        },
        ProductionSlot::ClothingFactory => IndustryPage {
            slot,
            name: "Clothing Factory",
            orders: &CLOTHING_ORDERS,
            stocks: &CLOTHING_STOCKS,
        },
        ProductionSlot::SteelMill => IndustryPage {
            slot,
            name: "Steel Mill",
            orders: &STEEL_ORDERS,
            stocks: &STEEL_STOCKS,
        },
        ProductionSlot::Metalworks => IndustryPage {
            slot,
            name: "Metalworks",
            orders: &METALWORKS_ORDERS,
            stocks: &METALWORKS_STOCKS,
        },
        ProductionSlot::LumberMill => IndustryPage {
            slot,
            name: "Lumber Mill",
            orders: &LUMBER_ORDERS,
            stocks: &LUMBER_STOCKS,
        },
        ProductionSlot::FurnitureFactory => IndustryPage {
            slot,
            name: "Furniture Factory",
            orders: &FURNITURE_ORDERS,
            stocks: &FURNITURE_STOCKS,
        },
        ProductionSlot::OilRefinery => IndustryPage {
            slot,
            name: "Oil Refinery",
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
    if slot == ProductionSlot::Shipyard {
        // Retail uses the active nation's per-tech status row for this level.
        // That row is not yet represented by GameState.
        return None;
    }
    let major = state.nations.major(nation);
    Some(major.city().next_building_type(
        slot,
        major.economy(),
        major.common().owned_regions.len() as i32,
        false,
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

#[derive(Component, Clone, Copy)]
struct CityBuildingDialog {
    nation: MajorNationId,
    slot: ProductionSlot,
}

#[derive(Component)]
struct CityDialogNeedsSync;

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
}

#[derive(Component, Clone, Copy)]
struct CityValueBinding {
    dialog: Option<Entity>,
    value: CityValue,
}

#[derive(Component, Clone, Copy)]
struct CityExpansionIndicator {
    dialog: Entity,
    slot: ProductionSlot,
}

pub(crate) struct CityPlugin;

impl Plugin for CityPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::City), enter_city_screen)
            .add_systems(Update, sync_city_values.run_if(in_state(AppState::City)))
            .add_observer(on_city_canvas_click)
            .add_observer(on_armory_row_selected)
            .add_observer(on_city_amount_bar_click)
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
    disable_control(&mut commands, &spawned, fourcc!("end "));
    let mut root = commands.entity(spawned.root);
    root.insert((
        GameScreenRoot(view_id),
        CityScreenRoot,
        CityScreenNeedsSync,
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
                                commands.spawn((
                                    Node {
                                        position_type: PositionType::Absolute,
                                        left: Val::Px(visual.origin[0] as f32),
                                        top: Val::Px(visual.origin[1] as f32),
                                        width: Val::Px(mask.width as f32),
                                        height: Val::Px(mask.height as f32),
                                        ..default()
                                    },
                                    ImageNode::new(handle),
                                    ZIndex(visual.draw_order as i32),
                                    Pickable::IGNORE,
                                    ChildOf(main),
                                    Name::new(format!("city-building:{:?}", visual.slot)),
                                ));
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
}

fn on_city_canvas_click(
    click: On<Pointer<Click>>,
    canvases: Query<(&RelativeCursorPosition, &CityCanvas)>,
    dialogs: Query<&CityBuildingDialog>,
    modal_dialogs: Query<(), With<ModalDialog>>,
    session: Res<GameSession>,
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
    let major = session.0.nations.major(nation);
    if CityState::is_capacity_center(building.slot)
        && major.city().building_type(
            building.slot,
            major.economy(),
            major.common().owned_regions.len() as i32,
        ) == 0
    {
        return;
    }
    if dialogs
        .iter()
        .any(|dialog| dialog.nation == nation && dialog.slot == building.slot)
    {
        return;
    }
    open_city_dialog(
        &mut ui,
        &catalog,
        nation,
        building.slot,
        building.dialog.clone(),
    );
}

fn open_city_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    nation: MajorNationId,
    slot: ProductionSlot,
    view_id: ScopedViewId,
) {
    if industry_page(slot).is_none()
        && !matches!(
            slot,
            ProductionSlot::TradeSchool
                | ProductionSlot::Armory
                | ProductionSlot::FoodProcessing
                | ProductionSlot::PowerPlant
                | ProductionSlot::Transport
                | ProductionSlot::RegionalPopulation
        )
    {
        return;
    }
    let bar_color = ui.palette_color(0x16);
    let spawned = ui.spawn(view_id);
    if let Some(page) = industry_page(slot) {
        bind_industry_dialog(&mut ui.commands, catalog, &spawned, nation, page, bar_color);
        return;
    }
    match slot {
        ProductionSlot::TradeSchool => {
            bind_training_dialog(&mut ui.commands, catalog, &spawned, nation)
        }
        ProductionSlot::Armory => bind_armory_dialog(&mut ui.commands, catalog, &spawned, nation),
        ProductionSlot::FoodProcessing => {
            bind_food_dialog(&mut ui.commands, catalog, &spawned, nation)
        }
        ProductionSlot::PowerPlant => {
            bind_power_dialog(&mut ui.commands, catalog, &spawned, nation)
        }
        ProductionSlot::Transport => {
            bind_transport_capacity_dialog(&mut ui.commands, catalog, &spawned, nation)
        }
        ProductionSlot::RegionalPopulation => {
            bind_population_dialog(&mut ui.commands, catalog, &spawned, nation)
        }
        _ => unreachable!("supported ordinary city dialog handled above"),
    }
}

fn bind_city_dialog_root(
    commands: &mut Commands,
    spawned: &SpawnedView,
    nation: MajorNationId,
    slot: ProductionSlot,
) -> Entity {
    let root = spawned.root;
    commands.entity(root).insert((
        CityBuildingDialog { nation, slot },
        CityDialogNeedsSync,
        DespawnOnExit(AppState::City),
        GlobalZIndex(10),
        Pickable::IGNORE,
    ));
    let window = spawned
        .require_unique(fourcc!("WIND"))
        .expect("validated city window binding");
    commands.entity(window).insert(Pickable::default());
    root
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

fn bind_industry_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    page: IndustryPage,
    bar_color: Color,
) {
    let root = bind_city_dialog_root(commands, spawned, nation, page.slot);

    let name = spawned
        .require_unique(fourcc!("name"))
        .expect("validated industry name binding");
    commands.entity(name).insert(Text::new(page.name));
    let capacity = spawned
        .require_unique(fourcc!("capT"))
        .expect("validated industry capacity binding");
    commands.entity(capacity).insert((
        Text::new(""),
        CityValueBinding {
            dialog: Some(root),
            value: CityValue::BuildingCapacity(page.slot),
        },
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
    commands.entity(expansion).insert(InteractionDisabled);
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
) {
    let root = bind_city_dialog_root(commands, spawned, nation, ProductionSlot::TradeSchool);
    let name = spawned
        .require_unique(fourcc!("name"))
        .expect("validated trade-school name binding");
    commands.entity(name).insert(Text::new("Trade School"));
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
) {
    let root = bind_city_dialog_root(commands, spawned, nation, ProductionSlot::Armory);
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

#[allow(clippy::too_many_arguments)]
fn bind_rail_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    slot: ProductionSlot,
    name: &'static str,
    bindings: &[CityOrderBinding],
    step: i16,
) -> Entity {
    let root = bind_city_dialog_root(commands, spawned, nation, slot);
    let name_control = spawned
        .require_unique(fourcc!("name"))
        .expect("validated city dialog name binding");
    commands.entity(name_control).insert(Text::new(name));
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
) {
    let root = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        ProductionSlot::FoodProcessing,
        "Food Processing",
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
) {
    bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        ProductionSlot::PowerPlant,
        "Power Plant",
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
) {
    let root = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        ProductionSlot::Transport,
        "Railyard",
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
) {
    let root = bind_rail_dialog(
        commands,
        catalog,
        spawned,
        nation,
        ProductionSlot::RegionalPopulation,
        "Capitol",
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
}

fn on_city_amount_bar_click(
    mut click: On<Pointer<Click>>,
    bars: Query<(&RelativeCursorPosition, &CityIndustryAmountBar)>,
    dialogs: Query<Entity, With<CityBuildingDialog>>,
    screen_roots: Query<Entity, With<CityScreenRoot>>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
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
    mut selections: Query<&mut ArmorySelection>,
    mut commands: Commands,
) {
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

#[allow(clippy::too_many_arguments)]
fn on_city_order_adjust(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    dialogs: Query<Entity, With<CityBuildingDialog>>,
    mut armory_selections: Query<&mut ArmorySelection>,
    armory_rows: Query<(Entity, &ArmoryRowChoice, Has<Checked>)>,
    screen_roots: Query<Entity, With<CityScreenRoot>>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
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
    mut values: Query<
        (&CityValueBinding, &mut Text, &mut Visibility),
        Without<CityExpansionIndicator>,
    >,
    amount_bars: Query<&CityIndustryAmountBar>,
    mut amount_nodes: Query<&mut Node>,
    mut indicators: Query<(&CityExpansionIndicator, &mut Visibility), Without<CityValueBinding>>,
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
        if dialog.slot != ProductionSlot::Armory {
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

    for (binding, mut text, mut visibility) in &mut values {
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
        let value = match binding.value {
            CityValue::LaborLow => labor.low,
            CityValue::LaborMedium => labor.medium,
            CityValue::LaborHigh => labor.high,
            CityValue::LaborAvailable => labor_available,
            CityValue::PowerAvailable => city.power_available,
            CityValue::PredictedNeed(resource) => city.population.predicted_need(resource),
            CityValue::Treasury => {
                text.0 = format!("${}", major.common().treasury);
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
            CityValue::BuildingCapacity(slot) => {
                text.0 = format!("Capacity: {}", city.production_orders[slot]);
                continue;
            }
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
                text.0 = format!("${}", spec.cash_per_unit);
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
                text.0 = format!("${}", major.common().treasury);
                continue;
            }
        };
        text.0 = value.to_string();
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
            Color::WHITE,
        );
        TestDialog {
            root: spawned.root,
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
        bind_training_dialog(&mut commands, &catalog, &spawned, MajorNationId::new(6));
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
}
