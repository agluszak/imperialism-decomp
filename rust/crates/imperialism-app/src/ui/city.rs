use super::catalog::{
    ModalDialog, SpawnedView, UiAssetResources, UiCatalogResource, UiSpawner, spawn_view,
};
use super::game_shell::{GameScreenRoot, bind_game_screen_nav, city_view_id, disable_control};
use super::random_setup::GameSession;
use crate::AppState;
use bevy::log::warn;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::{InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::Activate;
use imperialism_core::*;
use imperialism_formats::*;

const CITY_WIDTH: f32 = 640.0;
const CITY_HEIGHT: f32 = 480.0;

const TEXTILE_ORDERS: [IndustryOrderBinding; 1] = [IndustryOrderBinding {
    output: ResourceKind::Fabric,
    tag: fourcc!("fabr"),
}];
const CLOTHING_ORDERS: [IndustryOrderBinding; 1] = [IndustryOrderBinding {
    output: ResourceKind::Clothing,
    tag: fourcc!("clot"),
}];
const STEEL_ORDERS: [IndustryOrderBinding; 1] = [IndustryOrderBinding {
    output: ResourceKind::Steel,
    tag: fourcc!("stee"),
}];
const METALWORKS_ORDERS: [IndustryOrderBinding; 2] = [
    IndustryOrderBinding {
        output: ResourceKind::Hardware,
        tag: fourcc!("hard"),
    },
    IndustryOrderBinding {
        output: ResourceKind::Arms,
        tag: fourcc!("arma"),
    },
];
const LUMBER_ORDERS: [IndustryOrderBinding; 2] = [
    IndustryOrderBinding {
        output: ResourceKind::Lumber,
        tag: fourcc!("lumb"),
    },
    IndustryOrderBinding {
        output: ResourceKind::Paper,
        tag: fourcc!("pape"),
    },
];
const FURNITURE_ORDERS: [IndustryOrderBinding; 1] = [IndustryOrderBinding {
    output: ResourceKind::Furniture,
    tag: fourcc!("furn"),
}];
const OIL_ORDERS: [IndustryOrderBinding; 1] = [IndustryOrderBinding {
    output: ResourceKind::Fuel,
    tag: fourcc!("fuel"),
}];

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
struct IndustryOrderBinding {
    output: ResourceKind,
    tag: FourCc,
}

#[derive(Clone, Copy)]
struct IndustryPage {
    slot: ProductionSlot,
    name: &'static str,
    orders: &'static [IndustryOrderBinding],
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

fn ordinary_industry_level(
    state: &GameState,
    nation: MajorNationId,
    slot: ProductionSlot,
) -> Option<i16> {
    if !is_ordinary_industry(slot) {
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
        let view_id = &city
            .city_buildings
            .iter()
            .find(|building| building.slot == slot)
            .ok_or_else(|| format!("Citymain.rsrc:2011 is missing {slot:?}"))?
            .dialog;
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
struct CityIndustryDialog {
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
enum CityValue {
    LaborLow,
    LaborMedium,
    LaborHigh,
    LaborAvailable,
    PowerAvailable,
    Treasury,
    PredictedNeed(ResourceKind),
    OrderQuantity(CityOrderId),
    LaborIndicator,
    StockIndicator(ResourceKind, i16),
    BuildingCapacity(ProductionSlot),
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
    let mut buildings = Vec::new();
    for visual in visuals {
        let Some(level) = ordinary_industry_level(state, nation, visual.slot) else {
            continue;
        };
        if level < 1 {
            continue;
        }
        let offset = i16::from(visual.slot as u8);
        let picture = PictureId::new(7000 + level * 16 + offset);
        let indexed_picture = match assets.indexed_picture(picture) {
            Ok(picture) => picture,
            Err(error) => {
                warn!("could not decode indexed city building picture {picture}: {error}");
                continue;
            }
        };
        if let Err(error) = assets.with_picture_image_mut(picture, |image| {
            apply_city_picture_transparency(image, &indexed_picture);
        }) {
            warn!("could not decode city building picture {picture}: {error}");
            continue;
        }
        let handle = match assets.picture(picture) {
            Ok(handle) => handle,
            Err(error) => {
                warn!("could not load city building picture {picture}: {error}");
                continue;
            }
        };
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
    dialogs: Query<&CityIndustryDialog>,
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
    if dialogs
        .iter()
        .any(|dialog| dialog.nation == nation && dialog.slot == building.slot)
    {
        return;
    }
    open_industry_dialog(
        &mut ui,
        &catalog,
        nation,
        building.slot,
        building.dialog.clone(),
    );
}

fn open_industry_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    nation: MajorNationId,
    slot: ProductionSlot,
    view_id: ScopedViewId,
) {
    let Some(page) = industry_page(slot) else {
        return;
    };
    let spawned = ui.spawn(view_id);
    bind_industry_dialog(&mut ui.commands, catalog, &spawned, nation, page);
}

fn bind_industry_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    page: IndustryPage,
) {
    let root = spawned.root;
    commands.entity(root).insert((
        CityIndustryDialog {
            nation,
            slot: page.slot,
        },
        CityDialogNeedsSync,
        DespawnOnExit(AppState::City),
        GlobalZIndex(10),
        Pickable::IGNORE,
    ));
    let window = spawned
        .require_unique(fourcc!("WIND"))
        .expect("validated industry window binding");
    commands.entity(window).insert(Pickable::default());

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
    for binding in page.orders {
        let order = CityOrderId::Item(binding.output);
        let left = spawned
            .require_under(catalog, binding.tag, fourcc!("left"))
            .expect("validated industry decrease binding");
        let right = spawned
            .require_under(catalog, binding.tag, fourcc!("rght"))
            .expect("validated industry increase binding");
        let quantity = spawned
            .require_under(catalog, binding.tag, fourcc!("move"))
            .expect("validated industry quantity binding");
        commands.entity(left).insert(CityOrderAdjust {
            dialog: root,
            nation,
            order,
            delta: -1,
        });
        commands.entity(right).insert(CityOrderAdjust {
            dialog: root,
            nation,
            order,
            delta: 1,
        });
        commands.entity(quantity).insert((
            Text::new(""),
            CityValueBinding {
                dialog: Some(root),
                value: CityValue::OrderQuantity(order),
            },
        ));
    }
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

fn on_city_order_adjust(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    dialogs: Query<Entity, With<CityIndustryDialog>>,
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
    session
        .0
        .adjust_city_order(action.nation, action.order, action.delta);
    for dialog in &dialogs {
        commands.entity(dialog).insert(CityDialogNeedsSync);
    }
    for root in &screen_roots {
        commands.entity(root).insert(CityScreenNeedsSync);
    }
}

fn sync_city_values(
    mut commands: Commands,
    mut session: ResMut<GameSession>,
    screens: Query<Entity, With<CityScreenNeedsSync>>,
    dialogs: Query<(Entity, &CityIndustryDialog), With<CityDialogNeedsSync>>,
    mut values: Query<
        (&CityValueBinding, &mut Text, &mut Visibility),
        Without<CityExpansionIndicator>,
    >,
    mut indicators: Query<(&CityExpansionIndicator, &mut Visibility), Without<CityValueBinding>>,
) {
    if screens.is_empty() && dialogs.is_empty() {
        return;
    }

    let screen_nation = MajorNationId::from_nation(session.0.turn.active_nation);
    let mut dialog_states = Vec::new();
    for (root, dialog) in &dialogs {
        let mut order_views = Vec::new();
        let page = industry_page(dialog.slot).expect("industry dialog has an ordinary page");
        for binding in page.orders {
            let order = CityOrderId::Item(binding.output);
            let view = session.0.refresh_city_order(dialog.nation, order);
            order_views.push((order, view));
        }
        dialog_states.push((root, dialog.nation, order_views));
    }

    for (binding, mut text, mut visibility) in &mut values {
        let (nation, order_views): (MajorNationId, &[(CityOrderId, CityOrderView)]) =
            match binding.dialog {
                Some(root) => {
                    let Some((_, nation, order_views)) = dialog_states
                        .iter()
                        .find(|(candidate, _, _)| *candidate == root)
                    else {
                        continue;
                    };
                    (*nation, order_views)
                }
                None => {
                    let Some(nation) = screen_nation else {
                        continue;
                    };
                    (nation, &[])
                }
            };
        let major = session.0.nations.major(nation);
        let city = major.city();
        let labor = city.population.baseline_labor();
        let labor_available = city.population.strength();
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
            CityValue::BuildingCapacity(slot) => {
                text.0 = format!("Capacity: {}", city.production_orders[slot]);
                continue;
            }
        };
        text.0 = value.to_string();
    }
    for (indicator, mut visibility) in &mut indicators {
        let Some((_, nation, _)) = dialog_states
            .iter()
            .find(|(root, _, _)| *root == indicator.dialog)
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
    for (root, _) in &dialogs {
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

    fn quantity(app: &mut App) -> i16 {
        app.world_mut()
            .resource_mut::<GameSession>()
            .0
            .refresh_city_order(
                MajorNationId::new(6),
                CityOrderId::Item(ResourceKind::Clothing),
            )
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
        assert_eq!(quantity(&mut app), 0);
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
        assert_eq!(quantity(&mut app), 1);
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
        assert_eq!(quantity(&mut app), 0);
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
}
