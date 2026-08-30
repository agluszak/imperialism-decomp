use crate::ui::RetailUiAssets;
use crate::ui::fill_brackets;
use crate::ui::generated;
use crate::ui::hover_help::bind_hover_help_texts;
use crate::ui::linger::{bind_linger_dialog, spawn_linger_dialog};
use crate::ui::query_floater::bind_query_floater_control;
use crate::ui::retail::{RetailTree, retail_text_color, retail_text_style};
use crate::ui::retail_resources::ResourceKindRetailResources;
use crate::ui::session::apply_turn_stop;
use crate::ui::strategic_map::{
    StrategicBaseTerrainCanvas, bind_minimap, bind_strategic_base_terrain,
    compose_city_site_terrain, strategic_base_terrain_tile_at_cursor, sync_minimap,
};
use crate::ui::window::{bind_modal_keys, dismiss_on_activate, no_modal, spawn_modal_window};
use crate::ui::{GameSession, StrategicMapSession};
use crate::{AppState, RetailAssetsResource};
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use bevy::ui_widgets::Activate;
use imperialism_core::*;
use imperialism_formats::{
    OKAY, PictureId, RetailTextStylePreset, StringGroup, StringResourceId, fourcc,
};

const PLACE_CITY_STRING_GROUP: u16 = 0x273f;
const BAD_CITY_SITE_STRINGS: StringGroup = StringGroup::new(0x273b);
const MINISTER_STRING_GROUP: u16 = 0x2749;
const NEW_CITY_DIALOG_WIDTH: i32 = 328;
const RESOURCE_ITEM_WIDTH: i32 = 0x2c;
const RESOURCE_ITEM_HEIGHT: i32 = 0x20;
const CITY_SITE_INTRO_GOLD_PICTURE: PictureId = PictureId::new(0x24d1);
const COAT_PICTURE_BASE: PictureId = PictureId::new(9500);

fn city_site_error_string(
    error: CitySiteError,
    state: &GameState,
    tile: TileId,
) -> StringResourceId {
    let offset = match error {
        CitySiteError::NotOwned => {
            if state.map()[tile].terrain == TerrainKind::Water {
                3
            } else {
                0
            }
        }
        CitySiteError::UnsupportedTerrain | CitySiteError::InvalidHomeSite => {
            if supports_city_site_terrain(state.map()[tile].terrain)
                && state.can_build_port_at_tile(tile)
            {
                2
            } else {
                1
            }
        }
    };
    BAD_CITY_SITE_STRINGS.offset(offset)
}

fn city_site_coat_picture(nation: MajorNationId) -> PictureId {
    COAT_PICTURE_BASE.offset(i16::from(nation.get()))
}

#[derive(Component)]
struct NewCityDialogRoot(CapitalSite);

#[derive(Component, Default)]
struct CitySiteHover(Option<TileId>);

#[derive(Component)]
struct CitySiteRoot;

#[derive(Component)]
struct CitySiteIntro;

#[derive(Component)]
struct CitySiteNotice(String);

pub(crate) struct CitySitePlugin;

impl Plugin for CitySitePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::CitySite),
            (enter_city_site, bind_city_site).chain(),
        )
        .add_systems(
            Update,
            (
                bind_city_site_intro,
                bind_new_city_dialog,
                bind_city_site_notice,
                sync_city_site_hover.run_if(no_modal),
                sync_minimap,
            )
                .run_if(in_state(AppState::CitySite)),
        );
    }
}

fn enter_city_site(mut commands: Commands) {
    let root = commands.spawn_scene(generated::startup_952()).id();
    commands
        .entity(root)
        .insert((CitySiteRoot, DespawnOnExit(AppState::CitySite)));
}

fn bind_city_site(
    mut commands: Commands,
    root: Single<Entity, Added<CitySiteRoot>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    map: Res<StrategicMapSession>,
) {
    let root = *root;
    bind_city_site_controls(&mut commands, root, &tree, &mut assets);
    let origin = map.view.detailed_origin(&session.game);
    let map_entity =
        bind_strategic_base_terrain(&mut commands, root, &tree, &mut assets, &session, origin);
    bind_minimap(&mut commands, root, &tree, &mut assets, &session, origin);
    commands
        .entity(map_entity)
        .insert(CitySiteHover::default())
        .observe(on_city_site_map_click);
    open_city_site_intro(&mut commands);
}

fn bind_city_site_controls(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
) {
    bind_query_floater_control(commands, root, tree);
    let cancel = tree.find(root, fourcc!("canc"));
    commands.entity(cancel).observe(
        |_: On<Activate>, mut next_state: ResMut<NextState<AppState>>| {
            next_state.set(AppState::RandomSetup);
        },
    );
    // HoverHelpBar + recovered curs style come from codegen / Windows deltas.
    bind_hover_help_texts(
        commands,
        root,
        tree,
        [
            (fourcc!("main"), String::new()),
            (fourcc!("DLOG"), String::new()),
            (
                fourcc!("canc"),
                assets.ui_string(PLACE_CITY_STRING_GROUP, 9),
            ),
            (fourcc!("quer"), assets.ui_string(0x2730, 3)),
        ],
    );
}

fn open_city_site_intro(commands: &mut Commands) {
    spawn_linger_dialog(commands, CitySiteIntro, AppState::CitySite);
}

fn bind_city_site_intro(
    mut commands: Commands,
    roots: Query<Entity, Added<CitySiteIntro>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let Ok(root) = roots.single() else {
        return;
    };
    let nation = session.active_major_nation();
    let minister = assets.get_string(MINISTER_STRING_GROUP, 2);
    let mut title = fill_brackets(&assets.get_string(MINISTER_STRING_GROUP, 4), &[&minister]);
    title.push_str("\n\n");
    title.push_str(&assets.get_string(PLACE_CITY_STRING_GROUP, 3));
    let body = assets.get_string(PLACE_CITY_STRING_GROUP, 4);
    stuff_minister_dialog(
        &mut commands,
        root,
        &tree,
        &mut assets,
        &title,
        &body,
        Some(CITY_SITE_INTRO_GOLD_PICTURE),
        Some(city_site_coat_picture(nation)),
        true,
    );
    let okay = tree.find(root, OKAY);
    commands
        .entity(okay)
        .remove::<bevy::ui::InteractionDisabled>();
}

fn sync_city_site_hover(
    session: Res<GameSession>,
    map: Res<StrategicMapSession>,
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut maps: Query<(
        &StrategicBaseTerrainCanvas,
        &RelativeCursorPosition,
        &ImageNode,
        &mut CitySiteHover,
    )>,
) {
    let nation = session.active_major_nation();
    let origin = map.view.detailed_origin(&session.game);
    for (canvas, cursor, image_node, mut hover) in &mut maps {
        let tile = strategic_base_terrain_tile_at_cursor(&session.game, origin, cursor);
        if hover.0 == tile && !session.is_changed() && !map.is_changed() {
            continue;
        }
        hover.0 = tile;
        let highlighted =
            tile.filter(|&tile| highlights_city_site_candidate(&session.game, nation, tile));
        let image = compose_city_site_terrain(
            &session.game,
            origin,
            canvas,
            nation,
            highlighted,
            retail_assets.assets().default_dib_palette(),
        );
        let Some(mut existing) = images.get_mut(&image_node.image) else {
            continue;
        };
        *existing = image;
    }
}

fn highlights_city_site_candidate(state: &GameState, nation: MajorNationId, tile: TileId) -> bool {
    let tile_state = state.map()[tile];
    tile_state.owner_nation == Some(TileOwnerTag::from_nation(nation.nation()))
        && !matches!(
            tile_state.terrain,
            TerrainKind::Hills | TerrainKind::Mountain | TerrainKind::Swamp
        )
        && is_valid_secondary_nation_home_tile_candidate(state.map(), tile)
}

fn on_city_site_map_click(
    click: On<Pointer<Click>>,
    session: Res<GameSession>,
    map: Res<StrategicMapSession>,
    maps: Query<&RelativeCursorPosition, With<StrategicBaseTerrainCanvas>>,
    mut commands: Commands,
    assets: RetailUiAssets,
) {
    let cursor = maps
        .get(click.entity)
        .expect("city-site map click is bound on the strategic canvas");
    let origin = map.view.detailed_origin(&session.game);
    let Some(tile) = strategic_base_terrain_tile_at_cursor(&session.game, origin, cursor) else {
        return;
    };
    let nation = session.active_major_nation();
    match validate_capital_site_selection(&session.game, nation, tile) {
        Ok(site) => open_new_city_dialog(&mut commands, site),
        Err(error) => {
            let body = assets.string(city_site_error_string(error, &session.game, tile));
            open_city_site_notice(&mut commands, body);
        }
    }
}

fn open_new_city_dialog(commands: &mut Commands, site: CapitalSite) {
    let (modal, _window) = spawn_modal_window(commands, generated::startup_953());
    commands
        .entity(modal)
        .insert((NewCityDialogRoot(site), DespawnOnExit(AppState::CitySite)));
}

fn open_city_site_notice(commands: &mut Commands, body: String) {
    spawn_linger_dialog(commands, CitySiteNotice(body), AppState::CitySite);
}

fn bind_new_city_dialog(
    mut commands: Commands,
    dialogs: Query<(Entity, &NewCityDialogRoot), Added<NewCityDialogRoot>>,
    tree: RetailTree,
    mut nodes: Query<&mut Node>,
    mut pictures: Query<&mut ImageNode>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let Ok((root, dialog)) = dialogs.single() else {
        return;
    };
    let report = capital_site_report(&session.game, dialog.0);
    stuff_new_city_dialog(
        &mut commands,
        root,
        &tree,
        &mut nodes,
        &mut pictures,
        &mut assets,
        &report,
    );
    let okay = tree.find(root, OKAY);
    commands
        .entity(okay)
        .remove::<bevy::ui::InteractionDisabled>()
        .observe(on_new_city_activate);
    let cancel = tree.find(root, fourcc!("cncl"));
    commands
        .entity(cancel)
        .remove::<bevy::ui::InteractionDisabled>();
    dismiss_on_activate(&mut commands, okay, root);
    dismiss_on_activate(&mut commands, cancel, root);
    bind_modal_keys(&mut commands, root, Some(okay), Some(cancel));
}

fn stuff_new_city_dialog(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    nodes: &mut Query<&mut Node>,
    pictures: &mut Query<&mut ImageNode>,
    assets: &mut RetailUiAssets,
    report: &CapitalSiteReport,
) {
    let extra_height = new_city_extra_height(report.visible_resource_count());
    for tag in [fourcc!("WIND"), fourcc!("DLOG")] {
        let entity = tree.find(root, tag);
        let mut node = nodes
            .get_mut(entity)
            .expect("new-city dialog chrome has Node");
        if let Val::Px(height) = node.height {
            node.height = Val::Px(height + extra_height as f32);
        }
    }
    let dialog_height = (175 + extra_height) as f32;
    pictures
        .get_mut(tree.find(root, fourcc!("DLOG")))
        .expect("new-city dialog background has ImageNode")
        .rect = Some(Rect::new(
        0.0,
        0.0,
        NEW_CITY_DIALOG_WIDTH as f32,
        dialog_height,
    ));
    for tag in [OKAY, fourcc!("cncl")] {
        let entity = tree.find(root, tag);
        let mut node = nodes
            .get_mut(entity)
            .expect("new-city dialog button has Node");
        if let Val::Px(top) = node.top {
            node.top = Val::Px(top + extra_height as f32);
        }
    }

    let title = assets.get_string(PLACE_CITY_STRING_GROUP, 7);
    set_text(
        commands,
        tree.find(root, fourcc!("titl")),
        assets,
        title,
        0x5c,
    );
    let summary = fill_brackets(
        &assets.get_string(PLACE_CITY_STRING_GROUP, 5),
        &[
            &report.sustainable_population.to_string(),
            &report.total_food.to_string(),
        ],
    );
    set_styled_text(
        commands,
        tree.find(root, fourcc!("sust")),
        assets,
        summary,
        12,
        1,
        0x5c,
    );

    let dlog = tree.find(root, fourcc!("DLOG"));
    let mut x = NEW_CITY_DIALOG_WIDTH;
    let mut y = 0x50;
    for index in 0..ResourceKind::LENGTH {
        let resource = ResourceKind::from_index(index as u8)
            .expect("resource index is inside the retail table");
        let count = report.yields[resource];
        if count == 0 {
            continue;
        }
        x += RESOURCE_ITEM_WIDTH;
        if x > NEW_CITY_DIALOG_WIDTH - 0x10 {
            x = 0x10;
            y += RESOURCE_ITEM_HEIGHT;
        }
        spawn_numbered_resource_item(commands, assets, dlog, x, y, resource, count);
    }
}

fn spawn_numbered_resource_item(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    parent: Entity,
    x: i32,
    y: i32,
    resource: ResourceKind,
    count: i16,
) {
    let icon = commodity_icon(assets, resource);
    commands
        .spawn_scene(numbered_resource_item_scene(x, y, icon, count))
        .insert(ChildOf(parent));
}

fn numbered_resource_item_scene(x: i32, y: i32, icon: Handle<Image>, count: i16) -> impl Scene {
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(x),
            top: px(y),
            width: px(RESOURCE_ITEM_WIDTH),
            height: px(RESOURCE_ITEM_HEIGHT),
        }
        Children [
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0), top: px(0), width: px(31), height: px(23),
                }
                template(move |_context| Ok(ImageNode::new(icon.clone())))
                Pickable::IGNORE
            ),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0), top: px(RESOURCE_ITEM_HEIGHT - 12),
                    width: px(RESOURCE_ITEM_WIDTH), height: px(12),
                }
                template(move |_context| Ok(Text::new(count.to_string())))
                retail_text_style(3, 0, 9, -1)
                retail_text_color(0)
                Pickable::IGNORE
            )
        ]
    }
}

fn new_city_extra_height(visible: i16) -> i32 {
    ((i32::from(visible) * RESOURCE_ITEM_WIDTH) / (NEW_CITY_DIALOG_WIDTH - 0x20) + 1)
        * RESOURCE_ITEM_HEIGHT
}

fn bind_city_site_notice(
    mut commands: Commands,
    notices: Query<(Entity, &CitySiteNotice), Added<CitySiteNotice>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let Ok((root, notice)) = notices.single() else {
        return;
    };
    let nation = session.active_major_nation();
    stuff_minister_dialog(
        &mut commands,
        root,
        &tree,
        &mut assets,
        "",
        &notice.0,
        None,
        Some(city_site_coat_picture(nation)),
        true,
    );
    let okay = tree.find(root, OKAY);
    commands
        .entity(okay)
        .remove::<bevy::ui::InteractionDisabled>();
}

fn on_new_city_activate(
    _activate: On<Activate>,
    dialog: Single<&NewCityDialogRoot>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let stop = confirm_capital_site(&mut session.game, dialog.0);
    apply_turn_stop(stop, &mut next_state);
}

#[allow(clippy::too_many_arguments)]
fn stuff_minister_dialog(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
    title: &str,
    body: &str,
    gold_picture: Option<PictureId>,
    coat_picture: Option<PictureId>,
    hide_cancel: bool,
) {
    let linger = bind_linger_dialog(commands, root, tree);
    if let Some(picture) = gold_picture {
        let gold = assets.picture(picture);
        commands
            .entity(tree.find(root, fourcc!("DLOG")))
            .insert(ImageNode::new(gold));
    }
    if let Some(picture) = coat_picture {
        commands
            .entity(linger.coat)
            .insert(ImageNode::new(assets.picture(picture)));
    } else {
        commands.entity(linger.coat).insert(Visibility::Hidden);
    }
    linger.set_title(commands, assets, retail_lines(title));
    linger.set_body(commands, assets, retail_lines(body));
    if hide_cancel {
        commands.entity(linger.cancel).insert(Visibility::Hidden);
    }
}

fn set_text(
    commands: &mut Commands,
    entity: Entity,
    assets: &mut RetailUiAssets,
    value: impl AsRef<str>,
    palette: u8,
) {
    commands.entity(entity).insert((
        Text::new(retail_lines(value.as_ref())),
        TextColor(assets.palette_color(palette)),
    ));
}

fn set_styled_text(
    commands: &mut Commands,
    entity: Entity,
    assets: &mut RetailUiAssets,
    value: impl AsRef<str>,
    point_size: i32,
    alignment: i32,
    palette: u8,
) {
    let (font, layout, line_height, _) =
        assets.text_style(RetailTextStylePreset::explicit(1, 0, point_size, alignment));
    commands.entity(entity).insert((
        Text::new(retail_lines(value.as_ref())),
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(palette)),
    ));
}

fn commodity_icon(assets: &mut RetailUiAssets, resource: ResourceKind) -> Handle<Image> {
    assets.keyed_picture(resource.material_picture(), 0x10)
}

fn retail_lines(text: &str) -> String {
    text.replace('\r', "\n")
}
