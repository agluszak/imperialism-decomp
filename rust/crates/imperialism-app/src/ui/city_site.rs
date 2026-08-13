use crate::ui::GameSession;
use crate::ui::RetailUiAssets;
use crate::ui::generated;
use crate::ui::retail::ModalDialog;
use crate::ui::retail::{RetailTag, find_descendant};
use crate::ui::session::apply_turn_stop;
use crate::ui::strategic_map::{
    StrategicBaseTerrainCanvas, bind_strategic_base_terrain, compose_city_site_terrain,
    strategic_base_terrain_tile_at_cursor,
};
use crate::{AppState, RetailAssetsResource};
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use bevy::ui_widgets::Activate;
use imperialism_core::*;
use imperialism_formats::{OKAY, fourcc};

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum CitySiteAction {
    Cancel,
}

#[derive(Component)]
struct NewCityDialogRoot(CapitalSite);

#[derive(Component, Default)]
struct CitySiteHover(Option<TileId>);

#[derive(Component)]
struct CitySiteRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum NewCityAction {
    Accept,
    Cancel,
}

pub(crate) struct CitySitePlugin;

impl Plugin for CitySitePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::CitySite),
            (enter_city_site, bind_city_site).chain(),
        )
        .add_systems(
            Update,
            (bind_new_city_dialog, sync_city_site_hover).run_if(in_state(AppState::CitySite)),
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
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    bind_city_site_controls(&mut commands, *root, &children, &tags);
    let map = bind_strategic_base_terrain(
        &mut commands,
        *root,
        &children,
        &tags,
        &mut assets,
        &session.game,
    );
    commands
        .entity(map)
        .insert(CitySiteHover::default())
        .observe(on_city_site_map_click);
}

fn sync_city_site_hover(
    session: Res<GameSession>,
    retail_assets: Res<RetailAssetsResource>,
    dialog_open: Query<(), With<ModalDialog>>,
    mut images: ResMut<Assets<Image>>,
    mut maps: Query<(
        &StrategicBaseTerrainCanvas,
        &RelativeCursorPosition,
        &ImageNode,
        &mut CitySiteHover,
    )>,
) {
    if !dialog_open.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("City-site screen requires an active major nation");
    for (canvas, cursor, image_node, mut hover) in &mut maps {
        let Some(tile) = strategic_base_terrain_tile_at_cursor(&session.game, cursor) else {
            continue;
        };
        if hover.0 == Some(tile) && !session.is_changed() {
            continue;
        }
        hover.0 = Some(tile);
        let highlighted =
            highlights_city_site_candidate(&session.game, nation, tile).then_some(tile);
        let image = compose_city_site_terrain(
            &session.game,
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

fn bind_city_site_controls(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) {
    let cancel = find_descendant(root, fourcc!("canc"), children, tags);
    commands
        .entity(cancel)
        .insert(CitySiteAction::Cancel)
        .observe(on_city_site_activate);
}

fn on_city_site_activate(
    activate: On<Activate>,
    actions: Query<&CitySiteAction>,
    dialog_open: Query<(), With<ModalDialog>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let action = actions
        .get(activate.entity)
        .expect("city-site Activate is bound on a CitySiteAction control");
    if !dialog_open.is_empty() {
        return;
    }
    match *action {
        CitySiteAction::Cancel => next_state.set(AppState::RandomSetup),
    }
}

fn on_city_site_map_click(
    click: On<Pointer<Click>>,
    dialog_open: Query<(), With<ModalDialog>>,
    session: Res<GameSession>,
    maps: Query<&RelativeCursorPosition, With<StrategicBaseTerrainCanvas>>,
    mut commands: Commands,
) {
    if !dialog_open.is_empty() {
        return;
    }
    let cursor = maps
        .get(click.entity)
        .expect("city-site map click is bound on the strategic canvas");
    let Some(tile) = strategic_base_terrain_tile_at_cursor(&session.game, cursor) else {
        return;
    };
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("City-site screen requires an active major nation");
    let Ok(site) = validate_capital_site_selection(&session.game, nation, tile) else {
        return;
    };
    open_new_city_dialog(&mut commands, site);
}

fn open_new_city_dialog(commands: &mut Commands, site: CapitalSite) {
    let root = commands.spawn_scene(generated::startup_953()).id();
    commands.entity(root).insert((
        NewCityDialogRoot(site),
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::CitySite),
    ));
}

fn bind_new_city_dialog(
    mut commands: Commands,
    root: Single<Entity, Added<NewCityDialogRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
) {
    for (tag, action) in [
        (OKAY, NewCityAction::Accept),
        (fourcc!("cncl"), NewCityAction::Cancel),
    ] {
        let entity = find_descendant(*root, tag, &children, &tags);
        commands
            .entity(entity)
            .insert(action)
            .remove::<bevy::ui::InteractionDisabled>()
            .observe(on_new_city_activate);
    }
}

fn on_new_city_activate(
    activate: On<Activate>,
    actions: Query<&NewCityAction>,
    dialogs: Query<(Entity, &NewCityDialogRoot)>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
    retail: Res<RetailAssetsResource>,
) {
    let action = actions
        .get(activate.entity)
        .expect("new-city Activate is bound on a NewCityAction control");
    match *action {
        NewCityAction::Accept => {
            let Ok((_, dialog)) = dialogs.single() else {
                return;
            };
            let stop = confirm_capital_site(&mut session.game, dialog.0);
            for (root, _) in &dialogs {
                commands.entity(root).despawn();
            }
            apply_turn_stop(stop, &mut session.game, retail.assets(), &mut next_state);
        }
        NewCityAction::Cancel => {
            for (root, _) in &dialogs {
                commands.entity(root).despawn();
            }
        }
    }
}
