//! Post-combat `TBattleReportView` / `TBattleDetailBook`.

use super::fill_brackets;
use super::generated;
use super::retail::RetailTree;
use super::retail_raster::IndexedRasterExt;
use super::satellite_preview::nation_owner_palette;
use super::session::{BattleReportPresentation, GameSession, apply_turn_stop};
use super::window::{ModalWindow, bind_modal_keys, dismiss_on_activate};
use crate::AppState;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::{InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::Activate;
use imperialism_core::*;
use imperialism_formats::{
    BattleReportSideText, BattleReportText, PictureId, RetailTextStylePreset, fourcc,
};

const MAP_LEFT: f32 = 49.0;
const MAP_TOP: f32 = 45.0;
const MAP_WIDTH: f32 = 540.0;
const MAP_HEIGHT: f32 = 300.0;
const MARKER_ATLAS: PictureId = PictureId::new(803);
const MARKER_CELL: f32 = 18.0;
const DETAIL_ROW_WIDTH: f32 = 236.0;
const DETAIL_ROW_HEIGHT: f32 = 49.0;
const DETAIL_ROWS_PER_PAGE: usize = 6;
const ARMY_CHECKBOX_ATLAS: i16 = 0xdb8;
const NAVY_CHECKBOX_ATLAS: i16 = 0xdba;
const MERC_CHECKBOX_ATLAS: i16 = 0xdbb;
const EXPERIENCE_STRIP: i16 = 800;
/// Retail's blit selects palette index `0x10` as transparent; `0x24` is the blitter flags.
const KEYED_TRANSPARENT: u8 = 0x10;
const COMMODITY_ICON_BASE: i16 = 700;
const COMMODITY_ICON_WIDTH: f32 = 32.0;
const COMMODITY_ICON_HEIGHT: f32 = 23.0;
const BATTLE_REPORT_ITEM_IDENTITY: u32 = 0x6974_656d;
const BATTLE_REPORT_RUPT_IDENTITY: u32 = 0x7275_7074;
const BATTLE_REPORT_MERC_IDENTITY: u32 = 0x6d65_7263;
const SHIP_ATLAS_OFFSETS: [i16; 14] = [
    0, 0, 0, 0, 0xa0, 0, 0, 0x140, 0x1e0, 0x280, 0, 0x320, 0x3c0, 0x460,
];
const MERCHANT_ATLAS_SLOTS: [i16; 14] = [0, 0, 1, 0, 0, 2, 3, 0, 0, 0, 4, 0, 0, 0];

#[derive(Component)]
struct BattleReportScreen;

/// The fixed diplomacy-map destination behind the reports. The map base and
/// marker set recompose only when the report collection changes; the map
/// surface is independent of which report is selected.
#[derive(Component)]
struct BattleReportMap {
    marker_atlas: Handle<Image>,
}

/// One dynamic map marker. A report's location is world-ish state, so the
/// marker is an entity that owns its position, sprite, and blink.
#[derive(Component)]
struct BattleReportMarker {
    report: usize,
    sprite: i32,
}

#[derive(Component)]
struct BattleReportView {
    selected: usize,
    result: Entity,
    location: Entity,
    friendly_admiral: Entity,
    enemy_admiral: Entity,
    friendly_ships: Entity,
    enemy_ships: Entity,
    friendly_flag: Entity,
    enemy_flag: Entity,
    previous: Entity,
    next: Entity,
    info: Entity,
}

#[derive(Component)]
struct BattleReportDetailView {
    page: usize,
    /// Summary selection last projected into this book; used to reset paging.
    selected_report: usize,
    nat_l: Entity,
    nat_r: Entity,
    flg_l: Entity,
    flg_r: Entity,
    page_panel: Entity,
    pagf_panel: Entity,
    lcor: Entity,
    rcor: Entity,
    army_atlas: Handle<Image>,
    navy_atlas: Handle<Image>,
    merc_atlas: Handle<Image>,
    experience_strip: Handle<Image>,
}

#[derive(Component)]
struct BattleDetailLine;

pub(crate) struct BattleReportPlugin;

impl Plugin for BattleReportPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::BattleReport),
            (spawn_battle_report, bind_battle_report).chain(),
        )
        .add_systems(
            Update,
            (
                render_battle_report,
                render_battle_report_map,
                super::diplomacy_map::layout_diplomacy_nation_label_entities,
                blink_selected_battle_report_marker,
                bind_detail,
                render_detail,
            )
                .run_if(in_state(AppState::BattleReport).and_then(resource_exists::<GameSession>)),
        );
    }
}

fn spawn_battle_report(mut commands: Commands) {
    let root = commands.spawn_scene(generated::diplo_1351()).id();
    commands
        .entity(root)
        .insert((BattleReportScreen, DespawnOnExit(AppState::BattleReport)));
}

fn bind_battle_report(
    mut commands: Commands,
    root: Single<Entity, Added<BattleReportScreen>>,
    tree: RetailTree,
    mut assets: super::RetailUiAssets,
    mut session: ResMut<GameSession>,
    mut reports: ResMut<BattleReportPresentation>,
) {
    let root = *root;
    let main = tree.find(root, fourcc!("main"));
    let marker_atlas = assets.keyed_picture(MARKER_ATLAS, KEYED_TRANSPARENT);
    let map_entity = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(MAP_LEFT),
                top: px(MAP_TOP),
                width: px(MAP_WIDTH),
                height: px(MAP_HEIGHT),
                overflow: Overflow::clip(),
                ..default()
            },
            ImageNode::default(),
            RelativeCursorPosition::default(),
            BattleReportMap { marker_atlas },
            ChildOf(main),
        ))
        .observe(on_battle_report_map_click)
        .id();
    let countries = session
        .game
        .nations()
        .common_states()
        .map(|(nation, common)| (nation, common.display_name.clone()))
        .filter(|(_, name)| !name.is_empty())
        .collect::<Vec<_>>();
    let mut labels = Vec::new();
    let session = &mut *session;
    for (nation, name) in countries {
        if let Some(anchor) = session.game.overlay_anchor_for_nation(nation) {
            labels.push((nation, name, anchor));
        }
    }
    super::diplomacy_map::spawn_diplomacy_nation_labels(
        &mut commands,
        &mut assets,
        map_entity,
        labels,
    );
    ensure_battle_report_presentation(&mut assets, session, &mut reports.0);
    let okay = tree.find(root, fourcc!("okay"));
    commands.entity(okay).observe(on_battle_report_close);
    dismiss_on_activate(&mut commands, okay, root);
    bind_modal_keys(&mut commands, root, Some(okay), None);
    let info = tree.find(root, fourcc!("info"));
    commands.entity(info).observe(on_battle_report_detail);
    let previous = tree.find(root, fourcc!("prev"));
    let next = tree.find(root, fourcc!("next"));
    for (entity, is_previous) in [(previous, true), (next, false)] {
        commands.entity(entity).observe(
            move |_: On<Activate>,
                  mut views: Query<&mut BattleReportView>,
                  session: Res<GameSession>| {
                let count = session.game.battle_reports().len();
                if count == 0 {
                    return;
                }
                let Ok(mut view) = views.single_mut() else {
                    return;
                };
                view.selected = if is_previous {
                    view.selected.saturating_sub(1)
                } else {
                    (view.selected + 1).min(count.saturating_sub(1))
                };
            },
        );
    }
    commands.entity(root).insert(BattleReportView {
        selected: 0,
        result: tree.find(root, fourcc!("resu")),
        location: tree.find(root, fourcc!("loca")),
        friendly_admiral: tree.find(root, fourcc!("fadm")),
        enemy_admiral: tree.find(root, fourcc!("eadm")),
        friendly_ships: tree.find(root, fourcc!("fshp")),
        enemy_ships: tree.find(root, fourcc!("eshp")),
        friendly_flag: tree.find(root, fourcc!("fflg")),
        enemy_flag: tree.find(root, fourcc!("eflg")),
        previous,
        next,
        info,
    });
}

/// Projects the selected report's text, flags, and step/info visibility.
fn render_battle_report(
    mut commands: Commands,
    session: Res<GameSession>,
    reports: Res<BattleReportPresentation>,
    views: Query<Ref<BattleReportView>>,
    mut assets: super::RetailUiAssets,
    mut texts: Query<&mut Text>,
    mut flags: Query<&mut ImageNode>,
) {
    let Ok(view) = views.single() else {
        return;
    };
    if !session.is_changed() && !view.is_added() && !view.is_changed() && !reports.is_changed() {
        return;
    }
    let reports_game = session.game.battle_reports();
    let Some(report) = reports_game.get(view.selected) else {
        for entity in [
            view.result,
            view.location,
            view.friendly_admiral,
            view.enemy_admiral,
            view.friendly_ships,
            view.enemy_ships,
        ] {
            texts
                .get_mut(entity)
                .expect("bound battle-report text")
                .0
                .clear();
        }
        return;
    };
    let report_text = battle_report_text(Some(&assets), &session, &reports.0, view.selected);
    let participant = report.displayed_side;
    let other = other_side(participant);
    texts
        .get_mut(view.result)
        .expect("bound battle-report text")
        .0 = battle_report_result_text(&assets, &session.game, report);
    texts
        .get_mut(view.location)
        .expect("bound battle-report text")
        .0 = battle_report_location_text(&assets, &session.game, report);
    texts
        .get_mut(view.friendly_admiral)
        .expect("bound battle-report text")
        .0 = report_text[participant].name.clone();
    texts
        .get_mut(view.enemy_admiral)
        .expect("bound battle-report text")
        .0 = report_text[other].name.clone();
    texts
        .get_mut(view.friendly_ships)
        .expect("bound battle-report text")
        .0 = report_text[participant].overlay.clone();
    texts
        .get_mut(view.enemy_ships)
        .expect("bound battle-report text")
        .0 = report_text[other].overlay.clone();
    for (flag, side) in [(view.friendly_flag, participant), (view.enemy_flag, other)] {
        flags.get_mut(flag).expect("bound battle-report flag").image =
            assets.picture(battle_report_flag_picture(report.sides[side].nation));
    }
    let count = reports_game.len();
    let active = session.game.turn().active_nation;
    let participates = report.sides.iter().any(|(_, side)| side.nation == active);
    for (entity, visible) in [
        (view.previous, view.selected != 0),
        (view.next, view.selected + 1 < count),
        (view.info, participates),
    ] {
        commands.entity(entity).insert(if visible {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        });
        if visible {
            commands.entity(entity).remove::<InteractionDisabled>();
        } else {
            commands.entity(entity).insert(InteractionDisabled);
        }
    }
}

fn battle_report_flag_picture(nation: NationId) -> PictureId {
    PictureId::new(0x1130 + i16::from(nation.get()))
}

/// Recomposes the diplomacy map and rebuilds the marker set when the game or
/// report collection changes. Selection only blinks an existing marker, so
/// Prev/Next does not touch the expensive map surface.
fn render_battle_report_map(
    mut commands: Commands,
    session: Res<GameSession>,
    reports: Res<BattleReportPresentation>,
    map: Query<(Entity, Option<&ImageNode>, Ref<BattleReportMap>)>,
    markers: Query<Entity, With<BattleReportMarker>>,
    mut assets: super::RetailUiAssets,
) {
    let Ok((map_entity, map_image, map_data)) = map.single() else {
        return;
    };
    if !session.is_changed() && !reports.is_changed() && !map_data.is_added() {
        return;
    }
    let reports_game = session.game.battle_reports();
    let state = &session.game;
    let owner_at = |tile: TileId| {
        state.map()[tile]
            .owner_nation
            .and_then(TileOwnerTag::nation)
    };
    let (picture, _) =
        super::diplomacy_map::compose_diplomacy_map(owner_at, nation_owner_palette, None);
    let image = picture.to_keyed_image(assets.default_dib_palette(), 0x10);
    if let Some(image_node) = map_image {
        assets.replace_image(&image_node.image, image);
    } else {
        commands
            .entity(map_entity)
            .insert(ImageNode::new(assets.add_image(image)));
    }
    for marker in &markers {
        commands.entity(marker).despawn();
    }
    let mut crowd = vec![0u8; STRATEGIC_TILE_COUNT];
    let geometry = state.map().geometry();
    // Retail walks this one-based list from count down to one. The crowd grid
    // is mutated after every marker, so this order is observable.
    for (index, report) in reports_game.iter().enumerate().rev() {
        let Some(tile) = battle_report_tile(state, report) else {
            continue;
        };
        let tile = battle_report_marker_tile(geometry, tile, &mut crowd);
        let (row, column) = state.map().geometry().row_column(tile);
        let point = super::diplomacy_map::diplomacy_tile_pixel(row, column) - IVec2::splat(9);
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(point.x),
                top: px(point.y),
                width: px(MARKER_CELL),
                height: px(MARKER_CELL),
                ..default()
            },
            ImageNode {
                image: map_data.marker_atlas.clone(),
                rect: Some(marker_rect(battle_report_marker_sprite(state, report))),
                ..default()
            },
            BattleReportMarker {
                report: index,
                sprite: battle_report_marker_sprite(state, report),
            },
            ChildOf(map_entity),
            ZIndex(1),
        ));
    }
}

fn blink_selected_battle_report_marker(
    time: Res<Time>,
    views: Query<&BattleReportView>,
    mut markers: Query<(&BattleReportMarker, &mut ImageNode)>,
) {
    let Ok(view) = views.single() else {
        return;
    };
    // TBattleReportView flips the selected sprite column every 15 idle ticks.
    let phase = i32::from((time.elapsed().as_millis() / 250) & 1 == 0);
    for (marker, mut image) in &mut markers {
        image.rect = Some(marker_rect(
            marker.sprite + i32::from(marker.report == view.selected) * phase,
        ));
    }
}

fn on_battle_report_map_click(
    click: On<Pointer<Click>>,
    maps: Query<&RelativeCursorPosition, With<BattleReportMap>>,
    markers: Query<(&BattleReportMarker, &Node)>,
    mut views: Query<&mut BattleReportView>,
) {
    if click.event.button != PointerButton::Primary {
        return;
    }
    let Ok(cursor) = maps.get(click.entity) else {
        return;
    };
    let Some(point) = cursor.normalized.filter(|_| cursor.cursor_over()) else {
        return;
    };
    let point = Vec2::new((point.x + 0.5) * MAP_WIDTH, (point.y + 0.5) * MAP_HEIGHT);
    let Some(report) = markers.iter().find_map(|(marker, node)| {
        let (Val::Px(left), Val::Px(top)) = (node.left, node.top) else {
            return None;
        };
        Rect::from_corners(
            Vec2::new(left, top),
            Vec2::new(left + MARKER_CELL, top + MARKER_CELL),
        )
        .contains(point)
        .then_some(marker.report)
    }) else {
        return;
    };
    if let Ok(mut view) = views.single_mut() {
        view.selected = report;
    }
}

fn battle_report_location_text(
    assets: &super::RetailUiAssets,
    state: &GameState,
    report: &BattleReport,
) -> String {
    match report.location {
        BattleReportLocation::Zone(id) => state
            .ocean()
            .zones
            .get(usize::from(id.get()))
            .map(|zone| zone.zone().display_name.clone())
            .unwrap_or_default(),
        BattleReportLocation::Province(id) => {
            let province = &state.map().provinces[id];
            let owner = province
                .city_tile()
                .and_then(|tile| state.map()[tile].owner_nation)
                .and_then(TileOwnerTag::nation)
                .and_then(|nation| state.nation(nation))
                .map(|nation| nation.display_name.as_str())
                .unwrap_or("");
            assets
                .get_string(0x273d, 7)
                .replace("[1]", &province.name)
                .replace("[2]", owner)
                + " "
        }
    }
}

/// `TBattleReportView::DoPostCreate` marker placement: spiral outward from the
/// report's map cell on a 60×108 crowding grid until a free hex is found, then
/// mark a radius-3 neighborhood around it as crowded. The steps replicate retail
/// `TMapMgr::StepHexRowColByDirectionWithWrapRules`, which wraps columns around
/// the map edges when the map is bounded.
fn battle_report_marker_tile(geometry: MapGeometry, origin: TileId, crowd: &mut [u8]) -> TileId {
    let cell = i32::from(origin.get());
    let (mut row, mut column) = (cell / 108, cell % 108);
    let mut ring_leg = 1;
    let mut leg_step = 0;
    let mut radius = 0;
    let mut found_cell = cell;
    step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, 4);
    step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, ring_leg);
    while radius < 10 {
        if let Some(probe) = crowd_probe(row, column)
            && crowd[probe as usize] == 0
        {
            found_cell = probe;
            break;
        }
        leg_step += 1;
        if leg_step >= radius {
            leg_step = 0;
            ring_leg += 1;
            if ring_leg >= 6 {
                ring_leg = 0;
                radius += 1;
                step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, 4);
            }
        }
        step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, ring_leg);
    }
    (row, column) = (found_cell / 108, found_cell % 108);
    let mut ring = 0;
    let mut mark_leg = 1;
    let mut mark_step = 0;
    let mut mark_leg_len = found_cell % 108;
    step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, 4);
    step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, mark_leg);
    while ring < 3 {
        if let Some(probe) = crowd_probe(row, column) {
            crowd[probe as usize] += 1;
        }
        mark_step += 1;
        if mark_step >= mark_leg_len {
            mark_step = 0;
            mark_leg += 1;
            if mark_leg >= 6 {
                mark_leg = 0;
                mark_leg_len += 1;
                ring += 1;
                step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, 4);
            }
        }
        step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, mark_leg);
    }
    crowd[found_cell as usize] += 1;
    TileId::new(u16::try_from(found_cell).expect("battle-report marker tile fits the map"))
}

fn crowd_probe(row: i32, column: i32) -> Option<i32> {
    ((0..STRATEGIC_MAP_HEIGHT as i32).contains(&row)
        && (0..STRATEGIC_MAP_WIDTH as i32).contains(&column))
    .then_some(row * STRATEGIC_MAP_WIDTH as i32 + column)
}

/// Retail `TMapMgr::StepHexRowColByDirectionWithWrapRules` integer row/column
/// stepping, including its out-of-bounds column wrap quirk.
fn step_hex_row_col_by_wrap_rules(
    geometry: MapGeometry,
    row: &mut i32,
    column: &mut i32,
    direction: i32,
) {
    if direction == 4 || (direction > 2 && *row & 1 == 0) {
        let next = *column - 1;
        *column = next;
        if next < 0 && !geometry.wraps_horizontally() {
            *column = STRATEGIC_MAP_WIDTH as i32 - 1;
        }
    } else if direction == 1 || (direction < 3 && *row & 1 != 0) {
        let next = *column + 1;
        *column = next;
        if next >= STRATEGIC_MAP_WIDTH as i32 && !geometry.wraps_horizontally() {
            *column = 0;
        }
    }
    if direction == 5 || direction == 0 {
        *row -= 1;
    } else if direction == 3 || direction == 2 {
        *row += 1;
    }
}

fn battle_report_result_text(
    assets: &super::RetailUiAssets,
    state: &GameState,
    report: &BattleReport,
) -> String {
    let (group, index) = battle_report_result_string_index(state, report);
    assets.get_string(group, index)
}

/// `RefreshMapContextSelectionPanelAndInfoLabels`: the `resu` string group and
/// (0-based, pre-`GetString` increment) index recovered from the report kind,
/// the winner/active-nation relation, and land-battle site ownership.
fn battle_report_result_string_index(state: &GameState, report: &BattleReport) -> (u16, u16) {
    let active = state.turn().active_nation;
    let winner = report.participant.unwrap_or(report.displayed_side);
    let relation = if report.sides[winner].nation == active {
        1_i16
    } else if report.sides[other_side(winner)].nation == active {
        -1
    } else {
        0
    };
    match report.kind {
        BattleReportKind::MerchantInterception => (0x273c, (relation + 4) as u16),
        BattleReportKind::SeaBattle => (0x273c, (relation + 7) as u16),
        BattleReportKind::PreemptedLandBattle => (0x273d, (relation + 39) as u16),
        BattleReportKind::UncontestedTakeover => (0x273d, (relation + 42) as u16),
        BattleReportKind::LandBattle => {
            let report_sides_are_same = report.displayed_side == winner;
            let report_participant_is_active = report.sides[winner].nation == active;
            let active_nation_is_other_report_side = relation != 0 && !report_participant_is_active;
            let displayed_participant_is_active =
                report.sides[report.displayed_side].nation == active;
            let mut other_nation = report.sides[BattleReportSideSlot::Left].nation;
            if other_nation == active {
                other_nation = report.sides[BattleReportSideSlot::Right].nation;
            }
            let BattleReportLocation::Province(province) = report.location else {
                unreachable!("land battle reports store a province");
            };
            let active_nation_owns_battle_site = state.capitol_province(active) == Some(province);
            let other_nation_owns_battle_site =
                state.capitol_province(other_nation) == Some(province);
            let index = if active_nation_owns_battle_site && displayed_participant_is_active {
                47
            } else if active_nation_owns_battle_site && active_nation_is_other_report_side {
                48
            } else if report_participant_is_active
                && report_sides_are_same
                && other_nation_owns_battle_site
            {
                47
            } else if report_participant_is_active && report_sides_are_same {
                3
            } else if report_participant_is_active {
                6
            } else if active_nation_is_other_report_side && report_sides_are_same {
                4
            } else if active_nation_is_other_report_side {
                1
            } else if report_sides_are_same {
                2
            } else {
                5
            };
            (0x273d, index)
        }
    }
}

fn battle_report_tile(state: &GameState, report: &BattleReport) -> Option<TileId> {
    match report.location {
        BattleReportLocation::Province(province) => state.map().provinces[province].city_tile(),
        // Retail places Battle Report markers on `TZone::tileOrTerrainId0c`,
        // which projects to `target_tile` (not `active_tile`).
        BattleReportLocation::Zone(zone) => state
            .ocean()
            .zones
            .get(usize::from(zone.get()))
            .and_then(|zone| zone_report_marker_tile(zone.zone().target_tile)),
    }
}

/// Sea-report map markers use the zone's `target_tile` only.
fn zone_report_marker_tile(target_tile: Option<TileId>) -> Option<TileId> {
    target_tile
}

fn battle_report_marker_sprite(state: &GameState, report: &BattleReport) -> i32 {
    let active = state.turn().active_nation;
    let participant = report.participant.unwrap_or(BattleReportSideSlot::Left);
    let other = other_side(participant);
    let base = if report.sides[participant].nation == active {
        0
    } else if report.sides[other].nation == active {
        4
    } else {
        8
    };
    base + i32::from(report.kind == BattleReportKind::MerchantInterception) * 2
}

fn other_side(side: BattleReportSideSlot) -> BattleReportSideSlot {
    match side {
        BattleReportSideSlot::Left => BattleReportSideSlot::Right,
        BattleReportSideSlot::Right => BattleReportSideSlot::Left,
    }
}

fn marker_rect(sprite: i32) -> Rect {
    Rect::from_corners(
        Vec2::new(sprite as f32 * MARKER_CELL, 0.0),
        Vec2::new((sprite + 1) as f32 * MARKER_CELL, MARKER_CELL),
    )
}

fn on_battle_report_close(
    _activate: On<Activate>,
    mut session: ResMut<GameSession>,
    mut reports: ResMut<BattleReportPresentation>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    reports.0.clear();
    apply_turn_stop(session.game.close_post_combat_reports(), &mut next_state);
}

fn on_battle_report_detail(
    _activate: On<Activate>,
    mut commands: Commands,
    session: Res<GameSession>,
    details: Query<(), With<BattleReportDetailView>>,
) {
    if details.is_empty() && !session.game.battle_reports().is_empty() {
        spawn_detail(&mut commands);
    }
}

fn spawn_detail(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::diplo_1352()).id();
    commands.entity(root).insert((
        DetailBookRoot,
        ModalWindow,
        DespawnOnExit(AppState::BattleReport),
    ));
}

/// Marker on the diplo_1352 detail book so `bind_detail` does not claim other modals.
#[derive(Component)]
struct DetailBookRoot;

fn bind_detail(
    mut commands: Commands,
    root: Single<Entity, Added<DetailBookRoot>>,
    tree: RetailTree,
    mut assets: super::RetailUiAssets,
    session: Res<GameSession>,
    reports: Res<BattleReportPresentation>,
    views: Query<&BattleReportView>,
) {
    let root = *root;
    let Ok(view) = views.single() else {
        return;
    };
    let Some(report) = session.game.battle_reports().get(view.selected) else {
        return;
    };
    let nat_l = tree.find(root, fourcc!("natL"));
    let nat_r = tree.find(root, fourcc!("natR"));
    let flg_l = tree.find(root, fourcc!("flgL"));
    let flg_r = tree.find(root, fourcc!("flgR"));
    let page_panel = tree.find(root, fourcc!("page"));
    let pagf_panel = tree.find(root, fourcc!("pagf"));
    let lcor = tree.find(root, fourcc!("lcor"));
    let rcor = tree.find(root, fourcc!("rcor"));
    let okay = tree.find(root, fourcc!("okay"));
    dismiss_on_activate(&mut commands, okay, root);
    bind_modal_keys(&mut commands, root, Some(okay), None);
    for (entity, previous) in [(lcor, true), (rcor, false)] {
        commands.entity(entity).observe(
            move |_: On<Activate>,
                  session: Res<GameSession>,
                  selected: Query<&BattleReportView>,
                  mut details: Query<&mut BattleReportDetailView>| {
                let (Ok(selected), Ok(mut detail)) = (selected.single(), details.single_mut())
                else {
                    return;
                };
                let Some(report) = session.game.battle_reports().get(selected.selected) else {
                    return;
                };
                let count = detail_page_count(report);
                if previous {
                    if detail.page > 1 {
                        detail.page -= 1;
                    }
                } else if detail.page < count {
                    detail.page += 1;
                }
            },
        );
    }
    let (font, layout, line_height, _) = assets.text_style(RetailTextStylePreset::built(14, 1));
    let text_color = assets.palette_color(0x28);
    let shadow_color = assets.palette_color(0xd2);
    let report_text = battle_report_text(Some(&assets), &session, &reports.0, view.selected);
    for (entity, side) in [
        (nat_l, BattleReportSideSlot::Left),
        (nat_r, BattleReportSideSlot::Right),
    ] {
        commands.entity(entity).insert((
            Text::new(report_text[side].name.clone()),
            font.clone(),
            layout,
            line_height,
            TextColor(text_color),
            TextShadow {
                offset: Vec2::new(1.0, 1.0),
                color: shadow_color,
            },
        ));
    }
    let army_atlas = assets.keyed_picture(PictureId::new(ARMY_CHECKBOX_ATLAS), KEYED_TRANSPARENT);
    let navy_atlas = assets.keyed_picture(PictureId::new(NAVY_CHECKBOX_ATLAS), KEYED_TRANSPARENT);
    let merc_atlas = assets.keyed_picture(PictureId::new(MERC_CHECKBOX_ATLAS), KEYED_TRANSPARENT);
    let experience_strip =
        assets.keyed_picture(PictureId::new(EXPERIENCE_STRIP), KEYED_TRANSPARENT);
    for (entity, picture) in [
        (
            flg_l,
            0x1147 + i16::from(report.sides[BattleReportSideSlot::Left].nation.get()),
        ),
        (
            flg_r,
            0x114e + i16::from(report.sides[BattleReportSideSlot::Right].nation.get()),
        ),
    ] {
        commands
            .entity(entity)
            .insert(ImageNode::new(assets.picture(PictureId::new(picture))));
    }
    commands.entity(root).insert(BattleReportDetailView {
        page: 1,
        selected_report: view.selected,
        nat_l,
        nat_r,
        flg_l,
        flg_r,
        page_panel,
        pagf_panel,
        lcor,
        rcor,
        army_atlas,
        navy_atlas,
        merc_atlas,
        experience_strip,
    });
}

fn detail_page_count(report: &BattleReport) -> usize {
    report
        .sides
        .iter()
        .map(|(_, side)| side.children.len().div_ceil(DETAIL_ROWS_PER_PAGE))
        .max()
        .unwrap_or(1)
        .max(1)
}

fn render_detail(
    mut commands: Commands,
    session: Res<GameSession>,
    reports: Res<BattleReportPresentation>,
    selected: Query<Ref<BattleReportView>>,
    mut details: Query<&mut BattleReportDetailView>,
    lines: Query<Entity, With<BattleDetailLine>>,
    mut texts: Query<&mut Text>,
    mut images: Query<&mut ImageNode>,
    mut assets: super::RetailUiAssets,
) {
    let Ok(selected) = selected.single() else {
        return;
    };
    let Ok(mut detail) = details.single_mut() else {
        return;
    };
    let selection_changed = detail.selected_report != selected.selected;
    if !detail.is_added()
        && !detail.is_changed()
        && !selection_changed
        && !reports.is_changed()
        && !selected.is_changed()
    {
        return;
    }
    let Some(report) = session.game.battle_reports().get(selected.selected) else {
        return;
    };
    if selection_changed {
        detail.page = 1;
        detail.selected_report = selected.selected;
    }
    let page = detail.page;
    let report_text = battle_report_text(Some(&assets), &session, &reports.0, selected.selected);
    if let Ok(mut text) = texts.get_mut(detail.nat_l) {
        text.0 = report_text[BattleReportSideSlot::Left].name.clone();
    }
    if let Ok(mut text) = texts.get_mut(detail.nat_r) {
        text.0 = report_text[BattleReportSideSlot::Right].name.clone();
    }
    for (entity, picture) in [
        (
            detail.flg_l,
            0x1147 + i16::from(report.sides[BattleReportSideSlot::Left].nation.get()),
        ),
        (
            detail.flg_r,
            0x114e + i16::from(report.sides[BattleReportSideSlot::Right].nation.get()),
        ),
    ] {
        if let Ok(mut image) = images.get_mut(entity) {
            image.image = assets.picture(PictureId::new(picture));
        }
    }
    for line in &lines {
        commands.entity(line).despawn();
    }
    let skip = page.saturating_sub(1) * DETAIL_ROWS_PER_PAGE;
    for (panel, side) in [
        (detail.page_panel, BattleReportSideSlot::Left),
        (detail.pagf_panel, BattleReportSideSlot::Right),
    ] {
        for (index, row) in report.sides[side]
            .children
            .iter()
            .skip(skip)
            .take(DETAIL_ROWS_PER_PAGE)
            .enumerate()
        {
            spawn_detail_row(
                &mut commands,
                &mut assets,
                &session.game,
                &detail,
                panel,
                index,
                row,
            );
        }
    }
    let count = detail_page_count(report);
    for (entity, visible) in [(detail.lcor, page > 1), (detail.rcor, page < count)] {
        commands.entity(entity).insert(if visible {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        });
        if visible {
            commands.entity(entity).remove::<InteractionDisabled>();
        } else {
            commands.entity(entity).insert(InteractionDisabled);
        }
    }
}

fn spawn_detail_row(
    commands: &mut Commands,
    assets: &mut super::RetailUiAssets,
    state: &GameState,
    detail: &BattleReportDetailView,
    panel: Entity,
    index: usize,
    row: &BattleReportUnit,
) {
    let container = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(0),
                top: px(index as f32 * DETAIL_ROW_HEIGHT),
                width: px(DETAIL_ROW_WIDTH),
                height: px(DETAIL_ROW_HEIGHT),
                ..default()
            },
            Pickable::IGNORE,
            BattleDetailLine,
            ChildOf(panel),
        ))
        .id();
    match row.detail_identity {
        BATTLE_REPORT_ARMY_IDENTITY => {
            spawn_army_detail_row(commands, assets, detail, container, row)
        }
        BATTLE_REPORT_NAVY_IDENTITY => {
            spawn_navy_detail_row(commands, assets, detail, container, row)
        }
        BATTLE_REPORT_MERC_IDENTITY => {
            spawn_merchant_detail_row(commands, assets, detail, container, row)
        }
        BATTLE_REPORT_ITEM_IDENTITY => {
            spawn_item_detail_row(commands, assets, container, row, None)
        }
        BATTLE_REPORT_RUPT_IDENTITY => {
            spawn_item_detail_row(commands, assets, container, row, Some(state))
        }
        _ => spawn_text_only_detail_row(commands, assets, container, &row.name, 0),
    }
}

fn spawn_army_detail_row(
    commands: &mut Commands,
    assets: &mut super::RetailUiAssets,
    detail: &BattleReportDetailView,
    container: Entity,
    row: &BattleReportUnit,
) {
    let resource = match row.kind {
        BattleReportUnitKind::Military(kind) => i32::from(kind.retail()),
        _ => 0,
    };
    // SetState(1): ON frame sits 64px after the OFF base (resource << 7).
    let offset = (resource << 7) + 64;
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(0),
            top: px(0),
            width: px(64),
            height: px(49),
            ..default()
        },
        ImageNode {
            image: detail.army_atlas.clone(),
            rect: Some(Rect::from_corners(
                Vec2::new(offset as f32, 0.0),
                Vec2::new(offset as f32 + 64.0, 49.0),
            )),
            ..default()
        },
        Pickable::IGNORE,
        ChildOf(container),
    ));
    let (font, layout, line_height, _) = assets.text_style(RetailTextStylePreset::built(12, -1));
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(0x40),
            top: px(0x10),
            ..default()
        },
        Text::new(row.name.clone()),
        font,
        layout,
        line_height,
        // Windows COLORREF 0x1c474b is 0x00BBGGRR → R=0x4b, G=0x47, B=0x1c.
        TextColor(Color::srgb_u8(0x4b, 0x47, 0x1c)),
        Pickable::IGNORE,
        ChildOf(container),
    ));
    let level = row.stock_or_required;
    if level < 1 {
        let training = assets.get_string(0x273c, if level == -86 { 0x20 } else { 0x1f });
        let (font, layout, line_height, _) =
            assets.text_style(RetailTextStylePreset::explicit(1, 0, 12, -1));
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(0x43),
                top: px(0x1f),
                ..default()
            },
            Text::new(training),
            font,
            layout,
            line_height,
            Pickable::IGNORE,
            ChildOf(container),
        ));
    } else {
        let mut bucket = level / 0x19 + 1;
        if bucket > 0x14 {
            bucket = 0x14;
        }
        let row_y = if bucket < 5 {
            0x1a
        } else if bucket > 0xe {
            10
        } else {
            18
        };
        let width = bucket * 4;
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(0x43),
                top: px(0x1f),
                width: px(width),
                height: px(7),
                ..default()
            },
            ImageNode {
                image: detail.experience_strip.clone(),
                rect: Some(Rect::new(
                    0.0,
                    row_y as f32,
                    width as f32,
                    (row_y + 7) as f32,
                )),
                ..default()
            },
            Pickable::IGNORE,
            ChildOf(container),
        ));
    }
    let xp = row.strength_bucket;
    let mut bar_width = i32::from(xp) * 0xb;
    if xp % 100 > 0x31 {
        bar_width += 5;
    }
    if bar_width != 0 {
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(0x94),
                top: px(0x1f),
                width: px(bar_width),
                height: px(10),
                ..default()
            },
            ImageNode {
                image: detail.experience_strip.clone(),
                rect: Some(Rect::new(0.0, 0.0, bar_width as f32, 10.0)),
                ..default()
            },
            Pickable::IGNORE,
            ChildOf(container),
        ));
    }
}

fn spawn_navy_detail_row(
    commands: &mut Commands,
    assets: &mut super::RetailUiAssets,
    detail: &BattleReportDetailView,
    container: Entity,
    row: &BattleReportUnit,
) {
    let ship = match row.kind {
        BattleReportUnitKind::Ship(ship) => ship,
        _ => ShipType::NoShip,
    };
    let retail = usize::from(ship.retail());
    // SetState(1): ON frame sits 80px after the type's atlas base.
    let offset = i32::from(SHIP_ATLAS_OFFSETS.get(retail).copied().unwrap_or(0)) + 80;
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(0),
            top: px(0),
            width: px(80),
            height: px(45),
            ..default()
        },
        ImageNode {
            image: detail.navy_atlas.clone(),
            rect: Some(Rect::from_corners(
                Vec2::new(offset as f32, 0.0),
                Vec2::new(offset as f32 + 80.0, 45.0),
            )),
            ..default()
        },
        Pickable::IGNORE,
        ChildOf(container),
    ));
    let label = format!("{} {}", navy_type_name(assets, ship), row.name);
    // InitializeUiTextStyleDescriptor(2, 0xc, 0x2b6a, 3) → family 3, italic, 12pt.
    let (font, layout, line_height, _) =
        assets.text_style(RetailTextStylePreset::explicit(3, 2, 12, -1));
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(0x50),
            top: px(0x12),
            ..default()
        },
        Text::new(label),
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(0x5c)),
        Pickable::IGNORE,
        ChildOf(container),
    ));
    let level = row.stock_or_required;
    if level > 0 {
        let divisor = i32::from(ship_capabilities(ship).stock_capacity).max(1);
        let mut bucket = (i32::from(level) * 0x14) / divisor + 1;
        if bucket > 0x14 {
            bucket = 0x14;
        }
        let row_y = if bucket < 5 {
            0x1a
        } else if bucket > 0xe {
            10
        } else {
            18
        };
        let width = bucket * 4;
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(0x52),
                top: px(0x1e),
                width: px(width),
                height: px(7),
                ..default()
            },
            ImageNode {
                image: detail.experience_strip.clone(),
                rect: Some(Rect::new(
                    0.0,
                    row_y as f32,
                    width as f32,
                    (row_y + 7) as f32,
                )),
                ..default()
            },
            Pickable::IGNORE,
            ChildOf(container),
        ));
    } else {
        let training = assets.get_string(0x273c, 0x1b);
        let (font, layout, line_height, _) =
            assets.text_style(RetailTextStylePreset::explicit(1, 0, 12, -1));
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(0x52),
                top: px(0x1e),
                ..default()
            },
            Text::new(training),
            font,
            layout,
            line_height,
            Pickable::IGNORE,
            ChildOf(container),
        ));
    }
}

fn navy_type_name(assets: &super::RetailUiAssets, ship: ShipType) -> String {
    // TNavyBoyView slots 3,4,7,8,9,11,12,13 from group 0x2760; 12 and 13 share index 6.
    let index = match ship.retail() {
        3 => Some(0),
        4 => Some(1),
        7 => Some(2),
        8 => Some(3),
        9 => Some(4),
        11 => Some(5),
        12 | 13 => Some(6),
        _ => None,
    };
    index
        .map(|index| assets.get_string(0x2760, index as u16))
        .unwrap_or_default()
}

fn spawn_merchant_detail_row(
    commands: &mut Commands,
    assets: &mut super::RetailUiAssets,
    detail: &BattleReportDetailView,
    container: Entity,
    row: &BattleReportUnit,
) {
    let resource = match row.kind {
        BattleReportUnitKind::Resource(kind) => usize::from(kind.retail()),
        BattleReportUnitKind::Ship(ship) => usize::from(ship.retail()),
        _ => 0,
    };
    // SetState(0): OFF / base frame only (no +80 ON offset).
    let offset = i32::from(MERCHANT_ATLAS_SLOTS.get(resource).copied().unwrap_or(0)) * 0x50;
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(0),
            top: px(0),
            width: px(80),
            height: px(45),
            ..default()
        },
        ImageNode {
            image: detail.merc_atlas.clone(),
            rect: Some(Rect::from_corners(
                Vec2::new(offset as f32, 0.0),
                Vec2::new(offset as f32 + 80.0, 45.0),
            )),
            ..default()
        },
        Pickable::IGNORE,
        ChildOf(container),
    ));
    // FormatLocalizedCommodityCountLabelByIndex(count=-1): singular group, no number prefix.
    let commodity = assets.get_string(0x2716, resource as u16);
    let (font, layout, line_height, _) =
        assets.text_style(RetailTextStylePreset::explicit(3, 0, 12, -1));
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(0x50),
            top: px(0x10),
            ..default()
        },
        Text::new(commodity),
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(0x5c)),
        Pickable::IGNORE,
        ChildOf(container),
    ));
    let (status, palette) = if row.stock_or_required != 0 {
        // Theme 0x2b69 → palette 0xcb.
        (assets.get_string(0x273c, 0x1c), 0xcb)
    } else {
        // Theme 0x2b67 → palette 0.
        (assets.get_string(0x273c, 0x1b), 0)
    };
    let (font, layout, line_height, _) = assets.text_style(RetailTextStylePreset::built(12, -1));
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(0x50),
            top: px(0x1e),
            ..default()
        },
        Text::new(status),
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(palette)),
        Pickable::IGNORE,
        ChildOf(container),
    ));
}

/// Shared `TItemBoyView` / `TRuptBoyView` row: header + commodity icon strip.
/// When `state` is `Some`, uses the interruptus template with the nation from
/// `strength_bucket`.
fn spawn_item_detail_row(
    commands: &mut Commands,
    assets: &mut super::RetailUiAssets,
    container: Entity,
    row: &BattleReportUnit,
    state: Option<&GameState>,
) {
    let count = row.stock_or_required;
    let resource_type = report_unit_resource_type(row.kind);
    let kind_name = assets.get_string(0x2711, resource_type as u16);
    let count_text = count.to_string();
    let header = if let Some(state) = state {
        let nation_name = state
            .nation(NationId::new(row.strength_bucket as u8))
            .map(|nation| nation.display_name.as_str())
            .unwrap_or("");
        fill_brackets(
            &assets.get_string(0x273c, 0x1e),
            &[&count_text, &kind_name, nation_name],
        )
    } else {
        fill_brackets(&assets.get_string(0x273c, 0x1d), &[&count_text, &kind_name])
    };
    let (font, layout, line_height, _) = assets.text_style(RetailTextStylePreset::built(10, -1));
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(0x1a),
            top: px(0x0c),
            ..default()
        },
        Text::new(header),
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(0x5c)),
        Pickable::IGNORE,
        ChildOf(container),
    ));
    let icon_count = count.max(0) as usize;
    if icon_count == 0 {
        return;
    }
    let per_row = (0x20_i32).min(i32::from((236 - 0x3a) / count.max(1)));
    let icon = assets.keyed_picture(
        PictureId::new(COMMODITY_ICON_BASE + resource_type),
        KEYED_TRANSPARENT,
    );
    for index in 0..icon_count {
        let left = 0x1a + per_row * index as i32;
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(left),
                top: px(0x19),
                width: px(COMMODITY_ICON_WIDTH),
                height: px(0x17),
                ..default()
            },
            ImageNode {
                image: icon.clone(),
                rect: Some(Rect::from_corners(
                    Vec2::ZERO,
                    Vec2::new(COMMODITY_ICON_WIDTH, COMMODITY_ICON_HEIGHT),
                )),
                ..default()
            },
            Pickable::IGNORE,
            ChildOf(container),
        ));
    }
}

fn report_unit_resource_type(kind: BattleReportUnitKind) -> i16 {
    match kind {
        BattleReportUnitKind::Resource(resource) => i16::from(resource.retail()),
        BattleReportUnitKind::Ship(ship) => i16::from(ship.retail()),
        BattleReportUnitKind::Military(military) => i16::from(military.retail()),
    }
}

fn spawn_text_only_detail_row(
    commands: &mut Commands,
    assets: &mut super::RetailUiAssets,
    container: Entity,
    name: &str,
    left: i32,
) {
    let (font, layout, line_height, _) = assets.text_style(RetailTextStylePreset::built(10, 0));
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(left),
            top: px(0x12),
            ..default()
        },
        Text::new(name.to_owned()),
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(0xd2)),
        Pickable::IGNORE,
        ChildOf(container),
    ));
}

pub(crate) fn battle_report_texts_for_save(
    assets: Option<&super::RetailUiAssets>,
    session: &GameSession,
    captured: &[BattleReportText],
) -> Vec<BattleReportText> {
    session
        .game
        .battle_reports()
        .iter()
        .enumerate()
        .map(|(index, _)| battle_report_text(assets, session, captured, index))
        .collect()
}

/// Fill missing presentation entries so every live report has name/overlay
/// buffers before UI projection or save serialization.
fn ensure_battle_report_presentation(
    assets: &mut super::RetailUiAssets,
    session: &GameSession,
    captured: &mut Vec<BattleReportText>,
) {
    let count = session.game.battle_reports().len();
    if captured.len() >= count {
        return;
    }
    for index in captured.len()..count {
        captured.push(battle_report_text(Some(assets), session, captured, index));
    }
}

fn battle_report_text(
    assets: Option<&super::RetailUiAssets>,
    session: &GameSession,
    captured: &[BattleReportText],
    index: usize,
) -> BattleReportText {
    if let Some(text) = captured.get(index) {
        return text.clone();
    }
    let report = &session.game.battle_reports()[index];
    let Some(assets) = assets else {
        // Unit-test / asset-free save paths still emit one entry per report so
        // the legacy writer does not drop the parallel presentation slot.
        return BattleReportText::from_array([
            BattleReportSideText {
                name: session
                    .game
                    .nation(report.sides[BattleReportSideSlot::Left].nation)
                    .map(|nation| nation.display_name.clone())
                    .unwrap_or_default(),
                overlay: String::new(),
            },
            BattleReportSideText {
                name: session
                    .game
                    .nation(report.sides[BattleReportSideSlot::Right].nation)
                    .map(|nation| nation.display_name.clone())
                    .unwrap_or_default(),
                overlay: String::new(),
            },
        ]);
    };
    BattleReportText::from_array([
        generated_battle_report_side_text(
            assets,
            &session.game,
            report,
            BattleReportSideSlot::Left,
        ),
        generated_battle_report_side_text(
            assets,
            &session.game,
            report,
            BattleReportSideSlot::Right,
        ),
    ])
}

fn generated_battle_report_side_text(
    assets: &super::RetailUiAssets,
    state: &GameState,
    report: &BattleReport,
    slot: BattleReportSideSlot,
) -> BattleReportSideText {
    let side = &report.sides[slot];
    let nation_name = state
        .nation(side.nation)
        .map(|nation| nation.display_name.as_str())
        .unwrap_or("");
    if report.kind.is_land() {
        let template_index = if slot == BattleReportSideSlot::Left {
            0x10
        } else {
            0x11
        };
        let name = fill_brackets(&assets.get_string(0x273d, template_index), &[nation_name]);
        let overlay = generated_land_overlay(assets, side);
        return BattleReportSideText { name, overlay };
    }
    let name = nation_name.to_owned();
    let overlay = generated_sea_overlay(assets, state, report, side, nation_name);
    BattleReportSideText { name, overlay }
}

fn generated_land_overlay(assets: &super::RetailUiAssets, side: &BattleReportSide) -> String {
    let mut overlay = String::new();
    for kind_index in 0..MilitaryUnitKind::LENGTH {
        let kind = MilitaryUnitKind::from_index(kind_index as u8).expect("military kind index");
        let matching = side
            .children
            .iter()
            .filter(|row| row.kind == BattleReportUnitKind::Military(kind))
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        if !overlay.is_empty() {
            overlay.push_str(", ");
        }
        let unit_name = assets.get_string(0x2717, u16::from(kind.retail()));
        let active = matching
            .iter()
            .filter(|row| row.stock_or_required > 0)
            .count();
        let count = matching.len();
        let fragment = if active == count {
            fill_brackets("[1] [2]", &[&count.to_string(), &unit_name])
        } else {
            let inactive = assets.get_string(0x273d, 0xb);
            fill_brackets(
                "[1] [2] ([3] [4])",
                &[
                    &count.to_string(),
                    &unit_name,
                    &(count - active).to_string(),
                    &inactive,
                ],
            )
        };
        overlay.push_str(&fragment);
    }
    overlay
}

fn generated_sea_overlay(
    assets: &super::RetailUiAssets,
    state: &GameState,
    report: &BattleReport,
    side: &BattleReportSide,
    nation_name: &str,
) -> String {
    let child_count = side.children.len();
    let template = assets.ui_string(0x2762, u16::from(child_count != 1) + 0x11);
    let zone_name = match report.location {
        BattleReportLocation::Zone(id) => state
            .ocean()
            .zones
            .get(usize::from(id.get()))
            .map(|zone| zone.zone().display_name.as_str())
            .unwrap_or(""),
        BattleReportLocation::Province(_) => "",
    };
    let order_kind = assets.ui_string(
        0x2762,
        side.task_force_order
            .map(sea_overlay_order_string_index)
            .unwrap_or(0x13),
    );
    fill_brackets(
        &template,
        &[
            nation_name,
            zone_name,
            &child_count.to_string(),
            &order_kind,
        ],
    )
}

/// String-table index for a sea-side task-force order in group `0x2762`.
fn sea_overlay_order_string_index(order: TaskForceOrder) -> u16 {
    u16::try_from(order.get()).expect("task-force order fits u16") + 0x13
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::beginning_of_game;

    fn land_overlay_counts(side: &BattleReportSide) -> Vec<(MilitaryUnitKind, usize, usize)> {
        let mut counts = Vec::new();
        for kind_index in 0..MilitaryUnitKind::LENGTH {
            let kind = MilitaryUnitKind::from_index(kind_index as u8).expect("military kind index");
            let matching = side
                .children
                .iter()
                .filter(|row| row.kind == BattleReportUnitKind::Military(kind))
                .collect::<Vec<_>>();
            if matching.is_empty() {
                continue;
            }
            let active = matching
                .iter()
                .filter(|row| row.stock_or_required > 0)
                .count();
            counts.push((kind, matching.len(), matching.len() - active));
        }
        counts
    }

    #[test]
    fn battle_report_marker_spiral_matches_retail_placement_order() {
        let geometry = MapGeometry::new(MapTopology::Bounded);
        let mut crowd = vec![0u8; STRATEGIC_TILE_COUNT];
        assert_eq!(
            battle_report_marker_tile(geometry, TileId::new(1000), &mut crowd),
            TileId::new(1000)
        );
        assert_eq!(
            battle_report_marker_tile(geometry, TileId::new(1000), &mut crowd),
            TileId::new(1109)
        );
        let mut crowd = vec![0u8; STRATEGIC_TILE_COUNT];
        assert_eq!(
            battle_report_marker_tile(geometry, TileId::new(1000), &mut crowd),
            TileId::new(1000)
        );
        assert_eq!(
            battle_report_marker_tile(geometry, TileId::new(1001), &mut crowd),
            TileId::new(1110)
        );
        assert_eq!(
            battle_report_marker_tile(geometry, TileId::new(999), &mut crowd),
            TileId::new(996)
        );
    }

    #[test]
    fn battle_report_result_string_index_follows_retail_decision_tree() {
        let state = beginning_of_game();
        let active = state.turn().active_nation;
        let report = BattleReport {
            participant: Some(BattleReportSideSlot::Left),
            displayed_side: BattleReportSideSlot::Left,
            kind: BattleReportKind::LandBattle,
            location: BattleReportLocation::Province(ProvinceId::new(21)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation: active,
                    children: Vec::new(),
                    task_force_order: None,
                },
                BattleReportSide {
                    nation: NationId::new(0),
                    children: Vec::new(),
                    task_force_order: None,
                },
            ]),
        };
        assert_eq!(
            battle_report_result_string_index(&state, &report),
            (0x273d, 47)
        );
        // The enemy's capitol, won by that enemy while the active nation is the
        // displayed other side.
        let report = BattleReport {
            participant: Some(BattleReportSideSlot::Right),
            displayed_side: BattleReportSideSlot::Left,
            kind: BattleReportKind::LandBattle,
            location: BattleReportLocation::Province(ProvinceId::new(80)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation: active,
                    children: Vec::new(),
                    task_force_order: None,
                },
                BattleReportSide {
                    nation: NationId::new(0),
                    children: Vec::new(),
                    task_force_order: None,
                },
            ]),
        };
        assert_eq!(
            battle_report_result_string_index(&state, &report),
            (0x273d, 1)
        );
        // Sea-battle strings key off the winner/active relation alone.
        let report = BattleReport {
            participant: Some(BattleReportSideSlot::Left),
            displayed_side: BattleReportSideSlot::Left,
            kind: BattleReportKind::SeaBattle,
            location: BattleReportLocation::Zone(OceanZoneId::new(0)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation: active,
                    children: Vec::new(),
                    task_force_order: None,
                },
                BattleReportSide {
                    nation: NationId::new(0),
                    children: Vec::new(),
                    task_force_order: None,
                },
            ]),
        };
        assert_eq!(
            battle_report_result_string_index(&state, &report),
            (0x273c, 8)
        );
    }

    #[test]
    fn land_overlay_counts_preserve_retail_summary_order() {
        let side = BattleReportSide {
            nation: NationId::new(1),
            children: vec![
                BattleReportUnit {
                    kind: BattleReportUnitKind::Military(MilitaryUnitKind::Regulars),
                    stock_or_required: 100,
                    name: "1st Regulars".to_owned(),
                    strength_bucket: 1,
                    detail_identity: BATTLE_REPORT_ARMY_IDENTITY,
                },
                BattleReportUnit {
                    kind: BattleReportUnitKind::Military(MilitaryUnitKind::Regulars),
                    stock_or_required: 0,
                    name: "2nd Regulars".to_owned(),
                    strength_bucket: 1,
                    detail_identity: BATTLE_REPORT_ARMY_IDENTITY,
                },
            ],
            task_force_order: None,
        };
        assert_eq!(
            land_overlay_counts(&side),
            vec![(MilitaryUnitKind::Regulars, 2, 1)]
        );
    }

    #[test]
    fn detail_page_count_uses_six_rows_per_page() {
        let mut children = Vec::new();
        for index in 0..13 {
            children.push(BattleReportUnit {
                kind: BattleReportUnitKind::Military(MilitaryUnitKind::Regulars),
                stock_or_required: 100,
                name: format!("Unit {index}"),
                strength_bucket: 1,
                detail_identity: BATTLE_REPORT_ARMY_IDENTITY,
            });
        }
        let report = BattleReport {
            participant: Some(BattleReportSideSlot::Left),
            displayed_side: BattleReportSideSlot::Left,
            kind: BattleReportKind::LandBattle,
            location: BattleReportLocation::Province(ProvinceId::new(0)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation: NationId::new(1),
                    children,
                    task_force_order: None,
                },
                BattleReportSide {
                    nation: NationId::new(2),
                    children: Vec::new(),
                    task_force_order: None,
                },
            ]),
        };
        assert_eq!(detail_page_count(&report), 3);
    }

    #[test]
    fn sea_overlay_order_string_index_uses_task_force_order() {
        assert_eq!(sea_overlay_order_string_index(TaskForceOrder::None), 0x13);
        assert_eq!(sea_overlay_order_string_index(TaskForceOrder::Sail), 0x14);
        assert_eq!(sea_overlay_order_string_index(TaskForceOrder::Patrol), 0x16);
        assert_eq!(
            sea_overlay_order_string_index(TaskForceOrder::Blockade),
            0x19
        );
    }

    #[test]
    fn battle_report_tile_zone_prefers_target_tile() {
        let target = TileId::new(42);
        assert_eq!(zone_report_marker_tile(Some(target)), Some(target));
        assert_eq!(zone_report_marker_tile(None), None);
    }
}
