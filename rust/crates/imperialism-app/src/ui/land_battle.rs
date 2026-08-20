use super::RetailUiAssets;
use super::cursor::{RequestedCursor, request_arrow_cursor, request_turn_event_cursor};
use super::generated;
use super::hover_help::{
    HoverHelpBarStyle, HoverHelpText, bind_hover_help_bar, bind_hover_help_texts, ui_string,
};
use super::linger::{bind_linger_dialog, spawn_linger_dialog};
use super::retail::{RetailPictureSwap, RetailTree};
use super::session::{GameSession, apply_turn_stop};
use crate::AppState;
use crate::media::MusicDirector;
use bevy::picking::events::{Click, Pointer};
use bevy::picking::pointer::PointerButton;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui::RelativeCursorPosition;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use bevy::window::PrimaryWindow;
use imperialism_core::*;
use imperialism_formats::{MusicTrack, PictureId, SoundId, fourcc};

/// Retail setters 0x5a6830, 0x5a6860 and 0x5a6890.
const TACTICAL_TILE_WIDTH_PX: i32 = 0x32;
const TACTICAL_TILE_ROW_HEIGHT_PX: i32 = 0x1e;
const TACTICAL_SURFACE_WIDTH_PX: i32 = 0x5dc;
const TACTICAL_SURFACE_HEIGHT_PX: i32 = 0x1c2;
const TACTICAL_UNIT_CELL_PX: i32 = 0x32;
/// `TTacticalBattleView::ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset` grows the tile up by 0x14.
const UNIT_SPRITE_LIFT_PX: i32 = 0x14;
const BATTLEFIELD_WIDTH_PX: i32 = 575;
const BATTLEFIELD_HEIGHT_PX: i32 = 450;
const FORT_STRIP_WIDTH_PX: i32 = 0x11e;
const TACTICAL_COMPOSITION_PICTURE_BASE: i16 = 0xf0a;
const TACTICAL_FORT_STRIP_PICTURE: i16 = 0xf0e;
const TACTICAL_UNIT_ATLAS_PICTURE: i16 = 0xee2;
const TACTICAL_FORT_ATLAS_BASE: i16 = 0xee6;
const TACTICAL_NO_FORT_ATLAS_PICTURE: i16 = 0xee7;
const TACTICAL_EFFECT_ATLAS_PICTURE: i16 = 0xeeb;
const TACTICAL_EXPERIENCE_STRIP_PICTURE: i16 = 800;
const TACTICAL_UNIT_STATUS_ATLAS_PICTURE: i16 = 0x244;
const TACTICAL_TRANSPARENT_INDEX: u8 = 0x24;
const TACTICAL_FIRE_SFX: [u16; 30] = [
    0x3a98, 0x3a98, 0x3a98, 0x3a98, 0x3a99, 0x3a99, 0x3a9b, 0x3a9b, 0x3a98, 0x3a98, 0x3a98, 0x3a98,
    0x3a99, 0x3a99, 0x3a9b, 0x3a9b, 0x3aa6, 0x3aa6, 0x3aa6, 0x3a9c, 0x3aa6, 0x3a9a, 0x3a9b, 0x3a9b,
    0x3a9d, 0x3a9d, 0x3a9d, 0x3a98, 0x3a98, 0x3aa6,
];

/// Non-zero rows from retail `g_aTacticalUnitFacingOffsetTable[29][7][2]`.
const TACTICAL_UNIT_FACING_OFFSETS: [[[(i32, i32); 2]; 7]; 12] = [
    [
        [(7, 18), (7, 18)],
        [(0, 16), (0, 16)],
        [(2, 17), (2, 17)],
        [(-1, 17), (-1, 17)],
        [(7, 18), (7, 18)],
        [(6, 18), (6, 18)],
        [(6, 13), (6, 13)],
    ],
    [
        [(5, 16), (-4, 18)],
        [(6, 17), (-9, 18)],
        [(5, 13), (-11, 18)],
        [(0, 18), (-12, 18)],
        [(7, 16), (-4, 18)],
        [(5, 10), (-3, 15)],
        [(9, 13), (-6, 13)],
    ],
    [
        [(4, 18), (-2, 18)],
        [(2, 16), (-5, 17)],
        [(0, 16), (-7, 17)],
        [(-5, 17), (-10, 18)],
        [(3, 16), (-3, 18)],
        [(3, 16), (-4, 17)],
        [(3, 16), (-3, 17)],
    ],
    [
        [(11, 15), (-7, 17)],
        [(7, 15), (-9, 16)],
        [(5, 15), (-15, 16)],
        [(1, 15), (-15, 16)],
        [(8, 15), (-7, 16)],
        [(9, 15), (-8, 13)],
        [(10, 11), (-10, 11)],
    ],
    [
        [(6, 19), (6, 19)],
        [(2, 16), (2, 16)],
        [(0, 16), (0, 16)],
        [(-6, 20), (-6, 20)],
        [(3, 17), (3, 17)],
        [(5, 16), (5, 16)],
        [(3, 15), (3, 15)],
    ],
    [
        [(9, 15), (-2, 18)],
        [(5, 14), (-5, 16)],
        [(6, 13), (-6, 15)],
        [(1, 15), (-8, 18)],
        [(10, 15), (-3, 16)],
        [(10, 13), (-3, 15)],
        [(9, 14), (-4, 15)],
    ],
    [
        [(3, 18), (-3, 19)],
        [(1, 17), (-5, 18)],
        [(-1, 17), (-8, 17)],
        [(-4, 17), (-10, 19)],
        [(4, 17), (-3, 20)],
        [(5, 17), (-3, 18)],
        [(4, 16), (-4, 18)],
    ],
    [
        [(11, 16), (-3, 19)],
        [(8, 15), (-7, 16)],
        [(5, 14), (-8, 16)],
        [(0, 16), (-9, 19)],
        [(7, 15), (-2, 17)],
        [(12, 14), (0, 14)],
        [(8, 15), (-3, 13)],
    ],
    [
        [(4, 18), (1, 18)],
        [(2, 15), (-2, 16)],
        [(3, 15), (-5, 16)],
        [(-6, 16), (-7, 16)],
        [(6, 17), (0, 17)],
        [(3, 16), (2, 16)],
        [(4, 12), (-1, 16)],
    ],
    [
        [(4, 16), (2, 16)],
        [(-1, 15), (-3, 12)],
        [(-4, 14), (-6, 13)],
        [(-8, 17), (-8, 15)],
        [(2, 15), (3, 14)],
        [(3, 14), (-2, 13)],
        [(0, 13), (0, 13)],
    ],
    [
        [(4, 19), (0, 16)],
        [(2, 16), (-1, 15)],
        [(1, 15), (-5, 15)],
        [(-6, 18), (-5, 18)],
        [(5, 17), (3, 15)],
        [(3, 16), (0, 15)],
        [(3, 15), (0, 14)],
    ],
    [
        [(8, 14), (-6, 13)],
        [(3, 13), (-6, 12)],
        [(4, 13), (-9, 13)],
        [(0, 15), (-8, 13)],
        [(7, 14), (-5, 13)],
        [(6, 13), (-7, 13)],
        [(7, 9), (-6, 8)],
    ],
];

#[derive(Component)]
struct LandBattleRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum LandBattleAction {
    Help,
    Target,
    Done,
    Auto,
    Retreat,
}

#[derive(Component)]
struct LandBattlefield {
    battle: Option<PendingLandBattle>,
    view_origin_x: i32,
    centered_unit: Option<ArmyUnitId>,
    hovered_hex: Option<TacticalHex>,
    projected_origin_x: i32,
    projected_hover: Option<TacticalHex>,
}

#[derive(Component)]
struct LandBattleVisuals {
    composition_class: i32,
    backdrop: Handle<Image>,
    fort_strip: Handle<Image>,
    unit_atlas: Handle<Image>,
    fort_atlas: Handle<Image>,
    effect_atlas: Handle<Image>,
    experience_strip: Handle<Image>,
    unit_status_atlas: Handle<Image>,
    selection_color: Color,
    inset_color: Color,
    stat_background: Color,
    strength_color: Color,
    morale_color: Color,
    guide_primary: Color,
    guide_secondary: Color,
}

#[derive(Component)]
struct LandBattleBackdrop;

#[derive(Component)]
struct LandBattleFortStrip;

#[derive(Component)]
struct LandBattleTileOverlay;

#[derive(Component, Clone, Copy)]
#[allow(dead_code)]
struct LandBattleUnit(ArmyUnitId);

#[derive(Component, Clone, Copy)]
struct LandBattleHover;

#[derive(Component, Clone, Copy)]
enum LandBattleSelection {
    Blink(u128),
    Inset,
}

#[derive(Component, Clone, Copy)]
enum LandBattlePortrait {
    Current,
    Other,
}

#[derive(Component)]
struct LandBattleCoat;

#[derive(Component)]
struct LandBattleUnitStat;

#[derive(Component)]
struct LandBattleGuide;

#[derive(Component)]
struct LandBattleExperienceBar;

#[derive(Component)]
struct LandBattleRetreatPrompt;

#[derive(Component)]
struct LandBattleEffect {
    base_picture: i16,
    frame_count: u8,
    frame: u8,
    next_tick: u128,
}

#[derive(Component)]
struct LandBattleGlide {
    unit: ArmyUnitId,
    path: Vec<TacticalHex>,
    segment: usize,
    frame: u8,
    next_tick: u128,
}

#[derive(Component)]
struct LandBattleAnimationQueue {
    events: Vec<ArmyPresentationEvent>,
    next: usize,
}

#[derive(Component)]
struct LandBattleDeferredStop(TurnStop);

/// Pixel↔hex for this screen (`TTacticalBattleView` 0x5a86d0 / 0x5a87d0).
struct LandBattleHexMap {
    column_count: i32,
    view_origin_x: i32,
}

impl LandBattleHexMap {
    fn new(column_count: i32, view_origin_x: i32) -> Self {
        Self {
            column_count,
            view_origin_x,
        }
    }

    fn tile_rect(&self, hex: TacticalHex) -> (i32, i32, i32, i32) {
        let row = hex.row();
        let mut x = hex.column() * TACTICAL_TILE_WIDTH_PX - self.view_origin_x;
        if row & 1 != 0 {
            x += TACTICAL_TILE_WIDTH_PX / 2;
        }
        let y = row * TACTICAL_TILE_ROW_HEIGHT_PX;
        (x, y, TACTICAL_TILE_WIDTH_PX, TACTICAL_TILE_ROW_HEIGHT_PX)
    }

    fn unit_anchor(&self, hex: TacticalHex) -> (i32, i32, i32, i32) {
        let (x, y, width, height) = self.tile_rect(hex);
        (
            x,
            y - UNIT_SPRITE_LIFT_PX,
            width,
            height + UNIT_SPRITE_LIFT_PX,
        )
    }

    fn hex_at_pixel(&self, x: i32, y: i32) -> Option<TacticalHex> {
        let mut row = y / TACTICAL_TILE_ROW_HEIGHT_PX;
        if row < 0 {
            row = 0;
        }
        let max_row = BATTLEFIELD_HEIGHT_PX / TACTICAL_TILE_ROW_HEIGHT_PX - 1;
        if row >= max_row {
            row = max_row;
        }
        let mut col = self.view_origin_x + x;
        if row & 1 != 0 {
            col -= TACTICAL_TILE_WIDTH_PX / 2;
        }
        col /= TACTICAL_TILE_WIDTH_PX;
        if col < 0 {
            col = 0;
        }
        if col >= self.column_count {
            col = self.column_count - 1;
        }
        TacticalHex::from_row_column(row, col)
    }
}

fn battlefield_cursor_pixel(cursor: &RelativeCursorPosition) -> Option<(i32, i32)> {
    let position = cursor.normalized.filter(|_| cursor.cursor_over())?;
    Some((
        ((position.x + 0.5) * BATTLEFIELD_WIDTH_PX as f32).floor() as i32,
        ((position.y + 0.5) * BATTLEFIELD_HEIGHT_PX as f32).floor() as i32,
    ))
}

pub(crate) struct LandBattlePlugin;

impl Plugin for LandBattlePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::LandBattle),
            (
                spawn_land_battle,
                bind_land_battle,
                load_land_battle_visuals,
            )
                .chain(),
        )
        .add_systems(
            Update,
            (
                synchronize_interactive_army_battle,
                bind_land_battle_retreat_prompt,
                synchronize_land_battle_visuals,
                scroll_land_battle,
                track_land_battle_hover,
                project_land_battle,
                project_land_battle_toolbar,
                animate_land_battle_selection,
                animate_land_battle_actions,
                land_battle_keyboard,
            )
                .chain()
                .run_if(in_state(AppState::LandBattle).and_then(resource_exists::<GameSession>)),
        )
        .add_systems(OnExit(AppState::LandBattle), reset_land_battle_cursor);
    }
}

fn reset_land_battle_cursor(mut requested: ResMut<RequestedCursor>) {
    request_arrow_cursor(&mut requested);
}

fn synchronize_interactive_army_battle(
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    assets: Option<Res<crate::RetailAssetsResource>>,
    mut fields: Query<(Entity, &mut LandBattlefield)>,
    mut commands: Commands,
) {
    if session.game.pending_land_battle().is_some()
        && session.game.army_battle().is_none()
        && let Some(progress) = session
            .game
            .synchronize_army_battle(super::session::news_story_ids(assets.as_deref()))
        && let Ok((field, mut view)) = fields.single_mut()
    {
        queue_land_battle_progress(&mut commands, field, &mut view, progress, &mut next_state);
    }
}

fn spawn_land_battle(mut commands: Commands) {
    let root = commands.spawn_scene(generated::tactical_3800()).id();
    commands
        .entity(root)
        .insert((LandBattleRoot, DespawnOnExit(AppState::LandBattle)));
}

fn bind_land_battle(
    mut commands: Commands,
    root: Single<Entity, Added<LandBattleRoot>>,
    tree: RetailTree,
    mut nodes: Query<&mut Node>,
    mut assets: RetailUiAssets,
) {
    bind_land_battle_controls(&mut commands, *root, &tree);
    let curs = tree.find(*root, fourcc!("curs"));
    bind_hover_help_bar(
        &mut commands,
        &mut assets,
        curs,
        &mut nodes
            .get_mut(curs)
            .expect("tactical hover-help bar has Node"),
        HoverHelpBarStyle::TACTICAL,
    );
    bind_hover_help_texts(
        &mut commands,
        *root,
        &tree,
        [
            (fourcc!("help"), ui_string(&assets, 0x273d, 0x20)),
            (fourcc!("targ"), ui_string(&assets, 0x273d, 0x21)),
            (fourcc!("done"), ui_string(&assets, 0x273d, 0x22)),
            (fourcc!("retr"), ui_string(&assets, 0x273d, 0x23)),
            (fourcc!("auto"), ui_string(&assets, 0x273d, 0x24)),
            (fourcc!("DLOG"), String::new()),
        ],
    );
}

fn bind_land_battle_controls(commands: &mut Commands, root: Entity, tree: &RetailTree) {
    for (tag, action) in [
        (fourcc!("help"), LandBattleAction::Help),
        (fourcc!("targ"), LandBattleAction::Target),
        (fourcc!("done"), LandBattleAction::Done),
        (fourcc!("auto"), LandBattleAction::Auto),
        (fourcc!("retr"), LandBattleAction::Retreat),
    ] {
        commands
            .entity(tree.find(root, tag))
            .insert((action, ActivateOnPress))
            .observe(on_land_battle_activate)
            .remove::<InteractionDisabled>();
    }
    commands
        .entity(tree.find(root, fourcc!("coat")))
        .insert(LandBattleCoat);
    commands
        .entity(tree.find(root, fourcc!("curr")))
        .insert(LandBattlePortrait::Current);
    commands
        .entity(tree.find(root, fourcc!("tpic")))
        .insert(LandBattlePortrait::Other);
    let field = tree.find(root, fourcc!("DLOG"));
    commands
        .entity(field)
        .insert((
            LandBattlefield {
                battle: None,
                view_origin_x: 0,
                centered_unit: None,
                hovered_hex: None,
                projected_origin_x: -1,
                projected_hover: None,
            },
            RelativeCursorPosition::default(),
        ))
        .observe(on_battlefield_click);
    commands
        .entity(field)
        .entry::<Node>()
        .and_modify(|mut node| node.overflow = Overflow::clip());
}

fn bind_land_battle_retreat_prompt(
    mut commands: Commands,
    prompts: Query<Entity, Added<LandBattleRetreatPrompt>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    for root in &prompts {
        let linger = bind_linger_dialog(&mut commands, root, &tree);
        let body = ui_string(&assets, 0x273d, 0x32);
        linger.set_body(&mut commands, &mut assets, body);
        commands
            .entity(linger.okay)
            .remove::<InteractionDisabled>()
            .observe(on_confirm_land_battle_retreat);
        commands
            .entity(linger.cancel)
            .remove::<InteractionDisabled>();
    }
}

fn on_confirm_land_battle_retreat(
    _activate: On<Activate>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    assets: Option<Res<crate::RetailAssetsResource>>,
    mut fields: Query<(Entity, &mut LandBattlefield)>,
    mut commands: Commands,
) {
    let Ok(progress) = session
        .game
        .retreat_from_army_battle(super::session::news_story_ids(assets.as_deref()))
    else {
        return;
    };
    if let Ok((field, mut view)) = fields.single_mut() {
        queue_land_battle_progress(&mut commands, field, &mut view, progress, &mut next_state);
    }
}

fn load_land_battle_visuals(
    mut commands: Commands,
    session: Res<GameSession>,
    fields: Query<Entity, Added<LandBattlefield>>,
    mut assets: RetailUiAssets,
) {
    let Some(battle) = session.game.army_battle() else {
        return;
    };
    for field in &fields {
        insert_land_battle_visuals(&mut commands, field, battle, &mut assets);
    }
}

fn synchronize_land_battle_visuals(
    mut commands: Commands,
    session: Res<GameSession>,
    fields: Query<(Entity, Option<&LandBattleVisuals>), With<LandBattlefield>>,
    mut assets: RetailUiAssets,
) {
    let Some(battle) = session.game.army_battle() else {
        return;
    };
    for (field, visuals) in &fields {
        if visuals.is_none_or(|visuals| visuals.composition_class != battle.composition_class()) {
            insert_land_battle_visuals(&mut commands, field, battle, &mut assets);
        }
    }
}

fn insert_land_battle_visuals(
    commands: &mut Commands,
    field: Entity,
    battle: &ArmyBattle,
    assets: &mut RetailUiAssets,
) {
    let composition_class = battle.composition_class();
    let picture = i16::try_from(composition_class)
        .expect("retail tactical composition class fits i16")
        + TACTICAL_COMPOSITION_PICTURE_BASE;
    let visuals = LandBattleVisuals {
        composition_class,
        backdrop: assets
            .picture(PictureId::new(picture))
            .expect("retail tactical composition backdrop must load"),
        fort_strip: assets
            .picture(PictureId::new(TACTICAL_FORT_STRIP_PICTURE))
            .expect("retail tactical fort strip must load"),
        unit_atlas: assets
            .transparent_picture(
                PictureId::new(TACTICAL_UNIT_ATLAS_PICTURE),
                TACTICAL_TRANSPARENT_INDEX,
            )
            .expect("retail tactical unit atlas must load"),
        fort_atlas: assets
            .transparent_picture(
                PictureId::new(if battle.fort_level() == FortLevel::None {
                    TACTICAL_NO_FORT_ATLAS_PICTURE
                } else {
                    TACTICAL_FORT_ATLAS_BASE + i16::from(battle.fort_level().retail())
                }),
                TACTICAL_TRANSPARENT_INDEX,
            )
            .expect("retail tactical fort atlas must load"),
        effect_atlas: assets
            .transparent_picture(
                PictureId::new(TACTICAL_EFFECT_ATLAS_PICTURE),
                TACTICAL_TRANSPARENT_INDEX,
            )
            .expect("retail tactical effect atlas must load"),
        experience_strip: assets
            .transparent_picture(
                PictureId::new(TACTICAL_EXPERIENCE_STRIP_PICTURE),
                TACTICAL_TRANSPARENT_INDEX,
            )
            .expect("retail tactical experience strip must load"),
        unit_status_atlas: assets
            .transparent_picture(PictureId::new(TACTICAL_UNIT_STATUS_ATLAS_PICTURE), 0)
            .expect("retail tactical unit-status atlas must load"),
        selection_color: assets.palette_color(0x13),
        inset_color: assets.palette_color(0),
        stat_background: assets.palette_color(0x33),
        strength_color: assets.palette_color(6),
        morale_color: assets.palette_color(0x34),
        guide_primary: assets.palette_color(0x35),
        guide_secondary: assets.palette_color(0x34),
    };
    commands.entity(field).insert(visuals);
}

fn track_land_battle_hover(
    session: Res<GameSession>,
    mut fields: Query<(&RelativeCursorPosition, &mut LandBattlefield)>,
    mut requested: ResMut<RequestedCursor>,
) {
    let Some(battle) = session.game.army_battle() else {
        request_arrow_cursor(&mut requested);
        return;
    };
    let mut cursor_set = false;
    for (cursor, mut view) in &mut fields {
        let hovered = battlefield_cursor_pixel(cursor).and_then(|(x, y)| {
            LandBattleHexMap::new(battle.column_count(), view.view_origin_x).hex_at_pixel(x, y)
        });
        if view.hovered_hex != hovered {
            view.hovered_hex = hovered;
        }
        if let Some(resource) = hovered
            .and_then(|hex| battle.hover_cursor_resource_id(hex, session.game.turn().active_nation))
        {
            request_turn_event_cursor(&mut requested, resource);
            cursor_set = true;
        }
    }
    if !cursor_set {
        request_arrow_cursor(&mut requested);
    }
}

#[allow(clippy::type_complexity)]
fn project_land_battle(
    mut commands: Commands,
    time: Res<Time>,
    session: Res<GameSession>,
    mut battlefields: Query<(
        Entity,
        &mut LandBattlefield,
        Option<&LandBattleVisuals>,
        Option<&Children>,
    )>,
    projected: Query<
        Entity,
        Or<(
            With<LandBattleBackdrop>,
            With<LandBattleFortStrip>,
            With<LandBattleTileOverlay>,
            With<LandBattleUnit>,
            With<LandBattleHover>,
            With<LandBattleSelection>,
            With<LandBattleUnitStat>,
            With<LandBattleGuide>,
        )>,
    >,
    glides: Query<&LandBattleGlide>,
) {
    let Some(pending) = session.game.pending_land_battle() else {
        return;
    };
    let selected = session.game.selected_army_unit().map(|unit| unit.id);
    let reachable_hexes = session.game.selected_army_unit_reachable_hexes();
    let Some(battle) = session.game.army_battle() else {
        return;
    };
    for (field, mut view, visuals, children) in &mut battlefields {
        if view.battle.as_ref() != Some(pending) {
            view.battle = Some(pending.clone());
            view.view_origin_x = 0;
            view.centered_unit = None;
            view.projected_origin_x = -1;
            view.projected_hover = None;
        }
        if view.centered_unit != selected {
            if let Some(unit) = selected.and_then(|id| battle.unit(id))
                && let Some(hex) = unit.hex
            {
                view.view_origin_x =
                    centered_view_origin(view.view_origin_x, battle.column_count(), hex);
            }
            view.centered_unit = selected;
        }
        if !session.is_changed()
            && view.projected_origin_x == view.view_origin_x
            && view.projected_hover == view.hovered_hex
        {
            continue;
        }
        view.projected_origin_x = view.view_origin_x;
        view.projected_hover = view.hovered_hex;
        let hex_map = LandBattleHexMap::new(battle.column_count(), view.view_origin_x);
        if let Some(children) = children {
            for child in children.iter() {
                if projected.contains(child) {
                    commands.entity(child).despawn();
                }
            }
        }
        if let Some(visuals) = visuals {
            let source_offset = (TacticalHex::COLUMNS - battle.column_count())
                * TACTICAL_TILE_WIDTH_PX
                + view.view_origin_x;
            commands.spawn((
                LandBattleBackdrop,
                ChildOf(field),
                Node {
                    position_type: PositionType::Absolute,
                    left: px(-source_offset),
                    top: px(0),
                    width: px(TACTICAL_SURFACE_WIDTH_PX),
                    height: px(TACTICAL_SURFACE_HEIGHT_PX),
                    ..default()
                },
                ImageNode::new(visuals.backdrop.clone()),
                Pickable::IGNORE,
                ZIndex(-2),
            ));
            if battle.fort_level() != FortLevel::None {
                commands.spawn((
                    LandBattleFortStrip,
                    ChildOf(field),
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(TACTICAL_SURFACE_WIDTH_PX - FORT_STRIP_WIDTH_PX - source_offset),
                        top: px(0),
                        width: px(FORT_STRIP_WIDTH_PX),
                        height: px(TACTICAL_SURFACE_HEIGHT_PX),
                        ..default()
                    },
                    ImageNode::new(visuals.fort_strip.clone()),
                    Pickable::IGNORE,
                    ZIndex(-1),
                ));
            }
            project_tile_atlases(&mut commands, field, battle, &hex_map, visuals);
        }
        if let Some(hex) = view.hovered_hex {
            spawn_hex_outline(
                &mut commands,
                field,
                &hex_map,
                hex,
                LandBattleHover,
                Color::WHITE,
                5,
            );
        }
        let tiles: Vec<_> = battle.tiles().collect();
        if battle.stage() == ArmyBattleStage::Deploying {
            let colors = visuals.map_or([Color::WHITE, Color::BLACK], |visuals| {
                [visuals.guide_primary, visuals.guide_secondary]
            });
            for &hex in &reachable_hexes {
                if hex.row() > 0 && !tiles[hex.index() as usize].occupied {
                    spawn_deployment_guide(&mut commands, field, &hex_map, hex, colors);
                }
            }
        }
        for &hex in &reachable_hexes {
            let tile = tiles[hex.index() as usize];
            spawn_move_guide(
                &mut commands,
                field,
                &hex_map,
                hex,
                battle.active_side(),
                battle.column_count(),
                tile.threatened,
                visuals.map_or(
                    [Color::BLACK, Color::WHITE, Color::BLACK, Color::BLACK],
                    |visuals| {
                        [
                            visuals.inset_color,
                            visuals.selection_color,
                            visuals.morale_color,
                            visuals.stat_background,
                        ]
                    },
                ),
            );
        }
        for unit in battle.units() {
            if glides.iter().any(|glide| glide.unit == unit.id) {
                continue;
            }
            let Some(hex) = unit.hex else {
                continue;
            };
            let (mut x, mut y, width, height) = hex_map.unit_anchor(hex);
            let selected = selected == Some(unit.id);
            if selected {
                spawn_hex_outline(
                    &mut commands,
                    field,
                    &hex_map,
                    hex,
                    LandBattleSelection::Blink(time.elapsed().as_millis()),
                    visuals.map_or(Color::WHITE, |visuals| visuals.selection_color),
                    3,
                );
                spawn_hex_outline(
                    &mut commands,
                    field,
                    &hex_map,
                    hex,
                    LandBattleSelection::Inset,
                    visuals.map_or(Color::BLACK, |visuals| visuals.inset_color),
                    4,
                );
            }
            spawn_unit_stat_bars(
                &mut commands,
                field,
                &hex_map,
                unit,
                visuals.map_or(
                    [
                        Color::BLACK,
                        Color::srgb(0.0, 0.7, 0.0),
                        Color::srgb(0.8, 0.7, 0.0),
                    ],
                    |visuals| {
                        [
                            visuals.stat_background,
                            visuals.strength_color,
                            visuals.morale_color,
                        ]
                    },
                ),
            );
            if let Some(visuals) = visuals {
                spawn_unit_status_flag(&mut commands, field, &hex_map, unit, visuals);
            }
            if (24..=26).contains(&unit.unit_type.retail())
                && tiles[hex.index() as usize].trench_mask != 0
            {
                continue;
            }
            if tiles[hex.index() as usize].unit_cover {
                let orientation = tactical_unit_orientation(&tiles, hex);
                let (dx, dy) = tactical_unit_facing_offset(unit, orientation);
                x += dx;
                y += dy;
            }
            let mut entity = commands.spawn((
                LandBattleUnit(unit.id),
                ChildOf(field),
                Node {
                    position_type: PositionType::Absolute,
                    left: px(x),
                    top: px(y),
                    width: px(width),
                    height: px(height),
                    ..default()
                },
                Pickable::IGNORE,
                ZIndex(2),
            ));
            if let Some(visuals) = visuals {
                let source = Vec2::new(
                    f32::from(unit.unit_type.retail()) * TACTICAL_UNIT_CELL_PX as f32,
                    match unit.side {
                        BattleSide::Attacker => 0.0,
                        BattleSide::Defender => TACTICAL_UNIT_CELL_PX as f32,
                    },
                );
                entity.insert(ImageNode {
                    image: visuals.unit_atlas.clone(),
                    rect: Some(Rect::from_corners(
                        source,
                        source + Vec2::splat(TACTICAL_UNIT_CELL_PX as f32),
                    )),
                    ..default()
                });
            }
        }
    }
}

fn tactical_unit_orientation(tiles: &[ArmyTileView], hex: TacticalHex) -> usize {
    const ORIENTATION: [usize; 8] = [6, 3, 5, 1, 6, 0, 2, 4];
    let neighbors = tactical_neighbors(hex.index());
    let covered = |index: i32| {
        usize::try_from(index)
            .ok()
            .and_then(|index| tiles.get(index))
            .is_some_and(|tile| tile.unit_cover)
    };
    let code = if hex.row() & 1 != 0 {
        usize::from(covered(neighbors[5])) * 2 + usize::from(covered(neighbors[3]))
    } else {
        4 + usize::from(covered(neighbors[0])) * 2 + usize::from(covered(neighbors[2]))
    };
    ORIENTATION[code]
}

fn tactical_unit_facing_offset(unit: ArmyUnitView, orientation: usize) -> (i32, i32) {
    let unit_type = unit.unit_type.retail();
    let row = match unit_type {
        0..=3 => unit_type,
        8..=11 => unit_type - 4,
        16..=19 => unit_type - 8,
        _ => return (0, 0),
    } as usize;
    let side = match unit.side {
        BattleSide::Attacker => 0,
        BattleSide::Defender => 1,
    };
    TACTICAL_UNIT_FACING_OFFSETS[row][orientation][side]
}

fn tactical_neighbors(tile: i32) -> [i32; 6] {
    let mut neighbors = if (tile / TacticalHex::COLUMNS) & 1 != 0 {
        [
            tile - TacticalHex::COLUMNS + 1,
            tile + 1,
            tile + TacticalHex::COLUMNS + 1,
            tile + TacticalHex::COLUMNS,
            tile - 1,
            tile - TacticalHex::COLUMNS,
        ]
    } else {
        [
            tile - TacticalHex::COLUMNS,
            tile + 1,
            tile + TacticalHex::COLUMNS,
            tile + TacticalHex::COLUMNS - 1,
            tile - 1,
            tile - TacticalHex::COLUMNS - 1,
        ]
    };
    if (tile + 1) % TacticalHex::COLUMNS == 0 {
        neighbors[1] = -1;
        if (tile / TacticalHex::COLUMNS) & 1 != 0 {
            neighbors[0] = -1;
            neighbors[2] = -1;
        }
    } else if tile % TacticalHex::COLUMNS == 0 {
        neighbors[4] = -1;
        if (tile / TacticalHex::COLUMNS) & 1 == 0 {
            neighbors[3] = -1;
            neighbors[5] = -1;
        }
    }
    for neighbor in &mut neighbors {
        if *neighbor < 0 || *neighbor >= TacticalHex::COLUMNS * TacticalHex::ROWS {
            *neighbor = -1;
        }
    }
    neighbors
}

fn spawn_hex_outline<M: Component + Copy>(
    commands: &mut Commands,
    field: Entity,
    map: &LandBattleHexMap,
    hex: TacticalHex,
    marker: M,
    color: Color,
    inset: i32,
) {
    let (x, y, width, height) = map.tile_rect(hex);
    let left = x + inset;
    let top = y + inset;
    let right = x + width - inset - 1;
    let bottom = y + height - inset - 1;
    for (line_x, line_y, line_width, line_height) in [
        (left, top, 6, 1),
        (left, top, 1, 6),
        (right - 5, top, 6, 1),
        (right, top, 1, 6),
        (left, bottom, 6, 1),
        (left, bottom - 5, 1, 6),
        (right - 5, bottom, 6, 1),
        (right, bottom - 5, 1, 6),
    ] {
        commands.spawn((
            marker,
            ChildOf(field),
            Node {
                position_type: PositionType::Absolute,
                left: px(line_x),
                top: px(line_y),
                width: px(line_width),
                height: px(line_height),
                ..default()
            },
            BackgroundColor(color),
            Pickable::IGNORE,
            ZIndex(4),
        ));
    }
}

fn animate_land_battle_selection(
    time: Res<Time>,
    visuals: Query<&LandBattleVisuals>,
    mut lines: Query<(&LandBattleSelection, &mut BackgroundColor)>,
) {
    let Ok(visuals) = visuals.single() else {
        return;
    };
    let now = time.elapsed().as_millis();
    for (line, mut color) in &mut lines {
        color.0 = match line {
            LandBattleSelection::Blink(start) if ((now - start) / 160) & 1 == 0 => {
                visuals.selection_color
            }
            LandBattleSelection::Blink(_) | LandBattleSelection::Inset => visuals.inset_color,
        };
    }
}

fn spawn_deployment_guide(
    commands: &mut Commands,
    field: Entity,
    map: &LandBattleHexMap,
    hex: TacticalHex,
    colors: [Color; 2],
) {
    let (x, y, width, height) = map.tile_rect(hex);
    let center_x = x + width / 2;
    let center_y = y + height / 2;
    for (left, top, width, color) in [
        (center_x - 2, center_y, 5, colors[0]),
        (center_x - 1, center_y + 1, 3, colors[0]),
        (center_x - 1, center_y - 1, 3, colors[1]),
        (center_x - 1, center_y, 3, colors[1]),
    ] {
        commands.spawn((
            LandBattleGuide,
            ChildOf(field),
            Node {
                position_type: PositionType::Absolute,
                left: px(left),
                top: px(top),
                width: px(width),
                height: px(1),
                ..default()
            },
            BackgroundColor(color),
            Pickable::IGNORE,
            ZIndex(3),
        ));
    }
}

fn spawn_move_guide(
    commands: &mut Commands,
    field: Entity,
    map: &LandBattleHexMap,
    hex: TacticalHex,
    side: BattleSide,
    column_count: i32,
    threatened: bool,
    colors: [Color; 4],
) {
    let (x, y, width, height) = map.tile_rect(hex);
    let center_x = x + width / 2;
    let center_y = y + height / 2;
    let accent = if (hex.row() < 2 && side == BattleSide::Attacker)
        || (hex.column() == column_count - 1 && side == BattleSide::Defender)
    {
        colors[1]
    } else if threatened {
        colors[3]
    } else {
        colors[2]
    };
    for (left, top, width, color) in [
        (center_x - 2, center_y, 5, colors[0]),
        (center_x - 1, center_y + 1, 3, colors[0]),
        (center_x - 1, center_y - 1, 3, accent),
        (center_x - 1, center_y, 3, accent),
    ] {
        commands.spawn((
            LandBattleGuide,
            ChildOf(field),
            Node {
                position_type: PositionType::Absolute,
                left: px(left),
                top: px(top),
                width: px(width),
                height: px(1),
                ..default()
            },
            BackgroundColor(color),
            Pickable::IGNORE,
            ZIndex(3),
        ));
    }
}

fn spawn_tactical_effect(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    field: Entity,
    map: &LandBattleHexMap,
    target: TacticalHex,
    base_picture: i16,
    frame_count: u8,
    now: u128,
    unit_sized: bool,
) {
    let (x, y, width, height) = if unit_sized {
        map.unit_anchor(target)
    } else {
        map.tile_rect(target)
    };
    let image = assets
        .transparent_picture(PictureId::new(base_picture), TACTICAL_TRANSPARENT_INDEX)
        .expect("retail tactical effect frame");
    commands.spawn((
        LandBattleEffect {
            base_picture,
            frame_count,
            frame: 0,
            next_tick: now + 32,
        },
        ChildOf(field),
        Node {
            position_type: PositionType::Absolute,
            left: px(x),
            top: px(y),
            width: px(width),
            height: px(height),
            ..default()
        },
        ImageNode::new(image),
        Pickable::IGNORE,
        ZIndex(6),
    ));
}

fn spawn_tactical_glide(
    commands: &mut Commands,
    field: Entity,
    map: &LandBattleHexMap,
    visuals: &LandBattleVisuals,
    moved: &MoveResult,
    unit_type: MilitaryUnitKind,
    now: u128,
) -> bool {
    if moved.path.len() < 2 {
        return false;
    }
    let (x, y, width, height) = map.unit_anchor(moved.path[0]);
    let moving_right = tactical_half_column(moved.path[0]) < tactical_half_column(moved.path[1]);
    let source = Vec2::new(
        f32::from(unit_type.retail()) * TACTICAL_UNIT_CELL_PX as f32,
        if moving_right {
            0.0
        } else {
            TACTICAL_UNIT_CELL_PX as f32
        },
    );
    commands.spawn((
        LandBattleGlide {
            unit: moved.unit,
            path: moved.path.clone(),
            segment: 0,
            frame: 0,
            next_tick: now + 32,
        },
        ChildOf(field),
        Node {
            position_type: PositionType::Absolute,
            left: px(x),
            top: px(y - 4),
            width: px(width),
            height: px(height),
            ..default()
        },
        ImageNode {
            image: visuals.unit_atlas.clone(),
            rect: Some(Rect::from_corners(
                source,
                source + Vec2::splat(TACTICAL_UNIT_CELL_PX as f32),
            )),
            ..default()
        },
        Pickable::IGNORE,
        ZIndex(6),
    ));
    true
}

fn tactical_half_column(hex: TacticalHex) -> i32 {
    hex.column() * 2 + (hex.row() & 1)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn animate_land_battle_actions(
    time: Res<Time>,
    mut commands: Commands,
    mut effects: Query<(Entity, &mut LandBattleEffect, &mut ImageNode), Without<LandBattleGlide>>,
    mut glides: Query<
        (Entity, &mut LandBattleGlide, &mut Node, &mut ImageNode),
        Without<LandBattleEffect>,
    >,
    mut fields: Query<(
        Entity,
        &mut LandBattlefield,
        &LandBattleVisuals,
        Option<&mut LandBattleAnimationQueue>,
        Option<&LandBattleDeferredStop>,
    )>,
    mut next_state: ResMut<NextState<AppState>>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    preferences: Res<super::GamePreferences>,
    mut audio: crate::media::RetailAudioAssets,
) {
    let now = time.elapsed().as_millis();
    for (entity, mut effect, mut image) in &mut effects {
        if now < effect.next_tick {
            continue;
        }
        effect.frame += 1;
        effect.next_tick += 32;
        if effect.frame >= effect.frame_count {
            commands.entity(entity).despawn();
            continue;
        }
        image.image = assets
            .transparent_picture(
                PictureId::new(effect.base_picture + i16::from(effect.frame)),
                TACTICAL_TRANSPARENT_INDEX,
            )
            .expect("retail tactical effect frame");
    }
    let Ok((field_entity, mut field, visuals, queue, deferred)) = fields.single_mut() else {
        return;
    };
    let column_count = session
        .game
        .army_battle()
        .map_or(TacticalHex::COLUMNS, ArmyBattle::column_count);
    let map = LandBattleHexMap::new(column_count, field.view_origin_x);
    for (entity, mut glide, mut node, mut image) in &mut glides {
        if now < glide.next_tick {
            continue;
        }
        glide.next_tick += 32;
        if glide.frame < 3 {
            glide.frame += 1;
        } else {
            glide.segment += 1;
            glide.frame = 0;
            if glide.segment + 1 >= glide.path.len() {
                commands.entity(entity).despawn();
                field.projected_origin_x = -1;
                continue;
            }
            let moving_right = tactical_half_column(glide.path[glide.segment])
                < tactical_half_column(glide.path[glide.segment + 1]);
            if let Some(rect) = image.rect.as_mut() {
                let top = if moving_right {
                    0.0
                } else {
                    TACTICAL_UNIT_CELL_PX as f32
                };
                rect.min.y = top;
                rect.max.y = top + TACTICAL_UNIT_CELL_PX as f32;
            }
        }
        let (from_x, from_y, _, _) = map.unit_anchor(glide.path[glide.segment]);
        let (to_x, to_y, _, _) = map.unit_anchor(glide.path[glide.segment + 1]);
        let frame = f32::from(glide.frame) / 3.0;
        node.left = px(from_x as f32 + (to_x - from_x) as f32 * frame);
        node.top = px(from_y as f32 + (to_y - from_y) as f32 * frame - 4.0);
    }
    if !effects.is_empty() || !glides.is_empty() {
        return;
    }
    if let Some(mut queue) = queue {
        while let Some(event) = queue.events.get(queue.next).copied() {
            queue.next += 1;
            match event {
                ArmyPresentationEvent::Move { unit, from, to } => {
                    if !preferences.tactical_movement_animations_enabled() {
                        continue;
                    }
                    let Some(unit_type) = session
                        .game
                        .military_unit(unit.source())
                        .map(MilitaryUnitState::unit_type)
                    else {
                        continue;
                    };
                    let moved = MoveResult {
                        unit,
                        from,
                        to,
                        path: vec![from, to],
                    };
                    spawn_tactical_glide(
                        &mut commands,
                        field_entity,
                        &map,
                        visuals,
                        &moved,
                        unit_type,
                        now,
                    );
                    return;
                }
                ArmyPresentationEvent::Attack {
                    attacker,
                    target,
                    fort_target,
                } => {
                    let unit_type = session
                        .game
                        .military_unit(attacker.source())
                        .map_or(MilitaryUnitKind::Minutemen, MilitaryUnitState::unit_type);
                    audio.play(
                        &mut commands,
                        SoundId::new(TACTICAL_FIRE_SFX[unit_type.retail() as usize]),
                    );
                    let (base, frames) = if fort_target {
                        (0xf98, 6)
                    } else if matches!(unit_type.retail(), 6 | 7 | 14 | 15 | 21 | 22 | 23) {
                        (0xf6e, 6)
                    } else {
                        (0xf78, 3)
                    };
                    spawn_tactical_effect(
                        &mut commands,
                        &mut assets,
                        field_entity,
                        &map,
                        target,
                        base,
                        frames,
                        now,
                        true,
                    );
                    return;
                }
                ArmyPresentationEvent::Mine { target } => {
                    audio.play(&mut commands, SoundId::new(0x3a9d));
                    spawn_tactical_effect(
                        &mut commands,
                        &mut assets,
                        field_entity,
                        &map,
                        target,
                        0xf98,
                        6,
                        now,
                        false,
                    );
                    return;
                }
                ArmyPresentationEvent::Rally => {
                    audio.play(&mut commands, SoundId::new(0x3aae));
                }
            }
        }
        commands
            .entity(field_entity)
            .remove::<LandBattleAnimationQueue>();
        return;
    }
    if let Some(stop) = deferred {
        apply_turn_stop(stop.0, &mut next_state);
        commands
            .entity(field_entity)
            .remove::<LandBattleDeferredStop>();
    }
}

fn spawn_unit_stat_bars(
    commands: &mut Commands,
    field: Entity,
    map: &LandBattleHexMap,
    unit: ArmyUnitView,
    colors: [Color; 3],
) {
    let Some(hex) = unit.hex else {
        return;
    };
    let (x, y, width, _) = map.tile_rect(hex);
    let left = x + width / 2 - 10;
    let bar = |commands: &mut Commands, width: i32, color: Color, z: i32| {
        commands.spawn((
            LandBattleUnitStat,
            ChildOf(field),
            Node {
                position_type: PositionType::Absolute,
                left: px(left),
                top: px(y - 5),
                width: px(width.clamp(0, 20)),
                height: px(3),
                ..default()
            },
            BackgroundColor(color),
            Pickable::IGNORE,
            ZIndex(z),
        ));
    };
    bar(commands, 20, colors[0], 4);
    bar(commands, (unit.strength + 0x18) / 0x19, colors[1], 5);
    bar(commands, (unit.morale + 0x18) / 0x19, colors[2], 5);
}

fn spawn_unit_status_flag(
    commands: &mut Commands,
    field: Entity,
    map: &LandBattleHexMap,
    unit: ArmyUnitView,
    visuals: &LandBattleVisuals,
) {
    let Some(hex) = unit.hex else {
        return;
    };
    let (x, y, width, _) = map.tile_rect(hex);
    let bar_left = x + width / 2 - 10;
    // 0x005aba77..0x005abb3f places the 9x6 destination left of the stat bar
    // and transposes the 6x9 tier-zero source cell.
    let left = bar_left - 12;
    let top = y - 8;
    commands.spawn((
        LandBattleUnitStat,
        ChildOf(field),
        Node {
            position_type: PositionType::Absolute,
            left: px(left),
            top: px(top),
            width: px(9),
            height: px(6),
            ..default()
        },
        ImageNode {
            image: visuals.unit_status_atlas.clone(),
            rect: Some(Rect::new(0.0, 0.0, 6.0, 9.0)),
            ..default()
        },
        Pickable::IGNORE,
        ZIndex(6),
    ));
    let frame = |commands: &mut Commands, inset: i32, color: Color, z: i32| {
        commands.spawn((
            LandBattleUnitStat,
            ChildOf(field),
            Node {
                position_type: PositionType::Absolute,
                left: px(left - inset),
                top: px(top - inset),
                width: px(9 + inset * 2),
                height: px(6 + inset * 2),
                border: UiRect::all(px(1)),
                ..default()
            },
            BorderColor::all(color),
            Pickable::IGNORE,
            ZIndex(z),
        ));
    };
    frame(
        commands,
        1,
        if unit.selected {
            Color::WHITE
        } else {
            Color::BLACK
        },
        7,
    );
    if unit.selected {
        frame(commands, 2, Color::BLACK, 8);
    }
}

#[allow(clippy::type_complexity)]
fn project_land_battle_toolbar(
    mut commands: Commands,
    session: Res<GameSession>,
    mut fields: Query<(&LandBattlefield, &LandBattleVisuals, &mut HoverHelpText)>,
    mut buttons: Query<
        (
            Entity,
            &LandBattleAction,
            &mut Visibility,
            Option<&mut ImageNode>,
            Option<&mut RetailPictureSwap>,
            Option<&mut HoverHelpText>,
        ),
        (
            Without<LandBattlePortrait>,
            Without<LandBattleCoat>,
            Without<LandBattlefield>,
        ),
    >,
    mut portraits: Query<
        (
            Entity,
            &LandBattlePortrait,
            &mut ImageNode,
            &mut Visibility,
            Option<&Children>,
        ),
        (Without<LandBattleAction>, Without<LandBattleCoat>),
    >,
    experience_bars: Query<(), With<LandBattleExperienceBar>>,
    mut coats: Query<
        &mut ImageNode,
        (
            With<LandBattleCoat>,
            Without<LandBattleAction>,
            Without<LandBattlePortrait>,
        ),
    >,
    mut assets: RetailUiAssets,
) {
    let Some(battle) = session.game.army_battle() else {
        return;
    };
    let Ok((view, visuals, mut field_help)) = fields.single_mut() else {
        return;
    };
    let stage = battle.stage();
    for (entity, action, mut visibility, image, swap, help) in &mut buttons {
        let live_only = matches!(action, LandBattleAction::Target | LandBattleAction::Auto);
        *visibility = if live_only && stage == ArmyBattleStage::Deploying {
            Visibility::Hidden
        } else {
            Visibility::Inherited
        };
        if live_only && stage == ArmyBattleStage::Deploying {
            commands.entity(entity).insert(InteractionDisabled);
        } else {
            commands.entity(entity).remove::<InteractionDisabled>();
        }
        let (idle_id, active_id, help_index) = match (*action, stage) {
            (LandBattleAction::Done, ArmyBattleStage::Deploying) => (0xed4, 0xed5, 0x2e),
            (LandBattleAction::Retreat, ArmyBattleStage::Deploying) => (0xed2, 0xed3, 0x2f),
            (LandBattleAction::Done, ArmyBattleStage::Live) => (0xece, 0xecf, 0x22),
            (LandBattleAction::Retreat, ArmyBattleStage::Live) => (0xed0, 0xed1, 0x23),
            _ => continue,
        };
        let idle = assets
            .picture(PictureId::new(idle_id))
            .expect("retail tactical toolbar picture");
        let active = assets
            .picture(PictureId::new(active_id))
            .expect("retail tactical toolbar pressed picture");
        if let Some(mut image) = image {
            image.image = idle.clone();
        }
        if let Some(mut swap) = swap {
            swap.idle = idle;
            swap.active = active;
        }
        if let Some(mut help) = help {
            help.0 = ui_string(&assets, 0x273d, help_index);
        }
    }

    let hovered = view.hovered_hex;
    let current = session.game.selected_army_unit();
    field_help.0 = current
        .and_then(|unit| session.game.military_unit(unit.id.source()))
        .map_or_else(String::new, |unit| unit.name().to_owned());
    let other = hovered.and_then(|hex| battle.unit_at(hex));
    for (entity, portrait, mut image, mut visibility, children) in &mut portraits {
        if let Some(children) = children {
            for child in children.iter() {
                if experience_bars.contains(child) {
                    commands.entity(child).despawn();
                }
            }
        }
        let unit = match portrait {
            LandBattlePortrait::Current => current,
            LandBattlePortrait::Other => other,
        };
        let Some(unit) = unit else {
            *visibility = Visibility::Hidden;
            continue;
        };
        *visibility = Visibility::Inherited;
        let side = match unit.side {
            BattleSide::Attacker => 0,
            BattleSide::Defender => 1,
        };
        image.image = assets
            .picture(PictureId::new(
                0xf1e + i16::from(unit.unit_type.retail()) * 2 + side,
            ))
            .expect("retail tactical unit portrait");
        let experience = session
            .game
            .military_unit(unit.id.source())
            .map_or(0, MilitaryUnitState::experience);
        let width = i32::from(unit.quality) * 11 + i32::from(experience % 100 > 0x31) * 5;
        if width > 0 {
            let strip = visuals.experience_strip.clone();
            commands.spawn((
                LandBattleExperienceBar,
                ChildOf(entity),
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0),
                    top: px(match portrait {
                        LandBattlePortrait::Current => -10,
                        LandBattlePortrait::Other => -11,
                    }),
                    width: px(width),
                    height: px(10),
                    ..default()
                },
                ImageNode {
                    image: strip,
                    rect: Some(Rect::new(0.0, 0.0, width as f32, 10.0)),
                    ..default()
                },
                Pickable::IGNORE,
            ));
        }
    }
    let coat = assets
        .picture(PictureId::new(
            0xea6 + i16::from(battle.nation(battle.active_side()).get()),
        ))
        .expect("retail tactical current-player coat");
    for mut image in &mut coats {
        image.image = coat.clone();
    }
}

fn project_tile_atlases(
    commands: &mut Commands,
    field: Entity,
    battle: &ArmyBattle,
    hex_map: &LandBattleHexMap,
    visuals: &LandBattleVisuals,
) {
    let tiles: Vec<_> = battle.tiles().collect();
    for tile in &tiles {
        if tile.trench_mask != 0 {
            if tile.trench_mask & 0x80 != 0 {
                spawn_tile_atlas_cell(
                    commands,
                    field,
                    hex_map,
                    tile.hex,
                    &visuals.effect_atlas,
                    0,
                    0,
                );
            }
            if let Some(cell) = trench_sprite_cell(tile.trench_mask) {
                spawn_tile_atlas_cell(
                    commands,
                    field,
                    hex_map,
                    tile.hex,
                    &visuals.effect_atlas,
                    cell,
                    0,
                );
            }
        }

        if tile.unit_cover {
            let orientation = tactical_unit_orientation(&tiles, tile.hex) as i32;
            for (cell, layer) in [
                (orientation * 3, 0),
                (orientation * 3 + 1, 1),
                (orientation * 3 + 2, 3),
            ] {
                spawn_tile_atlas_cell(
                    commands,
                    field,
                    hex_map,
                    tile.hex,
                    &visuals.fort_atlas,
                    cell,
                    layer,
                );
            }
        }

        let neighbors = tactical_neighbors(tile.hex.index());
        let covered = |slot: usize| {
            usize::try_from(neighbors[slot])
                .ok()
                .and_then(|index| tiles.get(index))
                .is_some_and(|neighbor| neighbor.unit_cover)
        };
        let links = if tile.hex.row() & 1 == 0 {
            [
                covered(4) && covered(3),
                false,
                covered(4) && covered(5),
                false,
            ]
        } else {
            [
                false,
                covered(1) && covered(2),
                false,
                covered(1) && covered(0),
            ]
        };
        for (link, present) in links.into_iter().enumerate() {
            if present {
                spawn_tile_atlas_cell(
                    commands,
                    field,
                    hex_map,
                    tile.hex,
                    &visuals.fort_atlas,
                    0x15 + link as i32,
                    1,
                );
            }
        }

        let index = tile.hex.index() as usize;
        let edge = if tile.hex.row() & 1 == 0 {
            if tile.fort_wall {
                1
            } else if index > 0 && tiles[index - 1].fort_wall {
                2
            } else {
                0
            }
        } else if tile.fort_wall {
            3
        } else {
            0
        };
        if edge == 0 {
            continue;
        }
        let wall_index = match edge {
            2 => index - 1,
            _ => index,
        };
        let breached = !tiles[wall_index].fort_wall_intact;
        if edge == 2 || breached {
            let cell = if breached { edge + 0xb } else { 1 };
            spawn_tile_atlas_cell(
                commands,
                field,
                hex_map,
                tile.hex,
                &visuals.fort_atlas,
                cell,
                0,
            );
        }
        if edge != 2 {
            let wall_neighbor = match edge {
                1 => tile.hex.index() + TacticalHex::COLUMNS,
                3 => tile.hex.index(),
                _ => unreachable!(),
            };
            let gun_slot = fort_gun_slot(battle.column_count(), wall_neighbor);
            let gun_occupied = usize::try_from(wall_neighbor)
                .ok()
                .and_then(|neighbor| tiles.get(neighbor))
                .is_some_and(|neighbor| gun_slot && neighbor.occupied);
            let cell = if breached {
                edge + 0xe
            } else if gun_slot && !gun_occupied {
                edge + 2
            } else if gun_occupied {
                edge + 8
            } else {
                edge - 1
            };
            spawn_tile_atlas_cell(
                commands,
                field,
                hex_map,
                tile.hex,
                &visuals.fort_atlas,
                cell,
                if gun_occupied { 3 } else { 1 },
            );
        }
    }
}

fn spawn_tile_atlas_cell(
    commands: &mut Commands,
    field: Entity,
    hex_map: &LandBattleHexMap,
    hex: TacticalHex,
    atlas: &Handle<Image>,
    cell: i32,
    layer: i32,
) {
    let (x, y, width, height) = hex_map.tile_rect(hex);
    let source = Vec2::new((cell * TACTICAL_TILE_WIDTH_PX) as f32, 0.0);
    commands.spawn((
        LandBattleTileOverlay,
        ChildOf(field),
        Node {
            position_type: PositionType::Absolute,
            left: px(x),
            top: px(y),
            width: px(width),
            height: px(height),
            ..default()
        },
        ImageNode {
            image: atlas.clone(),
            rect: Some(Rect::from_corners(
                source,
                source
                    + Vec2::new(
                        TACTICAL_TILE_WIDTH_PX as f32,
                        TACTICAL_TILE_ROW_HEIGHT_PX as f32,
                    ),
            )),
            ..default()
        },
        Pickable::IGNORE,
        ZIndex(layer),
    ));
}

fn trench_sprite_cell(mask: u8) -> Option<i32> {
    const PAIRS: [i32; 36] = [
        0, 0x0e, 0x0a, 0x07, 0x14, 0x0d, 0x0e, 0, 0x13, 0x11, 0x09, 0x15, 0x0a, 0x13, 0, 0x0c,
        0x10, 0x08, 0x07, 0x11, 0x0c, 0, 0x12, 0x0b, 0x14, 0x09, 0x10, 0x12, 0, 0x0f, 0x0d, 0x15,
        0x08, 0x0b, 0x0f, 0,
    ];
    const SINGLES: [i32; 6] = [0x19, 0x1a, 0x1b, 0x16, 0x17, 0x18];
    let bits: Vec<_> = (0..6).filter(|bit| mask & (1 << bit) != 0).collect();
    let first = *bits.first()?;
    if mask & 0x80 != 0 {
        Some(first + 1)
    } else if let Some(&second) = bits.get(1) {
        Some(PAIRS[second as usize + first as usize * 6])
    } else {
        Some(SINGLES[first as usize])
    }
}

fn fort_gun_slot(column_count: i32, tile: i32) -> bool {
    let row = tile / TacticalHex::COLUMNS;
    let doubled = (row & 1) + (tile % TacticalHex::COLUMNS) * 2;
    (row == 5 || row == 7 || row == 9) && doubled / 2 == column_count - 6
}

fn centered_view_origin(current: i32, column_count: i32, selected: TacticalHex) -> i32 {
    let first_visible = current / TACTICAL_TILE_WIDTH_PX;
    let visible_columns = BATTLEFIELD_WIDTH_PX / TACTICAL_TILE_WIDTH_PX;
    let last_visible = first_visible + visible_columns;
    let column = selected.column();
    if column >= first_visible + 2 && column <= last_visible - 2 {
        return current;
    }
    let max_origin = ((column_count + 1) * TACTICAL_TILE_WIDTH_PX - BATTLEFIELD_WIDTH_PX).max(0);
    let centered =
        (column * TACTICAL_TILE_WIDTH_PX - BATTLEFIELD_WIDTH_PX / 2).clamp(0, max_origin);
    centered / TACTICAL_TILE_WIDTH_PX * TACTICAL_TILE_WIDTH_PX
}

fn queue_land_battle_progress(
    commands: &mut Commands,
    field: Entity,
    view: &mut LandBattlefield,
    progress: ArmyBattleProgress,
    next_state: &mut NextState<AppState>,
) {
    if progress.events.is_empty() {
        if let Some(stop) = progress.stop
            && stop != TurnStop::LandBattle
        {
            apply_turn_stop(stop, next_state);
        }
        return;
    }
    view.projected_origin_x = -1;
    commands.entity(field).insert(LandBattleAnimationQueue {
        events: progress.events,
        next: 0,
    });
    if let Some(stop) = progress.stop
        && stop != TurnStop::LandBattle
    {
        commands.entity(field).insert(LandBattleDeferredStop(stop));
    }
}

#[allow(clippy::type_complexity)]
fn scroll_land_battle(
    time: Res<Time>,
    mut last_scroll_tick: Local<Option<u128>>,
    window: Single<&Window, With<PrimaryWindow>>,
    mut fields: Query<&mut LandBattlefield>,
    session: Res<GameSession>,
    animations: Query<
        (),
        Or<(
            With<LandBattleEffect>,
            With<LandBattleGlide>,
            With<LandBattleAnimationQueue>,
        )>,
    >,
) {
    if !animations.is_empty() {
        return;
    }
    let Ok(mut view) = fields.single_mut() else {
        return;
    };
    let Some(cursor) = window.cursor_position() else {
        return;
    };
    let direction = if cursor.x <= 4.0 {
        -1
    } else if cursor.x >= window.width() - 4.0 {
        1
    } else {
        return;
    };
    let tick16 = time.elapsed().as_millis() / 16;
    if last_scroll_tick.is_some_and(|last| last + 3 >= tick16) {
        return;
    }
    *last_scroll_tick = Some(tick16);
    let Some(battle) = session.game.army_battle() else {
        return;
    };
    let max_origin =
        ((battle.column_count() + 1) * TACTICAL_TILE_WIDTH_PX - BATTLEFIELD_WIDTH_PX).max(0);
    if direction < 0 {
        if view.view_origin_x > 0 {
            view.view_origin_x -= TACTICAL_TILE_WIDTH_PX;
        }
    } else if view.view_origin_x < max_origin - TACTICAL_TILE_WIDTH_PX {
        view.view_origin_x += TACTICAL_TILE_WIDTH_PX;
    }
    view.centered_unit = session.game.selected_army_unit().map(|unit| unit.id);
}

#[allow(clippy::type_complexity)]
fn on_battlefield_click(
    click: On<Pointer<Click>>,
    mut fields: Query<(Entity, &RelativeCursorPosition, &mut LandBattlefield)>,
    animations: Query<
        (),
        Or<(
            With<LandBattleEffect>,
            With<LandBattleGlide>,
            With<LandBattleAnimationQueue>,
        )>,
    >,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    assets: Option<Res<crate::RetailAssetsResource>>,
    mut commands: Commands,
) {
    if click.event.button != PointerButton::Primary || !animations.is_empty() {
        return;
    }
    let Ok((field, cursor, mut view)) = fields.get_mut(click.entity) else {
        return;
    };
    let Some((x, y)) = battlefield_cursor_pixel(cursor) else {
        return;
    };
    let Some(battle) = session.game.army_battle() else {
        return;
    };
    let map = LandBattleHexMap::new(battle.column_count(), view.view_origin_x);
    let Some(target) = map.hex_at_pixel(x, y) else {
        return;
    };
    let Ok((_action, progress)) = session
        .game
        .army_action_at(target, super::session::news_story_ids(assets.as_deref()))
    else {
        return;
    };
    queue_land_battle_progress(&mut commands, field, &mut view, progress, &mut next_state);
}

#[cfg(test)]
fn apply_battlefield_click(
    session: &mut GameSession,
    x: i32,
    y: i32,
    view_origin_x: i32,
    story_ids: &[i32],
) -> Option<TurnStop> {
    let column_count = session.game.army_battle().map(ArmyBattle::column_count)?;
    let hex_map = LandBattleHexMap::new(column_count, view_origin_x);
    let hex = hex_map.hex_at_pixel(x, y)?;
    session
        .game
        .army_action_at(hex, story_ids)
        .ok()
        .and_then(|(_, progress)| progress.stop)
}

#[allow(clippy::type_complexity)]
fn on_land_battle_activate(
    activate: On<Activate>,
    actions: Query<&LandBattleAction>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    mut music: Option<ResMut<MusicDirector>>,
    time: Option<Res<Time>>,
    assets: Option<Res<crate::RetailAssetsResource>>,
    mut fields: Query<(Entity, &mut LandBattlefield)>,
    animations: Query<
        (),
        Or<(
            With<LandBattleEffect>,
            With<LandBattleGlide>,
            With<LandBattleAnimationQueue>,
        )>,
    >,
    mut commands: Commands,
    mut audio: crate::media::RetailAudioAssets,
) {
    if !animations.is_empty() {
        return;
    }
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    match *action {
        LandBattleAction::Help => super::map_help::spawn(&mut commands, AppState::LandBattle),
        LandBattleAction::Target => {
            if let Ok(cycle) = session.game.cycle_selected_army_target() {
                if !cycle.has_target {
                    audio.play(&mut commands, SoundId::new(0x1b5a));
                }
                if let Some(center) = cycle.center
                    && let Some(battle) = session.game.army_battle()
                {
                    for (_, mut view) in &mut fields {
                        view.view_origin_x =
                            centered_view_origin(view.view_origin_x, battle.column_count(), center);
                        view.centered_unit = session.game.selected_army_unit().map(|unit| unit.id);
                    }
                }
            }
        }
        LandBattleAction::Done => {
            if let Ok(progress) = session
                .game
                .finish_selected_army_unit_action(super::session::news_story_ids(assets.as_deref()))
                && let Ok((field, mut view)) = fields.single_mut()
            {
                queue_land_battle_progress(
                    &mut commands,
                    field,
                    &mut view,
                    progress,
                    &mut next_state,
                );
            }
        }
        LandBattleAction::Auto => {
            if let Ok(progress) = session
                .game
                .auto_play_army_battle_side(super::session::news_story_ids(assets.as_deref()))
                && let Ok((field, mut view)) = fields.single_mut()
            {
                queue_land_battle_progress(
                    &mut commands,
                    field,
                    &mut view,
                    progress,
                    &mut next_state,
                );
            }
        }
        LandBattleAction::Retreat => {
            if session
                .game
                .army_battle()
                .is_some_and(|battle| battle.stage() == ArmyBattleStage::Live)
            {
                spawn_linger_dialog(&mut commands, LandBattleRetreatPrompt, AppState::LandBattle);
                return;
            }
            if let Ok(progress) = session
                .game
                .retreat_from_army_battle(super::session::news_story_ids(assets.as_deref()))
                && let Ok((field, mut view)) = fields.single_mut()
            {
                queue_land_battle_progress(
                    &mut commands,
                    field,
                    &mut view,
                    progress,
                    &mut next_state,
                );
            }
        }
    }
    if let Some(music) = music.as_mut() {
        cue_tactical_result(&session.game, music, time.as_deref());
    }
}

#[allow(clippy::type_complexity)]
fn land_battle_keyboard(
    keys: Res<ButtonInput<KeyCode>>,
    actions: Query<(Entity, &LandBattleAction)>,
    mut commands: Commands,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    assets: Option<Res<crate::RetailAssetsResource>>,
    mut fields: Query<(Entity, &mut LandBattlefield)>,
    animations: Query<
        (),
        Or<(
            With<LandBattleEffect>,
            With<LandBattleGlide>,
            With<LandBattleAnimationQueue>,
        )>,
    >,
) {
    if !animations.is_empty() {
        return;
    }
    let action = if keys.just_pressed(KeyCode::Space) {
        Some(LandBattleAction::Target)
    } else if keys.just_pressed(KeyCode::KeyD) {
        Some(LandBattleAction::Done)
    } else if keys.just_pressed(KeyCode::KeyH) {
        Some(LandBattleAction::Help)
    } else {
        None
    };
    if let Some(action) = action
        && let Some((entity, _)) = actions.iter().find(|(_, bound)| **bound == action)
    {
        commands.trigger(Activate { entity });
    }
    if keys.just_pressed(KeyCode::KeyS)
        && let Ok(progress) = session
            .game
            .skip_selected_army_unit_action(super::session::news_story_ids(assets.as_deref()))
        && let Ok((field, mut view)) = fields.single_mut()
    {
        queue_land_battle_progress(&mut commands, field, &mut view, progress, &mut next_state);
    }
}

/// `TTacticalBattle` result dialog: `RequestAudioPresetChangeWithDeferredApply(9 or 10, 0)`.
fn cue_tactical_result(game: &GameState, music: &mut MusicDirector, time: Option<&Time>) {
    let Some(report) = game.battle_reports().last() else {
        return;
    };
    let winner = report.sides[report
        .participant
        .expect("resolved land battle report has a winner")]
    .nation;
    let cue = if winner == game.turn().active_nation {
        MusicTrack::BATTLE_VICTORY
    } else {
        MusicTrack::BATTLE_DEFEAT
    };
    let now = time.map_or(0, |time| {
        u32::try_from(time.elapsed().as_millis() / 16).unwrap_or(u32::MAX)
    });
    music.request_preset(cue, false, now);
}

#[cfg(test)]
mod tests {
    use super::super::retail::RetailTag;
    use super::*;
    use crate::ui::test_support::beginning_of_game_parts;
    use bevy::state::app::StatesPlugin;

    fn fixture_parts() -> GameStateParts {
        beginning_of_game_parts()
    }

    fn idle_unit(unit: &MilitaryUnitState) -> MilitaryUnitState {
        let stationed = unit.stationed_province();
        MilitaryUnitState::new(
            unit.nation(),
            unit.unit_type(),
            stationed,
            MilitaryOrder::idle([stationed; 3], [stationed; 3]),
            unit.owner_nation(),
            unit.roster_id(),
            unit.registered(),
            unit.name().to_string(),
            unit.strength(),
            unit.era(),
            unit.experience(),
            unit.battle_flags(),
        )
    }

    fn redeploy_unit(
        nation: NationId,
        kind: MilitaryUnitKind,
        from: ProvinceId,
        to: ProvinceId,
        strength: i16,
    ) -> MilitaryUnitState {
        MilitaryUnitState::new(
            nation,
            kind,
            Some(from),
            MilitaryOrder::retail(
                MilitaryOrderCode::Redeploy,
                Some(to),
                [Some(to); 3],
                [Some(to); 3],
            ),
            nation,
            0,
            true,
            String::new(),
            strength,
            MilitaryEra::First,
            0,
            0,
        )
    }

    fn garrison_unit(
        nation: NationId,
        kind: MilitaryUnitKind,
        province: ProvinceId,
        strength: i16,
    ) -> MilitaryUnitState {
        MilitaryUnitState::new(
            nation,
            kind,
            Some(province),
            MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
            nation,
            0,
            true,
            String::new(),
            strength,
            MilitaryEra::First,
            0,
            0,
        )
    }

    fn adjacent_major_frontiers(map: &MapMgr) -> Vec<(ProvinceId, ProvinceId, NationId, NationId)> {
        let mut pairs = Vec::new();
        for province in ProvinceId::all() {
            let Some(owner) = map.provinces[province].owner() else {
                continue;
            };
            if MajorNationId::from_nation(owner).is_none() {
                continue;
            }
            for &neighbor in map.provinces[province].adjacency() {
                if neighbor.get() <= province.get() {
                    continue;
                }
                let Some(other) = map.provinces[neighbor].owner() else {
                    continue;
                };
                if other == owner || MajorNationId::from_nation(other).is_none() {
                    continue;
                }
                pairs.push((province, neighbor, owner, other));
            }
        }
        pairs
    }

    fn two_land_battles_state() -> GameState {
        let mut parts = fixture_parts();
        let frontiers = adjacent_major_frontiers(&parts.map);
        let first = frontiers
            .first()
            .copied()
            .expect("beginning-of-game map has a major-power border");
        let second = frontiers
            .iter()
            .copied()
            .find(|&(from, to, ..)| {
                from != first.0 && from != first.1 && to != first.0 && to != first.1
            })
            .expect("beginning-of-game map has two distinct major-power borders");

        parts.military_units = parts
            .military_units
            .iter()
            .map(|(id, unit)| (*id, idle_unit(unit)))
            .collect();
        parts.diplomacy.relationships[first.2][first.3] = DiplomaticRelationship::War;
        parts.diplomacy.relationships[first.3][first.2] = DiplomaticRelationship::War;
        parts.diplomacy.relationships[second.2][second.3] = DiplomaticRelationship::War;
        parts.diplomacy.relationships[second.3][second.2] = DiplomaticRelationship::War;
        parts.diplomacy.relationship_turns[first.2][first.3] = None;
        parts.diplomacy.relationship_turns[first.3][first.2] = None;
        parts.diplomacy.relationship_turns[second.2][second.3] = None;
        parts.diplomacy.relationship_turns[second.3][second.2] = None;

        let next = parts.unit_ids.current();
        parts.unit_ids = UnitIdAllocator::from_retail(next + 4);
        parts.military_units.insert(
            MilitaryUnitId::from_serialized(next + 1),
            redeploy_unit(first.2, MilitaryUnitKind::Regulars, first.0, first.1, 500),
        );
        parts.military_units.insert(
            MilitaryUnitId::from_serialized(next + 2),
            garrison_unit(first.3, MilitaryUnitKind::Militia, first.1, 100),
        );
        parts.military_units.insert(
            MilitaryUnitId::from_serialized(next + 3),
            redeploy_unit(
                second.2,
                MilitaryUnitKind::Regulars,
                second.0,
                second.1,
                500,
            ),
        );
        parts.military_units.insert(
            MilitaryUnitId::from_serialized(next + 4),
            garrison_unit(second.3, MilitaryUnitKind::Militia, second.1, 100),
        );

        parts.turn = TurnState::new(
            parts.turn.scenario_map,
            parts.turn.economic_turn,
            parts.turn.diplomacy_year_term_raw,
            PhaseCode::COMBAT_MOVES,
            parts.turn.turn_flow_status_flags,
            parts.turn.quarter_gate_by_decade,
            parts.turn.difficulty,
            parts.turn.active_nation,
        );

        let mut state = GameState::from_parts(parts);
        assert_eq!(state.advance_turn(&[]), TurnStop::LandBattle);
        assert!(state.pending_land_battle().is_some());
        state
    }

    fn test_app(state: GameState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(StatesPlugin)
            .insert_resource(GameSession::new(state))
            .insert_state(AppState::LandBattle)
            .add_systems(
                OnEnter(AppState::LandBattle),
                (spawn_test_land_battle, bind_test_land_battle).chain(),
            )
            .add_systems(
                Update,
                (synchronize_interactive_army_battle, project_land_battle)
                    .chain()
                    .run_if(
                        in_state(AppState::LandBattle).and_then(resource_exists::<GameSession>),
                    ),
            );
        app
    }

    fn spawn_test_land_battle(mut commands: Commands) {
        let root = commands
            .spawn((
                LandBattleRoot,
                Node::default(),
                DespawnOnExit(AppState::LandBattle),
            ))
            .id();
        commands.spawn((RetailTag(fourcc!("curs")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("help")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("targ")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("done")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("auto")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("retr")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("coat")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("curr")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("tpic")), Node::default(), ChildOf(root)));
        commands.spawn((
            RetailTag(fourcc!("DLOG")),
            Node {
                position_type: PositionType::Absolute,
                width: px(BATTLEFIELD_WIDTH_PX),
                height: px(BATTLEFIELD_HEIGHT_PX),
                ..default()
            },
            ChildOf(root),
        ));
    }

    fn bind_test_land_battle(
        mut commands: Commands,
        root: Option<Single<Entity, Added<LandBattleRoot>>>,
        tree: RetailTree,
    ) {
        let Some(root) = root else {
            return;
        };
        bind_land_battle_controls(&mut commands, *root, &tree);
    }

    fn node_left_top(node: &Node) -> (i32, i32) {
        let Val::Px(left) = node.left else {
            panic!("unit node uses pixel left");
        };
        let Val::Px(top) = node.top else {
            panic!("unit node uses pixel top");
        };
        (left as i32, top as i32)
    }

    #[test]
    fn hex_pixel_round_trip_uses_retail_stagger() {
        let map = LandBattleHexMap::new(16, 100);
        let hex = TacticalHex::from_row_column(2, 4).unwrap();
        let (x, y, width, height) = map.tile_rect(hex);
        let center = (x + width / 2, y + height / 2);
        assert_eq!(map.hex_at_pixel(center.0, center.1), Some(hex));
        let odd = TacticalHex::from_row_column(3, 4).unwrap();
        let (ox, oy, ow, oh) = map.tile_rect(odd);
        assert_eq!(
            ox,
            4 * TACTICAL_TILE_WIDTH_PX + TACTICAL_TILE_WIDTH_PX / 2 - 100
        );
        assert_eq!(map.hex_at_pixel(ox + ow / 2, oy + oh / 2), Some(odd));
    }

    #[test]
    fn center_selected_snaps_and_clamps_the_retail_view_origin() {
        let selected = TacticalHex::from_row_column(4, 14).unwrap();
        let origin = centered_view_origin(0, 20, selected);
        assert_eq!(origin % TACTICAL_TILE_WIDTH_PX, 0);
        assert_eq!(origin, 400);
        assert_eq!(
            centered_view_origin(origin, 20, TacticalHex::from_row_column(4, 10).unwrap()),
            origin
        );
    }

    #[test]
    fn trench_cells_follow_the_retail_direction_tables() {
        assert_eq!(trench_sprite_cell(1), Some(0x19));
        assert_eq!(trench_sprite_cell(1 | 4), Some(0x0a));
        assert_eq!(trench_sprite_cell(0x80 | 8), Some(4));
    }

    #[test]
    fn land_battle_projects_units_onto_retail_hex_anchors() {
        let state = two_land_battles_state();
        let mut probe = state.clone();
        probe.ensure_army_battle();
        let expected: Vec<_> = probe
            .army_battle()
            .expect("interactive battle starts on enter")
            .units()
            .filter_map(|unit| {
                let hex = unit.hex?;
                let (x, y, _, _) =
                    LandBattleHexMap::new(probe.army_battle().unwrap().column_count(), 0)
                        .unit_anchor(hex);
                Some((unit.id, x, y))
            })
            .collect();
        assert_eq!(
            probe.army_battle().unwrap().stage(),
            ArmyBattleStage::Deploying
        );

        let mut app = test_app(state);
        app.update();
        app.update();

        let mut projected: Vec<_> = app
            .world_mut()
            .query::<(&LandBattleUnit, &Node)>()
            .iter(app.world())
            .map(|(unit, node)| {
                let (left, top) = node_left_top(node);
                (unit.0, left, top)
            })
            .collect();
        projected.sort_by_key(|(id, _, _)| id.source().get());
        let mut expected = expected;
        expected.sort_by_key(|(id, _, _)| id.source().get());
        assert_eq!(projected, expected);
    }

    #[test]
    fn clicking_a_deployment_hex_places_the_core_selected_unit() {
        let mut app = test_app(two_land_battles_state());
        app.update();
        app.update();

        let unit_id = {
            let session = app.world().resource::<GameSession>();
            let unit = session
                .game
                .selected_army_unit()
                .expect("core selected unit");
            assert_eq!(unit.hex, None);
            unit.id
        };
        let destination = app
            .world_mut()
            .resource_scope(|_, session: Mut<GameSession>| {
                session
                    .game
                    .selected_army_unit_reachable_hexes()
                    .iter()
                    .copied()
                    .next()
                    .expect("attacker has a deployment hex")
            });
        let dest_pixel = {
            let session = app.world().resource::<GameSession>();
            let map = LandBattleHexMap::new(
                session
                    .game
                    .army_battle()
                    .expect("live battle")
                    .column_count(),
                0,
            );
            let (x, y, w, h) = map.tile_rect(destination);
            (x + w / 2, y + h / 2)
        };

        app.world_mut()
            .resource_scope(|_, mut session: Mut<GameSession>| {
                assert_eq!(
                    apply_battlefield_click(&mut session, dest_pixel.0, dest_pixel.1, 0, &[]),
                    None
                );
            });
        app.update();
        let after = app
            .world()
            .resource::<GameSession>()
            .game
            .army_battle()
            .and_then(|battle| battle.unit(unit_id))
            .and_then(|unit| unit.hex)
            .expect("unit still on the grid");
        assert_eq!(after, destination);
    }
}
