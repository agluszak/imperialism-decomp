//! Right-hand army command page (`uarm` / `TArmyToolbar`).

use super::super::retail::{RetailTree, RetailUiAssets};
use super::map_interaction::{
    MapInteractionMode, StrategicInteraction, StrategicViewport, cycle_map_interaction_selection,
};
use super::map_modals::{spawn_army_roster, spawn_garrison};
use crate::AppState;
use crate::ui::GameSession;
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::*;

const PAGE_TAG: FourCc = fourcc!("uarm");
const ARMY_PAGE_VISIBLE: Vec2 = Vec2::new(0.0, 0x92 as f32);
const PAGE_PARKED: Vec2 = Vec2::new(-1000.0, -1000.0);
const ARROW_ATLAS: i16 = 804;
const TRANSPARENT_INDEX: u8 = 0x10;
const COUNT_PALETTE: u8 = 0x28;
const COUNT_SHADOW_PALETTE: u8 = 0xd2;

fn placard_picture_id(
    counts: ArmyToolbarCounts,
    nation: MajorNationId,
    state: &GameState,
    category: ArmyUnitCategory,
) -> i16 {
    let kind = state.technology().selected_capability_slots[nation][category];
    let mut picture = 0x4c4 + i16::from(kind.retail());
    if counts.totals[category] <= 0 {
        picture += 0x1e;
    }
    picture
}

#[derive(Component)]
pub(super) struct ArmyToolbarPage;

#[derive(Component, Clone, Copy)]
struct ArmyPlacard(ArmyUnitCategory);

#[derive(Component, Clone, Copy)]
struct ArmyArrow(ArmyUnitCategory);

#[derive(Component, Clone, Copy)]
enum ArmyCommand {
    Defend,
    Later,
    Done,
    Garrison,
}

#[derive(Component)]
struct ArmyCountLabel;

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        sync_army_toolbar.run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn bind_army_toolbar(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let page = tree.find(root, PAGE_TAG);
    commands.entity(page).insert((
        ArmyToolbarPage,
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(PAGE_PARKED.x),
            top: Val::Px(PAGE_PARKED.y),
            width: Val::Px(120.0),
            height: Val::Px(307.0),
            ..default()
        },
    ));
    let arrow_atlas = assets
        .transparent_picture(PictureId::new(ARROW_ATLAS), TRANSPARENT_INDEX)
        .expect("retail numbered-arrow atlas 804 must load");
    for category in ArmyUnitCategory::all() {
        let pic = tree.child(page, placard_tag(category));
        commands.entity(pic).insert(ArmyPlacard(category));
        spawn_count_label(commands, pic, assets, true);
        let arrow = tree.child(page, arrow_tag(category));
        commands
            .entity(arrow)
            .insert((
                ArmyArrow(category),
                ImageNode {
                    image: arrow_atlas.clone(),
                    rect: Some(Rect::from_corners(
                        Vec2::new(10.0, 0.0),
                        Vec2::new(21.0, 16.0),
                    )),
                    ..default()
                },
                RelativeCursorPosition::default(),
                ActivateOnPress,
                Visibility::Hidden,
            ))
            .observe(on_army_arrow);
        spawn_count_label(commands, arrow, assets, false);
    }
    for (tag, command) in [
        (fourcc!("dfnd"), ArmyCommand::Defend),
        (fourcc!("latr"), ArmyCommand::Later),
        (fourcc!("done"), ArmyCommand::Done),
        (fourcc!("garr"), ArmyCommand::Garrison),
    ] {
        commands
            .entity(tree.child(page, tag))
            .insert((command, ActivateOnPress))
            .observe(on_army_command);
    }
}

pub(crate) fn army_page_position(mode: MapInteractionMode) -> Vec2 {
    if mode == MapInteractionMode::Army {
        ARMY_PAGE_VISIBLE
    } else {
        PAGE_PARKED
    }
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn sync_army_toolbar(
    session: Res<GameSession>,
    interactions: Query<Ref<StrategicInteraction>>,
    mut assets: RetailUiAssets,
    mut pages: Query<&mut Node, With<ArmyToolbarPage>>,
    mut placards: Query<(Entity, &ArmyPlacard, &mut ImageNode), Without<ArmyArrow>>,
    mut arrows: Query<
        (Entity, &ArmyArrow, &mut ImageNode, &mut Visibility),
        (Without<ArmyPlacard>, Without<ArmyCommand>),
    >,
    mut counts: Query<(&ChildOf, &mut Text, &ArmyCountLabel)>,
    mut garrisons: Query<
        (&ArmyCommand, &mut ImageNode),
        (With<ArmyCommand>, Without<ArmyPlacard>, Without<ArmyArrow>),
    >,
) {
    let Ok(interaction) = interactions.single() else {
        return;
    };
    if !session.is_changed() && !interaction.is_changed() {
        return;
    }
    let Ok(mut page) = pages.single_mut() else {
        return;
    };
    let position = army_page_position(interaction.mode);
    page.left = Val::Px(position.x);
    page.top = Val::Px(position.y);
    let Some(province) = interaction
        .army
        .filter(|_| interaction.mode == MapInteractionMode::Army)
    else {
        hide_empty_toolbar(
            &mut assets,
            &session.game,
            &mut placards,
            &mut arrows,
            &mut counts,
        );
        return;
    };
    let nation = NationId::as_major(session.game.turn().active_nation)
        .expect("army toolbar requires an active major nation");
    let counts_state = session.game.army_toolbar_counts(province);
    for (entity, placard, mut image) in &mut placards {
        let picture_id = placard_picture_id(counts_state, nation, &session.game, placard.0);
        image.image = assets
            .picture(PictureId::new(picture_id))
            .expect("retail army placard picture must load");
        set_count_text(
            entity,
            &mut counts,
            (counts_state.totals[placard.0] != 0).then_some(counts_state.totals[placard.0]),
        );
    }
    for (entity, arrow, mut image, mut visibility) in &mut arrows {
        if counts_state.totals[arrow.0] != 0 && arrow.0 != ArmyUnitCategory::Garrison {
            *visibility = Visibility::Visible;
            image.rect = Some(Rect::from_corners(
                Vec2::new(10.0, 0.0),
                Vec2::new(21.0, 16.0),
            ));
            set_count_text(entity, &mut counts, Some(counts_state.available[arrow.0]));
        } else {
            *visibility = Visibility::Hidden;
            set_count_text(entity, &mut counts, None);
        }
    }
    for (command, mut image) in &mut garrisons {
        if matches!(*command, ArmyCommand::Garrison) {
            image.image = assets
                .picture(PictureId::new(if counts_state.can_upgrade {
                    0x24d5
                } else {
                    0x04b5
                }))
                .expect("retail garrison picture must load");
        }
    }
}

#[allow(clippy::type_complexity)]
fn hide_empty_toolbar(
    assets: &mut RetailUiAssets,
    state: &GameState,
    placards: &mut Query<(Entity, &ArmyPlacard, &mut ImageNode), Without<ArmyArrow>>,
    arrows: &mut Query<
        (Entity, &ArmyArrow, &mut ImageNode, &mut Visibility),
        (Without<ArmyPlacard>, Without<ArmyCommand>),
    >,
    counts: &mut Query<(&ChildOf, &mut Text, &ArmyCountLabel)>,
) {
    let Some(nation) = NationId::as_major(state.turn().active_nation) else {
        return;
    };
    let empty = ArmyToolbarCounts::default();
    for (entity, placard, mut image) in placards.iter_mut() {
        let picture_id = placard_picture_id(empty, nation, state, placard.0);
        image.image = assets
            .picture(PictureId::new(picture_id))
            .expect("retail army placard picture must load");
        set_count_text(entity, counts, None);
    }
    for (entity, _, _, mut visibility) in arrows.iter_mut() {
        *visibility = Visibility::Hidden;
        set_count_text(entity, counts, None);
    }
}

fn set_count_text(
    parent: Entity,
    counts: &mut Query<(&ChildOf, &mut Text, &ArmyCountLabel)>,
    value: Option<i32>,
) {
    for (child_of, mut text, _) in counts.iter_mut() {
        if child_of.parent() == parent {
            text.0 = value.map(|count| count.to_string()).unwrap_or_default();
        }
    }
}

fn spawn_count_label(
    commands: &mut Commands,
    parent: Entity,
    assets: &mut RetailUiAssets,
    placard: bool,
) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 0,
            face_flags: 0,
            point_size: 10,
            alignment: if placard { -1 } else { 1 },
        })
        .expect("retail army count text style");
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            right: Val::Px(0.0),
            bottom: Val::Px(if placard { 2.0 } else { 0.0 }),
            left: if placard { Val::Auto } else { Val::Px(7.0) },
            top: if placard { Val::Auto } else { Val::Px(0.0) },
            width: Val::Px(if placard { 42.0 } else { 11.0 }),
            height: Val::Px(16.0),
            ..default()
        },
        Text::new(""),
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(COUNT_PALETTE)),
        TextShadow {
            offset: Vec2::new(-1.0, -1.0),
            color: assets.palette_color(COUNT_SHADOW_PALETTE),
        },
        Pickable::IGNORE,
        ArmyCountLabel,
        ChildOf(parent),
    ));
}

fn on_army_command(
    activate: On<Activate>,
    command_query: Query<&ArmyCommand>,
    keys: Res<ButtonInput<KeyCode>>,
    mut commands: Commands,
    mut session: ResMut<GameSession>,
    mut interactions: Query<(&mut StrategicInteraction, &mut StrategicViewport)>,
) {
    let Ok(command) = command_query.get(activate.entity) else {
        return;
    };
    let Ok((mut interaction, mut viewport)) = interactions.single_mut() else {
        return;
    };
    let Some(province) = interaction.army else {
        return;
    };
    match *command {
        ArmyCommand::Defend => {
            session
                .game
                .set_idle_unit_orders_on_province(province, ArmyIdleOrderMode::Sleep);
            cycle_map_interaction_selection(&mut session, &mut interaction, &mut viewport);
        }
        ArmyCommand::Later => {
            session
                .game
                .set_idle_unit_orders_on_province(province, ArmyIdleOrderMode::Latr);
            cycle_map_interaction_selection(&mut session, &mut interaction, &mut viewport);
        }
        ArmyCommand::Done => {
            session
                .game
                .set_idle_unit_orders_on_province(province, ArmyIdleOrderMode::Done);
            cycle_map_interaction_selection(&mut session, &mut interaction, &mut viewport);
        }
        ArmyCommand::Garrison => {
            if keys.pressed(KeyCode::ControlLeft) || keys.pressed(KeyCode::ControlRight) {
                spawn_army_roster(&mut commands);
            } else {
                spawn_garrison(&mut commands, province);
            }
        }
    }
}

fn on_army_arrow(
    activate: On<Activate>,
    arrows: Query<(&ArmyArrow, &RelativeCursorPosition)>,
    mut session: ResMut<GameSession>,
    interactions: Query<&StrategicInteraction>,
) {
    let Ok((arrow, cursor)) = arrows.get(activate.entity) else {
        return;
    };
    let Ok(interaction) = interactions.single() else {
        return;
    };
    let Some(province) = interaction.army else {
        return;
    };
    let Some(normalized) = cursor.normalized else {
        return;
    };
    // `TNumberedArrowButton::TrackMouse`: top half command 100, bottom 0x65; midline ignored.
    if normalized.y == 0.0 {
        return;
    }
    if normalized.y < 0.0 {
        session
            .game
            .activate_first_active_unit_by_category(province, arrow.0);
    } else {
        session
            .game
            .activate_first_idle_unit_by_category(province, arrow.0);
    }
}

fn placard_tag(category: ArmyUnitCategory) -> FourCc {
    match category {
        ArmyUnitCategory::Garrison => fourcc!("pic0"),
        ArmyUnitCategory::LightInfantry => fourcc!("pic1"),
        ArmyUnitCategory::LineInfantry => fourcc!("pic2"),
        ArmyUnitCategory::EliteInfantry => fourcc!("pic3"),
        ArmyUnitCategory::LightCavalry => fourcc!("pic4"),
        ArmyUnitCategory::HeavyCavalry => fourcc!("pic5"),
        ArmyUnitCategory::FieldArtillery => fourcc!("pic6"),
        ArmyUnitCategory::SiegeArtillery => fourcc!("pic7"),
        ArmyUnitCategory::Engineers => fourcc!("pic8"),
        ArmyUnitCategory::Generals => fourcc!("pic9"),
    }
}

fn arrow_tag(category: ArmyUnitCategory) -> FourCc {
    match category {
        ArmyUnitCategory::Garrison => fourcc!("arr0"),
        ArmyUnitCategory::LightInfantry => fourcc!("arr1"),
        ArmyUnitCategory::LineInfantry => fourcc!("arr2"),
        ArmyUnitCategory::EliteInfantry => fourcc!("arr3"),
        ArmyUnitCategory::LightCavalry => fourcc!("arr4"),
        ArmyUnitCategory::HeavyCavalry => fourcc!("arr5"),
        ArmyUnitCategory::FieldArtillery => fourcc!("arr6"),
        ArmyUnitCategory::SiegeArtillery => fourcc!("arr7"),
        ArmyUnitCategory::Engineers => fourcc!("arr8"),
        ArmyUnitCategory::Generals => fourcc!("arr9"),
    }
}
