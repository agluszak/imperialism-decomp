//! Right-hand navy command page (`unav` / `TNavyToolbarCluster`).

use super::super::retail::{RetailTree, RetailUiAssets};
use super::map_interaction::{
    MapInteractionMode, StrategicInteraction, StrategicViewport, cycle_map_interaction_selection,
};
use super::map_modals::spawn_navy_roster;
use crate::AppState;
use crate::ui::{GameSession, MapViewOrigin};
use bevy::prelude::*;
use bevy::ui::{Checked, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::{NavalAggression, NavyRosterKind, NavyToolbarClass};
use imperialism_formats::*;

const PAGE_TAG: FourCc = fourcc!("unav");
const NAVY_PAGE_VISIBLE: Vec2 = Vec2::new(0.0, 0x90 as f32);
const PAGE_PARKED: Vec2 = Vec2::new(-1000.0, -1000.0);
const ARROW_ATLAS: i16 = 804;
const TRANSPARENT_INDEX: u8 = 0x10;

#[derive(Component)]
pub(super) struct NavyToolbarPage;

#[derive(Component, Clone, Copy)]
struct NavyClass(NavyToolbarClass);

#[derive(Component)]
struct NavyClassShip;

#[derive(Component, Clone, Copy)]
struct NavyClassArrow(NavyToolbarClass);

#[derive(Component, Clone, Copy)]
enum NavyCommand {
    Defend,
    Done,
    Next,
    Bomb,
    Aggression(NavalAggression),
}

#[derive(Component)]
struct NavyCountLabel;

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        sync_navy_toolbar.run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn bind_navy_toolbar(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let page = tree.find(root, PAGE_TAG);
    commands.entity(page).insert((
        NavyToolbarPage,
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(PAGE_PARKED.x),
            top: Val::Px(PAGE_PARKED.y),
            width: Val::Px(123.0),
            height: Val::Px(308.0),
            ..default()
        },
    ));
    let arrow_atlas = assets
        .transparent_picture(PictureId::new(ARROW_ATLAS), TRANSPARENT_INDEX)
        .expect("retail numbered-arrow atlas 804 must load");
    const CLASS_TAGS: [(NavyToolbarClass, FourCc); 4] = [
        (NavyToolbarClass::Class0, fourcc!("cls0")),
        (NavyToolbarClass::Class1, fourcc!("cls1")),
        (NavyToolbarClass::Class2, fourcc!("cls2")),
        (NavyToolbarClass::Class3, fourcc!("cls3")),
    ];
    for (class, tag) in CLASS_TAGS {
        let cluster = tree.child(page, tag);
        commands.entity(cluster).insert(NavyClass(class));
        let ship = tree.child(cluster, fourcc!("ship"));
        commands
            .entity(ship)
            .insert((NavyClassShip, Visibility::Hidden));
        let arrow = tree.child(cluster, fourcc!("arro"));
        commands
            .entity(arrow)
            .insert((
                NavyClassArrow(class),
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
            .observe(on_navy_class_arrow);
        spawn_count_label(commands, arrow, assets);
    }
    for (tag, command) in [
        (fourcc!("dfnd"), NavyCommand::Defend),
        (fourcc!("done"), NavyCommand::Done),
        (fourcc!("next"), NavyCommand::Next),
        (fourcc!("bomb"), NavyCommand::Bomb),
        (
            fourcc!("agr0"),
            NavyCommand::Aggression(NavalAggression::Cautious),
        ),
        (
            fourcc!("agr1"),
            NavyCommand::Aggression(NavalAggression::Balanced),
        ),
        (
            fourcc!("agr2"),
            NavyCommand::Aggression(NavalAggression::Aggressive),
        ),
    ] {
        commands
            .entity(tree.child(page, tag))
            .insert((command, ActivateOnPress))
            .observe(on_navy_command);
    }
}

pub(crate) fn navy_page_position(mode: MapInteractionMode) -> Vec2 {
    if mode == MapInteractionMode::Navy {
        NAVY_PAGE_VISIBLE
    } else {
        PAGE_PARKED
    }
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn sync_navy_toolbar(
    session: Res<GameSession>,
    interactions: Query<Ref<StrategicInteraction>>,
    mut assets: RetailUiAssets,
    mut pages: Query<&mut Node, With<NavyToolbarPage>>,
    mut ships: Query<
        (&ChildOf, &mut ImageNode, &mut Visibility),
        (With<NavyClassShip>, Without<NavyClassArrow>),
    >,
    mut arrows: Query<
        (
            Entity,
            &NavyClassArrow,
            &mut ImageNode,
            &mut Visibility,
            &ChildOf,
        ),
        Without<NavyClassShip>,
    >,
    mut counts: Query<(&ChildOf, &mut Text, &NavyCountLabel)>,
    classes: Query<(Entity, &NavyClass)>,
    mut radios: Query<(&NavyCommand, Entity)>,
    mut commands: Commands,
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
    let position = navy_page_position(interaction.mode);
    page.left = Val::Px(position.x);
    page.top = Val::Px(position.y);
    let force = interaction
        .navy
        .force
        .filter(|_| interaction.mode == MapInteractionMode::Navy);
    let toolbar = session.game.navy_toolbar_counts(force);
    for (entity, class) in &classes {
        let available = toolbar.available[class.0];
        let selected = toolbar.selected[class.0];
        let picture = session
            .game
            .navy_toolbar_class_ship_type(class.0)
            .map(|ship_type| i16::from(ship_type.retail()) + 0x5e6);
        for (child_of, mut image, mut visibility) in &mut ships {
            if child_of.parent() != entity {
                continue;
            }
            if available > 0 {
                if let Some(picture_id) = picture {
                    image.image = assets
                        .picture(PictureId::new(picture_id))
                        .expect("retail navy class picture must load");
                }
                *visibility = Visibility::Visible;
            } else {
                *visibility = Visibility::Hidden;
            }
        }
        for (arrow_entity, arrow, _, mut visibility, child_of) in &mut arrows {
            if child_of.parent() != entity || arrow.0 != class.0 {
                continue;
            }
            if available > 0 {
                *visibility = Visibility::Visible;
                set_count_text(arrow_entity, &mut counts, Some(i32::from(selected.max(0))));
            } else {
                *visibility = Visibility::Hidden;
                set_count_text(arrow_entity, &mut counts, None);
            }
        }
    }
    let aggression = force.and_then(|id| session.game.task_force(id).map(|f| f.aggression));
    for (command, entity) in &mut radios {
        if let NavyCommand::Aggression(level) = *command {
            if aggression == Some(level) {
                commands.entity(entity).insert(Checked);
            } else {
                commands.entity(entity).remove::<Checked>();
            }
        }
    }
}

fn set_count_text(
    parent: Entity,
    counts: &mut Query<(&ChildOf, &mut Text, &NavyCountLabel)>,
    value: Option<i32>,
) {
    for (child_of, mut text, _) in counts.iter_mut() {
        if child_of.parent() == parent {
            text.0 = value
                .filter(|&count| count >= 0)
                .map(|count| count.to_string())
                .unwrap_or_default();
        }
    }
}

fn spawn_count_label(commands: &mut Commands, parent: Entity, assets: &mut RetailUiAssets) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 0,
            face_flags: 0,
            point_size: 10,
            alignment: 1,
        })
        .expect("retail navy count text style");
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(7.0),
            top: Val::Px(0.0),
            width: Val::Px(11.0),
            height: Val::Px(16.0),
            ..default()
        },
        Text::new(""),
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(0x28)),
        Pickable::IGNORE,
        NavyCountLabel,
        ChildOf(parent),
    ));
}

fn on_navy_command(
    activate: On<Activate>,
    commands_query: Query<&NavyCommand>,
    keys: Res<ButtonInput<KeyCode>>,
    mut commands: Commands,
    mut session: ResMut<GameSession>,
    mut origin: ResMut<MapViewOrigin>,
    mut interactions: Query<(&mut StrategicInteraction, &mut StrategicViewport)>,
) {
    let Ok(command) = commands_query.get(activate.entity) else {
        return;
    };
    let Ok((mut interaction, mut viewport)) = interactions.single_mut() else {
        return;
    };
    match *command {
        NavyCommand::Aggression(level) => {
            if let Some(force) = interaction.navy.force {
                session.game.set_task_force_aggression(force, level);
            }
        }
        NavyCommand::Defend => {
            if let Some(force) = interaction.navy.force {
                session.game.drop_task_force_ships(force, false);
            }
            cycle_map_interaction_selection(
                &mut session,
                &mut origin,
                &mut interaction,
                &mut viewport,
            );
        }
        NavyCommand::Done => {
            if let Some(force) = interaction.navy.force {
                session.game.drop_task_force_ships(force, true);
            }
            cycle_map_interaction_selection(
                &mut session,
                &mut origin,
                &mut interaction,
                &mut viewport,
            );
        }
        NavyCommand::Next => {
            cycle_map_interaction_selection(
                &mut session,
                &mut origin,
                &mut interaction,
                &mut viewport,
            );
        }
        NavyCommand::Bomb => {
            let roster =
                if keys.pressed(KeyCode::ControlLeft) || keys.pressed(KeyCode::ControlRight) {
                    NavyRosterKind::Nation
                } else if let Some(force) = interaction.navy.force {
                    NavyRosterKind::TaskForce(force)
                } else {
                    return;
                };
            spawn_navy_roster(&mut commands, roster);
        }
    }
}

fn on_navy_class_arrow(
    activate: On<Activate>,
    arrows: Query<(&NavyClassArrow, &RelativeCursorPosition)>,
    mut session: ResMut<GameSession>,
    interactions: Query<&StrategicInteraction>,
) {
    let Ok((arrow, cursor)) = arrows.get(activate.entity) else {
        return;
    };
    let Ok(interaction) = interactions.single() else {
        return;
    };
    let Some(force) = interaction.navy.force else {
        return;
    };
    let Some(normalized) = cursor.normalized else {
        return;
    };
    if normalized.y == 0.0 {
        return;
    }
    // Top half 0x64 increment/select; bottom 0x65 decrement/deselect.
    session
        .game
        .select_task_force_toolbar_class(force, arrow.0, normalized.y < 0.0);
}
