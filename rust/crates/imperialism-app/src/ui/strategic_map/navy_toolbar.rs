//! Right-hand navy command page (`unav` / `TNavyToolbarCluster`).

use super::super::retail::{RetailTree, RetailUiAssets};
use super::map_interaction::{
    MapInteractionMode, StrategicInteraction, StrategicViewport, cycle_map_interaction_selection,
};
use super::map_modals::spawn_navy_roster;
use crate::AppState;
use crate::ui::GameSession;
use bevy::prelude::*;
use bevy::ui::{Checked, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::{NavalAggression, NavyToolbarClass};
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
        (sync_navy_toolbar, sync_navy_aggression).run_if(in_state(AppState::StrategicMap)),
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
}

fn sync_navy_aggression(
    session: Res<GameSession>,
    interactions: Query<Ref<StrategicInteraction>>,
    radios: Query<(&NavyCommand, Entity)>,
    mut commands: Commands,
) {
    let Ok(interaction) = interactions.single() else {
        return;
    };
    if !session.is_changed() && !interaction.is_changed() {
        return;
    }
    let force = interaction
        .navy
        .force
        .filter(|_| interaction.mode == MapInteractionMode::Navy);
    let aggression = force.and_then(|id| session.game.task_force(id).map(|f| f.aggression));
    for (command, entity) in &radios {
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
    mut commands: Commands,
    mut session: ResMut<GameSession>,
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
            cycle_map_interaction_selection(&mut session, &mut interaction, &mut viewport);
        }
        NavyCommand::Done => {
            if let Some(force) = interaction.navy.force {
                session.game.drop_task_force_ships(force, true);
            }
            cycle_map_interaction_selection(&mut session, &mut interaction, &mut viewport);
        }
        NavyCommand::Next => {
            cycle_map_interaction_selection(&mut session, &mut interaction, &mut viewport);
        }
        NavyCommand::Bomb => {
            if let Some(force) = interaction.navy.force {
                spawn_navy_roster(&mut commands, force);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::beginning_of_game_parts;
    use bevy::state::app::StatesPlugin;
    use imperialism_core::*;
    use indexmap::IndexMap;

    fn two_forces() -> (GameState, TaskForceId, TaskForceId) {
        let mut parts = beginning_of_game_parts();
        let nation = parts.turn.active_nation;
        let location = OceanZoneId::new(0);
        let ship = |name: &str, aggression: NavalAggression| ShipState {
            ship_type: ShipType::Frigate,
            location,
            aggression,
            nation,
            name: name.to_string(),
            strength: 900,
            experience: 0,
            selection: ShipSelection::Available,
        };
        let cautious_ship = parts.object_ids.ship();
        let aggressive_ship = parts.object_ids.ship();
        let cautious = parts.object_ids.task_force();
        let aggressive = parts.object_ids.task_force();
        parts
            .ships
            .insert(cautious_ship, ship("Cautious", NavalAggression::Cautious));
        parts.ships.insert(
            aggressive_ship,
            ship("Aggressive", NavalAggression::Aggressive),
        );
        parts.task_forces.insert(
            cautious,
            TaskForceState::from_parts(
                NavalAggression::Cautious,
                TaskForceOrder::None,
                TaskForceTarget::None,
                location,
                nation,
                false,
                -1,
                [(cautious_ship, true)]
                    .into_iter()
                    .collect::<IndexMap<_, _>>(),
            ),
        );
        parts.task_forces.insert(
            aggressive,
            TaskForceState::from_parts(
                NavalAggression::Aggressive,
                TaskForceOrder::None,
                TaskForceTarget::None,
                location,
                nation,
                false,
                -1,
                [(aggressive_ship, true)]
                    .into_iter()
                    .collect::<IndexMap<_, _>>(),
            ),
        );
        (GameState::from_parts(parts), cautious, aggressive)
    }

    #[test]
    fn aggression_radios_follow_selected_force_on_interaction_change() {
        let (state, cautious, aggressive) = two_forces();
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(StatesPlugin)
            .insert_state(AppState::StrategicMap)
            .insert_resource(GameSession::new(state))
            .add_systems(Update, sync_navy_aggression);

        let agr0 = app
            .world_mut()
            .spawn(NavyCommand::Aggression(NavalAggression::Cautious))
            .id();
        let agr1 = app
            .world_mut()
            .spawn(NavyCommand::Aggression(NavalAggression::Balanced))
            .id();
        let agr2 = app
            .world_mut()
            .spawn(NavyCommand::Aggression(NavalAggression::Aggressive))
            .id();
        let mut interaction = StrategicInteraction {
            mode: MapInteractionMode::Navy,
            ..default()
        };
        interaction.navy.force = Some(cautious);
        let interaction_entity = app.world_mut().spawn(interaction).id();

        app.update();
        assert!(app.world().entity(agr0).contains::<Checked>());
        assert!(!app.world().entity(agr1).contains::<Checked>());
        assert!(!app.world().entity(agr2).contains::<Checked>());

        app.world_mut()
            .entity_mut(interaction_entity)
            .get_mut::<StrategicInteraction>()
            .expect("navy interaction")
            .navy
            .force = Some(aggressive);
        app.update();
        assert!(!app.world().entity(agr0).contains::<Checked>());
        assert!(!app.world().entity(agr1).contains::<Checked>());
        assert!(app.world().entity(agr2).contains::<Checked>());
    }
}
