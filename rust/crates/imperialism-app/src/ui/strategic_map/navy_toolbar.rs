//! Right-hand navy command page (`unav` / `TNavyToolbarCluster`).

use super::super::retail::{
    NumberedArrowAction, NumberedArrowClick, NumberedArrowValue, RetailTree, RetailUiAssets,
    install_numbered_arrow,
};
use super::map_interaction::{StrategicMapSession, StrategicSelection};
use super::map_modals::spawn_navy_roster;
use crate::AppState;
use crate::ui::GameSession;
use bevy::prelude::*;
use bevy::ui::Checked;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::{NavalAggression, NavyRosterKind, NavyToolbarClass};
use imperialism_formats::*;

const PAGE_TAG: FourCc = fourcc!("unav");
const NAVY_PAGE_VISIBLE: Vec2 = Vec2::new(0.0, 0x90 as f32);
const PAGE_PARKED: Vec2 = Vec2::new(-1000.0, -1000.0);

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
        install_numbered_arrow(commands, arrow, assets);
        let class_capture = class;
        commands
            .entity(arrow)
            .insert((NavyClassArrow(class), Visibility::Hidden))
            .observe(
                move |click: On<NumberedArrowClick>,
                      mut session: ResMut<GameSession>,
                      map: Res<StrategicMapSession>| {
                    let Some(force) = map.selection.navy_force() else {
                        return;
                    };
                    match click.action {
                        NumberedArrowAction::Upper => {
                            session.game.select_task_force_toolbar_class(
                                force,
                                class_capture,
                                true,
                            );
                        }
                        NumberedArrowAction::Lower => {
                            session.game.select_task_force_toolbar_class(
                                force,
                                class_capture,
                                false,
                            );
                        }
                    }
                },
            );
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

pub(crate) fn navy_page_position(selection: StrategicSelection) -> Vec2 {
    if matches!(selection, StrategicSelection::Navy { .. }) {
        NAVY_PAGE_VISIBLE
    } else {
        PAGE_PARKED
    }
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn sync_navy_toolbar(
    session: Res<GameSession>,
    map: Res<StrategicMapSession>,
    mut assets: RetailUiAssets,
    mut pages: Query<&mut Node, With<NavyToolbarPage>>,
    mut ships: Query<(&ChildOf, &mut ImageNode, &mut Visibility), With<NavyClassShip>>,
    mut arrows: Query<(
        Entity,
        &NavyClassArrow,
        &mut Visibility,
        &mut NumberedArrowValue,
        &ChildOf,
    )>,
    classes: Query<(Entity, &NavyClass)>,
) {
    if !session.is_changed() && !map.is_changed() {
        return;
    }
    let Ok(mut page) = pages.single_mut() else {
        return;
    };
    let position = navy_page_position(map.selection);
    page.left = Val::Px(position.x);
    page.top = Val::Px(position.y);
    let force = map.selection.navy_force();
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
        for (_, arrow, mut visibility, mut numbered, child_of) in &mut arrows {
            if child_of.parent() != entity || arrow.0 != class.0 {
                continue;
            }
            if available > 0 {
                *visibility = Visibility::Visible;
                numbered.set_if_neq(NumberedArrowValue(i32::from(selected.max(0))));
            } else {
                *visibility = Visibility::Hidden;
                numbered.set_if_neq(NumberedArrowValue(0));
            }
        }
    }
}

fn sync_navy_aggression(
    session: Res<GameSession>,
    map: Res<StrategicMapSession>,
    radios: Query<(&NavyCommand, Entity)>,
    mut commands: Commands,
) {
    if !session.is_changed() && !map.is_changed() {
        return;
    }
    let force = map.selection.navy_force();
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

fn on_navy_command(
    activate: On<Activate>,
    commands_query: Query<&NavyCommand>,
    keys: Res<ButtonInput<KeyCode>>,
    mut commands: Commands,
    mut session: ResMut<GameSession>,
    mut map: ResMut<StrategicMapSession>,
) {
    let Ok(command) = commands_query.get(activate.entity) else {
        return;
    };
    match *command {
        NavyCommand::Aggression(level) => {
            if let Some(force) = map.selection.navy_force() {
                session.game.set_task_force_aggression(force, level);
            }
        }
        NavyCommand::Defend => {
            if let Some(force) = map.selection.navy_force() {
                session.game.drop_task_force_ships(force, false);
            }
            map.cycle_selection(&mut session.game);
        }
        NavyCommand::Done => {
            if let Some(force) = map.selection.navy_force() {
                session.game.drop_task_force_ships(force, true);
            }
            map.cycle_selection(&mut session.game);
        }
        NavyCommand::Next => {
            map.cycle_selection(&mut session.game);
        }
        NavyCommand::Bomb => {
            let roster =
                if keys.pressed(KeyCode::ControlLeft) || keys.pressed(KeyCode::ControlRight) {
                    NavyRosterKind::Nation
                } else if let Some(force) = map.selection.navy_force() {
                    NavyRosterKind::TaskForce(force)
                } else {
                    return;
                };
            spawn_navy_roster(&mut commands, roster);
        }
    }
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
        app.insert_resource(StrategicMapSession {
            selection: StrategicSelection::Navy {
                zone: None,
                force: Some(cautious),
            },
            view: Default::default(),
        });

        app.update();
        assert!(app.world().entity(agr0).contains::<Checked>());
        assert!(!app.world().entity(agr1).contains::<Checked>());
        assert!(!app.world().entity(agr2).contains::<Checked>());

        app.world_mut()
            .resource_mut::<StrategicMapSession>()
            .selection = StrategicSelection::Navy {
            zone: None,
            force: Some(aggressive),
        };
        app.update();
        assert!(!app.world().entity(agr0).contains::<Checked>());
        assert!(!app.world().entity(agr1).contains::<Checked>());
        assert!(app.world().entity(agr2).contains::<Checked>());
    }
}
