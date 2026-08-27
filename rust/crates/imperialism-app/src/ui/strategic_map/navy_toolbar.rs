//! Right-hand navy command page (`unav` / `TNavyToolbarCluster`).

use super::super::retail::{
    NumberedArrowParts, RetailTree, RetailUiAssets, ShipPlacardParts,
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
const NAVY_CLASS_ORDER: [NavyToolbarClass; 4] = [
    NavyToolbarClass::Class0,
    NavyToolbarClass::Class1,
    NavyToolbarClass::Class2,
    NavyToolbarClass::Class3,
];
const AGGRESSION_LEVELS: [NavalAggression; 3] = [
    NavalAggression::Cautious,
    NavalAggression::Balanced,
    NavalAggression::Aggressive,
];

#[derive(Clone, Copy)]
struct ArrowBinding {
    root: Entity,
    upper: Entity,
    lower: Entity,
    count: Entity,
}

#[derive(Clone, Copy)]
struct NavyClassView {
    ship_root: Entity,
    ship_text: Entity,
    arrow: ArrowBinding,
}

#[derive(Component)]
struct NavyToolbarView {
    classes: [NavyClassView; 4],
    aggression: [Entity; 3],
}

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        (sync_navy_toolbar, sync_navy_aggression).run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn bind_navy_toolbar(
    commands: &mut Commands,
    _assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    arrow_parts: &Query<&NumberedArrowParts>,
    ship_parts: &Query<&ShipPlacardParts>,
) {
    let page = tree.find(root, PAGE_TAG);
    const CLASS_TAGS: [(NavyToolbarClass, FourCc); 4] = [
        (NavyToolbarClass::Class0, fourcc!("cls0")),
        (NavyToolbarClass::Class1, fourcc!("cls1")),
        (NavyToolbarClass::Class2, fourcc!("cls2")),
        (NavyToolbarClass::Class3, fourcc!("cls3")),
    ];
    let mut classes = [NavyClassView {
        ship_root: Entity::PLACEHOLDER,
        ship_text: Entity::PLACEHOLDER,
        arrow: ArrowBinding {
            root: Entity::PLACEHOLDER,
            upper: Entity::PLACEHOLDER,
            lower: Entity::PLACEHOLDER,
            count: Entity::PLACEHOLDER,
        },
    }; 4];
    for (index, (class, tag)) in CLASS_TAGS.into_iter().enumerate() {
        let cluster = tree.child(page, tag);
        let ship = tree.child(cluster, fourcc!("ship"));
        let ShipPlacardParts { text: ship_text } = ship_parts
            .get(ship)
            .expect("navy ship placard parts")
            .clone();
        commands.entity(ship).insert(Visibility::Hidden);
        let arrow = tree.child(cluster, fourcc!("arro"));
        let NumberedArrowParts {
            upper,
            lower,
            count,
        } = arrow_parts
            .get(arrow)
            .expect("navy arrow parts")
            .clone();
        classes[index] = NavyClassView {
            ship_root: ship,
            ship_text,
            arrow: ArrowBinding {
                root: arrow,
                upper,
                lower,
                count,
            },
        };
        let class_capture = class;
        commands.entity(arrow).insert(Visibility::Hidden);
        commands.entity(upper).observe(
            move |_: On<Activate>,
                  mut session: ResMut<GameSession>,
                  map: Res<StrategicMapSession>| {
                let Some(force) = map.selection.navy_force() else {
                    return;
                };
                session
                    .game
                    .select_task_force_toolbar_class(force, class_capture, true);
            },
        );
        commands.entity(lower).observe(
            move |_: On<Activate>,
                  mut session: ResMut<GameSession>,
                  map: Res<StrategicMapSession>| {
                let Some(force) = map.selection.navy_force() else {
                    return;
                };
                session
                    .game
                    .select_task_force_toolbar_class(force, class_capture, false);
            },
        );
    }
    let aggression = [
        tree.child(page, fourcc!("agr0")),
        tree.child(page, fourcc!("agr1")),
        tree.child(page, fourcc!("agr2")),
    ];
    commands.entity(page).insert((
        NavyToolbarView {
            classes,
            aggression,
        },
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(PAGE_PARKED.x),
            top: Val::Px(PAGE_PARKED.y),
            width: Val::Px(123.0),
            height: Val::Px(308.0),
            ..default()
        },
    ));
    for (tag, level) in [
        (fourcc!("agr0"), NavalAggression::Cautious),
        (fourcc!("agr1"), NavalAggression::Balanced),
        (fourcc!("agr2"), NavalAggression::Aggressive),
    ] {
        commands
            .entity(tree.child(page, tag))
            .insert(ActivateOnPress)
            .observe(
                move |_: On<Activate>,
                      mut session: ResMut<GameSession>,
                      map: Res<StrategicMapSession>| {
                    if let Some(force) = map.selection.navy_force() {
                        session.game.set_task_force_aggression(force, level);
                    }
                },
            );
    }
    commands
        .entity(tree.child(page, fourcc!("dfnd")))
        .insert(ActivateOnPress)
        .observe(
            |_: On<Activate>,
             mut session: ResMut<GameSession>,
             mut map: ResMut<StrategicMapSession>| {
                if let Some(force) = map.selection.navy_force() {
                    session.game.drop_task_force_ships(force, false);
                }
                map.cycle_selection(&mut session.game);
            },
        );
    commands
        .entity(tree.child(page, fourcc!("done")))
        .insert(ActivateOnPress)
        .observe(
            |_: On<Activate>,
             mut session: ResMut<GameSession>,
             mut map: ResMut<StrategicMapSession>| {
                if let Some(force) = map.selection.navy_force() {
                    session.game.drop_task_force_ships(force, true);
                }
                map.cycle_selection(&mut session.game);
            },
        );
    commands
        .entity(tree.child(page, fourcc!("next")))
        .insert(ActivateOnPress)
        .observe(
            |_: On<Activate>,
             mut session: ResMut<GameSession>,
             mut map: ResMut<StrategicMapSession>| {
                map.cycle_selection(&mut session.game);
            },
        );
    commands
        .entity(tree.child(page, fourcc!("bomb")))
        .insert(ActivateOnPress)
        .observe(
            |_: On<Activate>,
             keys: Res<ButtonInput<KeyCode>>,
             mut commands: Commands,
             map: Res<StrategicMapSession>| {
                let roster =
                    if keys.pressed(KeyCode::ControlLeft) || keys.pressed(KeyCode::ControlRight) {
                        NavyRosterKind::Nation
                    } else if let Some(force) = map.selection.navy_force() {
                        NavyRosterKind::TaskForce(force)
                    } else {
                        return;
                    };
                spawn_navy_roster(&mut commands, roster);
            },
        );
}

pub(crate) fn navy_page_position(selection: StrategicSelection) -> Vec2 {
    if matches!(selection, StrategicSelection::Navy { .. }) {
        NAVY_PAGE_VISIBLE
    } else {
        PAGE_PARKED
    }
}

fn sync_navy_toolbar(
    session: Res<GameSession>,
    map: Res<StrategicMapSession>,
    mut assets: RetailUiAssets,
    mut pages: Query<(&mut Node, &NavyToolbarView)>,
    mut images: Query<&mut ImageNode>,
    mut visibility: Query<&mut Visibility>,
    mut texts: Query<&mut Text>,
) {
    if !session.is_changed() && !map.is_changed() {
        return;
    }
    let Ok((mut page, view)) = pages.single_mut() else {
        return;
    };
    let position = navy_page_position(map.selection);
    page.left = Val::Px(position.x);
    page.top = Val::Px(position.y);
    let force = map.selection.navy_force();
    let toolbar = session.game.navy_toolbar_counts(force);
    for (index, class) in NAVY_CLASS_ORDER.into_iter().enumerate() {
        let available = toolbar.available[class];
        let selected = toolbar.selected[class];
        let picture = session
            .game
            .navy_toolbar_class_ship_type(class)
            .map(|ship_type| i16::from(ship_type.retail()) + 0x5e6);
        let row = view.classes[index];
        if available > 0 {
            if let Some(picture_id) = picture {
                images.get_mut(row.ship_root).expect("navy ship").image = assets
                    .picture(PictureId::new(picture_id))
                    .expect("retail navy class picture must load");
            }
            *visibility.get_mut(row.ship_root).expect("navy ship") = Visibility::Visible;
            *visibility
                .get_mut(row.arrow.root)
                .expect("navy arrow") = Visibility::Visible;
            texts.get_mut(row.ship_text).expect("navy ship text").0 = available.to_string();
            texts.get_mut(row.arrow.count).expect("navy arrow count").0 =
                selected.max(0).to_string();
        } else {
            *visibility.get_mut(row.ship_root).expect("navy ship") = Visibility::Hidden;
            *visibility
                .get_mut(row.arrow.root)
                .expect("navy arrow") = Visibility::Hidden;
            texts.get_mut(row.ship_text).expect("navy ship text").0 = String::new();
            texts.get_mut(row.arrow.count).expect("navy arrow count").0 = String::new();
        }
    }
}

fn sync_navy_aggression(
    session: Res<GameSession>,
    map: Res<StrategicMapSession>,
    pages: Query<&NavyToolbarView>,
    mut commands: Commands,
) {
    if !session.is_changed() && !map.is_changed() {
        return;
    }
    let Ok(view) = pages.single() else {
        return;
    };
    let force = map.selection.navy_force();
    let aggression = force.and_then(|id| session.game.task_force(id).map(|f| f.aggression));
    for (&entity, &level) in view.aggression.iter().zip(AGGRESSION_LEVELS.iter()) {
        if aggression == Some(level) {
            commands.entity(entity).insert(Checked);
        } else {
            commands.entity(entity).remove::<Checked>();
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

        let agr0 = app.world_mut().spawn_empty().id();
        let agr1 = app.world_mut().spawn_empty().id();
        let agr2 = app.world_mut().spawn_empty().id();
        app.world_mut().spawn(NavyToolbarView {
            classes: [NavyClassView {
                ship_root: Entity::PLACEHOLDER,
                ship_text: Entity::PLACEHOLDER,
                arrow: ArrowBinding {
                    root: Entity::PLACEHOLDER,
                    upper: Entity::PLACEHOLDER,
                    lower: Entity::PLACEHOLDER,
                    count: Entity::PLACEHOLDER,
                },
            }; 4],
            aggression: [agr0, agr1, agr2],
        });
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
