use crate::AppState;
use crate::ui::{SpawnedView, UiActivated, UiCatalogResource, UiPictureResources, spawn_view};
use bevy::prelude::*;
use imperialism_formats::{ScopedViewId, UiNodeId, UiView as CatalogView};
use std::collections::HashMap;

const TOOLBAR_PARENT_TAGS: &[&str] = &["tool", "topB"];
/// Retail leave/end controls hang under `tool` or the diplomacy `too3` strip.
const LEAVE_PARENT_TAGS: &[&str] = &["tool", "too2", "too3"];

pub(crate) fn strategic_map_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "MapView.rsrc".to_owned(),
        resource_id: 2013,
    }
}

pub(crate) fn trade_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Trade.rsrc".to_owned(),
        resource_id: 2009,
    }
}

pub(crate) fn city_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Citymain.rsrc".to_owned(),
        resource_id: 2011,
    }
}

pub(crate) fn transport_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Transport.rsrc".to_owned(),
        resource_id: 2014,
    }
}

pub(crate) fn diplomacy_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Diplo.rsrc".to_owned(),
        resource_id: 2008,
    }
}

fn view_id_for_state(state: AppState) -> Option<ScopedViewId> {
    match state {
        AppState::StrategicMap => Some(strategic_map_view_id()),
        AppState::Trade => Some(trade_view_id()),
        AppState::City => Some(city_view_id()),
        AppState::Transport => Some(transport_view_id()),
        AppState::Diplomacy => Some(diplomacy_view_id()),
        AppState::MainMenu | AppState::RandomSetup => None,
    }
}

/// Toolbar navigation controls resolved once at spawn for the active main view.
#[derive(Resource, Clone, Copy, Debug, Eq, PartialEq)]
struct GameScreenNav {
    root: Entity,
    trade: Entity,
    transport: Entity,
    city: Entity,
    diplomacy: Entity,
    /// Present on trade/city/transport/diplomacy; returns to the strategic map.
    end_turn_or_leave: Option<Entity>,
}

#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
struct GameScreenInstance {
    root: Option<Entity>,
}

pub(crate) struct GameScreensPlugin;

impl Plugin for GameScreensPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<GameScreenInstance>().add_systems(
            Update,
            translate_game_screen_activations.run_if(in_game_screen),
        );
        for state in [
            AppState::StrategicMap,
            AppState::Trade,
            AppState::City,
            AppState::Transport,
            AppState::Diplomacy,
        ] {
            app.add_systems(OnEnter(state), enter_game_screen)
                .add_systems(OnExit(state), exit_game_screen);
        }
    }
}

fn in_game_screen(state: Res<State<AppState>>) -> bool {
    matches!(
        *state.get(),
        AppState::StrategicMap
            | AppState::Trade
            | AppState::City
            | AppState::Transport
            | AppState::Diplomacy
    )
}

fn enter_game_screen(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut pictures: UiPictureResources,
    state: Res<State<AppState>>,
    mut instance: ResMut<GameScreenInstance>,
) {
    let Some(view_id) = view_id_for_state(*state.get()) else {
        return;
    };
    let Some(spawned) = spawn_view(&mut commands, catalog.catalog(), &view_id, &mut pictures)
    else {
        return;
    };
    let view = catalog
        .catalog()
        .views
        .iter()
        .find(|view| view.id == view_id)
        .expect("game screen view was just spawned");
    let Some(nav) = resolve_game_screen_nav(view, &spawned) else {
        commands.entity(spawned.root).despawn();
        return;
    };
    commands.insert_resource(nav);
    instance.root = Some(spawned.root);
}

fn exit_game_screen(mut commands: Commands, mut instance: ResMut<GameScreenInstance>) {
    if let Some(root) = instance.root.take() {
        commands.entity(root).despawn();
    }
    commands.remove_resource::<GameScreenNav>();
}

fn resolve_game_screen_nav(view: &CatalogView, spawned: &SpawnedView) -> Option<GameScreenNav> {
    Some(GameScreenNav {
        root: spawned.root,
        trade: control_under_parents(view, spawned, "trad", TOOLBAR_PARENT_TAGS)?,
        transport: control_under_parents(view, spawned, "tran", TOOLBAR_PARENT_TAGS)?,
        city: control_under_parents(view, spawned, "city", TOOLBAR_PARENT_TAGS)?,
        diplomacy: control_under_parents(view, spawned, "dipl", TOOLBAR_PARENT_TAGS)?,
        end_turn_or_leave: control_under_parents(view, spawned, "end ", LEAVE_PARENT_TAGS),
    })
}

/// Resolve an interactive control under one of the given ancestor tags.
fn control_under_parents(
    view: &CatalogView,
    spawned: &SpawnedView,
    tag: &str,
    parents: &[&str],
) -> Option<Entity> {
    let by_id: HashMap<UiNodeId, &imperialism_formats::UiNode> =
        view.nodes.iter().map(|node| (node.id, node)).collect();
    view.nodes.iter().find_map(|node| {
        if node.tag.0 != tag || !node.interactive {
            return None;
        }
        let mut parent = node.parent;
        while let Some(parent_id) = parent {
            let parent_node = by_id.get(&parent_id)?;
            if parents.contains(&parent_node.tag.0.as_str()) {
                return Some(spawned.nodes[&node.id]);
            }
            parent = parent_node.parent;
        }
        None
    })
}

fn translate_game_screen_activations(
    mut activations: MessageReader<UiActivated>,
    nav: Option<Res<GameScreenNav>>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Some(nav) = nav.as_deref() else {
        return;
    };
    let current = *state.get();
    for activation in activations.read() {
        if activation.view != nav.root {
            continue;
        }
        let destination = if activation.control == nav.trade {
            Some(AppState::Trade)
        } else if activation.control == nav.transport {
            Some(AppState::Transport)
        } else if activation.control == nav.city {
            Some(AppState::City)
        } else if activation.control == nav.diplomacy {
            Some(AppState::Diplomacy)
        } else if nav.end_turn_or_leave == Some(activation.control) {
            Some(AppState::StrategicMap)
        } else {
            None
        };
        let Some(destination) = destination else {
            continue;
        };
        if destination != current {
            next_state.set(destination);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{
        PresentedViewId, UiRuntimePlugin, UiViewRoot, ViewRoot, WidgetTag, spawn_view_nodes,
    };
    use bevy::ui::InteractionDisabled;
    use imperialism_formats::{FourCc, UiCatalog};
    use std::collections::HashSet;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    fn catalog() -> UiCatalog {
        serde_json::from_str(CATALOG_JSON).unwrap()
    }

    fn register_structure_screens(app: &mut App) {
        app.init_resource::<GameScreenInstance>().add_systems(
            Update,
            translate_game_screen_activations.run_if(in_game_screen),
        );
        for state in [
            AppState::StrategicMap,
            AppState::Trade,
            AppState::City,
            AppState::Transport,
            AppState::Diplomacy,
        ] {
            app.add_systems(OnEnter(state), enter_game_screen_structure_only)
                .add_systems(OnExit(state), exit_game_screen);
        }
    }

    fn enter_game_screen_structure_only(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
        state: Res<State<AppState>>,
        mut instance: ResMut<GameScreenInstance>,
    ) {
        let Some(view_id) = view_id_for_state(*state.get()) else {
            return;
        };
        let catalog = catalog.catalog();
        let view = catalog
            .views
            .iter()
            .find(|view| view.id == view_id)
            .unwrap();
        let spawned = spawn_view_nodes(&mut commands, catalog.logical_resolution, view);
        let nav = resolve_game_screen_nav(view, &spawned).expect("toolbar nav controls");
        commands.insert_resource(nav);
        instance.root = Some(spawned.root);
    }

    fn app_at(state: AppState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog()))
            .add_plugins(bevy::state::app::StatesPlugin)
            .add_plugins(UiRuntimePlugin)
            .init_state::<AppState>();
        register_structure_screens(&mut app);
        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(state);
        app.update();
        app.update();
        app
    }

    fn current_roots(app: &mut App) -> HashSet<ScopedViewId> {
        let world = app.world_mut();
        world
            .query_filtered::<&PresentedViewId, With<UiViewRoot>>()
            .iter(world)
            .map(|view| view.0.clone())
            .collect()
    }

    fn activate_nav(app: &mut App, control: Entity) {
        let nav = *app.world().resource::<GameScreenNav>();
        let tag = app.world().get::<WidgetTag>(control).unwrap().0.clone();
        app.world_mut()
            .write_message(UiActivated {
                view: nav.root,
                control,
                tag,
            })
            .unwrap();
        app.update();
        app.update();
    }

    #[test]
    fn strategic_map_spawns_combined_map_with_toolbar_navigation() {
        let mut app = app_at(AppState::StrategicMap);
        assert_eq!(
            current_roots(&mut app),
            HashSet::from([strategic_map_view_id()])
        );
        let nav = *app.world().resource::<GameScreenNav>();
        for entity in [nav.trade, nav.transport, nav.city, nav.diplomacy] {
            assert!(app.world().get::<Button>(entity).is_some());
            assert!(app.world().get::<InteractionDisabled>(entity).is_none());
        }
        assert!(nav.end_turn_or_leave.is_none());
    }

    #[test]
    fn map_toolbar_opens_trade_city_transport_and_diplomacy() {
        let mut app = app_at(AppState::StrategicMap);
        let nav = *app.world().resource::<GameScreenNav>();
        activate_nav(&mut app, nav.trade);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Trade
        );
        assert_eq!(current_roots(&mut app), HashSet::from([trade_view_id()]));

        let nav = *app.world().resource::<GameScreenNav>();
        activate_nav(&mut app, nav.city);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::City
        );
        assert_eq!(current_roots(&mut app), HashSet::from([city_view_id()]));

        let nav = *app.world().resource::<GameScreenNav>();
        activate_nav(&mut app, nav.transport);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Transport
        );
        assert_eq!(
            current_roots(&mut app),
            HashSet::from([transport_view_id()])
        );

        let nav = *app.world().resource::<GameScreenNav>();
        activate_nav(&mut app, nav.diplomacy);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Diplomacy
        );
        assert_eq!(
            current_roots(&mut app),
            HashSet::from([diplomacy_view_id()])
        );
    }

    #[test]
    fn leave_control_returns_to_the_strategic_map() {
        let mut app = app_at(AppState::Trade);
        let nav = *app.world().resource::<GameScreenNav>();
        let leave = nav.end_turn_or_leave.expect("trade has end control");
        activate_nav(&mut app, leave);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::StrategicMap
        );
        assert_eq!(
            current_roots(&mut app),
            HashSet::from([strategic_map_view_id()])
        );
    }

    #[test]
    fn diplomacy_trade_radio_does_not_steal_toolbar_navigation() {
        let mut app = app_at(AppState::Diplomacy);
        let nav = *app.world().resource::<GameScreenNav>();
        let world = app.world_mut();
        let radio_trad = world
            .query::<(Entity, &ViewRoot, &WidgetTag, &Button)>()
            .iter(world)
            .find(|(entity, root, tag, _)| {
                root.0 == nav.root && tag.0.0 == "trad" && *entity != nav.trade
            })
            .map(|(entity, _, _, _)| entity)
            .expect("diplomacy has a non-toolbar trad control");
        app.world_mut()
            .write_message(UiActivated {
                view: nav.root,
                control: radio_trad,
                tag: FourCc("trad".to_owned()),
            })
            .unwrap();
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Diplomacy
        );
        activate_nav(&mut app, nav.trade);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Trade
        );
    }

    #[test]
    fn diplomacy_leave_returns_to_the_strategic_map() {
        let mut app = app_at(AppState::Diplomacy);
        let leave = app
            .world()
            .resource::<GameScreenNav>()
            .end_turn_or_leave
            .expect("diplomacy has end control");
        activate_nav(&mut app, leave);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::StrategicMap
        );
        assert_eq!(
            current_roots(&mut app),
            HashSet::from([strategic_map_view_id()])
        );
    }

    #[test]
    fn catalog_game_screens_expose_expected_roots() {
        let catalog = catalog();
        for (view_id, min_nodes) in [
            (strategic_map_view_id(), 70usize),
            (trade_view_id(), 160),
            (city_view_id(), 20),
            (transport_view_id(), 60),
            (diplomacy_view_id(), 60),
        ] {
            let view = catalog
                .views
                .iter()
                .find(|view| view.id == view_id)
                .unwrap_or_else(|| panic!("missing {view_id:?}"));
            assert!(view.nodes.len() >= min_nodes, "{view_id:?}");
            let spawned_ids = view
                .nodes
                .iter()
                .map(|node| node.id)
                .collect::<HashSet<_>>();
            assert_eq!(spawned_ids.len(), view.nodes.len());
        }
    }
}
