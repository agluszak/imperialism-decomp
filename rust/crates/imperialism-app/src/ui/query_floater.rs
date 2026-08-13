use super::RetailUiAssets;
use super::deal_book::DealBookReturn;
use super::generated;
use super::retail::{ModalDialog, RetailTag, find_descendant};
use crate::AppState;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_formats::{FourCc, fourcc};

const QUERY_LABELS: [(FourCc, i16); 8] = [
    (fourcc!("titl"), 1),
    (fourcc!("tex0"), 2),
    (fourcc!("tex1"), 3),
    (fourcc!("tex2"), 4),
    (fourcc!("tex3"), 5),
    (fourcc!("tex4"), 6),
    (fourcc!("tex5"), 7),
    (fourcc!("tex6"), 8),
];

#[derive(Component)]
struct OpenQueryFloater;

#[derive(Component)]
struct QueryFloaterRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum QueryFloaterAction {
    DealBook,
    Cancel,
}

pub(crate) struct QueryFloaterPlugin;

impl Plugin for QueryFloaterPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Update, bind_query_floaters);
    }
}

pub(crate) fn bind_query_floater_control(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) {
    commands
        .entity(find_descendant(root, fourcc!("quer"), children, tags))
        .insert((OpenQueryFloater, ActivateOnPress))
        .remove::<InteractionDisabled>()
        .observe(on_open_query_floater);
}

fn on_open_query_floater(
    activate: On<Activate>,
    controls: Query<(), With<OpenQueryFloater>>,
    modals: Query<(), With<ModalDialog>>,
    state: Res<State<AppState>>,
    mut commands: Commands,
) {
    if controls.get(activate.entity).is_err() || !modals.is_empty() {
        return;
    }
    let root = commands.spawn_scene(generated::linger_4122()).id();
    commands.entity(root).insert((
        QueryFloaterRoot,
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(*state.get()),
    ));
}

fn bind_query_floaters(
    mut commands: Commands,
    roots: Query<Entity, Added<QueryFloaterRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    assets: RetailUiAssets,
) {
    for root in &roots {
        for (tag, index) in QUERY_LABELS {
            let text = assets
                .string(0x2757, index)
                .expect("retail query-floater label must load");
            commands
                .entity(find_descendant(root, tag, &children, &tags))
                .insert(Text::new(text));
        }
        commands
            .entity(find_descendant(root, fourcc!("deal"), &children, &tags))
            .insert((QueryFloaterAction::DealBook, ActivateOnPress))
            .remove::<InteractionDisabled>()
            .observe(on_query_floater_activate);
        commands
            .entity(find_descendant(root, fourcc!("cncl"), &children, &tags))
            .insert((QueryFloaterAction::Cancel, ActivateOnPress))
            .remove::<InteractionDisabled>()
            .observe(on_query_floater_activate);
        for tag in [
            fourcc!("advi"),
            fourcc!("oref"),
            fourcc!("news"),
            fourcc!("batt"),
            fourcc!("char"),
        ] {
            commands
                .entity(find_descendant(root, tag, &children, &tags))
                .insert(InteractionDisabled);
        }
    }
}

fn on_query_floater_activate(
    activate: On<Activate>,
    actions: Query<&QueryFloaterAction>,
    parents: Query<&ChildOf>,
    roots: Query<(), With<QueryFloaterRoot>>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let mut entity = activate.entity;
    let root = loop {
        if roots.contains(entity) {
            break entity;
        }
        entity = parents
            .get(entity)
            .expect("query floater action belongs to its dialog")
            .parent();
    };
    match *action {
        QueryFloaterAction::DealBook => {
            commands.entity(root).despawn();
            commands.insert_resource(DealBookReturn(*state.get()));
            next_state.set(AppState::DealBook);
        }
        QueryFloaterAction::Cancel => {
            commands.entity(root).despawn();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deal_book_action_enters_the_book_and_records_the_origin() {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .insert_state(AppState::Trade)
            .add_observer(on_query_floater_activate);
        let root = app.world_mut().spawn(QueryFloaterRoot).id();
        let action = app
            .world_mut()
            .spawn((QueryFloaterAction::DealBook, ChildOf(root)))
            .id();

        app.world_mut()
            .commands()
            .trigger(Activate { entity: action });
        app.world_mut().flush();
        app.update();

        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::DealBook
        );
        assert_eq!(app.world().resource::<DealBookReturn>().0, AppState::Trade);
        assert!(app.world().get_entity(root).is_err());
    }
}
