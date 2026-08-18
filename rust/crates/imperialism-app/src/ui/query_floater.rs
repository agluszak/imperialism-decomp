use super::generated;
use super::retail::{ModalDialog, RetailTree, RetailUiAssets, ancestor_with};
use crate::{AppState, ReturnTo};
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
    Advice,
    DealBook,
    Cancel,
}

pub(crate) struct QueryFloaterPlugin;

impl Plugin for QueryFloaterPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Update, bind_query_floaters);
    }
}

pub(crate) fn bind_query_floater_control(commands: &mut Commands, root: Entity, tree: &RetailTree) {
    commands
        .entity(tree.find(root, fourcc!("quer")))
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
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    for root in &roots {
        let view = tree.view(root);
        let (font, layout, line_height, _) = assets
            .text_style(imperialism_formats::RetailTextStylePreset {
                font_family: 1,
                face_flags: 0,
                point_size: 12,
                alignment: -2,
            })
            .expect("retail query-floater label style");
        for (tag, index) in QUERY_LABELS {
            let text = assets
                .string(0x2757, index)
                .expect("retail query-floater label must load");
            commands.entity(view.find(tag)).insert((
                Text::new(text),
                font.clone(),
                layout,
                line_height,
                TextColor(Color::WHITE),
            ));
        }
        commands
            .entity(view.find(fourcc!("advi")))
            .insert((QueryFloaterAction::Advice, ActivateOnPress))
            .remove::<InteractionDisabled>()
            .observe(on_query_floater_activate);
        commands
            .entity(view.find(fourcc!("deal")))
            .insert((QueryFloaterAction::DealBook, ActivateOnPress))
            .remove::<InteractionDisabled>()
            .observe(on_query_floater_activate);
        commands
            .entity(view.find(fourcc!("cncl")))
            .insert((QueryFloaterAction::Cancel, ActivateOnPress))
            .remove::<InteractionDisabled>()
            .observe(on_query_floater_activate);
        for tag in [
            fourcc!("oref"),
            fourcc!("news"),
            fourcc!("batt"),
            fourcc!("char"),
        ] {
            commands.entity(view.find(tag)).insert(InteractionDisabled);
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
    let root = ancestor_with(activate.entity, &parents, &roots)
        .expect("query floater action belongs to its dialog");
    match *action {
        QueryFloaterAction::Advice => {
            commands.entity(root).despawn();
            super::map_help::spawn(&mut commands);
        }
        QueryFloaterAction::DealBook => {
            commands.entity(root).despawn();
            commands.insert_resource(ReturnTo(*state.get()));
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
        assert_eq!(app.world().resource::<ReturnTo>().0, AppState::Trade);
        assert!(app.world().get_entity(root).is_err());
    }
}
