use super::generated;
use super::retail::{RetailTree, RetailUiAssets};
use super::window::{ModalWindow, bind_modal_keys, dismiss_on_activate};
use crate::{AppState, ReturnTo};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Activate;
use imperialism_formats::{FourCc, fourcc};

const QUERY_LABELS: [(FourCc, u16); 8] = [
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
struct QueryFloaterRoot;

pub(crate) struct QueryFloaterPlugin;

impl Plugin for QueryFloaterPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Update, bind_query_floaters);
    }
}

pub(crate) fn bind_query_floater_control(commands: &mut Commands, root: Entity, tree: &RetailTree) {
    commands
        .entity(tree.find(root, fourcc!("quer")))
        .remove::<InteractionDisabled>()
        .observe(on_open_query_floater);
}

fn on_open_query_floater(
    _activate: On<Activate>,
    state: Res<State<AppState>>,
    mut commands: Commands,
) {
    let root = commands.spawn_scene(generated::linger_4122()).id();
    commands
        .entity(root)
        .insert((QueryFloaterRoot, ModalWindow, DespawnOnExit(*state.get())));
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
            .text_style(imperialism_formats::RetailTextStylePreset::explicit(
                1, 0, 12, -2,
            ))
            .expect("retail query-floater label style");
        for (tag, index) in QUERY_LABELS {
            let text = assets.ui_string(0x2757, index);
            commands.entity(view.find(tag)).insert((
                Text::new(text),
                font.clone(),
                layout,
                line_height,
                TextColor(Color::WHITE),
            ));
        }
        let advice = view.find(fourcc!("advi"));
        commands
            .entity(advice)
            .remove::<InteractionDisabled>()
            .observe(on_query_floater_advice);
        let deal = view.find(fourcc!("deal"));
        commands
            .entity(deal)
            .remove::<InteractionDisabled>()
            .observe(on_query_floater_deal_book);
        let cancel = view.find(fourcc!("cncl"));
        commands.entity(cancel).remove::<InteractionDisabled>();
        for button in [advice, deal, cancel] {
            dismiss_on_activate(&mut commands, button, root);
        }
        bind_modal_keys(&mut commands, root, None, Some(cancel));
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

fn on_query_floater_advice(
    _activate: On<Activate>,
    state: Res<State<AppState>>,
    mut commands: Commands,
) {
    super::map_help::spawn(&mut commands, *state.get());
}

fn on_query_floater_deal_book(
    _activate: On<Activate>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    commands.insert_resource(ReturnTo(*state.get()));
    next_state.set(AppState::DealBook);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deal_book_action_enters_the_book_and_records_the_origin() {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .add_plugins(crate::ui::UiWindowPlugin)
            .insert_state(AppState::Trade)
            .add_observer(on_query_floater_deal_book);
        let root = app.world_mut().spawn((QueryFloaterRoot, ModalWindow)).id();
        let action = app.world_mut().spawn(ChildOf(root)).id();
        dismiss_on_activate(&mut app.world_mut().commands(), action, root);
        app.world_mut().flush();

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
