use super::generated::{self, Linger4122};
use super::retail::RetailUiAssets;
use super::window::{DismissWindow, ModalCancel, ModalWindow};
use crate::{AppState, ReturnTo};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};

#[derive(Component)]
struct OpenQueryFloater;

#[derive(Component)]
struct QueryFloaterRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum QueryFloaterAction {
    Advice,
    DealBook,
}

pub(crate) struct QueryFloaterPlugin;

impl Plugin for QueryFloaterPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Update, bind_query_floaters);
    }
}

pub(crate) fn bind_query_floater_control(commands: &mut Commands, quer: Entity) {
    commands
        .entity(quer)
        .insert((OpenQueryFloater, ActivateOnPress))
        .remove::<InteractionDisabled>()
        .observe(on_open_query_floater);
}

fn on_open_query_floater(
    _activate: On<Activate>,
    state: Res<State<AppState>>,
    mut commands: Commands,
) {
    let ui = generated::spawn_linger_4122(&mut commands);
    commands.entity(ui.root).insert((
        QueryFloaterRoot,
        ui,
        ModalWindow,
        DespawnOnExit(*state.get()),
    ));
}

fn bind_query_floaters(
    mut commands: Commands,
    added: Query<&Linger4122, Added<QueryFloaterRoot>>,
    mut assets: RetailUiAssets,
) {
    for ui in &added {
        let (font, layout, line_height, _) = assets
            .text_style(imperialism_formats::RetailTextStylePreset {
                font_family: 1,
                face_flags: 0,
                point_size: 12,
                alignment: -2,
            })
            .expect("retail query-floater label style");
        for (entity, index) in [
            (ui.titl, 1),
            (ui.tex0, 2),
            (ui.tex1, 3),
            (ui.tex2, 4),
            (ui.tex3, 5),
            (ui.tex4, 6),
            (ui.tex5, 7),
            (ui.tex6, 8),
        ] {
            let text = assets
                .string(0x2757, index)
                .expect("retail query-floater label must load");
            commands.entity(entity).insert((
                Text::new(text),
                font.clone(),
                layout,
                line_height,
                TextColor(Color::WHITE),
            ));
        }
        commands
            .entity(ui.advi)
            .insert((QueryFloaterAction::Advice, ActivateOnPress, DismissWindow))
            .remove::<InteractionDisabled>()
            .observe(on_query_floater_activate);
        commands
            .entity(ui.deal)
            .insert((QueryFloaterAction::DealBook, ActivateOnPress, DismissWindow))
            .remove::<InteractionDisabled>()
            .observe(on_query_floater_activate);
        commands
            .entity(ui.cncl)
            .insert((ActivateOnPress, ModalCancel, DismissWindow))
            .remove::<InteractionDisabled>();
        for entity in [ui.oref, ui.news, ui.batt, ui.char] {
            commands.entity(entity).insert(InteractionDisabled);
        }
    }
}

fn on_query_floater_activate(
    activate: On<Activate>,
    actions: Query<&QueryFloaterAction>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    match *action {
        QueryFloaterAction::Advice => {
            super::map_help::spawn(&mut commands, *state.get());
        }
        QueryFloaterAction::DealBook => {
            commands.insert_resource(ReturnTo(*state.get()));
            next_state.set(AppState::DealBook);
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
            .add_plugins(crate::ui::UiWindowPlugin)
            .insert_state(AppState::Trade)
            .add_observer(on_query_floater_activate);
        let root = app.world_mut().spawn((QueryFloaterRoot, ModalWindow)).id();
        let action = app
            .world_mut()
            .spawn((QueryFloaterAction::DealBook, DismissWindow, ChildOf(root)))
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
    }
}
