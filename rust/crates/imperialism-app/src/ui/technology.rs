use super::game_shell::bind_game_status_display;
use super::generated;
use super::retail::{RetailTree, RetailUiAssets};
use super::retail_resources::TechnologyRetailResources;
use super::session::{GameSession, apply_turn_stop};
use crate::AppState;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::fourcc;

#[derive(Component)]
struct TechnologyAdvanceRoot;

#[derive(Component)]
struct TechnologyAdvanceView {
    picture: Entity,
    text: Entity,
}

pub(crate) struct TechnologyAdvancePlugin;

impl Plugin for TechnologyAdvancePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::TechnologyAdvance),
            (spawn_technology_advance, bind_technology_advance).chain(),
        )
        .add_systems(
            Update,
            render_technology_advance.run_if(
                in_state(AppState::TechnologyAdvance).and_then(resource_exists::<GameSession>),
            ),
        );
    }
}

fn spawn_technology_advance(mut commands: Commands) {
    let root = commands.spawn_scene(generated::tech_2200()).id();
    commands.entity(root).insert((
        TechnologyAdvanceRoot,
        DespawnOnExit(AppState::TechnologyAdvance),
    ));
}

fn bind_technology_advance(
    mut commands: Commands,
    root: Single<Entity, Added<TechnologyAdvanceRoot>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    let root = *root;
    bind_game_status_display(&mut commands, &mut assets, root, &tree);
    commands.entity(root).insert(TechnologyAdvanceView {
        picture: tree.find(root, fourcc!("main")),
        text: tree.find(root, fourcc!("text")),
    });
    commands
        .entity(tree.find(root, fourcc!("end ")))
        .insert(ActivateOnPress)
        .remove::<InteractionDisabled>()
        .observe(on_technology_advance_activate);
}

fn render_technology_advance(
    session: Res<GameSession>,
    view: Single<Ref<TechnologyAdvanceView>>,
    mut assets: RetailUiAssets,
    mut pictures: Query<&mut ImageNode>,
    mut texts: Query<&mut Text>,
) {
    if !session.is_changed() && !view.is_added() {
        return;
    }
    let Some(tech) = session.game.current_technology_report() else {
        return;
    };
    let picture = assets.picture(tech.status_picture());
    let status = assets.string(tech.name_string());
    let prefix = assets.string(tech.description_string());
    let body = format!("{status}\n\n{prefix}");
    pictures
        .get_mut(view.picture)
        .expect("bound technology picture must exist")
        .image = picture;
    texts
        .get_mut(view.text)
        .expect("bound technology text must exist")
        .0 = body;
}

fn on_technology_advance_activate(
    _activate: On<Activate>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    session.game.acknowledge_technology_report();
    if !matches!(session.game.stop(), TurnStop::TechnologyReport(_)) {
        apply_turn_stop(session.game.stop(), &mut next_state);
    }
}
