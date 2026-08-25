use super::game_shell::bind_game_status_display;
use super::generated;
use super::hover_help::get_string;
use super::retail::{RetailTree, RetailUiAssets};
use super::session::{GameSession, apply_turn_stop};
use crate::AppState;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::{PictureId, fourcc};

const ABILITY_STATUS_PICTURE_INDEX: TechnologyTable<i16> = TechnologyTable::from_array([
    0, 1, 3, 2, 7, 5, 6, 9, 10, 4, 8, 16, 12, 19, 22, 11, 17, 13, 14, 21, 15, 18, 26, 20, 23, 28,
    24, 25, 27,
]);

#[derive(Component)]
struct TechnologyAdvanceRoot;

#[derive(Component, Clone, Copy)]
enum TechnologyAdvanceDisplay {
    Picture,
    Text,
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
            project_technology_advance.run_if(
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
    commands
        .entity(tree.find(root, fourcc!("main")))
        .insert(TechnologyAdvanceDisplay::Picture);
    commands
        .entity(tree.find(root, fourcc!("text")))
        .insert((TechnologyAdvanceDisplay::Text, Text::default()));
    commands
        .entity(tree.find(root, fourcc!("end ")))
        .insert(ActivateOnPress)
        .remove::<InteractionDisabled>()
        .observe(on_technology_advance_activate);
}

fn project_technology_advance(
    session: Res<GameSession>,
    added: Query<(), Added<TechnologyAdvanceDisplay>>,
    mut assets: RetailUiAssets,
    mut pictures: Query<(&TechnologyAdvanceDisplay, &mut ImageNode)>,
    mut texts: Query<(&TechnologyAdvanceDisplay, &mut Text), Without<ImageNode>>,
) {
    if super::projection_idle(&session, !added.is_empty()) {
        return;
    }
    let Some(tech) = session.game.current_technology_report() else {
        return;
    };
    let picture_id = PictureId::new(ABILITY_STATUS_PICTURE_INDEX[tech] + 0x897);
    let picture = assets
        .picture(picture_id)
        .expect("technology status picture must load");
    let status = get_string(&assets, 0x2712, i16::from(tech.retail()));
    let prefix = get_string(&assets, 0x274e, i16::from(tech.retail()) - 1);
    let body = format!("{status}\n\n{prefix}");
    for (display, mut image) in &mut pictures {
        if matches!(*display, TechnologyAdvanceDisplay::Picture) {
            image.image = picture.clone();
        }
    }
    for (display, mut text) in &mut texts {
        if matches!(*display, TechnologyAdvanceDisplay::Text) {
            text.0.clone_from(&body);
        }
    }
}

fn on_technology_advance_activate(
    _activate: On<Activate>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    match session.game.acknowledge_technology_report() {
        TurnStop::TechnologyAdvance => {}
        stop => apply_turn_stop(stop, &mut next_state),
    }
}
