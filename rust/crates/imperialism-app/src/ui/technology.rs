use super::game_shell::bind_game_status_display;
use super::generated;
use super::retail::{RetailTag, RetailUiAssets, find_descendant};
use super::session::{GameSession, apply_turn_stop};
use crate::{AppState, RetailAssetsResource};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::fourcc;

const ABILITY_STATUS_PICTURE_INDEX: [i16; TECHNOLOGY_COUNT] = [
    0, 1, 3, 2, 7, 5, 6, 9, 10, 4, 8, 16, 12, 19, 22, 11, 17, 13, 14, 21, 15, 18, 26, 20, 23, 28,
    24, 25, 27,
];

#[derive(Component)]
struct TechnologyAdvanceRoot;

#[derive(Component, Clone, Copy)]
struct TechnologyAdvanceAction;

pub(crate) struct TechnologyAdvancePlugin;

impl Plugin for TechnologyAdvancePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::TechnologyAdvance),
            (spawn_technology_advance, bind_technology_advance).chain(),
        )
        .add_observer(on_technology_advance_activate.run_if(in_state(AppState::TechnologyAdvance)));
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
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let root = *root;
    let tech_id = session
        .game
        .current_technology_report()
        .expect("technology screen requires a core technology continuation");
    bind_game_status_display(&mut commands, &mut assets, root, &children, &tags, &session);
    fill_technology_advance(&mut commands, &mut assets, root, &children, &tags, tech_id);
    commands
        .entity(find_descendant(root, fourcc!("end "), &children, &tags))
        .insert((TechnologyAdvanceAction, ActivateOnPress))
        .remove::<InteractionDisabled>();
}

fn fill_technology_advance(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    tech_id: TechnologyId,
) {
    let picture_id =
        imperialism_formats::PictureId::new(ABILITY_STATUS_PICTURE_INDEX[tech_id.index()] + 0x897);
    let picture = assets
        .picture(picture_id)
        .expect("technology status picture must load");
    commands
        .entity(find_descendant(root, fourcc!("main"), children, tags))
        .insert(ImageNode::new(picture));

    let status = super::hover_help::get_string(assets, 0x2712, i16::from(tech_id.get()));
    let prefix = super::hover_help::get_string(assets, 0x274e, i16::from(tech_id.get()) - 1);
    commands
        .entity(find_descendant(root, fourcc!("text"), children, tags))
        .insert(Text::new(format!("{status}\n\n{prefix}")));
}

#[allow(clippy::too_many_arguments)]
fn on_technology_advance_activate(
    activate: On<Activate>,
    actions: Query<&TechnologyAdvanceAction>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    root: Option<Single<Entity, With<TechnologyAdvanceRoot>>>,
    mut assets: RetailUiAssets,
    retail: Res<RetailAssetsResource>,
    mut commands: Commands,
) {
    if actions.get(activate.entity).is_err() {
        return;
    }
    match session
        .game
        .acknowledge_technology_report(retail.assets().news_table().story_ids())
    {
        TurnStop::TechnologyAdvance(tech_id) => {
            let Some(root) = root else {
                return;
            };
            fill_technology_advance(&mut commands, &mut assets, *root, &children, &tags, tech_id);
        }
        stop => apply_turn_stop(stop, &mut next_state),
    }
}
