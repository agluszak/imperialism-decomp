use super::game_shell::project_date_and_treasury;
use super::generated;
use super::newspaper::enter_newspaper;
use super::retail::{RetailTag, RetailUiAssets, find_descendant};
use super::session::GameSession;
use crate::{AppState, RetailAssetsResource};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::{PictureId, RetailAssets, fourcc};

const ABILITY_STATUS_PICTURE_INDEX: [i16; TECHNOLOGY_COUNT] = [
    0, 1, 3, 2, 7, 5, 6, 9, 10, 4, 8, 16, 12, 19, 22, 11, 17, 13, 14, 21, 15, 18, 26, 20, 23, 28,
    24, 25, 27,
];

#[derive(Resource, Clone, Copy)]
pub(crate) struct TechnologyAdvance(pub u8);

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
        .add_observer(on_technology_advance_activate);
    }
}

pub(crate) fn continue_after_capital(
    tech_id: Option<u8>,
    session: &mut GameState,
    assets: &RetailAssets,
    commands: &mut Commands,
    next_state: &mut NextState<AppState>,
) {
    if let Some(tech_id) = tech_id {
        commands.insert_resource(TechnologyAdvance(tech_id));
        next_state.set(AppState::TechnologyAdvance);
    } else {
        enter_newspaper(session, assets, commands, next_state);
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
    advance: Res<TechnologyAdvance>,
) {
    let root = *root;
    project_date_and_treasury(&mut commands, &mut assets, root, &children, &tags, &session);
    fill_technology_advance(
        &mut commands,
        &mut assets,
        root,
        &children,
        &tags,
        advance.0,
    );
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
    tech_id: u8,
) {
    let picture_id = PictureId::new(ABILITY_STATUS_PICTURE_INDEX[usize::from(tech_id)] + 0x897);
    let picture = assets
        .picture(picture_id)
        .expect("technology status picture must load");
    commands
        .entity(find_descendant(root, fourcc!("main"), children, tags))
        .insert(ImageNode::new(picture));

    let status = super::hover_help::get_string(assets, 0x2712, i16::from(tech_id));
    let prefix = super::hover_help::get_string(assets, 0x274e, i16::from(tech_id) - 1);
    commands
        .entity(find_descendant(root, fourcc!("text"), children, tags))
        .insert(Text::new(format!("{status}\n\n{prefix}")));
}

#[allow(clippy::too_many_arguments)]
fn on_technology_advance_activate(
    activate: On<Activate>,
    actions: Query<&TechnologyAdvanceAction>,
    mut session: ResMut<GameSession>,
    mut advance: ResMut<TechnologyAdvance>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    root: Query<Entity, With<TechnologyAdvanceRoot>>,
    mut assets: RetailUiAssets,
    retail: Res<RetailAssetsResource>,
) {
    if actions.get(activate.entity).is_err() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("technology report requires an active major nation");
    if let Some(tech_id) = session.0.acknowledge_technology_unlock(nation) {
        advance.0 = tech_id;
        let Ok(root) = root.single() else {
            return;
        };
        fill_technology_advance(&mut commands, &mut assets, root, &children, &tags, tech_id);
        return;
    }
    enter_newspaper(
        &mut session.0,
        retail.assets(),
        &mut commands,
        &mut next_state,
    );
}
