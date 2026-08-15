use super::generated;
use super::retail::{RetailTag, RetailUiAssets, find_descendant};
use super::session::{GameSession, apply_turn_stop};
use crate::AppState;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::PhaseCode;
use imperialism_formats::{RetailTextStylePreset, fourcc};

#[derive(Component, Clone, Copy)]
enum TurnCinematicKind {
    GreatPowerDefeat,
    PostCombatDiplomacy,
    PlayerEliminated,
    Victory,
    DecadeCinematic,
}

#[derive(Component)]
struct TurnCinematicRoot;

#[derive(Component)]
struct TurnCinematicAction;

pub(crate) struct TurnCinematicPlugin;

impl Plugin for TurnCinematicPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::GreatPowerDefeat),
            (spawn_great_power_defeat, bind_turn_cinematic).chain(),
        )
        .add_systems(
            OnEnter(AppState::PostCombatDiplomacy),
            (spawn_post_combat_diplomacy, bind_turn_cinematic).chain(),
        )
        .add_systems(
            OnEnter(AppState::PlayerEliminated),
            (spawn_player_eliminated, bind_turn_cinematic).chain(),
        )
        .add_systems(
            OnEnter(AppState::Victory),
            (spawn_victory, bind_turn_cinematic).chain(),
        )
        .add_systems(
            OnEnter(AppState::DecadeCinematic),
            (spawn_decade_cinematic, bind_turn_cinematic).chain(),
        )
        .add_observer(on_turn_cinematic_activate.run_if(resource_exists::<GameSession>));
    }
}

fn spawn_great_power_defeat(commands: Commands) {
    spawn_kind(commands, TurnCinematicKind::GreatPowerDefeat);
}

fn spawn_post_combat_diplomacy(commands: Commands) {
    spawn_kind(commands, TurnCinematicKind::PostCombatDiplomacy);
}

fn spawn_player_eliminated(commands: Commands) {
    spawn_kind(commands, TurnCinematicKind::PlayerEliminated);
}

fn spawn_victory(commands: Commands) {
    spawn_kind(commands, TurnCinematicKind::Victory);
}

fn spawn_decade_cinematic(commands: Commands) {
    spawn_kind(commands, TurnCinematicKind::DecadeCinematic);
}

fn spawn_kind(mut commands: Commands, kind: TurnCinematicKind) {
    let app_state = match kind {
        TurnCinematicKind::GreatPowerDefeat => AppState::GreatPowerDefeat,
        TurnCinematicKind::PostCombatDiplomacy => AppState::PostCombatDiplomacy,
        TurnCinematicKind::PlayerEliminated => AppState::PlayerEliminated,
        TurnCinematicKind::Victory => AppState::Victory,
        TurnCinematicKind::DecadeCinematic => AppState::DecadeCinematic,
    };
    let root = commands.spawn_scene(generated::linger_2020()).id();
    commands
        .entity(root)
        .insert((TurnCinematicRoot, kind, DespawnOnExit(app_state)));
}

fn bind_turn_cinematic(
    mut commands: Commands,
    root: Single<(Entity, &TurnCinematicKind), Added<TurnCinematicRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
) {
    let (root, kind) = *root;
    let (title, body) = cinematic_copy(*kind);
    let notice_color = TextColor(assets.palette_color(0));
    let title_entity = find_descendant(root, fourcc!("titl"), &children, &tags);
    let (title_font, title_layout, title_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail turn-cinematic title style");
    commands.entity(title_entity).insert((
        Text::new(title),
        title_font,
        title_layout,
        title_line_height,
        notice_color,
    ));
    let body_entity = find_descendant(root, fourcc!("info"), &children, &tags);
    let (body_font, body_layout, body_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail turn-cinematic body style");
    commands.entity(body_entity).insert((
        Text::new(body),
        body_font,
        body_layout,
        body_line_height,
        notice_color,
    ));
    commands
        .entity(find_descendant(root, fourcc!("okay"), &children, &tags))
        .insert((TurnCinematicAction, ActivateOnPress))
        .remove::<InteractionDisabled>();
    commands
        .entity(find_descendant(root, fourcc!("cncl"), &children, &tags))
        .insert(Visibility::Hidden);
}

fn cinematic_copy(kind: TurnCinematicKind) -> (&'static str, &'static str) {
    match kind {
        TurnCinematicKind::GreatPowerDefeat => (
            "Defeat",
            "Your great power has collapsed under financial pressure.",
        ),
        TurnCinematicKind::PostCombatDiplomacy => (
            "War Report",
            "Combat reports are ready. Review the diplomatic consequences of this season's battles.",
        ),
        TurnCinematicKind::PlayerEliminated => (
            "Eliminated",
            "Your nation has fallen and is no longer an independent great power.",
        ),
        TurnCinematicKind::Victory => ("Victory", "You are the last remaining great power."),
        TurnCinematicKind::DecadeCinematic => (
            "A New Decade",
            "The great powers convene as another decade begins.",
        ),
    }
}

fn on_turn_cinematic_activate(
    activate: On<Activate>,
    actions: Query<(), With<TurnCinematicAction>>,
    roots: Query<&TurnCinematicKind, With<TurnCinematicRoot>>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    if actions.get(activate.entity).is_err() {
        return;
    }
    let Ok(kind) = roots.single() else {
        return;
    };
    match *kind {
        TurnCinematicKind::PostCombatDiplomacy => {
            apply_turn_stop(
                session.game.acknowledge_post_combat_diplomacy(),
                &mut next_state,
            );
        }
        TurnCinematicKind::DecadeCinematic => {
            apply_turn_stop(session.game.acknowledge_decade_cinematic(), &mut next_state);
        }
        TurnCinematicKind::GreatPowerDefeat
            if session.game.turn().phase() != PhaseCode::DEAL_BOOK =>
        {
            apply_turn_stop(session.game.advance_turn(), &mut next_state);
        }
        TurnCinematicKind::Victory
            if session.game.turn().phase() != PhaseCode::CITY_AND_TRANSPORT =>
        {
            apply_turn_stop(session.game.advance_turn(), &mut next_state);
        }
        TurnCinematicKind::GreatPowerDefeat
        | TurnCinematicKind::PlayerEliminated
        | TurnCinematicKind::Victory => {
            commands.remove_resource::<GameSession>();
            next_state.set(AppState::MainMenu);
        }
    }
}
