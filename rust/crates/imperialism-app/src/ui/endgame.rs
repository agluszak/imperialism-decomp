//! Retail cinematics, Council of Governors, Game Score, and high-score screens.

use super::generated;
use super::session::{GameSession, apply_turn_stop, remove_game_session};
use crate::media::{MovieBackend, MusicDirector, rgba_frame_to_image};
use crate::ui::load_save::SaveDirectory;
use crate::{AppState, RetailAssetsResource};
use bevy::prelude::*;
use bevy::ui::widget::NodeImageMode;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::{
    FourCc, MovieId, empty_high_score_table, fourcc, insert_high_score, read_scores_dat,
    write_scores_dat,
};
use std::time::Duration;

#[derive(Resource)]
struct ActiveCinematic {
    movie: MovieBackend,
    image: Handle<Image>,
}

#[derive(Component)]
struct CouncilRoot;

#[derive(Component)]
struct GameScoreRoot;

#[derive(Component)]
struct HighScoreRoot;

pub(crate) struct EndgamePlugin;

impl Plugin for EndgamePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::OpeningCinematic), spawn_opening_cinematic)
            .add_systems(
                Update,
                pump_opening_cinematic.run_if(in_state(AppState::OpeningCinematic)),
            )
            .add_systems(
                OnExit(AppState::OpeningCinematic),
                cleanup_opening_cinematic,
            )
            .add_systems(
                OnEnter(AppState::CouncilOfGovernors),
                (spawn_council, bind_council).chain(),
            )
            .add_systems(
                Update,
                project_council.run_if(
                    in_state(AppState::CouncilOfGovernors).and_then(resource_exists::<GameSession>),
                ),
            )
            .add_systems(
                OnEnter(AppState::GameScore),
                (spawn_game_score, bind_game_score).chain(),
            )
            .add_systems(
                Update,
                project_game_score
                    .run_if(in_state(AppState::GameScore).and_then(resource_exists::<GameSession>)),
            )
            .add_systems(
                OnEnter(AppState::HighScore),
                (spawn_high_score, bind_high_score).chain(),
            )
            .add_systems(
                Update,
                project_high_score.run_if(in_state(AppState::HighScore)),
            );
    }
}

fn spawn_opening_cinematic(
    mut commands: Commands,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut music: ResMut<MusicDirector>,
    mut session: Option<ResMut<GameSession>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    music.stop_all();
    let movie_id = session.as_ref().map_or(MovieId::Open, |session| {
        match session.game.opening_cinematic_movie() {
            CinematicKind::Vote => MovieId::Vote,
            CinematicKind::Win => MovieId::Win,
            CinematicKind::Lose => MovieId::Lose,
        }
    });
    let path = retail.assets().movie_path(movie_id);
    let movie = match MovieBackend::open(&path) {
        Ok(movie) => movie,
        Err(error) => {
            warn!("skipping unavailable retail movie {movie_id}: {error}");
            finish_opening_cinematic(&mut commands, &mut session, &mut next_state);
            return;
        }
    };
    if let Err(error) = movie.play() {
        warn!("skipping unplayable retail movie {movie_id}: {error}");
        finish_opening_cinematic(&mut commands, &mut session, &mut next_state);
        return;
    }

    let image = images.add(Image::default());
    commands.spawn_scene(opening_cinematic_scene(movie_id, image.clone()));
    commands.insert_resource(ActiveCinematic { movie, image });
}

fn opening_cinematic_scene(movie_id: MovieId, image: Handle<Image>) -> impl Scene {
    bsn! {
        template(move |_context| Ok(Name::new(format!("Retail movie: {movie_id}"))))
        template(|_context| Ok(DespawnOnExit(AppState::OpeningCinematic)))
        Node {
            position_type: PositionType::Absolute,
            width: Val::Percent(100.0),
            height: Val::Percent(100.0),
            justify_content: JustifyContent::Center,
            align_items: AlignItems::Center,
        }
        BackgroundColor(Color::BLACK)
        GlobalZIndex(100)
        Pickable::IGNORE
        Children [
            (
                Node {
                    width: Val::Px(640.0),
                    height: Val::Px(480.0),
                }
                template(move |_context| Ok(ImageNode::new(image.clone()).with_mode(NodeImageMode::Stretch)))
                Pickable::IGNORE
            )
        ]
    }
}

fn pump_opening_cinematic(
    active: Option<Res<ActiveCinematic>>,
    keyboard: Res<ButtonInput<KeyCode>>,
    mouse: Res<ButtonInput<MouseButton>>,
    mut images: ResMut<Assets<Image>>,
    mut commands: Commands,
    mut session: Option<ResMut<GameSession>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Some(active) = active else {
        return;
    };
    let skip = keyboard.just_pressed(KeyCode::Escape)
        || keyboard.just_pressed(KeyCode::Space)
        || keyboard.just_pressed(KeyCode::Enter)
        || keyboard.just_pressed(KeyCode::NumpadEnter)
        || mouse.get_just_pressed().next().is_some();

    let mut finished = skip;
    if !finished {
        match active.movie.pull_video_frame(Duration::ZERO) {
            Ok(Some(frame)) => {
                if let Some(mut image) = images.get_mut(&active.image) {
                    *image = rgba_frame_to_image(&frame);
                }
            }
            Ok(None) => {}
            Err(error) => {
                warn!("retail movie playback failed: {error}");
                finished = true;
            }
        }
        finished |= active.movie.reached_eos();
    }

    if finished {
        active.movie.stop();
        finish_opening_cinematic(&mut commands, &mut session, &mut next_state);
    }
}

fn cleanup_opening_cinematic(mut commands: Commands) {
    commands.remove_resource::<ActiveCinematic>();
}

fn finish_opening_cinematic(
    commands: &mut Commands,
    session: &mut Option<ResMut<GameSession>>,
    next_state: &mut NextState<AppState>,
) {
    commands.remove_resource::<ActiveCinematic>();
    let Some(session) = session.as_mut() else {
        next_state.set(AppState::MainMenu);
        return;
    };
    let stop = session.game.close_opening_cinematic();
    if stop == TurnStop::SessionEnded {
        remove_game_session(commands);
        next_state.set(AppState::MainMenu);
    } else {
        apply_turn_stop(stop, next_state);
    }
}

fn spawn_council(mut commands: Commands) {
    let ui = generated::spawn_diplo_2016(&mut commands);
    commands
        .entity(ui.root)
        .insert((CouncilRoot, ui, DespawnOnExit(AppState::CouncilOfGovernors)));
}

fn bind_council(mut commands: Commands, ui: Single<&generated::Diplo2016, Added<CouncilRoot>>) {
    commands
        .entity(ui.end)
        .insert(ActivateOnPress)
        .observe(on_council_close);
    for (entity, tag) in [
        (ui.can0, fourcc!("can0")),
        (ui.can1, fourcc!("can1")),
        (ui.num0, fourcc!("num0")),
        (ui.num1, fourcc!("num1")),
        (ui.num2, fourcc!("num2")),
    ] {
        commands.entity(entity).insert(CouncilText(tag));
    }
}

#[derive(Component)]
struct CouncilText(FourCc);

fn project_council(
    session: Res<GameSession>,
    added: Query<(), Added<CouncilRoot>>,
    mut texts: Query<(&CouncilText, &mut Text)>,
) {
    if super::projection_idle(&session, !added.is_empty()) {
        return;
    }
    let congress = &session.game.diplomacy().congress;
    let chairman = congress
        .chairman
        .and_then(|id| session.game.nations().display_name(id.nation()))
        .unwrap_or("")
        .to_owned();
    let counterpart = congress
        .counterpart
        .and_then(|id| session.game.nations().display_name(id.nation()))
        .unwrap_or("")
        .to_owned();
    for (label, mut text) in &mut texts {
        text.0 = match label.0 {
            tag if tag == fourcc!("can0") => chairman.clone(),
            tag if tag == fourcc!("can1") => counterpart.clone(),
            tag if tag == fourcc!("num0") => congress.chairman_support.to_string(),
            tag if tag == fourcc!("num1") => congress.counterpart_support.to_string(),
            tag if tag == fourcc!("num2") => congress.neutral_support.to_string(),
            _ => continue,
        };
    }
}

fn on_council_close(
    _activate: On<Activate>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    apply_turn_stop(session.game.close_council_of_governors(), &mut next_state);
}

fn spawn_game_score(mut commands: Commands) {
    let ui = generated::spawn_startup_1515(&mut commands);
    commands
        .entity(ui.root)
        .insert((GameScoreRoot, ui, DespawnOnExit(AppState::GameScore)));
}

fn bind_game_score(
    mut commands: Commands,
    ui: Single<&generated::Startup1515, Added<GameScoreRoot>>,
) {
    commands
        .entity(ui.done)
        .insert(ActivateOnPress)
        .observe(on_game_score_close);
    for (index, entity) in [
        ui.numa, ui.numb, ui.numc, ui.numd, ui.nume, ui.numf, ui.numg, ui.numh, ui.numi, ui.numj,
        ui.numk, ui.numl,
    ]
    .into_iter()
    .enumerate()
    {
        commands.entity(entity).insert(GameScoreValue(index));
    }
}

#[derive(Component)]
struct GameScoreValue(usize);

fn project_game_score(
    session: Res<GameSession>,
    added: Query<(), Added<GameScoreRoot>>,
    mut values: Query<(&GameScoreValue, &mut Text)>,
) {
    if super::projection_idle(&session, !added.is_empty()) {
        return;
    }
    let Some(nation) = MajorNationId::from_nation(session.game.turn().active_nation) else {
        return;
    };
    let rows = session.game.generate_game_score(nation).rows();
    for (slot, mut text) in &mut values {
        text.0 = rows[slot.0].to_string();
    }
}

fn on_game_score_close(
    _activate: On<Activate>,
    mut session: ResMut<GameSession>,
    save_dir: Res<SaveDirectory>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if let Some(nation) = MajorNationId::from_nation(session.game.turn().active_nation) {
        persist_high_score(&session.game, nation, &save_dir.0);
    }
    apply_turn_stop(session.game.close_game_score(), &mut next_state);
}

fn persist_high_score(state: &GameState, nation: MajorNationId, directory: &std::path::Path) {
    let path = directory.join("scores.dat");
    let mut table = std::fs::read(&path)
        .map(|bytes| read_scores_dat(&bytes))
        .unwrap_or_else(|_| empty_high_score_table());
    let score = state.generate_game_score(nation);
    let name = state.nations().display_name(nation.nation()).unwrap_or("");
    insert_high_score(&mut table, score.total, name);
    let _ = std::fs::write(&path, write_scores_dat(&table));
}

fn spawn_high_score(mut commands: Commands) {
    let ui = generated::spawn_startup_1504(&mut commands);
    commands
        .entity(ui.root)
        .insert((HighScoreRoot, ui, DespawnOnExit(AppState::HighScore)));
}

fn bind_high_score(
    mut commands: Commands,
    ui: Single<&generated::Startup1504, Added<HighScoreRoot>>,
) {
    commands
        .entity(ui.labl)
        .insert(ActivateOnPress)
        .observe(on_high_score_close);
}

fn project_high_score(
    save_dir: Option<Res<SaveDirectory>>,
    added: Query<(), Added<HighScoreRoot>>,
    ui: Query<&generated::Startup1504, With<HighScoreRoot>>,
    mut labels: Query<&mut Text>,
) {
    if added.is_empty() {
        return;
    }
    let Ok(ui) = ui.single() else {
        return;
    };
    let label = ui.labl;
    let table = save_dir
        .and_then(|dir| std::fs::read(dir.0.join("scores.dat")).ok())
        .map(|bytes| read_scores_dat(&bytes))
        .unwrap_or_else(empty_high_score_table);
    let mut listing = String::new();
    for (rank, entry) in table.iter().enumerate() {
        if !listing.is_empty() {
            listing.push('\n');
        }
        listing.push_str(&format!(
            "{:>2}. {:>6}  {}",
            rank + 1,
            entry.score,
            entry.name
        ));
    }
    if let Ok(mut text) = labels.get_mut(label) {
        text.0 = listing;
    }
}

fn on_high_score_close(
    _activate: On<Activate>,
    mut commands: Commands,
    mut session: Option<ResMut<GameSession>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if let Some(session) = session.as_mut() {
        let _ = session.game.close_high_scores();
    }
    remove_game_session(&mut commands);
    next_state.set(AppState::MainMenu);
}
