#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use imperialism_testkit::{
    EvidenceKind, check_coarse, check_random_game_start, check_random_setup,
    check_random_setup_initial, check_snapshot, check_terrain,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "imperialism-oracle",
    about = "Validate native Imperialism runtime captures"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a coarse_map_generation capture.
    Coarse {
        /// Native runtime result.json.
        result: PathBuf,
        /// Seed passed to random_map_generation.
        #[arg(long)]
        seed: u32,
    },
    /// Validate a random_map_terrain capture.
    Terrain {
        /// Native runtime result.json.
        result: PathBuf,
        /// Runtime catalog scenario that produced the capture.
        #[arg(long)]
        scenario: String,
        /// Seed passed to the scenario.
        #[arg(long)]
        seed: u32,
    },
    /// Validate random_game_setup plus terrain captures for an explicit preview seed.
    RandomSetup {
        /// Native runtime result.json.
        result: PathBuf,
        /// Seed passed to random_map_generation.
        #[arg(long)]
        seed: u32,
    },
    /// Validate initial random-game setup defaults against the clock seed.
    RandomSetupInitial {
        /// Native runtime result.json.
        result: PathBuf,
        /// Seed passed to random_map_generation.
        #[arg(long)]
        seed: u32,
    },
    /// Validate create_random_game against a Normal+ pre-capital game_state capture.
    RandomGameStart {
        /// Native runtime result.json containing random_game_setup and game_state.
        result: PathBuf,
        /// Seed passed to random_game_normal_start.
        #[arg(long)]
        seed: u32,
    },
    /// Summarize a game_state capture, optionally comparing two results.
    Snapshot {
        /// Native runtime result.json containing a game_state capture.
        result: PathBuf,
        /// Optional second result.json to compare semantically.
        comparison: Option<PathBuf>,
        /// Runtime catalog scenario expected in both results.
        #[arg(long)]
        scenario: String,
        /// Seed expected in both results.
        #[arg(long)]
        seed: u32,
        /// Evidence classification expected in both results.
        #[arg(long)]
        evidence: EvidenceKind,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Coarse { result, seed } => check_coarse(&result, seed),
        Command::Terrain {
            result,
            scenario,
            seed,
        } => check_terrain(&result, &scenario, seed),
        Command::RandomSetup { result, seed } => check_random_setup(&result, seed),
        Command::RandomSetupInitial { result, seed } => check_random_setup_initial(&result, seed),
        Command::RandomGameStart { result, seed } => check_random_game_start(&result, seed),
        Command::Snapshot {
            result,
            comparison,
            scenario,
            seed,
            evidence,
        } => check_snapshot(&result, comparison.as_deref(), &scenario, seed, evidence),
    }
}
