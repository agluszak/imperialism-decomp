#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use imperialism_testkit::{
    check_coarse, check_random_setup, check_random_setup_initial, check_snapshot, check_terrain,
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
    },
    /// Validate a random_map_terrain capture.
    Terrain {
        /// Native runtime result.json.
        result: PathBuf,
    },
    /// Validate random_game_setup plus terrain captures for an explicit preview seed.
    RandomSetup {
        /// Native runtime result.json.
        result: PathBuf,
    },
    /// Validate initial random-game setup defaults against the clock seed.
    RandomSetupInitial {
        /// Native runtime result.json.
        result: PathBuf,
    },
    /// Summarize a game_state capture, optionally comparing two results.
    Snapshot {
        /// Native runtime result.json containing a game_state capture.
        result: PathBuf,
        /// Optional second result.json to compare semantically.
        comparison: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Coarse { result } => check_coarse(&result),
        Command::Terrain { result } => check_terrain(&result),
        Command::RandomSetup { result } => check_random_setup(&result),
        Command::RandomSetupInitial { result } => check_random_setup_initial(&result),
        Command::Snapshot { result, comparison } => check_snapshot(&result, comparison.as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_snapshot_with_optional_comparison() {
        let cli =
            Cli::try_parse_from(["imperialism-oracle", "snapshot", "left.json", "right.json"])
                .unwrap();
        match cli.command {
            Command::Snapshot { result, comparison } => {
                assert_eq!(result, PathBuf::from("left.json"));
                assert_eq!(comparison, Some(PathBuf::from("right.json")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_kebab_case_subcommands() {
        let cli =
            Cli::try_parse_from(["imperialism-oracle", "random-setup-initial", "result.json"])
                .unwrap();
        match cli.command {
            Command::RandomSetupInitial { result } => {
                assert_eq!(result, PathBuf::from("result.json"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
