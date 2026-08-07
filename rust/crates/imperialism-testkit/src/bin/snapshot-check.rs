#![forbid(unsafe_code)]

use imperialism_core::GameState;
use imperialism_testkit::{first_snapshot_difference, read_game_snapshot};
use std::env;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let program = arguments.next().unwrap_or_else(|| "snapshot-check".into());
    let Some(snapshot_path) = arguments.next() else {
        eprintln!("usage: {} SNAPSHOT.json", Path::new(&program).display());
        return ExitCode::from(2);
    };
    let comparison_path = arguments.next();
    if arguments.next().is_some() {
        eprintln!("snapshot-check accepts one snapshot path and an optional comparison path");
        return ExitCode::from(2);
    }

    match read_game_snapshot(Path::new(&snapshot_path)) {
        Ok(snapshot) => {
            let state = match GameState::try_from(snapshot.clone()) {
                Ok(state) => state,
                Err(error) => {
                    eprintln!("snapshot cannot populate GameState: {error}");
                    return ExitCode::FAILURE;
                }
            };
            println!(
                "{}: {} tiles, {} nations, {} cities, {} units, {} ships, {} missions, state {}",
                snapshot.schema,
                snapshot.world.tiles.len(),
                state.nations.iter().flatten().count(),
                state.cities.iter().flatten().count(),
                state.military_units.len(),
                state.ships.len(),
                state.missions.len(),
                snapshot.hashes.state
            );
            if let Some(comparison_path) = comparison_path {
                let comparison = match read_game_snapshot(Path::new(&comparison_path)) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        eprintln!("{error}");
                        return ExitCode::FAILURE;
                    }
                };
                match first_snapshot_difference(&snapshot, &comparison) {
                    Ok(None) => println!("semantic snapshots are identical"),
                    Ok(Some(difference)) => {
                        eprintln!(
                            "{} differs: C++ {:?}, Rust {:?}",
                            difference.path, difference.original, difference.reimplementation
                        );
                        return ExitCode::FAILURE;
                    }
                    Err(error) => {
                        eprintln!("could not compare snapshots: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
