#![forbid(unsafe_code)]

use imperialism_testkit::read_game_snapshot;
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
    if arguments.next().is_some() {
        eprintln!("snapshot-check accepts exactly one snapshot path");
        return ExitCode::from(2);
    }

    match read_game_snapshot(Path::new(&snapshot_path)) {
        Ok(snapshot) => {
            println!(
                "{}: {} tiles, state {}",
                snapshot.schema,
                snapshot.world.tiles.len(),
                snapshot.hashes.state
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
