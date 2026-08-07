#![forbid(unsafe_code)]

use imperialism_formats::{LegacySaveV62, parse_country_base_at};
use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = env::args_os().nth(1) else {
        eprintln!("usage: legacy-inspect SAVE.imp");
        return ExitCode::FAILURE;
    };
    match inspect(Path::new(&path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn inspect(path: &Path) -> Result<(), String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let save = LegacySaveV62::parse(&bytes).map_err(|error| error.to_string())?;
    let (first_country, first_country_suffix_offset) =
        parse_country_base_at(&bytes, save.remaining_manager_chain_offset)
            .map_err(|error| error.to_string())?;
    eprintln!(
        "version={} zones={} ports={} ships={} task_forces={} nation_records_offset={:#x} first_nation={} units={} first_suffix_offset={:#x}",
        save.header.format_version,
        save.ocean.zones.len(),
        save.ocean.port_zones.len(),
        save.navy.ships.len(),
        save.navy.task_forces.len(),
        save.remaining_manager_chain_offset,
        first_country.identity,
        first_country.military_units.len(),
        first_country_suffix_offset
    );
    serde_json::to_writer(std::io::stdout(), &save.map.snapshot_world())
        .map_err(|error| format!("could not encode map snapshot: {error}"))?;
    Ok(())
}
