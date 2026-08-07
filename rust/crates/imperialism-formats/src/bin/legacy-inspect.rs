#![forbid(unsafe_code)]

use imperialism_formats::{LegacySaveV62, LegacySnapshotContext, parse_country_base_at};
use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(path) = arguments.next() else {
        eprintln!(
            "usage: legacy-inspect SAVE.imp [--canonical RUNTIME_SEED CRT_RAND MAP_LCG ZONE_LCG SELECTED_NATION]"
        );
        return ExitCode::FAILURE;
    };
    let trailing = arguments.collect::<Vec<_>>();
    match inspect(Path::new(&path), &trailing) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn inspect(path: &Path, arguments: &[std::ffi::OsString]) -> Result<(), String> {
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
    if arguments.is_empty() {
        return serde_json::to_writer(std::io::stdout(), &save.map.snapshot_world())
            .map_err(|error| format!("could not encode map snapshot: {error}"));
    }
    if arguments.len() != 6 || arguments[0] != "--canonical" {
        return Err("expected --canonical followed by five decimal runtime values".to_owned());
    }
    let values = arguments[1..]
        .iter()
        .map(|value| {
            value
                .to_str()
                .ok_or_else(|| "runtime values must be UTF-8 decimal integers".to_owned())?
                .parse::<u32>()
                .map_err(|error| format!("invalid runtime value: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let snapshot = save
        .snapshot(LegacySnapshotContext {
            runtime_seed: values[0],
            crt_rand_state: values[1],
            map_generation_lcg: values[2],
            zone_status_lcg: values[3],
            selected_nation: values[4] as i32,
        })
        .map_err(|error| format!("could not project canonical snapshot: {error}"))?;
    serde_json::to_writer(std::io::stdout(), &snapshot)
        .map_err(|error| format!("could not encode map snapshot: {error}"))?;
    Ok(())
}
