#![forbid(unsafe_code)]

use anyhow::{Context, bail};
use clap::Parser;
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62, parse_country_base_at};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(about = "Inspect an Imperialism 1.1 retail save")]
struct Args {
    /// Retail version 0x62 save file.
    save: PathBuf,

    /// Project semantic game state using four decimal runtime values.
    #[arg(
        long = "game-state",
        num_args = 4,
        value_names = ["CRT_RAND", "MAP_LCG", "ZONE_LCG", "SELECTED_NATION"]
    )]
    game_state: Option<Vec<u32>>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    inspect(&args.save, args.game_state.as_deref())
}

fn inspect(path: &Path, game_state: Option<&[u32]>) -> anyhow::Result<()> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let save = LegacySaveV62::parse(&bytes).context("decoding retail save")?;
    let (first_country, first_country_suffix_offset) =
        parse_country_base_at(&bytes, save.remaining_manager_chain_offset)
            .context("decoding the first nation record")?;
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
    let Some(values) = game_state else {
        return serde_json::to_writer(std::io::stdout(), &save.map.world_state())
            .context("encoding world state");
    };
    if values.len() != 4 {
        bail!("--game-state requires exactly four runtime values");
    }
    let game = save
        .game_state(LegacyGameStateContext {
            crt_rand_state: values[0],
            map_generation_lcg: values[1],
            zone_status_lcg: values[2],
            selected_nation: values[3] as i32,
        })
        .context("projecting semantic game state")?;
    serde_json::to_writer(std::io::stdout(), &game).context("encoding semantic game state")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_canonical_runtime_values() {
        let args = Args::try_parse_from([
            "legacy-inspect",
            "retail.imp",
            "--game-state",
            "1",
            "2",
            "3",
            "4",
        ])
        .unwrap();
        assert_eq!(args.save, PathBuf::from("retail.imp"));
        assert_eq!(args.game_state, Some(vec![1, 2, 3, 4]));
    }
}
