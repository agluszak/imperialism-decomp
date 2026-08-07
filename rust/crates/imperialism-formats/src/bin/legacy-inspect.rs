#![forbid(unsafe_code)]

use anyhow::{Context, bail};
use clap::Parser;
use imperialism_formats::{LegacySaveV62, LegacySnapshotContext, parse_country_base_at};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(about = "Inspect an Imperialism 1.1 retail save")]
struct Args {
    /// Retail version 0x62 save file.
    save: PathBuf,

    /// Project a canonical snapshot using five decimal runtime values.
    #[arg(
        long,
        num_args = 5,
        value_names = ["RUNTIME_SEED", "CRT_RAND", "MAP_LCG", "ZONE_LCG", "SELECTED_NATION"]
    )]
    canonical: Option<Vec<u32>>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    inspect(&args.save, args.canonical.as_deref())
}

fn inspect(path: &Path, canonical: Option<&[u32]>) -> anyhow::Result<()> {
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
    let Some(values) = canonical else {
        return serde_json::to_writer(std::io::stdout(), &save.map.snapshot_world())
            .context("encoding map snapshot");
    };
    if values.len() != 5 {
        bail!("--canonical requires exactly five runtime values");
    }
    let snapshot = save
        .snapshot(LegacySnapshotContext {
            runtime_seed: values[0],
            crt_rand_state: values[1],
            map_generation_lcg: values[2],
            zone_status_lcg: values[3],
            selected_nation: values[4] as i32,
        })
        .context("projecting canonical snapshot")?;
    serde_json::to_writer(std::io::stdout(), &snapshot).context("encoding canonical snapshot")?;
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
            "--canonical",
            "1",
            "2",
            "3",
            "4",
            "6",
        ])
        .unwrap();
        assert_eq!(args.save, PathBuf::from("retail.imp"));
        assert_eq!(args.canonical, Some(vec![1, 2, 3, 4, 6]));
    }
}
