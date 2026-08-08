#![forbid(unsafe_code)]

use anyhow::{Context, bail};
use clap::Parser;
use imperialism_core::NationId;
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};
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
    let Some(values) = game_state else {
        let world = save
            .world_state()
            .context("projecting semantic world state")?;
        return serde_json::to_writer(std::io::stdout(), &world).context("encoding world state");
    };
    if values.len() != 4 {
        bail!("--game-state requires exactly four runtime values");
    }
    let game = save
        .game_state(LegacyGameStateContext {
            crt_rand_state: values[0],
            map_generation_lcg: values[1],
            zone_status_lcg: values[2],
            selected_nation: u8::try_from(values[3])
                .ok()
                .and_then(NationId::try_new)
                .context("selected nation is outside the nation range")?,
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
