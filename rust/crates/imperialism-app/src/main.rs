#![forbid(unsafe_code)]

use anyhow::Context;
use clap::Parser;
use imperialism_core::NationId;
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62, RetailAssets};
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    retail_dir: PathBuf,
    #[arg(long, requires = "game_state")]
    load_save: Option<PathBuf>,
    #[arg(
        long = "game-state",
        num_args = 4,
        value_names = ["CRT_RAND", "MAP_LCG", "ZONE_LCG", "SELECTED_NATION"],
        requires = "load_save"
    )]
    game_state: Option<Vec<u32>>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let assets = RetailAssets::open(args.retail_dir)?;
    let initial_game = match (args.load_save, args.game_state) {
        (Some(path), Some(context)) => {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("failed to read retail save {}", path.display()))?;
            let selected = u8::try_from(context[3])
                .ok()
                .and_then(NationId::try_new)
                .context("selected nation is outside the retail nation range")?;
            let game = LegacySaveV62::parse(&bytes)?.game_state(LegacyGameStateContext {
                crt_rand_state: context[0],
                map_generation_lcg: context[1],
                zone_status_lcg: context[2],
                selected_nation: selected,
            })?;
            anyhow::ensure!(
                game.turn().phase() == imperialism_core::PhaseCode::STRATEGIC_MAP,
                "loaded save is in unsupported phase {:?}; only strategic-map saves can start the app",
                game.turn().phase()
            );
            Some(game)
        }
        (None, None) => None,
        _ => unreachable!("clap enforces the paired load-save and game-state arguments"),
    };
    imperialism_app::run(assets, initial_game);
    Ok(())
}
