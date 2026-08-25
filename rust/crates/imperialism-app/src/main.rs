#![forbid(unsafe_code)]

use anyhow::Context;
use clap::Parser;
use imperialism_core::NationId;
use imperialism_formats::{LegacyGameStateContext, RetailAssets, load_game_from_bytes};
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    retail_dir: PathBuf,
    #[arg(long)]
    save_dir: Option<PathBuf>,
    #[arg(long)]
    system_font: Option<PathBuf>,
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

fn load_system_font(explicit: Option<PathBuf>) -> anyhow::Result<Vec<u8>> {
    let path = explicit
        .or_else(|| std::env::var_os("IMPERIALISM_SYSTEM_FONT").map(PathBuf::from))
        .unwrap_or_else(|| {
            // Temporary host default until a vendored System compatibility face exists.
            PathBuf::from("/usr/share/wine/fonts/system.ttf")
        });
    std::fs::read(&path).with_context(|| {
        format!(
            "failed to read the Windows System compatibility font {}",
            path.display()
        )
    })
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let save_directory = args
        .save_dir
        .unwrap_or_else(|| args.retail_dir.join("Save"));
    let assets = RetailAssets::open(args.retail_dir)?;
    let system_font = load_system_font(args.system_font)?;
    let initial_game = match (args.load_save, args.game_state) {
        (Some(path), Some(context)) => {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("failed to read retail save {}", path.display()))?;
            let _selected = u8::try_from(context[3])
                .ok()
                .and_then(NationId::try_new)
                .context("selected nation is outside the retail nation range")?;
            Some(load_game_from_bytes(
                &bytes,
                LegacyGameStateContext {
                    crt_rand_state: context[0],
                    map_generation_lcg: context[1],
                    zone_status_lcg: context[2],
                },
            )?)
        }
        (None, None) => None,
        _ => unreachable!("clap enforces the paired load-save and game-state arguments"),
    };
    imperialism_app::run(assets, system_font, initial_game, save_directory)
}
