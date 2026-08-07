#![forbid(unsafe_code)]

use anyhow::Context;
use clap::Parser;
use imperialism_app::{load_viewer, run_viewer};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(about = "Present a canonical Imperialism snapshot")]
struct Args {
    /// Canonical snapshot JSON, either directly or inside a game_snapshot wrapper.
    snapshot: PathBuf,

    /// Imported asset-pack directory containing manifest.json.
    #[arg(long, default_value = "imported-assets", value_name = "ASSET_PACK")]
    assets: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let asset_manifest = args.assets.join("manifest.json");
    let input = load_viewer(&args.snapshot, &asset_manifest).with_context(|| {
        format!(
            "could not start strategic-map viewer from {}",
            args.snapshot.display()
        )
    })?;
    run_viewer(input);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_snapshot_and_asset_pack_paths() {
        let args = Args::try_parse_from([
            "imperialism-app",
            "snapshot.json",
            "--assets",
            "local-assets",
        ])
        .unwrap();
        assert_eq!(args.snapshot, PathBuf::from("snapshot.json"));
        assert_eq!(args.assets, PathBuf::from("local-assets"));
    }
}
