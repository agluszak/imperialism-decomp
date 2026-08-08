#![forbid(unsafe_code)]

use clap::Parser;
use imperialism_formats::RetailAssets;
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    retail_dir: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let assets = RetailAssets::open(args.retail_dir)?;
    imperialism_app::run(assets);
    Ok(())
}
