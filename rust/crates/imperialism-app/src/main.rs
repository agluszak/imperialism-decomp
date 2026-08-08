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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_an_explicit_retail_directory() {
        let args = Args::try_parse_from(["imperialism-app", "--retail-dir", "gog"]).unwrap();
        assert_eq!(args.retail_dir, PathBuf::from("gog"));
        assert!(Args::try_parse_from(["imperialism-app"]).is_err());
        assert!(Args::try_parse_from(["imperialism-app", "--cache-dir", "cache"]).is_err());
    }
}
