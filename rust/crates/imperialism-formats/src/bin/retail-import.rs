use imperialism_formats::{
    default_retail_cache_dir, import_english_gog_assets, parse_retail_import_args,
};
use std::error::Error;

fn main() {
    if let Err(error) = run() {
        eprintln!("retail-import: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let (retail_dir, cache_dir) = parse_retail_import_args(std::env::args_os().skip(1))?;
    let cache_dir = match cache_dir {
        Some(path) => path,
        None => default_retail_cache_dir()?,
    };
    let imported = import_english_gog_assets(&retail_dir, &cache_dir)?;
    println!("{}", imported.pack_dir.display());
    Ok(())
}
