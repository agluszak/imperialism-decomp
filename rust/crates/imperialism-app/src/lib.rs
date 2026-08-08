#![forbid(unsafe_code)]

mod audio;
mod flow;
mod launcher;
mod session;
mod ui;

use imperialism_formats::RetailAssets;

pub fn run(retail_assets: RetailAssets) {
    launcher::run(retail_assets);
}
