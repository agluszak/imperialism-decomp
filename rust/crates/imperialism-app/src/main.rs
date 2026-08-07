#![forbid(unsafe_code)]

use bevy::prelude::*;

fn main() {
    App::new().add_plugins(MinimalPlugins).run();
}
