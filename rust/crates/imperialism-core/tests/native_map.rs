//! Native runtime differentials for random-map generation.

use imperialism_testkit::{compare_map_generation_terrain, compare_random_game_names};

#[test]
#[ignore = "requires the native C++ oracle"]
fn random_name_game_start() {
    compare_random_game_names("random_name_game_normal_start").unwrap();
}

macro_rules! map_generation_terrain {
    ($name:ident, $scenario:expr) => {
        #[test]
        #[ignore = "requires the native C++ oracle"]
        fn $name() {
            compare_map_generation_terrain($scenario).unwrap();
        }
    };
}

map_generation_terrain!(
    ordinary_terrain_random_map_generation,
    "random_map_terrain_ordinary"
);
map_generation_terrain!(
    tuned_terrain_random_map_generation,
    "random_map_terrain_tuned"
);
map_generation_terrain!(
    dune_terrain_random_map_generation,
    "random_map_terrain_dune"
);
map_generation_terrain!(
    mirkwood_terrain_random_map_generation,
    "random_map_terrain_mirkwood"
);
map_generation_terrain!(
    eclectia_terrain_random_map_generation,
    "random_map_terrain_eclectia"
);
