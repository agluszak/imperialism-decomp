//! Native transition differentials for technology advances.

use imperialism_core::{GameData, MajorNationId};
use imperialism_testkit::compare_native;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NationCase {
    nation: MajorNationId,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn check_technology_advances() {
    compare_native("check_technology_advances", |state, (): ()| {
        state.check_technology_advances();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn check_technology_advances_ai_purchase() {
    compare_native("check_technology_advances_ai_purchase", |state, (): ()| {
        state.check_technology_advances();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn technology_naval_capability_upgrade() {
    compare_native(
        "technology_naval_capability_upgrade",
        |state, case: NationCase| {
            state.acknowledge_technology_unlock(case.nation);
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn technology_naval_capability_sequence() {
    compare_native(
        "technology_naval_capability_sequence",
        |state, case: NationCase| {
            while state.acknowledge_technology_unlock(case.nation).is_some() {}
        },
    )
    .unwrap();
}

#[derive(Debug, Deserialize)]
struct NewspaperCase {
    story_ids: Vec<i32>,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn construct_newspaper_page() {
    compare_native("construct_newspaper_page", |state, case: NewspaperCase| {
        state.set_game_data(GameData::from_news_story_ids(case.story_ids));
        state.construct_newspaper_pages();
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn construct_newspaper_page_misc_event() {
    compare_native(
        "construct_newspaper_page_misc_event",
        |state, case: NewspaperCase| {
            state.set_game_data(GameData::from_news_story_ids(case.story_ids));
            state.construct_newspaper_pages();
        },
    )
    .unwrap();
}
