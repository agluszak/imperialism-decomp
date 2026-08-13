//! Native transition differentials for technology advances.

use imperialism_core::*;
use imperialism_testkit::compare_native;
use serde::Deserialize;

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

#[derive(Debug, Deserialize)]
struct NewspaperCase {
    story_ids: Vec<i32>,
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn construct_newspaper_page() {
    compare_native("construct_newspaper_page", |state, case: NewspaperCase| {
        state.construct_newspaper_pages(&case.story_ids);
    })
    .unwrap();
}

#[test]
#[ignore = "requires the native C++ oracle"]
fn construct_newspaper_page_misc_event() {
    compare_native(
        "construct_newspaper_page_misc_event",
        |state, case: NewspaperCase| {
            state.construct_newspaper_pages(&case.story_ids);
        },
    )
    .unwrap();
}
