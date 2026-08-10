use imperialism_core::GameState;
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};
use imperialism_testkit::{
    EvidenceKind, RuntimeResultExpectations, assert_game_state_eq, read_runtime_result,
    run_native_scenario,
};

const BEGINNING_OF_GAME: &[u8] =
    include_bytes!("../../../../fixtures/retail/beginning_of_game.imp");

#[test]
#[ignore = "requires the native runtime harness and Wine"]
fn beginning_save_projection_matches_cpp_loaded_state() -> anyhow::Result<()> {
    let result_path = run_native_scenario("load_saved_game", 1)?;
    let runtime = read_runtime_result(
        &result_path,
        RuntimeResultExpectations {
            name: "load_saved_game",
            seed: 1,
            evidence_kind: EvidenceKind::RetailFixtureOracle,
            required_captures: &["game_state"],
        },
    )?;
    let mut expected: GameState = runtime.capture("game_state")?;

    let save = LegacySaveV62::parse(BEGINNING_OF_GAME)?;
    let actual = save.game_state(LegacyGameStateContext {
        crt_rand_state: expected.rng.crt_rand.state(),
        map_generation_lcg: expected.rng.map_generation.state(),
        zone_status_lcg: expected.rng.zone_status.state(),
        selected_nation: expected.turn.selected_nation,
    })?;

    // The save persists tile 1. Opening the strategic map then recenters the live retail
    // dialog on the selected civilian, so the runtime capture has a later viewport origin.
    // Keep the format projection at its persisted boundary and normalize only that proven
    // screen-entry mutation for the rest of the complete-state comparison.
    let persisted_view_origin = save.world_state()?.view_origin();
    assert_eq!(actual.world.view_origin(), persisted_view_origin);
    expected.world.set_view_origin(persisted_view_origin);

    assert_game_state_eq(&expected, &actual)
}
