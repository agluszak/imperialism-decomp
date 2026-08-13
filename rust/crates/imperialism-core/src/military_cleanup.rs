//! Military cleanup phase (`TSimMgr` turn-state 0x15) without navy straggler
//! removal, AI replanning, or power-score recomputation.

use crate::*;

impl GameState {
    /// Retail military-cleanup phase for a non-client host, limited to the
    /// operations already represented in `GameState`.
    pub fn do_military_cleanup(&mut self) {
        for ship in &mut self.ships {
            if ship.selection == 1 {
                ship.selection = 0;
            }
        }
        self.recompute_tile_strategic_score_heatmap();
        for nation in MajorNationId::all() {
            if !self.nation_is_eligible_for_optional_phase(nation.nation()) {
                continue;
            }
            self.commit_purchased_items(nation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    #[test]
    fn cleanup_clears_transient_ship_selection_and_rebuilds_the_heatmap() {
        let mut state = game_state();
        state.ships.push(ShipState {
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            task_force: None,
            aggression: 0,
            nation: NationId::new(0),
            name: String::new(),
            strength: 100,
            experience: 0,
            selection: 1,
        });
        state.do_military_cleanup();
        assert_eq!(state.ships[0].selection, 0);
        assert_eq!(state.map.city_score_total, 3200);
    }
}
