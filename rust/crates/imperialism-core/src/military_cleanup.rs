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
        for index in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(index);
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

    fn ship(selection: i32) -> ShipState {
        ShipState {
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            task_force: None,
            aggression: 0,
            nation: NationId::new(0),
            name: String::new(),
            strength: 100,
            experience: 0,
            selection,
        }
    }

    #[test]
    fn cleanup_resets_transient_selection_rebuilds_the_heatmap_and_commits_purchases() {
        let mut state = game_state();
        state.ships.extend([ship(1), ship(2)]);
        state.map[TileId::new(1)].province = Some(ProvinceId::new(0));
        state.map[TileId::new(1)].edge_resources = [Some(ResourceKind::Cotton), None];
        state.map.provinces[ProvinceId::new(0)].linked_tiles = vec![TileId::new(1)];

        let eligible = MajorNationId::new(0);
        let ineligible = MajorNationId::new(1);
        state.nations.majors[eligible].economy.purchased_items_by_resource[ResourceKind::Food] = 5;
        state.nations.majors[eligible].city.stockpile[ResourceKind::Food] = 1;
        state.nations.majors[ineligible].economy.purchased_items_by_resource[ResourceKind::Food] =
            7;
        state.nations.majors[ineligible].city.stockpile[ResourceKind::Food] = 2;
        state.set_country_status(
            ineligible.nation(),
            CountryStatus::ProtectorateOf(NationId::new(0)),
        );

        let mut expected = state.clone();
        expected.recompute_tile_strategic_score_heatmap();
        for province in (0..ProvinceId::COUNT).map(ProvinceId::new) {
            state.map.provinces[province].set_city_score(1);
        }
        state.map.city_score_total = 1;

        state.do_military_cleanup();

        assert_eq!(state.ships[0].selection, 0);
        assert_eq!(state.ships[1].selection, 2);
        assert_eq!(
            state.map.city_score_total, expected.map.city_score_total,
            "cleanup must rebuild the heatmap, not keep a corrupted total"
        );
        assert_ne!(state.map.city_score_total, 1);
        for province in (0..ProvinceId::COUNT).map(ProvinceId::new) {
            assert_eq!(
                state.map.provinces[province].city_score(),
                expected.map.provinces[province].city_score()
            );
        }
        assert_eq!(
            state.nations.majors[eligible].city.stockpile[ResourceKind::Food],
            6
        );
        assert_eq!(
            state.nations.majors[eligible]
                .economy
                .purchased_items_by_resource[ResourceKind::Food],
            0
        );
        assert_eq!(
            state.nations.majors[ineligible].city.stockpile[ResourceKind::Food],
            2,
            "protectorates skip purchase commit"
        );
        assert_eq!(
            state.nations.majors[ineligible]
                .economy
                .purchased_items_by_resource[ResourceKind::Food],
            7
        );
    }
}
