//! City and transport resolution (`TSimMgr::DoCityAndTransport`).

use crate::*;

impl GameState {
    pub fn do_city_and_transport(&mut self) {
        for index in (0..MajorNationId::COUNT).rev() {
            let nation = MajorNationId::new(index);
            if !self.city_and_transport_nation_is_eligible(nation) {
                continue;
            }
            if self.nations.major(nation).economy.controller.is_human() {
                self.nations.city_mut(nation).refresh_local_summary_flags();
                self.produce_city_units(nation);
                self.rebuild_nation_resource_yields(nation);
                self.add_created_items(nation);
                self.end_city_phase(nation);
            } else {
                self.fill_interior_minister_orders(nation);
                self.nations.city_mut(nation).refresh_local_summary_flags();
                self.produce_city_units(nation);
                self.rebuild_nation_resource_yields(nation);
            }
            self.refresh_merchant_capacity(nation);
        }
    }

    fn city_and_transport_nation_is_eligible(&self, nation: MajorNationId) -> bool {
        !matches!(
            self.nations.major(nation).common.status(),
            CountryStatus::ProtectorateOf(_)
        )
    }

    fn fill_interior_minister_orders(&mut self, nation: MajorNationId) {
        for resource in all_resources() {
            self.nations.majors[nation]
                .economy
                .update_need_target(resource, 0);
        }
        self.rebalance_ai_transport(nation);
        self.end_city_phase(nation);
        self.clear_ai_city_orders(nation);
        self.process_ai_pending_ship(nation);
        let temporary_lumber = self.rebalance_ai_labor(nation);
        self.choose_ai_expansion(nation);
        self.compute_ai_item_demands(nation);
        if temporary_lumber != 0 {
            self.nations
                .city_mut(nation)
                .adjust_stock(ResourceKind::Lumber, temporary_lumber);
        }
        self.issue_ai_item_orders(nation);
        self.fill_ai_transport_capacity(nation);
        self.rebuild_ai_allocation_average(nation);
        self.determine_ai_trade_bid(nation);
    }
}
