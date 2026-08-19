use super::*;

impl GameState {
    pub(super) fn change_master(&mut self, subject: NationId, master: NationId) {
        self.set_nation_pair_relationship(
            subject,
            master,
            DiplomaticRelationship::JoinedEmpire,
            true,
        );
        self.nations
            .set_country_status(subject, CountryStatus::ColonyOf(master));
        self.set_one_trade(subject, master, TradePolicyScore::NEUTRAL);
        for other in NationId::all() {
            if !self.event_eligible(other) || other == subject || other == master {
                continue;
            }
            let policy = self
                .nations
                .common(other)
                .map(|common| common.trade_policy_by_nation[master])
                .unwrap_or(TradePolicyScore::NEUTRAL);
            self.set_one_trade(other, subject, policy);
        }
        self.reset_mission_row(subject);
        if matches!(self.status_of(subject), CountryStatus::ColonyOf(_)) {
            self.set_mission_level(subject, master, DiplomaticMissionLevel::Embassy);
        }

        if NationId::as_major(subject).is_none() {
            self.reset_master_diplomacy_for_colony(master, subject);
            for unit in self.military_units.values_mut() {
                if unit.nation == subject {
                    unit.nation = master;
                    unit.owner_nation = master;
                }
            }
            self.set_boycott_policies_to_match(subject, master);
            self.set_relationships_to_match(subject, master);
            self.kill_enemy_civilians(subject);
            self.deport_civilians(subject);
            if let Some(major) = NationId::as_major(master) {
                let pending = &mut self.nations.majors[&major].economy.pending_actions
                    [PendingActionKind::ColonyMonumentMerchantCapacity];
                if !pending.status().has_reached(PendingActionStatus::HANDLED) {
                    pending.queue_with_payload(subject.table_index() as i32);
                }
            }
            self.add_treaty_event(InterNationNewsKind::NationJoinedEmpire, master, subject);
        }

        if let (Some(_), Some(master_major)) =
            (NationId::as_major(subject), NationId::as_major(master))
        {
            let pending = &mut self.nations.majors[&master_major].economy.pending_actions
                [PendingActionKind::AnnexedGreatPowerCapitalExpansion];
            if !pending.status().has_reached(PendingActionStatus::HANDLED) {
                pending.queue_with_payload(subject.table_index() as i32);
            }
        }
    }

    pub(super) fn reset_master_diplomacy_for_colony(&mut self, master: NationId, colony: NationId) {
        self.set_one_trade(master, colony, TradePolicyScore::NEUTRAL);
        if let Some(major) = NationId::as_major(master) {
            let _ = self.set_diplomacy_grant(major, colony, None);
        }
        let enemies: Vec<_> = NationId::all()
            .filter(|&other| self.at_war(master, other))
            .collect();
        for enemy in enemies {
            self.declare_war_for_colonies(master, enemy);
        }
    }

    pub(super) fn declare_war_for_colonies(&mut self, master: NationId, enemy: NationId) {
        for minor in MinorNationId::all().map(MinorNationId::nation) {
            if !self
                .nations
                .common(minor)
                .is_some_and(|common| common.status() == CountryStatus::ColonyOf(master))
                || self.at_war(minor, enemy)
            {
                continue;
            }
            self.set_nation_pair_relationship(minor, enemy, DiplomaticRelationship::War, false);
            if let Some(target) = NationId::as_major(enemy)
                && self.event_eligible(enemy)
                && self.is_auto(target)
            {
                self.add_diplomacy_notice(target, minor, DiplomacyPolicy::DeclareWar.retail());
            }
            self.kill_enemy_civilians(minor);
        }
    }

    pub(super) fn set_boycott_policies_to_match(&mut self, colony: NationId, master: NationId) {
        for other in NationId::all() {
            let war = self.at_war(master, other);
            let flagged = NationId::as_major(master).is_some_and(|major| {
                self.nations.majors[&major].economy.colony_boycott_flags[other] != 0
            });
            let policy = if !war && (other == colony || !flagged) {
                TradePolicyScore::NEUTRAL
            } else {
                TradePolicyScore::BOYCOTT
            };
            self.set_one_trade(colony, other, policy);
        }
    }

    pub(super) fn kill_enemy_civilians(&mut self, nation: NationId) {
        let owner = self.owner_slot(nation);
        let Some(common) = self.nations.common(nation) else {
            return;
        };
        let tiles: Vec<_> = common
            .owned_regions()
            .iter()
            .flat_map(|&province| self.map.provinces[province].linked_tiles.iter().copied())
            .collect();
        let enemies: [bool; MAJOR_NATION_COUNT] = std::array::from_fn(|index| {
            let other = MajorNationId::new(index).nation();
            other != owner && self.nation_is_present(other) && self.at_war(owner, other)
        });
        self.civilian_units.retain(|_, unit| {
            let Some(tile) = unit.location.tile() else {
                return true;
            };
            if !tiles.contains(&tile) {
                return true;
            }
            let Some(owner) = NationId::as_major(unit.owner_nation) else {
                return true;
            };
            !enemies[owner.get()]
        });
    }

    pub(super) fn deport_civilians(&mut self, nation: NationId) {
        self.kill_boycotted_foreign_companies(nation);
        let owner = self.owner_slot(nation);
        let Some(common) = self.nations.common(nation) else {
            return;
        };
        let tiles: Vec<_> = common
            .owned_regions()
            .iter()
            .flat_map(|&province| self.map.provinces[province].linked_tiles.iter().copied())
            .collect();
        let targets: [bool; MAJOR_NATION_COUNT] = std::array::from_fn(|index| {
            let other = MajorNationId::new(index).nation();
            other != owner && self.nation_is_present(other) && self.need_level_300(nation, other)
        });
        for id in self.civilian_units.keys().copied().collect::<Vec<_>>() {
            let Some(unit) = self.civilian_units.get(&id) else {
                continue;
            };
            let Some(tile) = unit.location.tile() else {
                continue;
            };
            if !tiles.contains(&tile) {
                continue;
            }
            let Some(owner) = NationId::as_major(unit.owner_nation) else {
                continue;
            };
            if !targets[owner.get()] {
                continue;
            }
            let Some(home) = self.nations.majors[&owner].common.home_tile else {
                self.civilian_units.shift_remove(&id);
                continue;
            };
            if let Some(destination) = self.find_reachable_recruit_spawn_tile(home, false) {
                self.civilian_units
                    .get_mut(&id)
                    .expect("civilian remains present")
                    .location = CivilianLocation::OnMap(destination);
            } else {
                self.civilian_units.shift_remove(&id);
            }
        }
    }

    pub(super) fn kill_boycotted_foreign_companies(&mut self, nation: NationId) {
        let Some(common) = self.nations.common(nation) else {
            return;
        };
        let boycott: [bool; MAJOR_NATION_COUNT] = std::array::from_fn(|index| {
            common.trade_policy_by_nation[MajorNationId::new(index).nation()]
                == TradePolicyScore::BOYCOTT
        });
        let tiles: Vec<_> = common
            .owned_regions()
            .iter()
            .flat_map(|&province| self.map.provinces[province].linked_tiles.iter().copied())
            .collect();
        let mut notify = [false; MAJOR_NATION_COUNT];
        for tile in tiles {
            let Some(owner) = self.map[tile].secondary_owner_nation else {
                continue;
            };
            let index = owner.get();
            if boycott[index] {
                notify[index] = true;
                self.map[tile].secondary_owner_nation = None;
            }
        }
        for (index, flagged) in notify.into_iter().enumerate() {
            if !flagged {
                continue;
            }
            let major = MajorNationId::new(index);
            self.add_diplomacy_notice(major, nation, 0x137);
            self.add_treaty_event(
                InterNationNewsKind::MinorTerritoryRelationshipAffected,
                major.nation(),
                nation,
            );
        }
    }

    pub(super) fn need_level_300(&self, source: NationId, target: NationId) -> bool {
        self.nations.common(source).is_some_and(|common| {
            common.trade_policy_by_nation[target] == TradePolicyScore::BOYCOTT
        }) || self.nations.common(target).is_some_and(|common| {
            common.trade_policy_by_nation[source] == TradePolicyScore::BOYCOTT
        })
    }
}
