use crate::market::all_trade_commodities;
use crate::resources::all_resources;
use crate::*;

const PAGE_BOTTOM: i32 = 339;
const LINE_HEIGHT: i32 = 30;
const AID_HEADING_MARGIN: i32 = 60;
const MAX_BIDDER_FLAGS: usize = 7;
const NAVY_STATUS_PRICES: [i32; 4] = [-123_456, -123_457, -123_458, -123_459];

const TABS_WITHOUT_OIL: [TradeCommodity; 15] = [
    TradeCommodity::Clothing,
    TradeCommodity::Furniture,
    TradeCommodity::Hardware,
    TradeCommodity::Arms,
    TradeCommodity::Food,
    TradeCommodity::Fabric,
    TradeCommodity::Lumber,
    TradeCommodity::Paper,
    TradeCommodity::Steel,
    TradeCommodity::Cotton,
    TradeCommodity::Wool,
    TradeCommodity::Timber,
    TradeCommodity::Coal,
    TradeCommodity::Iron,
    TradeCommodity::Horses,
];
const TABS_WITH_OIL: [TradeCommodity; 17] = [
    TradeCommodity::Clothing,
    TradeCommodity::Furniture,
    TradeCommodity::Hardware,
    TradeCommodity::Arms,
    TradeCommodity::Food,
    TradeCommodity::Fabric,
    TradeCommodity::Lumber,
    TradeCommodity::Paper,
    TradeCommodity::Steel,
    TradeCommodity::Fuel,
    TradeCommodity::Cotton,
    TradeCommodity::Wool,
    TradeCommodity::Timber,
    TradeCommodity::Coal,
    TradeCommodity::Iron,
    TradeCommodity::Horses,
    TradeCommodity::Oil,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealBookDealLine {
    pub commodity: TradeCommodity,
    pub kind: DealBookEntryKind,
    pub counterparty: NationId,
    pub amount: i16,
    pub unit_price: i32,
    pub market_price: i32,
}

impl DealBookDealLine {
    pub fn uses_navy_status_text(self) -> bool {
        self.amount == 0 && NAVY_STATUS_PRICES.contains(&self.unit_price)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealBookAidLine {
    pub nation: NationId,
    pub amount: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DealBookHistoryGroup {
    Commodity {
        commodity: TradeCommodity,
        market_price: i32,
        deals: Vec<DealBookDealLine>,
    },
    AidHeading,
    Aid {
        resource: ResourceKind,
        market_price: i32,
        lines: Vec<DealBookAidLine>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealBookTotals {
    pub budget_pool_base: i32,
    pub budget_pool_delta: i32,
    pub military_expenses: i32,
    pub aid_total: i32,
    pub pressure_counter: i16,
    pub escalation_counter: i16,
    pub pending_commitment_cost: i32,
    pub remaining: i32,
    pub diplomacy_budget_base: i32,
}

impl DealBookTotals {
    pub fn height(self) -> i32 {
        if self.pressure_counter > 0 {
            5 * LINE_HEIGHT
        } else {
            4 * LINE_HEIGHT
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealBookHistory {
    pub sold: Vec<DealBookHistoryGroup>,
    pub bought: Vec<DealBookHistoryGroup>,
    pub totals: DealBookTotals,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DealBookHistoryRow {
    CommodityHeader {
        commodity: TradeCommodity,
        market_price: i32,
    },
    Deal(DealBookDealLine),
    AidHeading,
    AidHeader {
        resource: ResourceKind,
        market_price: i32,
    },
    AidLine(DealBookAidLine),
    Totals(DealBookTotals),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealBookOfferRow {
    pub nation: NationId,
    pub amount: i16,
    pub bidder_nations: Vec<NationId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealBookBidRow {
    pub nation: NationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DealBookCategory {
    pub player_participated: bool,
    pub offers: Vec<DealBookOfferRow>,
    pub bids: Vec<DealBookBidRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DealBookCategoryRow {
    Header,
    FallbackHeader,
    Offer(DealBookOfferRow),
    Bid(DealBookBidRow),
}

pub fn deal_book_tab_count(oil_drilling: bool) -> u8 {
    if oil_drilling {
        TABS_WITH_OIL.len() as u8
    } else {
        TABS_WITHOUT_OIL.len() as u8
    }
}

pub fn deal_book_tab_commodity(oil_drilling: bool, tab: u8) -> Option<TradeCommodity> {
    if oil_drilling {
        TABS_WITH_OIL.get(usize::from(tab)).copied()
    } else {
        TABS_WITHOUT_OIL.get(usize::from(tab)).copied()
    }
}

impl DealBookHistory {
    pub fn bought_pages(&self) -> Vec<Vec<DealBookHistoryRow>> {
        paginate_history(&self.bought, None)
    }

    pub fn sold_pages(&self) -> Vec<Vec<DealBookHistoryRow>> {
        paginate_history(&self.sold, Some(self.totals))
    }

    pub fn last_page_index(&self) -> u16 {
        let bought = self.bought_pages().len() as u16;
        let sold = self.sold_pages().len() as u16;
        bought.max(sold).saturating_sub(1)
    }
}

impl DealBookCategory {
    pub fn sell_pages(&self) -> Vec<Vec<DealBookCategoryRow>> {
        let mut rows = Vec::new();
        if self.player_participated {
            rows.push(DealBookCategoryRow::Header);
            rows.extend(self.offers.iter().cloned().map(DealBookCategoryRow::Offer));
        } else {
            rows.push(DealBookCategoryRow::FallbackHeader);
        }
        paginate_category(rows)
    }

    pub fn buy_pages(&self) -> Vec<Vec<DealBookCategoryRow>> {
        if !self.player_participated {
            return vec![Vec::new()];
        }
        let mut rows = vec![DealBookCategoryRow::Header];
        rows.extend(self.bids.iter().copied().map(DealBookCategoryRow::Bid));
        paginate_category(rows)
    }

    pub fn last_page_index(&self) -> u16 {
        let bought = self.buy_pages().len() as u16;
        let sold = self.sell_pages().len() as u16;
        bought.max(sold).saturating_sub(1)
    }
}

impl GameState {
    pub fn deal_book_history(&self, nation: MajorNationId) -> DealBookHistory {
        let economy = &self.nations.major(nation).economy;
        let mut sold = Vec::new();
        let mut bought = Vec::new();
        for commodity in all_trade_commodities() {
            let entries = &economy.deal_book[commodity];
            if entries.is_empty() {
                continue;
            }
            let market_price = self.market.rows[commodity].price;
            let deals = entries
                .iter()
                .map(|entry| DealBookDealLine {
                    commodity,
                    kind: entry.kind,
                    counterparty: entry.nation,
                    amount: entry.amount,
                    unit_price: entry.unit_price,
                    market_price,
                })
                .collect();
            let group = DealBookHistoryGroup::Commodity {
                commodity,
                market_price,
                deals,
            };
            if entries[0].kind == DealBookEntryKind::Offer {
                bought.push(group);
            } else {
                sold.push(group);
            }
        }

        let aid_total = aid_allocation_total(economy);
        if aid_total != 0 {
            sold.push(DealBookHistoryGroup::AidHeading);
            for resource in all_resources() {
                if aid_column_total(economy, resource) == 0 {
                    continue;
                }
                let mut lines = Vec::new();
                for minor in MinorNationId::all() {
                    if self.nations.minor(minor).is_none() {
                        continue;
                    }
                    let amount = economy.aid_allocation_by_minor_nation[minor][resource];
                    if amount == 0 {
                        continue;
                    }
                    lines.push(DealBookAidLine {
                        nation: minor.nation(),
                        amount,
                    });
                }
                sold.push(DealBookHistoryGroup::Aid {
                    resource,
                    market_price: header_price(self, resource),
                    lines,
                });
            }
        }

        DealBookHistory {
            sold,
            bought,
            totals: DealBookTotals {
                budget_pool_base: economy.budget_pool_base,
                budget_pool_delta: economy.budget_pool_delta,
                military_expenses: economy.military_expenses,
                aid_total,
                pressure_counter: economy.pressure_counter,
                escalation_counter: economy.escalation_counter,
                pending_commitment_cost: economy.pending_commitment_cost,
                remaining: aid_total + economy.budget_pool_base + economy.budget_pool_delta
                    - economy.military_expenses
                    - economy.pending_commitment_cost,
                diplomacy_budget_base: economy.diplomacy_budget_base,
            },
        }
    }

    pub fn deal_book_category(
        &self,
        nation: MajorNationId,
        commodity: TradeCommodity,
    ) -> DealBookCategory {
        let current = &self.market.rows[commodity].current_offer_by_nation;
        let player = current[nation.nation()];
        let player_participated = player != 0;
        let mut offers = Vec::new();
        for other in NationId::all().rev() {
            if current[other] <= 0 {
                continue;
            }
            offers.push(DealBookOfferRow {
                nation: other,
                amount: current[other],
                bidder_nations: bidders_for(self, commodity, other),
            });
        }
        let mut bids = Vec::new();
        for other in NationId::all() {
            if current[other] < 0 {
                bids.push(DealBookBidRow { nation: other });
            }
        }
        DealBookCategory {
            player_participated,
            offers,
            bids,
        }
    }
}

fn header_price(state: &GameState, resource: ResourceKind) -> i32 {
    if let Some(commodity) = TradeCommodity::from_retail(resource as i16) {
        state.market.rows[commodity].price
    } else if resource == ResourceKind::Gems {
        500
    } else if resource == ResourceKind::Gold {
        200
    } else {
        0
    }
}

fn aid_column_total(economy: &GreatPowerState, resource: ResourceKind) -> i32 {
    economy
        .aid_allocation_by_minor_nation
        .iter()
        .map(|row| row[resource])
        .sum()
}

fn aid_allocation_total(economy: &GreatPowerState) -> i32 {
    all_resources()
        .map(|resource| aid_column_total(economy, resource))
        .sum()
}

fn bidders_for(state: &GameState, commodity: TradeCommodity, seller: NationId) -> Vec<NationId> {
    let mut bidders = Vec::new();
    for buyer in NationId::all() {
        if buyer == seller || bidders.len() == MAX_BIDDER_FLAGS {
            continue;
        }
        let from_seller = MajorNationId::from_nation(seller).is_some_and(|seller| {
            state.nations.major(seller).economy.deal_book[commodity]
                .iter()
                .any(|entry| entry.kind == DealBookEntryKind::Accept && entry.nation == buyer)
        });
        let from_buyer = MajorNationId::from_nation(buyer).is_some_and(|buyer| {
            state.nations.major(buyer).economy.deal_book[commodity]
                .iter()
                .any(|entry| entry.kind == DealBookEntryKind::Offer && entry.nation == seller)
        });
        if from_seller || from_buyer {
            bidders.push(buyer);
        }
    }
    bidders
}

fn paginate_history(
    groups: &[DealBookHistoryGroup],
    totals: Option<DealBookTotals>,
) -> Vec<Vec<DealBookHistoryRow>> {
    let mut pages = vec![Vec::new()];
    let mut y = 0;
    for group in groups {
        match group {
            DealBookHistoryGroup::Commodity {
                commodity,
                market_price,
                deals,
            } => {
                let mut header_pending = true;
                for &deal in deals {
                    let extra = if header_pending { LINE_HEIGHT } else { 0 };
                    if start_new_page_if_needed(&mut pages, &mut y, extra + LINE_HEIGHT) {
                        header_pending = true;
                    }
                    if header_pending {
                        pages.last_mut().expect("history has a page").push(
                            DealBookHistoryRow::CommodityHeader {
                                commodity: *commodity,
                                market_price: *market_price,
                            },
                        );
                        y += LINE_HEIGHT;
                        header_pending = false;
                    }
                    pages
                        .last_mut()
                        .expect("history has a page")
                        .push(DealBookHistoryRow::Deal(deal));
                    y += LINE_HEIGHT;
                }
            }
            DealBookHistoryGroup::AidHeading => {
                start_new_page_if_needed(&mut pages, &mut y, AID_HEADING_MARGIN + LINE_HEIGHT);
                pages
                    .last_mut()
                    .expect("history has a page")
                    .push(DealBookHistoryRow::AidHeading);
                y += LINE_HEIGHT;
            }
            DealBookHistoryGroup::Aid {
                resource,
                market_price,
                lines,
            } => {
                let mut header_pending = true;
                for &line in lines {
                    let extra = if header_pending { LINE_HEIGHT } else { 0 };
                    if start_new_page_if_needed(&mut pages, &mut y, extra + LINE_HEIGHT) {
                        header_pending = true;
                    }
                    if header_pending {
                        pages.last_mut().expect("history has a page").push(
                            DealBookHistoryRow::AidHeader {
                                resource: *resource,
                                market_price: *market_price,
                            },
                        );
                        y += LINE_HEIGHT;
                        header_pending = false;
                    }
                    pages
                        .last_mut()
                        .expect("history has a page")
                        .push(DealBookHistoryRow::AidLine(line));
                    y += LINE_HEIGHT;
                }
                if header_pending {
                    start_new_page_if_needed(&mut pages, &mut y, LINE_HEIGHT);
                    pages.last_mut().expect("history has a page").push(
                        DealBookHistoryRow::AidHeader {
                            resource: *resource,
                            market_price: *market_price,
                        },
                    );
                    y += LINE_HEIGHT;
                }
            }
        }
    }
    if let Some(totals) = totals {
        start_new_page_if_needed(&mut pages, &mut y, totals.height());
        pages
            .last_mut()
            .expect("history has a page")
            .push(DealBookHistoryRow::Totals(totals));
    }
    pages
}

fn paginate_category(rows: Vec<DealBookCategoryRow>) -> Vec<Vec<DealBookCategoryRow>> {
    if rows.is_empty() {
        return vec![Vec::new()];
    }
    let mut pages = vec![Vec::new()];
    let mut y = 0;
    for row in rows {
        start_new_page_if_needed(&mut pages, &mut y, LINE_HEIGHT);
        pages.last_mut().expect("category has a page").push(row);
        y += LINE_HEIGHT;
    }
    pages
}

fn start_new_page_if_needed<T>(pages: &mut Vec<Vec<T>>, y: &mut i32, needed: i32) -> bool {
    if *y + needed > PAGE_BOTTOM && pages.last().is_some_and(|page| !page.is_empty()) {
        pages.push(Vec::new());
        *y = 0;
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn nation(slot: u8) -> NationId {
        NationId::new(slot)
    }

    fn major(slot: u8) -> MajorNationId {
        MajorNationId::new(slot)
    }

    fn entry(
        kind: DealBookEntryKind,
        counterparty: u8,
        amount: i16,
        unit_price: i32,
    ) -> TradeDealBookEntry {
        TradeDealBookEntry {
            kind,
            nation: nation(counterparty),
            amount,
            unit_price,
        }
    }

    #[test]
    fn first_entry_kind_splits_bought_from_sold_and_keeps_the_commodity_together() {
        let mut state = game_state();
        let economy = &mut state.nations.major_mut(major(0)).economy;
        economy.deal_book[TradeCommodity::Cotton] = vec![
            entry(DealBookEntryKind::Accept, 3, 2, 100),
            entry(DealBookEntryKind::Offer, 4, 1, 100),
        ];
        economy.deal_book[TradeCommodity::Wool] = vec![entry(DealBookEntryKind::Offer, 2, 5, 90)];
        economy.deal_book[TradeCommodity::Arms] =
            vec![entry(DealBookEntryKind::Accept, 1, 0, -123_456)];

        let history = state.deal_book_history(major(0));
        assert!(matches!(
            &history.sold[..],
            [
                DealBookHistoryGroup::Commodity {
                    commodity: TradeCommodity::Cotton,
                    deals,
                    ..
                },
                DealBookHistoryGroup::Commodity {
                    commodity: TradeCommodity::Arms,
                    deals: arms,
                    ..
                }
            ] if deals.len() == 2 && arms[0].uses_navy_status_text()
        ));
        assert!(matches!(
            &history.bought[..],
            [DealBookHistoryGroup::Commodity {
                commodity: TradeCommodity::Wool,
                deals,
                ..
            }] if deals.len() == 1 && deals[0].amount == 5
        ));
    }

    #[test]
    fn empty_bought_page_still_exists_and_sold_always_has_totals() {
        let state = game_state();
        let history = state.deal_book_history(major(0));
        assert!(history.bought.is_empty());
        assert_eq!(history.bought_pages().len(), 1);
        assert!(history.bought_pages()[0].is_empty());
        assert_eq!(history.sold_pages().len(), 1);
        assert!(matches!(
            history.sold_pages()[0].last(),
            Some(DealBookHistoryRow::Totals(_))
        ));
        assert_eq!(history.last_page_index(), 0);
    }

    #[test]
    fn totals_include_the_pressure_line_and_remaining_budget() {
        let mut state = game_state();
        let economy = &mut state.nations.major_mut(major(0)).economy;
        economy.budget_pool_base = 200;
        economy.budget_pool_delta = 50;
        economy.military_expenses = 20;
        economy.pending_commitment_cost = 10;
        economy.pressure_counter = 1;
        economy.escalation_counter = 8;
        economy.diplomacy_budget_base = 50_000;
        let totals = state.deal_book_history(major(0)).totals;
        assert_eq!(totals.remaining, 220);
        assert_eq!(totals.height(), 150);
        assert_eq!(totals.diplomacy_budget_base, 50_000);
    }

    #[test]
    fn aid_groups_by_resource_and_skips_absent_minors() {
        let mut state = game_state();
        state.nations.minors.insert(
            MinorNationId::new(7),
            MinorNation {
                common: NationCommonState::from_parts(
                    "Konia".to_owned(),
                    CountryStatus::Independent,
                    Vec::new(),
                    0,
                    None,
                    NationTable::default(),
                ),
                consortium_members: [MinorNationId::new(7); 4],
                trade: MinorTradeState::default(),
            },
        );
        let economy = &mut state.nations.major_mut(major(0)).economy;
        economy.aid_allocation_by_minor_nation[MinorNationId::new(7)][ResourceKind::Grain] = 40;
        economy.aid_allocation_by_minor_nation[MinorNationId::new(8)][ResourceKind::Grain] = 15;

        let history = state.deal_book_history(major(0));
        assert!(matches!(
            &history.sold[..],
            [
                DealBookHistoryGroup::AidHeading,
                DealBookHistoryGroup::Aid {
                    resource: ResourceKind::Grain,
                    lines,
                    ..
                }
            ] if lines == &[DealBookAidLine {
                nation: nation(7),
                amount: 40
            }]
        ));
        assert_eq!(history.totals.aid_total, 55);
    }

    #[test]
    fn commodity_headers_repeat_when_a_group_continues_on_the_next_page() {
        let mut state = game_state();
        let economy = &mut state.nations.major_mut(major(0)).economy;
        economy.deal_book[TradeCommodity::Cotton] = (0..12)
            .map(|index| entry(DealBookEntryKind::Accept, 1, index + 1, 100))
            .collect();
        let pages = state.deal_book_history(major(0)).sold_pages();
        assert!(pages.len() >= 2);
        assert!(matches!(
            pages[0][0],
            DealBookHistoryRow::CommodityHeader {
                commodity: TradeCommodity::Cotton,
                ..
            }
        ));
        assert!(matches!(
            pages[1][0],
            DealBookHistoryRow::CommodityHeader {
                commodity: TradeCommodity::Cotton,
                ..
            }
        ));
        let deals: Vec<_> = pages
            .iter()
            .flatten()
            .filter_map(|row| match row {
                DealBookHistoryRow::Deal(deal) => Some(deal.amount),
                _ => None,
            })
            .collect();
        assert_eq!(deals, (1..=12).collect::<Vec<_>>());
    }

    #[test]
    fn tabs_map_clothing_through_steel_until_oil_unlocks_fuel() {
        assert_eq!(deal_book_tab_count(false), 15);
        assert_eq!(
            deal_book_tab_commodity(false, 0),
            Some(TradeCommodity::Clothing)
        );
        assert_eq!(
            deal_book_tab_commodity(false, 8),
            Some(TradeCommodity::Steel)
        );
        assert_eq!(
            deal_book_tab_commodity(false, 9),
            Some(TradeCommodity::Cotton)
        );
        assert_eq!(deal_book_tab_commodity(false, 15), None);
        assert_eq!(deal_book_tab_count(true), 17);
        assert_eq!(deal_book_tab_commodity(true, 9), Some(TradeCommodity::Fuel));
        assert_eq!(deal_book_tab_commodity(true, 16), Some(TradeCommodity::Oil));
    }

    #[test]
    fn category_rows_use_signed_current_offers_and_descending_offer_nations() {
        let mut state = game_state();
        let row = &mut state.market.rows[TradeCommodity::Cotton];
        row.current_offer_by_nation[nation(0)] = -2;
        row.current_offer_by_nation[nation(3)] = 4;
        row.current_offer_by_nation[nation(22)] = 1;
        row.current_offer_by_nation[nation(5)] = -1;
        let category = state.deal_book_category(major(0), TradeCommodity::Cotton);
        assert!(category.player_participated);
        assert_eq!(
            category
                .offers
                .iter()
                .map(|row| (row.nation.get(), row.amount))
                .collect::<Vec<_>>(),
            vec![(22, 1), (3, 4)]
        );
        assert_eq!(
            category
                .bids
                .iter()
                .map(|row| row.nation.get())
                .collect::<Vec<_>>(),
            vec![0, 5]
        );
        assert!(matches!(
            category.sell_pages()[0][0],
            DealBookCategoryRow::Header
        ));
    }

    #[test]
    fn category_sell_uses_the_fallback_header_when_the_player_did_not_participate() {
        let mut state = game_state();
        state.market.rows[TradeCommodity::Wool].current_offer_by_nation[nation(3)] = 2;
        let category = state.deal_book_category(major(0), TradeCommodity::Wool);
        assert!(!category.player_participated);
        assert!(matches!(
            category.sell_pages()[0][..],
            [DealBookCategoryRow::FallbackHeader]
        ));
        assert!(category.buy_pages()[0].is_empty());
    }
}
