use crate::*;
use enum_map::{Enum, EnumMap, enum_map};
use serde::{Deserialize, Serialize};

/// Commodities with a world-market price.
///
/// This is deliberately separate from [`crate::ResourceKind`]: the market has
/// rows only for the first seventeen resources.
#[derive(
    Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TradeCommodity {
    Cotton,
    Wool,
    Timber,
    Coal,
    Iron,
    Horses,
    Oil,
    Food,
    Fabric,
    Lumber,
    Paper,
    Steel,
    Fuel,
    Clothing,
    Furniture,
    Hardware,
    Arms,
}

impl TradeCommodity {
    pub const LENGTH: usize = enum_map::enum_len::<Self>();

    pub const fn from_retail(value: i16) -> Option<Self> {
        match value {
            0 => Some(Self::Cotton),
            1 => Some(Self::Wool),
            2 => Some(Self::Timber),
            3 => Some(Self::Coal),
            4 => Some(Self::Iron),
            5 => Some(Self::Horses),
            6 => Some(Self::Oil),
            7 => Some(Self::Food),
            8 => Some(Self::Fabric),
            9 => Some(Self::Lumber),
            10 => Some(Self::Paper),
            11 => Some(Self::Steel),
            12 => Some(Self::Fuel),
            13 => Some(Self::Clothing),
            14 => Some(Self::Furniture),
            15 => Some(Self::Hardware),
            16 => Some(Self::Arms),
            _ => None,
        }
    }

    pub const fn from_resource(resource: ResourceKind) -> Option<Self> {
        match resource {
            ResourceKind::Cotton => Some(Self::Cotton),
            ResourceKind::Wool => Some(Self::Wool),
            ResourceKind::Timber => Some(Self::Timber),
            ResourceKind::Coal => Some(Self::Coal),
            ResourceKind::Iron => Some(Self::Iron),
            ResourceKind::Horses => Some(Self::Horses),
            ResourceKind::Oil => Some(Self::Oil),
            ResourceKind::Food => Some(Self::Food),
            ResourceKind::Fabric => Some(Self::Fabric),
            ResourceKind::Lumber => Some(Self::Lumber),
            ResourceKind::Paper => Some(Self::Paper),
            ResourceKind::Steel => Some(Self::Steel),
            ResourceKind::Fuel => Some(Self::Fuel),
            ResourceKind::Clothing => Some(Self::Clothing),
            ResourceKind::Furniture => Some(Self::Furniture),
            ResourceKind::Hardware => Some(Self::Hardware),
            ResourceKind::Arms => Some(Self::Arms),
            ResourceKind::Grain
            | ResourceKind::Fruit
            | ResourceKind::Fish
            | ResourceKind::Livestock
            | ResourceKind::Gems
            | ResourceKind::Gold => None,
        }
    }

    pub const fn resource(self) -> ResourceKind {
        match self {
            Self::Cotton => ResourceKind::Cotton,
            Self::Wool => ResourceKind::Wool,
            Self::Timber => ResourceKind::Timber,
            Self::Coal => ResourceKind::Coal,
            Self::Iron => ResourceKind::Iron,
            Self::Horses => ResourceKind::Horses,
            Self::Oil => ResourceKind::Oil,
            Self::Food => ResourceKind::Food,
            Self::Fabric => ResourceKind::Fabric,
            Self::Lumber => ResourceKind::Lumber,
            Self::Paper => ResourceKind::Paper,
            Self::Steel => ResourceKind::Steel,
            Self::Fuel => ResourceKind::Fuel,
            Self::Clothing => ResourceKind::Clothing,
            Self::Furniture => ResourceKind::Furniture,
            Self::Hardware => ResourceKind::Hardware,
            Self::Arms => ResourceKind::Arms,
        }
    }
}

pub type TradeCommodityTable<T> = EnumMap<TradeCommodity, T>;

/// The six processed-resource slots retained by automated trade planning.
#[derive(
    Clone, Copy, Debug, Deserialize, Enum, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ProcessedTradeCommodity {
    Food,
    Fabric,
    Lumber,
    Paper,
    Steel,
    Fuel,
}

pub type ProcessedTradeCommodityTable<T> = EnumMap<ProcessedTradeCommodity, T>;

impl ProcessedTradeCommodity {
    pub(crate) const fn from_resource(resource: ResourceKind) -> Option<Self> {
        match resource {
            ResourceKind::Food => Some(Self::Food),
            ResourceKind::Fabric => Some(Self::Fabric),
            ResourceKind::Lumber => Some(Self::Lumber),
            ResourceKind::Paper => Some(Self::Paper),
            ResourceKind::Steel => Some(Self::Steel),
            ResourceKind::Fuel => Some(Self::Fuel),
            _ => None,
        }
    }

    pub(crate) const fn resource(self) -> ResourceKind {
        match self {
            Self::Food => ResourceKind::Food,
            Self::Fabric => ResourceKind::Fabric,
            Self::Lumber => ResourceKind::Lumber,
            Self::Paper => ResourceKind::Paper,
            Self::Steel => ResourceKind::Steel,
            Self::Fuel => ResourceKind::Fuel,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DealBookEntryKind {
    Offer,
    Accept,
}

/// One ordered line retained for a major nation's retail deal book.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TradeDealBookEntry {
    pub kind: DealBookEntryKind,
    pub nation: NationId,
    pub amount: i16,
    pub unit_price: i32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TradeMarketRow {
    pub previous_price: i32,
    pub price: i32,
    pub base_price: i32,
    pub request_count: i32,
    pub offer_count: i32,
    pub amount_offered: i32,
    pub adjusted_offer_count: f64,
    pub current_offer_by_nation: NationTable<i16>,
    pub accumulated_offer_by_nation: NationTable<i16>,
    pub maximum_offer_by_nation: NationTable<i16>,
}

impl TradeMarketRow {
    const fn at_base_price(base_price: i32) -> Self {
        Self {
            previous_price: base_price,
            price: base_price,
            base_price,
            request_count: 0,
            offer_count: 0,
            amount_offered: 0,
            adjusted_offer_count: 0.0,
            current_offer_by_nation: NationTable::from_array([0; NATION_COUNT]),
            accumulated_offer_by_nation: NationTable::from_array([0; NATION_COUNT]),
            maximum_offer_by_nation: NationTable::from_array([0; NATION_COUNT]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TradeMarketState {
    pub rows: TradeCommodityTable<TradeMarketRow>,
}

impl Default for TradeMarketState {
    fn default() -> Self {
        Self {
            rows: enum_map! {
                TradeCommodity::Cotton
                | TradeCommodity::Wool
                | TradeCommodity::Timber
                | TradeCommodity::Coal
                | TradeCommodity::Iron
                | TradeCommodity::Oil
                | TradeCommodity::Food => TradeMarketRow::at_base_price(100),
                TradeCommodity::Horses
                | TradeCommodity::Fabric
                | TradeCommodity::Lumber
                | TradeCommodity::Paper
                | TradeCommodity::Steel
                | TradeCommodity::Fuel => TradeMarketRow::at_base_price(300),
                TradeCommodity::Clothing
                | TradeCommodity::Furniture
                | TradeCommodity::Hardware
                | TradeCommodity::Arms => TradeMarketRow::at_base_price(900),
            },
        }
    }
}

impl TradeMarketState {
    /// The `SetEmpirePolicies` eligibility test for a minor trade partner.
    pub fn has_maximum_offer_from_minor(
        &self,
        commodity: TradeCommodity,
        nation: MinorNationId,
    ) -> bool {
        self.rows[commodity].maximum_offer_by_nation[nation.nation()] != 0
    }

    pub(crate) fn recalculate_prices(&mut self) {
        for commodity in all_trade_commodities() {
            let previous = self.rows[commodity].price;
            self.rows[commodity].previous_price = previous;
            self.rows[commodity].price = self.recalculated_price(commodity);
        }
    }

    fn recalculated_price(&self, commodity: TradeCommodity) -> i32 {
        let price = match commodity {
            TradeCommodity::Fabric => {
                let fibers = (self.rows[TradeCommodity::Cotton].price
                    + self.rows[TradeCommodity::Wool].price)
                    / 2;
                (fibers * 3 + self.rows[TradeCommodity::Clothing].price / 3) / 2
            }
            TradeCommodity::Lumber => {
                (self.rows[TradeCommodity::Furniture].price / 3
                    + self.rows[TradeCommodity::Timber].price * 3)
                    / 2
            }
            TradeCommodity::Paper => self.rows[TradeCommodity::Timber].price * 3,
            TradeCommodity::Steel => {
                let ore = (self.rows[TradeCommodity::Iron].price
                    + self.rows[TradeCommodity::Coal].price)
                    / 2;
                (ore * 3 + self.rows[TradeCommodity::Hardware].price / 3) / 2
            }
            TradeCommodity::Fuel => self.rows[TradeCommodity::Oil].price * 3,
            TradeCommodity::Arms => {
                (self.rows[TradeCommodity::Hardware].price
                    + self.rows[TradeCommodity::Steel].price * 3)
                    / 2
            }
            _ => market_price(&self.rows[commodity]),
        };
        price.min(32_000)
    }
}

pub(crate) fn all_trade_commodities() -> impl ExactSizeIterator<Item = TradeCommodity> {
    (0..TradeCommodity::LENGTH).map(TradeCommodity::from_usize)
}

fn market_price(row: &TradeMarketRow) -> i32 {
    let difference = f64::from(row.request_count) - row.adjusted_offer_count;
    let linear = truncate_price(f64::from(row.price) + difference);
    let proportional = truncate_price((1.0 + difference * 0.01) * f64::from(row.price));
    let price = if difference < 0.0 {
        linear.min(proportional)
    } else {
        linear.max(proportional)
    };
    price.max(truncate_price(f64::from(row.base_price) * 0.1))
}

fn truncate_price(value: f64) -> i32 {
    value.trunc() as i32
}
