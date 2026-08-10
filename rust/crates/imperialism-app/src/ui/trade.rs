use super::catalog::{SpawnedView, UiAssetResources, UiCatalogResource, spawn_view};
use super::game_shell::{GameScreenRoot, bind_game_screen_nav, disable_control, trade_view_id};
use super::random_setup::GameSession;
use crate::AppState;
use bevy::log::warn;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, Button as UiButton};
use imperialism_core::*;
use imperialism_formats::*;

#[derive(Clone, Copy)]
struct TradeRowBinding {
    tag: FourCc,
    commodity: TradeCommodity,
}

const TRADE_ROWS: [TradeRowBinding; 17] = [
    TradeRowBinding {
        tag: fourcc!("rs0 "),
        commodity: TradeCommodity::Cotton,
    },
    TradeRowBinding {
        tag: fourcc!("rs1 "),
        commodity: TradeCommodity::Wool,
    },
    TradeRowBinding {
        tag: fourcc!("rs2 "),
        commodity: TradeCommodity::Timber,
    },
    TradeRowBinding {
        tag: fourcc!("rs3 "),
        commodity: TradeCommodity::Coal,
    },
    TradeRowBinding {
        tag: fourcc!("rs4 "),
        commodity: TradeCommodity::Iron,
    },
    TradeRowBinding {
        tag: fourcc!("rs5 "),
        commodity: TradeCommodity::Horses,
    },
    TradeRowBinding {
        tag: fourcc!("rs6 "),
        commodity: TradeCommodity::Oil,
    },
    TradeRowBinding {
        tag: fourcc!("ma0 "),
        commodity: TradeCommodity::Food,
    },
    TradeRowBinding {
        tag: fourcc!("ma1 "),
        commodity: TradeCommodity::Fabric,
    },
    TradeRowBinding {
        tag: fourcc!("ma2 "),
        commodity: TradeCommodity::Lumber,
    },
    TradeRowBinding {
        tag: fourcc!("ma3 "),
        commodity: TradeCommodity::Paper,
    },
    TradeRowBinding {
        tag: fourcc!("ma4 "),
        commodity: TradeCommodity::Steel,
    },
    TradeRowBinding {
        tag: fourcc!("ma5 "),
        commodity: TradeCommodity::Fuel,
    },
    TradeRowBinding {
        tag: fourcc!("gd0 "),
        commodity: TradeCommodity::Clothing,
    },
    TradeRowBinding {
        tag: fourcc!("gd1 "),
        commodity: TradeCommodity::Furniture,
    },
    TradeRowBinding {
        tag: fourcc!("gd2 "),
        commodity: TradeCommodity::Hardware,
    },
    TradeRowBinding {
        tag: fourcc!("gd3 "),
        commodity: TradeCommodity::Arms,
    },
];

#[derive(Clone, Copy)]
enum TradeAdvisoryKind {
    Food,
    Textile,
    Timber,
    Coal,
    Iron,
    Oil,
    Fabric,
    Lumber,
    Steel,
}

const TRADE_ADVISORIES: [(FourCc, TradeAdvisoryKind); 10] = [
    (fourcc!("food"), TradeAdvisoryKind::Food),
    (fourcc!("cott"), TradeAdvisoryKind::Textile),
    (fourcc!("wool"), TradeAdvisoryKind::Textile),
    (fourcc!("timb"), TradeAdvisoryKind::Timber),
    (fourcc!("coal"), TradeAdvisoryKind::Coal),
    (fourcc!("iron"), TradeAdvisoryKind::Iron),
    (fourcc!("oil "), TradeAdvisoryKind::Oil),
    (fourcc!("fabr"), TradeAdvisoryKind::Fabric),
    (fourcc!("lumb"), TradeAdvisoryKind::Lumber),
    (fourcc!("stee"), TradeAdvisoryKind::Steel),
];

#[derive(Clone)]
struct TradePictures {
    bid_active: Handle<Image>,
    bid_idle: Handle<Image>,
    offer_active: Handle<Image>,
    offer_idle: Handle<Image>,
    clothing_bid_active: Handle<Image>,
    clothing_bid_idle: Handle<Image>,
    clothing_offer_active: Handle<Image>,
    clothing_offer_idle: Handle<Image>,
}

impl TradePictures {
    fn for_button(&self, commodity: TradeCommodity, kind: TradeCardKind) -> TradeCardPictures {
        let clothing = commodity == TradeCommodity::Clothing;
        match (kind, clothing) {
            (TradeCardKind::Bid, false) => TradeCardPictures {
                active: self.bid_active.clone(),
                idle: self.bid_idle.clone(),
            },
            (TradeCardKind::Offer, false) => TradeCardPictures {
                active: self.offer_active.clone(),
                idle: self.offer_idle.clone(),
            },
            (TradeCardKind::Bid, true) => TradeCardPictures {
                active: self.clothing_bid_active.clone(),
                idle: self.clothing_bid_idle.clone(),
            },
            (TradeCardKind::Offer, true) => TradeCardPictures {
                active: self.clothing_offer_active.clone(),
                idle: self.clothing_offer_idle.clone(),
            },
        }
    }
}

pub(crate) fn validate_application_bindings(catalog: &UiCatalogResource) -> Result<(), String> {
    let view_id = trade_view_id();
    catalog.require_unique_bindings(
        &view_id,
        &[
            fourcc!("main"),
            fourcc!("quer"),
            fourcc!("trea"),
            fourcc!("mCap"),
            fourcc!("trad"),
            fourcc!("curs"),
            fourcc!("food"),
            fourcc!("cott"),
            fourcc!("wool"),
            fourcc!("timb"),
            fourcc!("coal"),
            fourcc!("iron"),
            fourcc!("oil "),
            fourcc!("fabr"),
            fourcc!("lumb"),
            fourcc!("stee"),
            fourcc!("rs0 "),
            fourcc!("rs1 "),
            fourcc!("rs2 "),
            fourcc!("rs3 "),
            fourcc!("rs4 "),
            fourcc!("rs5 "),
            fourcc!("rs6 "),
            fourcc!("ma0 "),
            fourcc!("ma1 "),
            fourcc!("ma2 "),
            fourcc!("ma3 "),
            fourcc!("ma4 "),
            fourcc!("ma5 "),
            fourcc!("gd0 "),
            fourcc!("gd1 "),
            fourcc!("gd2 "),
            fourcc!("gd3 "),
        ],
    )?;
    for row in TRADE_ROWS {
        for tag in [
            fourcc!("Sell"),
            fourcc!("card"),
            fourcc!("offr"),
            fourcc!("left"),
            fourcc!("gree"),
            fourcc!("rght"),
            fourcc!("bar "),
        ] {
            catalog.require_control_under(&view_id, tag, &[row.tag])?;
        }
    }
    Ok(())
}

#[derive(Component, Clone, Copy)]
struct TradeScreen {
    nation: MajorNationId,
}

#[derive(Component, Clone, Copy)]
struct TradeRow {
    commodity: TradeCommodity,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TradeCardKind {
    Bid,
    Offer,
}

#[derive(Clone)]
struct TradeCardPictures {
    active: Handle<Image>,
    idle: Handle<Image>,
}

#[derive(Component, Clone)]
struct TradeCard {
    nation: MajorNationId,
    commodity: TradeCommodity,
    kind: TradeCardKind,
    pictures: TradeCardPictures,
}

#[derive(Component, Clone, Copy)]
struct TradeStep {
    nation: MajorNationId,
    commodity: TradeCommodity,
    delta: i16,
}

#[derive(Component, Clone, Copy)]
struct TradeOfferControl {
    nation: MajorNationId,
    commodity: TradeCommodity,
}

#[derive(Component, Clone, Copy)]
struct TradeSellCaption {
    nation: MajorNationId,
    commodity: TradeCommodity,
}

#[derive(Component, Clone, Copy)]
struct TradeAmountBar {
    nation: MajorNationId,
    commodity: TradeCommodity,
}

#[derive(Component, Clone, Copy)]
struct TradeGauge {
    nation: MajorNationId,
    commodity: TradeCommodity,
}

#[derive(Component, Clone, Copy)]
struct TradePriceCaption {
    commodity: TradeCommodity,
}

#[derive(Component, Clone, Copy)]
struct TradeStockCaption {
    nation: MajorNationId,
    commodity: TradeCommodity,
}

#[derive(Component, Clone, Copy)]
struct TradeCapacityCaption {
    nation: MajorNationId,
}

#[derive(Component, Clone, Copy)]
struct TradeTreasuryCaption {
    nation: MajorNationId,
}

#[derive(Component, Clone, Copy)]
struct TradeAdvisory {
    nation: MajorNationId,
    kind: TradeAdvisoryKind,
}

pub(crate) struct TradePlugin;

impl Plugin for TradePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::Trade), enter_trade_screen)
            .add_systems(OnExit(AppState::Trade), remember_trade_orders)
            .add_systems(
                Update,
                (
                    sync_trade_controls,
                    sync_trade_captions,
                    sync_trade_gauges,
                    sync_trade_advisories,
                )
                    .run_if(in_state(AppState::Trade)),
            )
            .add_observer(on_trade_activate)
            .add_observer(on_trade_amount_bar_click);
    }
}

fn enter_trade_screen(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
    session: Option<ResMut<GameSession>>,
) {
    let view_id = trade_view_id();
    let view = catalog
        .view(&view_id)
        .expect("validated trade-screen catalog view");
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_game_screen_nav(&mut commands, &catalog, &spawned);
    commands
        .entity(spawned.root)
        .insert((GameScreenRoot(view_id), DespawnOnExit(AppState::Trade)));

    let Some(mut session) = session else {
        warn!("trade screen opened without an authoritative game session");
        return;
    };
    let Some(nation) = MajorNationId::from_nation(session.0.turn().active_nation) else {
        warn!("trade screen active nation is not a major nation");
        return;
    };
    session.0.recall_player_trade_orders(nation);

    let (row_font, row_layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 2,
            face_flags: 0,
            point_size: 14,
            alignment: -1,
        })
        .expect("retail trade row text style");
    let (capacity_font, capacity_layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: 1,
        })
        .expect("retail trade merchant-capacity text style");
    let (treasury_font, treasury_layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail trade treasury text style");
    let pictures = TradePictures {
        bid_active: assets
            .picture(PictureId::new(2111))
            .expect("trade bid picture"),
        bid_idle: assets
            .picture(PictureId::new(2112))
            .expect("trade bid picture"),
        offer_active: assets
            .picture(PictureId::new(2113))
            .expect("trade offer picture"),
        offer_idle: assets
            .picture(PictureId::new(2114))
            .expect("trade offer picture"),
        clothing_bid_active: assets
            .picture(PictureId::new(2125))
            .expect("clothing trade bid picture"),
        clothing_bid_idle: assets
            .picture(PictureId::new(2126))
            .expect("clothing trade bid picture"),
        clothing_offer_active: assets
            .picture(PictureId::new(2127))
            .expect("clothing trade offer picture"),
        clothing_offer_idle: assets
            .picture(PictureId::new(2128))
            .expect("clothing trade offer picture"),
    };
    bind_trade_screen(
        &mut commands,
        &catalog,
        &spawned,
        nation,
        row_font,
        row_layout,
        assets.palette_color(0x13),
        capacity_font,
        capacity_layout,
        treasury_font,
        treasury_layout,
        pictures,
        assets.palette_color(0x37),
    );
}

#[allow(clippy::too_many_arguments)]
fn bind_trade_screen(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    row_font: TextFont,
    row_layout: TextLayout,
    row_color: Color,
    capacity_font: TextFont,
    capacity_layout: TextLayout,
    treasury_font: TextFont,
    treasury_layout: TextLayout,
    pictures: TradePictures,
    gauge_color: Color,
) {
    commands.entity(spawned.root).insert(TradeScreen { nation });
    disable_control(commands, spawned, fourcc!("quer"));
    let selected = spawned
        .require_unique(fourcc!("trad"))
        .expect("validated selected trade binding");
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));
    let capacity = spawned
        .require_unique(fourcc!("mCap"))
        .expect("validated trade capacity binding");
    commands.entity(capacity).insert((
        Text::new(""),
        capacity_font,
        capacity_layout,
        TextColor(Color::BLACK),
        TradeCapacityCaption { nation },
        InteractionDisabled,
    ));
    let treasury = spawned
        .require_unique(fourcc!("trea"))
        .expect("validated trade treasury binding");
    commands.entity(treasury).insert((
        Text::new(""),
        treasury_font,
        treasury_layout,
        TextColor(Color::BLACK),
        TradeTreasuryCaption { nation },
    ));
    for (tag, kind) in TRADE_ADVISORIES {
        let advisory = spawned
            .require_unique(tag)
            .expect("validated trade advisory binding");
        commands
            .entity(advisory)
            .insert(TradeAdvisory { nation, kind });
    }

    for binding in TRADE_ROWS {
        let row = spawned
            .require_unique(binding.tag)
            .expect("validated trade row binding");
        commands.entity(row).insert(TradeRow {
            commodity: binding.commodity,
        });

        let card = spawned
            .require_under(catalog, binding.tag, fourcc!("card"))
            .expect("validated trade bid binding");
        commands.entity(card).insert((
            UiButton,
            ImageNode::new(
                pictures
                    .for_button(binding.commodity, TradeCardKind::Bid)
                    .idle
                    .clone(),
            ),
            TradeCard {
                nation,
                commodity: binding.commodity,
                kind: TradeCardKind::Bid,
                pictures: pictures.for_button(binding.commodity, TradeCardKind::Bid),
            },
        ));
        let offer = spawned
            .require_under(catalog, binding.tag, fourcc!("offr"))
            .expect("validated trade offer binding");
        commands.entity(offer).insert((
            UiButton,
            ImageNode::new(
                pictures
                    .for_button(binding.commodity, TradeCardKind::Offer)
                    .idle
                    .clone(),
            ),
            TradeCard {
                nation,
                commodity: binding.commodity,
                kind: TradeCardKind::Offer,
                pictures: pictures.for_button(binding.commodity, TradeCardKind::Offer),
            },
        ));

        for (tag, delta) in [(fourcc!("left"), -1), (fourcc!("rght"), 1)] {
            let step = spawned
                .require_under(catalog, binding.tag, tag)
                .expect("validated trade quantity binding");
            commands.entity(step).insert(TradeStep {
                nation,
                commodity: binding.commodity,
                delta,
            });
        }

        let sell = spawned
            .require_under(catalog, binding.tag, fourcc!("Sell"))
            .expect("validated trade sell binding");
        commands.entity(sell).insert((
            Text::new(""),
            row_font.clone(),
            row_layout,
            TextColor(row_color),
            TradeOfferControl {
                nation,
                commodity: binding.commodity,
            },
            TradeSellCaption {
                nation,
                commodity: binding.commodity,
            },
            InteractionDisabled,
        ));
        let green = spawned
            .require_under(catalog, binding.tag, fourcc!("gree"))
            .expect("validated trade gauge track binding");
        commands.entity(green).insert(TradeOfferControl {
            nation,
            commodity: binding.commodity,
        });
        let bar = spawned
            .require_under(catalog, binding.tag, fourcc!("bar "))
            .expect("validated trade amount-bar binding");
        commands.entity(bar).insert((
            TradeOfferControl {
                nation,
                commodity: binding.commodity,
            },
            TradeAmountBar {
                nation,
                commodity: binding.commodity,
            },
            RelativeCursorPosition::default(),
        ));
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(0.0),
                top: Val::Px(0.0),
                width: Val::Px(0.0),
                height: Val::Px(7.0),
                ..default()
            },
            BackgroundColor(gauge_color),
            Pickable::IGNORE,
            ChildOf(bar),
            TradeGauge {
                nation,
                commodity: binding.commodity,
            },
        ));
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(200.0),
                top: Val::Px(-2.0),
                width: Val::Px(38.0),
                height: Val::Px(14.0),
                ..default()
            },
            Text::new(""),
            row_font.clone(),
            row_layout,
            TextColor(row_color),
            Pickable::IGNORE,
            ChildOf(row),
            TradePriceCaption {
                commodity: binding.commodity,
            },
        ));
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(282.0),
                top: Val::Px(-2.0),
                width: Val::Px(18.0),
                height: Val::Px(14.0),
                ..default()
            },
            Text::new(""),
            row_font.clone(),
            row_layout,
            TextColor(row_color),
            Pickable::IGNORE,
            ChildOf(row),
            TradeStockCaption {
                nation,
                commodity: binding.commodity,
            },
        ));
    }
}

fn remember_trade_orders(screens: Query<&TradeScreen>, mut session: Option<ResMut<GameSession>>) {
    let Some(session) = session.as_mut() else {
        return;
    };
    for screen in &screens {
        session.0.remember_trade_bids(screen.nation);
    }
}

fn on_trade_activate(
    activate: On<Activate>,
    cards: Query<(&TradeCard, Has<InteractionDisabled>)>,
    steps: Query<(&TradeStep, Has<InteractionDisabled>)>,
    screens: Query<&TradeScreen>,
    mut session: Option<ResMut<GameSession>>,
) {
    if let Ok((card, disabled)) = cards.get(activate.entity) {
        if disabled || !screens.iter().any(|screen| screen.nation == card.nation) {
            return;
        }
        let Some(session) = session.as_mut() else {
            return;
        };
        let current = session.0.player_trade_order(card.nation, card.commodity);
        let order = match (card.kind, current) {
            (TradeCardKind::Bid, PlayerTradeOrder::Buy)
            | (TradeCardKind::Offer, PlayerTradeOrder::Sell(_)) => PlayerTradeOrder::None,
            (TradeCardKind::Bid, _) => PlayerTradeOrder::Buy,
            (TradeCardKind::Offer, _) => PlayerTradeOrder::Sell(i16::MAX),
        };
        session
            .0
            .set_player_trade_order(card.nation, card.commodity, order);
        return;
    }
    let Ok((step, disabled)) = steps.get(activate.entity) else {
        return;
    };
    if disabled || !screens.iter().any(|screen| screen.nation == step.nation) {
        return;
    }
    let Some(mut session) = session else {
        return;
    };
    if matches!(
        session.0.player_trade_order(step.nation, step.commodity),
        PlayerTradeOrder::Sell(_)
    ) {
        session
            .0
            .step_player_trade_offer(step.nation, step.commodity, step.delta);
    }
}

fn on_trade_amount_bar_click(
    mut click: On<Pointer<Click>>,
    bars: Query<(
        &TradeAmountBar,
        &RelativeCursorPosition,
        Has<InteractionDisabled>,
    )>,
    screens: Query<&TradeScreen>,
    session: Option<ResMut<GameSession>>,
) {
    let Ok((bar, cursor, disabled)) = bars.get(click.entity) else {
        return;
    };
    if disabled || !screens.iter().any(|screen| screen.nation == bar.nation) {
        return;
    }
    let Some(normalized) = cursor.normalized.filter(|_| cursor.cursor_over()) else {
        return;
    };
    let Some(mut session) = session else {
        return;
    };
    if !matches!(
        session.0.player_trade_order(bar.nation, bar.commodity),
        PlayerTradeOrder::Sell(_)
    ) {
        return;
    }
    click.propagate(false);
    let capacity = session
        .0
        .nations()
        .major(bar.nation)
        .economy()
        .capacities
        .trade_offer;
    if capacity <= 0 {
        return;
    }
    let x = (((normalized.x + 0.5) * 100.0).floor() as i16).clamp(0, 99);
    if x == 0 {
        session
            .0
            .set_player_trade_order(bar.nation, bar.commodity, PlayerTradeOrder::None);
        return;
    }
    let quantity = i32::from(x) * i32::from(capacity) / 100 + 1;
    session.0.set_player_trade_order(
        bar.nation,
        bar.commodity,
        PlayerTradeOrder::Sell(quantity as i16),
    );
}

fn sync_trade_controls(
    session: Res<GameSession>,
    mut commands: Commands,
    rows: Query<(Entity, &TradeRow)>,
    mut cards: Query<(Entity, &TradeCard, &mut ImageNode, &mut Node)>,
    steps: Query<(Entity, &TradeStep)>,
    offer_controls: Query<(Entity, &TradeOfferControl)>,
) {
    for (entity, row) in &rows {
        commands
            .entity(entity)
            .insert(if trade_row_locked(row.commodity) {
                Visibility::Hidden
            } else {
                Visibility::Visible
            });
    }

    for (entity, card, mut image, mut node) in &mut cards {
        let major = session.0.nations().major(card.nation);
        let capacity = major.economy().capacities.trade_offer;
        let stock = major.city().stockpile[card.commodity.resource()];
        let order = session.0.player_trade_order(card.nation, card.commodity);
        let bid_count = TRADE_ROWS
            .iter()
            .filter(|row| {
                session.0.player_trade_order(card.nation, row.commodity) == PlayerTradeOrder::Buy
            })
            .count();
        let active = match card.kind {
            TradeCardKind::Bid => order == PlayerTradeOrder::Buy,
            TradeCardKind::Offer => matches!(order, PlayerTradeOrder::Sell(_)),
        };
        image.image = if active {
            card.pictures.active.clone()
        } else {
            card.pictures.idle.clone()
        };
        let (left, width) = match (card.kind, active) {
            (TradeCardKind::Bid, false) => (82.0, 17.0),
            (TradeCardKind::Bid, true) => (82.0, 65.0),
            (TradeCardKind::Offer, false) => (163.0, 17.0),
            (TradeCardKind::Offer, true) => (115.0, 65.0),
        };
        node.left = Val::Px(left);
        node.width = Val::Px(width);
        node.height = Val::Px(20.0);
        let visible = !trade_row_locked(card.commodity)
            && match card.kind {
                TradeCardKind::Bid => active || (capacity > 0 && bid_count < 4),
                TradeCardKind::Offer => capacity > 0 && (active || stock > 0),
            };
        set_trade_control(&mut commands, entity, visible, visible);
    }

    for (entity, step) in &steps {
        let major = session.0.nations().major(step.nation);
        let order = session.0.player_trade_order(step.nation, step.commodity);
        let quantity = match order {
            PlayerTradeOrder::Sell(quantity) => quantity,
            _ => 0,
        };
        let visible = !trade_row_locked(step.commodity)
            && quantity > 0
            && major.economy().capacities.trade_offer > 0;
        set_trade_control(&mut commands, entity, visible, visible);
    }

    for (entity, control) in &offer_controls {
        let capacity = session
            .0
            .nations()
            .major(control.nation)
            .economy()
            .capacities
            .trade_offer;
        let visible = capacity > 0
            && !trade_row_locked(control.commodity)
            && matches!(
                session
                    .0
                    .player_trade_order(control.nation, control.commodity),
                PlayerTradeOrder::Sell(quantity) if quantity > 0
            );
        commands.entity(entity).insert(if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        });
    }
}

fn sync_trade_gauges(session: Res<GameSession>, mut gauges: Query<(&TradeGauge, &mut Node)>) {
    for (gauge, mut node) in &mut gauges {
        let capacity = session
            .0
            .nations()
            .major(gauge.nation)
            .economy()
            .capacities
            .trade_offer;
        let quantity = match session.0.player_trade_order(gauge.nation, gauge.commodity) {
            PlayerTradeOrder::Sell(quantity) => quantity,
            _ => 0,
        };
        node.width = Val::Px(trade_gauge_width(quantity, capacity));
    }
}

fn sync_trade_advisories(
    session: Res<GameSession>,
    mut advisories: Query<(&TradeAdvisory, &mut Visibility)>,
) {
    for (advisory, mut visibility) in &mut advisories {
        *visibility =
            if trade_advisory_needed(session.0.nations().major(advisory.nation), advisory.kind) {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
    }
}

fn trade_advisory_needed(major: &MajorNation, kind: TradeAdvisoryKind) -> bool {
    let city = major.city();
    let economy = major.economy();
    let building = |slot| {
        i32::from(city.building_type(slot, economy, major.common().owned_region_count() as i32))
    };
    let stock_and_target = |resource| {
        i32::from(city.stockpile[resource]) + i32::from(economy.need_target_by_type[resource])
    };
    match kind {
        TradeAdvisoryKind::Food => {
            let on_hand = i32::from(city.stockpile[ResourceKind::Food])
                + i32::from(city.stockpile[ResourceKind::Livestock])
                + i32::from(city.stockpile[ResourceKind::Grain])
                + i32::from(city.stockpile[ResourceKind::Fruit])
                + i32::from(economy.need_target_by_type[ResourceKind::Livestock])
                + i32::from(economy.need_target_by_type[ResourceKind::Fruit])
                + i32::from(economy.need_target_by_type[ResourceKind::Fish])
                + i32::from(economy.need_target_by_type[ResourceKind::Grain]);
            let required = i32::from(city.population.predicted_need(ResourceKind::Livestock))
                + i32::from(city.population.predicted_need(ResourceKind::Fruit))
                + i32::from(city.population.predicted_need(ResourceKind::Grain));
            on_hand < required
        }
        TradeAdvisoryKind::Textile => {
            stock_and_target(ResourceKind::Cotton) + stock_and_target(ResourceKind::Wool)
                < building(CityFacilitySlot::TextileMill) * 2
        }
        TradeAdvisoryKind::Timber => {
            stock_and_target(ResourceKind::Timber) < building(CityFacilitySlot::LumberMill) * 2
        }
        TradeAdvisoryKind::Coal => {
            stock_and_target(ResourceKind::Coal) < building(CityFacilitySlot::SteelMill)
        }
        TradeAdvisoryKind::Iron => {
            stock_and_target(ResourceKind::Iron) < building(CityFacilitySlot::SteelMill)
        }
        TradeAdvisoryKind::Oil => {
            stock_and_target(ResourceKind::Oil) < building(CityFacilitySlot::OilRefinery) * 2
        }
        TradeAdvisoryKind::Fabric => {
            stock_and_target(ResourceKind::Fabric) < building(CityFacilitySlot::ClothingFactory) * 2
        }
        TradeAdvisoryKind::Lumber => {
            stock_and_target(ResourceKind::Lumber) < building(CityFacilitySlot::FurnitureFactory) * 2
        }
        TradeAdvisoryKind::Steel => {
            stock_and_target(ResourceKind::Steel) < building(CityFacilitySlot::Metalworks) * 2
        }
    }
}

#[allow(clippy::type_complexity)]
fn sync_trade_captions(
    session: Res<GameSession>,
    mut captions: Query<(
        &mut Text,
        Option<&TradeSellCaption>,
        Option<&TradePriceCaption>,
        Option<&TradeStockCaption>,
        Option<&TradeCapacityCaption>,
        Option<&TradeTreasuryCaption>,
    )>,
) {
    for (mut text, sell, price, stock, capacity, treasury) in &mut captions {
        if let Some(caption) = sell {
            text.0 = match session
                .0
                .player_trade_order(caption.nation, caption.commodity)
            {
                PlayerTradeOrder::Sell(quantity) => quantity.to_string(),
                _ => String::new(),
            };
        } else if let Some(caption) = price {
            text.0 = format_currency(session.0.market().rows[caption.commodity].price);
        } else if let Some(caption) = stock {
            let stock = session.0.nations().major(caption.nation).city().stockpile
                [caption.commodity.resource()];
            text.0 = if stock == 0 {
                "--".to_owned()
            } else {
                stock.to_string()
            };
        } else if let Some(caption) = capacity {
            text.0 = session
                .0
                .nations()
                .major(caption.nation)
                .economy()
                .capacities
                .trade_offer
                .to_string();
        } else if let Some(caption) = treasury {
            text.0 = format_currency(session.0.nations().major(caption.nation).common().treasury);
        }
    }
}

fn set_trade_control(commands: &mut Commands, entity: Entity, visible: bool, enabled: bool) {
    commands.entity(entity).insert(if visible {
        Visibility::Visible
    } else {
        Visibility::Hidden
    });
    if enabled {
        commands.entity(entity).remove::<InteractionDisabled>();
    } else {
        commands.entity(entity).insert(InteractionDisabled);
    }
}

const fn trade_row_locked(commodity: TradeCommodity) -> bool {
    // Retail's advanced-production unlock is not yet represented in semantic state.
    matches!(commodity, TradeCommodity::Oil | TradeCommodity::Fuel)
}

fn trade_gauge_width(quantity: i16, capacity: i16) -> f32 {
    if quantity <= 0 || capacity <= 0 {
        0.0
    } else {
        f32::from((i32::from(quantity) * 100 / i32::from(capacity)).clamp(0, 100) as i16)
    }
}

fn format_currency(value: i32) -> String {
    let negative = value < 0;
    let digits = i64::from(value).abs().to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    if negative {
        format!("-${grouped}")
    } else {
        format!("${grouped}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::catalog::spawn_view_nodes;
    use bevy::ecs::system::RunSystemOnce;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");
    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

    #[derive(Clone, Copy)]
    struct TestTrade {
        root: Entity,
        selected: Entity,
        return_to_map: Entity,
        fabric_offer: Entity,
        fabric_left: Entity,
        fabric_right: Entity,
    }

    fn fixture_session() -> GameSession {
        let save = LegacySaveV62::parse(BEGINNING_OF_GAME).unwrap();
        let state = save
            .game_state(LegacyGameStateContext {
                crt_rand_state: 1,
                map_generation_lcg: 0,
                zone_status_lcg: 3_916_827_792,
                selected_nation: NationId::new(6),
            })
            .unwrap();
        GameSession(state)
    }

    fn test_pictures() -> TradePictures {
        TradePictures {
            bid_active: Handle::default(),
            bid_idle: Handle::default(),
            offer_active: Handle::default(),
            offer_idle: Handle::default(),
            clothing_bid_active: Handle::default(),
            clothing_bid_idle: Handle::default(),
            clothing_offer_active: Handle::default(),
            clothing_offer_idle: Handle::default(),
        }
    }

    fn spawn_trade(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
        mut session: ResMut<GameSession>,
    ) -> TestTrade {
        let view = catalog.view(&trade_view_id()).unwrap();
        let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
        bind_game_screen_nav(&mut commands, &catalog, &spawned);
        let nation = MajorNationId::from_nation(session.0.turn().active_nation).unwrap();
        session.0.recall_player_trade_orders(nation);
        bind_trade_screen(
            &mut commands,
            &catalog,
            &spawned,
            nation,
            TextFont::default(),
            TextLayout::default(),
            Color::BLACK,
            TextFont::default(),
            TextLayout::default(),
            TextFont::default(),
            TextLayout::default(),
            test_pictures(),
            Color::BLACK,
        );
        let fabric_tag = fourcc!("ma1 ");
        TestTrade {
            root: spawned.root,
            selected: spawned.require_unique(fourcc!("trad")).unwrap(),
            return_to_map: spawned.require_unique(fourcc!("end ")).unwrap(),
            fabric_offer: spawned
                .require_under(&catalog, fabric_tag, fourcc!("offr"))
                .unwrap(),
            fabric_left: spawned
                .require_under(&catalog, fabric_tag, fourcc!("left"))
                .unwrap(),
            fabric_right: spawned
                .require_under(&catalog, fabric_tag, fourcc!("rght"))
                .unwrap(),
        }
    }

    fn activate(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
    }

    fn row_text(app: &mut App, commodity: TradeCommodity, price: bool) -> String {
        if price {
            let mut query = app.world_mut().query::<(&TradePriceCaption, &Text)>();
            query
                .iter(app.world())
                .find(|(caption, _)| caption.commodity == commodity)
                .unwrap()
                .1
                .0
                .clone()
        } else {
            let mut query = app.world_mut().query::<(&TradeStockCaption, &Text)>();
            query
                .iter(app.world())
                .find(|(caption, _)| caption.commodity == commodity)
                .unwrap()
                .1
                .0
                .clone()
        }
    }

    fn sell_text(app: &mut App, commodity: TradeCommodity) -> String {
        let mut query = app.world_mut().query::<(&TradeSellCaption, &Text)>();
        query
            .iter(app.world())
            .find(|(caption, _)| caption.commodity == commodity)
            .unwrap()
            .1
            .0
            .clone()
    }

    fn gauge_width(app: &mut App, commodity: TradeCommodity) -> f32 {
        let mut query = app.world_mut().query::<(&TradeGauge, &Node)>();
        let node = query
            .iter(app.world())
            .find(|(gauge, _)| gauge.commodity == commodity)
            .unwrap()
            .1;
        match node.width {
            Val::Px(width) => width,
            other => panic!("expected pixel gauge width, found {other:?}"),
        }
    }

    fn single_caption<C: Component>(app: &mut App) -> String {
        let mut query = app.world_mut().query_filtered::<&Text, With<C>>();
        query.single(app.world()).unwrap().0.clone()
    }

    #[test]
    fn trade_offer_round_trips_without_premature_settlement() {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog).unwrap())
            .insert_resource(fixture_session())
            .add_observer(on_trade_activate)
            .add_observer(on_trade_amount_bar_click)
            .add_systems(
                Update,
                (
                    sync_trade_controls,
                    sync_trade_captions,
                    sync_trade_gauges,
                    sync_trade_advisories,
                ),
            );

        let first = app.world_mut().run_system_once(spawn_trade).unwrap();
        app.update();
        assert!(app.world().get::<Checked>(first.selected).is_some());
        assert!(
            app.world()
                .get::<InteractionDisabled>(first.selected)
                .is_some()
        );
        assert!(
            app.world()
                .get::<InteractionDisabled>(first.return_to_map)
                .is_none()
        );
        assert_eq!(single_caption::<TradeCapacityCaption>(&mut app), "4");
        assert_eq!(single_caption::<TradeTreasuryCaption>(&mut app), "$10,000");
        assert_eq!(row_text(&mut app, TradeCommodity::Fabric, true), "$300");
        assert_eq!(row_text(&mut app, TradeCommodity::Fabric, false), "10");

        let nation = MajorNationId::new(6);
        let (stock_before, treasury_before) = {
            let session = app.world().resource::<GameSession>();
            let major = session.0.nations().major(nation);
            (major.city().stockpile, major.common().treasury)
        };
        activate(&mut app, first.fabric_offer);
        {
            let session = app.world().resource::<GameSession>();
            let major = session.0.nations().major(nation);
            assert_eq!(
                session.0.player_trade_order(nation, TradeCommodity::Fabric),
                PlayerTradeOrder::Sell(4)
            );
            assert_eq!(major.city().stockpile, stock_before);
            assert_eq!(major.common().treasury, treasury_before);
        }
        assert_eq!(sell_text(&mut app, TradeCommodity::Fabric), "4");
        assert_eq!(gauge_width(&mut app, TradeCommodity::Fabric), 100.0);
        let offer_node = app.world().get::<Node>(first.fabric_offer).unwrap();
        assert_eq!(offer_node.left, Val::Px(115.0));
        assert_eq!(offer_node.width, Val::Px(65.0));

        activate(&mut app, first.fabric_left);
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .0
                .player_trade_order(nation, TradeCommodity::Fabric),
            PlayerTradeOrder::Sell(3)
        );
        assert_eq!(sell_text(&mut app, TradeCommodity::Fabric), "3");
        assert_eq!(gauge_width(&mut app, TradeCommodity::Fabric), 75.0);
        assert!(
            app.world()
                .get::<InteractionDisabled>(first.fabric_right)
                .is_none()
        );

        app.world_mut()
            .run_system_once(remember_trade_orders)
            .unwrap();
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .0
                .nations()
                .major(nation)
                .economy()
                .remembered_trade_offers_by_resource[ResourceKind::Fabric],
            3
        );
        app.world_mut()
            .resource_mut::<GameSession>()
            .0
            .set_player_trade_order(nation, TradeCommodity::Fabric, PlayerTradeOrder::None);
        app.world_mut().commands().entity(first.root).despawn();
        app.world_mut().flush();

        app.world_mut().run_system_once(spawn_trade).unwrap();
        app.update();
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .0
                .player_trade_order(nation, TradeCommodity::Fabric),
            PlayerTradeOrder::Sell(3)
        );
        assert_eq!(sell_text(&mut app, TradeCommodity::Fabric), "3");
    }
}
