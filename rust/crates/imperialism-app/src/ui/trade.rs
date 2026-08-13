use super::RetailUiAssets;
use super::format_currency;
use super::game_shell::bind_native_game_screen_nav;
use super::generated;
use super::random_setup::GameSession;
use super::retail::{RetailTag, find_descendant};
use crate::AppState;
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

#[derive(Component)]
struct TradeScreen;

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

#[derive(Component, Clone, Copy)]
enum TradeAction {
    Card {
        commodity: TradeCommodity,
        kind: TradeCardKind,
    },
    Step {
        commodity: TradeCommodity,
        delta: i16,
    },
    Amount(TradeCommodity),
}

#[derive(Component)]
enum TradeDisplay {
    Card {
        commodity: TradeCommodity,
        kind: TradeCardKind,
        pictures: TradeCardPictures,
    },
    Step(TradeCommodity),
    Offer(TradeCommodity),
    Sell(TradeCommodity),
    Gauge(TradeCommodity),
    Price(TradeCommodity),
    Stock(TradeCommodity),
    Capacity,
    Treasury,
    Advisory(TradeAdvisoryKind),
}

pub(crate) struct TradePlugin;

impl Plugin for TradePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::Trade),
            (enter_trade_screen, bind_trade_screen).chain(),
        )
        .add_systems(OnExit(AppState::Trade), remember_trade_orders)
        .add_systems(
            Update,
            (sync_trade_text, sync_trade_visual, sync_trade_presence)
                .run_if(in_state(AppState::Trade)),
        )
        .add_observer(on_trade_activate.run_if(in_state(AppState::Trade)))
        .add_observer(on_trade_amount_bar_click.run_if(in_state(AppState::Trade)));
    }
}

fn enter_trade_screen(mut commands: Commands) {
    let root = commands.spawn_scene(generated::trade_2009()).id();
    commands
        .entity(root)
        .insert((TradeScreen, DespawnOnExit(AppState::Trade)));
}

fn bind_trade_screen(
    mut commands: Commands,
    root: Single<Entity, Added<TradeScreen>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    mut session: ResMut<GameSession>,
) {
    bind_native_game_screen_nav(
        &mut commands,
        *root,
        &children,
        &tags,
        fourcc!("topB"),
        Some(fourcc!("tool")),
    );
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Trade active nation is a major nation");
    session.0.recall_player_trade_orders(nation);

    let (row_font, row_layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 2,
            face_flags: 0,
            point_size: 14,
            alignment: -1,
        })
        .expect("retail trade row text style");
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
    bind_trade_controls(
        &mut commands,
        *root,
        &children,
        &tags,
        row_font,
        row_layout,
        assets.palette_color(0x13),
        pictures,
        assets.palette_color(0x37),
    );
}

#[allow(clippy::too_many_arguments)]
fn bind_trade_controls(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    row_font: TextFont,
    row_layout: TextLayout,
    row_color: Color,
    pictures: TradePictures,
    gauge_color: Color,
) {
    commands
        .entity(find_descendant(root, fourcc!("quer"), children, tags))
        .insert(InteractionDisabled);
    let selected = find_descendant(root, fourcc!("trad"), children, tags);
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));
    let capacity = find_descendant(root, fourcc!("mCap"), children, tags);
    commands
        .entity(capacity)
        .insert((TradeDisplay::Capacity, InteractionDisabled));
    let treasury = find_descendant(root, fourcc!("trea"), children, tags);
    commands.entity(treasury).insert(TradeDisplay::Treasury);
    for (tag, kind) in TRADE_ADVISORIES {
        let advisory = find_descendant(root, tag, children, tags);
        commands
            .entity(advisory)
            .insert(TradeDisplay::Advisory(kind));
    }

    for binding in TRADE_ROWS {
        let row = find_descendant(root, binding.tag, children, tags);
        if trade_row_locked(binding.commodity) {
            commands.entity(row).insert(Visibility::Hidden);
        }

        let card = find_descendant(row, fourcc!("card"), children, tags);
        let card_pictures = pictures.for_button(binding.commodity, TradeCardKind::Bid);
        let offer = find_descendant(row, fourcc!("offr"), children, tags);
        let offer_pictures = pictures.for_button(binding.commodity, TradeCardKind::Offer);
        commands.entity(card).despawn();
        commands.entity(offer).despawn();
        commands.entity(row).apply_scene(trade_order_controls(
            binding.commodity,
            card_pictures,
            offer_pictures,
        ));

        for (tag, delta) in [(fourcc!("left"), -1), (fourcc!("rght"), 1)] {
            let step = find_descendant(row, tag, children, tags);
            commands.entity(step).insert((
                TradeAction::Step {
                    commodity: binding.commodity,
                    delta,
                },
                TradeDisplay::Step(binding.commodity),
            ));
        }

        let sell = find_descendant(row, fourcc!("Sell"), children, tags);
        commands
            .entity(sell)
            .insert(TradeDisplay::Sell(binding.commodity));
        let green = find_descendant(row, fourcc!("gree"), children, tags);
        commands
            .entity(green)
            .insert(TradeDisplay::Offer(binding.commodity));
        let bar = find_descendant(row, fourcc!("bar "), children, tags);
        commands.entity(bar).insert((
            TradeAction::Amount(binding.commodity),
            TradeDisplay::Offer(binding.commodity),
            RelativeCursorPosition::default(),
        ));
        commands
            .entity(bar)
            .apply_scene(trade_gauge_overlay(binding.commodity, gauge_color));
        commands.entity(row).apply_scene(trade_row_overlay(
            binding.commodity,
            row_font.clone(),
            row_layout,
            row_color,
        ));
    }
}

fn trade_order_controls(
    commodity: TradeCommodity,
    bid: TradeCardPictures,
    offer: TradeCardPictures,
) -> impl Scene {
    let bid_image = bid.idle.clone();
    let offer_image = offer.idle.clone();
    bsn! {
        Children [
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(82),
                    top: px(0),
                    width: px(17),
                    height: px(20),
                }
                UiButton
                template(move |_context| Ok(ImageNode::new(bid_image.clone())))
                template(move |_context| Ok(TradeAction::Card {
                    commodity,
                    kind: TradeCardKind::Bid,
                }))
                template(move |_context| Ok(TradeDisplay::Card {
                    commodity,
                    kind: TradeCardKind::Bid,
                    pictures: bid.clone(),
                }))
            ),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(163),
                    top: px(0),
                    width: px(17),
                    height: px(20),
                }
                UiButton
                template(move |_context| Ok(ImageNode::new(offer_image.clone())))
                template(move |_context| Ok(TradeAction::Card {
                    commodity,
                    kind: TradeCardKind::Offer,
                }))
                template(move |_context| Ok(TradeDisplay::Card {
                    commodity,
                    kind: TradeCardKind::Offer,
                    pictures: offer.clone(),
                }))
            ),
        ]
    }
}

fn trade_gauge_overlay(commodity: TradeCommodity, color: Color) -> impl Scene {
    bsn! {
        Children [
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0),
                    top: px(0),
                    width: px(0),
                    height: px(7),
                }
                BackgroundColor(color)
                Pickable::IGNORE
                template(move |_context| Ok(TradeDisplay::Gauge(commodity)))
            ),
        ]
    }
}

fn trade_row_overlay(
    commodity: TradeCommodity,
    font: TextFont,
    layout: TextLayout,
    color: Color,
) -> impl Scene {
    let price_font = font.clone();
    bsn! {
        Children [
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(200),
                    top: px(-2),
                    width: px(38),
                    height: px(14),
                }
                Text("")
                template(move |_context| Ok(price_font.clone()))
                template(move |_context| Ok(layout))
                TextColor(color)
                Pickable::IGNORE
                template(move |_context| Ok(TradeDisplay::Price(commodity)))
            ),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(282),
                    top: px(-2),
                    width: px(18),
                    height: px(14),
                }
                Text("")
                template(move |_context| Ok(font.clone()))
                template(move |_context| Ok(layout))
                TextColor(color)
                Pickable::IGNORE
                template(move |_context| Ok(TradeDisplay::Stock(commodity)))
            ),
        ]
    }
}

fn remember_trade_orders(mut session: ResMut<GameSession>) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Trade active nation is a major nation");
    session.0.remember_trade_bids(nation);
}

fn on_trade_activate(
    activate: On<Activate>,
    actions: Query<(&TradeAction, Has<InteractionDisabled>)>,
    mut session: ResMut<GameSession>,
) {
    let Ok((action, disabled)) = actions.get(activate.entity) else {
        return;
    };
    if disabled {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Trade active nation is a major nation");
    match *action {
        TradeAction::Card { commodity, kind } => {
            let current = session.0.player_trade_order(nation, commodity);
            let order = match (kind, current) {
                (TradeCardKind::Bid, PlayerTradeOrder::Buy)
                | (TradeCardKind::Offer, PlayerTradeOrder::Sell(_)) => PlayerTradeOrder::None,
                (TradeCardKind::Bid, _) => PlayerTradeOrder::Buy,
                (TradeCardKind::Offer, _) => PlayerTradeOrder::Sell(i16::MAX),
            };
            session.0.set_player_trade_order(nation, commodity, order);
        }
        TradeAction::Step { commodity, delta } => {
            if matches!(
                session.0.player_trade_order(nation, commodity),
                PlayerTradeOrder::Sell(_)
            ) {
                session.0.step_player_trade_offer(nation, commodity, delta);
            }
        }
        TradeAction::Amount(_) => {}
    }
}

fn on_trade_amount_bar_click(
    mut click: On<Pointer<Click>>,
    bars: Query<(
        &TradeAction,
        &RelativeCursorPosition,
        Has<InteractionDisabled>,
    )>,
    mut session: ResMut<GameSession>,
) {
    let Ok((action, cursor, disabled)) = bars.get(click.entity) else {
        return;
    };
    let TradeAction::Amount(commodity) = *action else {
        return;
    };
    if disabled {
        return;
    }
    let Some(normalized) = cursor.normalized.filter(|_| cursor.cursor_over()) else {
        return;
    };
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Trade active nation is a major nation");
    if !matches!(
        session.0.player_trade_order(nation, commodity),
        PlayerTradeOrder::Sell(_)
    ) {
        return;
    }
    click.propagate(false);
    let capacity = session
        .0
        .nations()
        .major(nation)
        .economy
        .capacities
        .trade_offer;
    if capacity <= 0 {
        return;
    }
    let x = (((normalized.x + 0.5) * 100.0).floor() as i16).clamp(0, 99);
    if x == 0 {
        session
            .0
            .set_player_trade_order(nation, commodity, PlayerTradeOrder::None);
        return;
    }
    let quantity = i32::from(x) * i32::from(capacity) / 100 + 1;
    session
        .0
        .set_player_trade_order(nation, commodity, PlayerTradeOrder::Sell(quantity as i16));
}

fn sync_trade_text(
    session: Res<GameSession>,
    roots: Query<(), Added<TradeScreen>>,
    mut texts: Query<(&TradeDisplay, &mut Text)>,
) {
    if !session.is_changed() && roots.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Trade active nation is a major nation");
    let major = session.0.nations().major(nation);
    let capacity = major.economy.capacities.trade_offer;
    for (display, mut text) in &mut texts {
        match *display {
            TradeDisplay::Sell(commodity) => {
                text.0 = match session.0.player_trade_order(nation, commodity) {
                    PlayerTradeOrder::Sell(quantity) => quantity.to_string(),
                    _ => String::new(),
                };
            }
            TradeDisplay::Price(commodity) => {
                text.0 = format_currency(session.0.market().rows[commodity].price);
            }
            TradeDisplay::Stock(commodity) => {
                let stock = major.city.stockpile[commodity.resource()];
                text.0 = if stock == 0 {
                    "--".to_owned()
                } else {
                    stock.to_string()
                };
            }
            TradeDisplay::Capacity => text.0 = capacity.to_string(),
            TradeDisplay::Treasury => text.0 = format_currency(major.common.treasury),
            _ => {}
        }
    }
}

fn sync_trade_visual(
    session: Res<GameSession>,
    roots: Query<(), Added<TradeScreen>>,
    mut cards: Query<(&TradeDisplay, &mut ImageNode, &mut Node)>,
    mut gauges: Query<(&TradeDisplay, &mut Node), With<BackgroundColor>>,
) {
    if !session.is_changed() && roots.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Trade active nation is a major nation");
    let capacity = session
        .0
        .nations()
        .major(nation)
        .economy
        .capacities
        .trade_offer;
    for (display, mut image, mut node) in &mut cards {
        let TradeDisplay::Card {
            commodity,
            kind,
            pictures,
        } = display
        else {
            continue;
        };
        let order = session.0.player_trade_order(nation, *commodity);
        let active = match kind {
            TradeCardKind::Bid => order == PlayerTradeOrder::Buy,
            TradeCardKind::Offer => matches!(order, PlayerTradeOrder::Sell(_)),
        };
        image.image = if active {
            pictures.active.clone()
        } else {
            pictures.idle.clone()
        };
        let (left, width) = match (kind, active) {
            (TradeCardKind::Bid, false) => (82.0, 17.0),
            (TradeCardKind::Bid, true) => (82.0, 65.0),
            (TradeCardKind::Offer, false) => (163.0, 17.0),
            (TradeCardKind::Offer, true) => (115.0, 65.0),
        };
        node.left = Val::Px(left);
        node.width = Val::Px(width);
        node.height = Val::Px(20.0);
    }
    for (display, mut node) in &mut gauges {
        let TradeDisplay::Gauge(commodity) = *display else {
            continue;
        };
        let quantity = match session.0.player_trade_order(nation, commodity) {
            PlayerTradeOrder::Sell(quantity) => quantity,
            _ => 0,
        };
        node.width = Val::Px(trade_gauge_width(quantity, capacity));
    }
}

fn sync_trade_presence(
    session: Res<GameSession>,
    roots: Query<(), Added<TradeScreen>>,
    mut commands: Commands,
    displays: Query<(Entity, &TradeDisplay)>,
    mut advisories: Query<(&TradeDisplay, &mut Visibility)>,
) {
    if !session.is_changed() && roots.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Trade active nation is a major nation");
    let major = session.0.nations().major(nation);
    let capacity = major.economy.capacities.trade_offer;
    let bid_count = TRADE_ROWS
        .iter()
        .filter(|row| session.0.player_trade_order(nation, row.commodity) == PlayerTradeOrder::Buy)
        .count();

    for (entity, display) in &displays {
        match *display {
            TradeDisplay::Card {
                commodity, kind, ..
            } => {
                let order = session.0.player_trade_order(nation, commodity);
                let active = match kind {
                    TradeCardKind::Bid => order == PlayerTradeOrder::Buy,
                    TradeCardKind::Offer => matches!(order, PlayerTradeOrder::Sell(_)),
                };
                match kind {
                    TradeCardKind::Bid => {
                        let enabled = !trade_row_locked(commodity) && (active || bid_count < 4);
                        set_trade_interaction(&mut commands, entity, enabled);
                    }
                    TradeCardKind::Offer => {
                        let visible = capacity > 0
                            && !trade_row_locked(commodity)
                            && (active || major.city.stockpile[commodity.resource()] > 0);
                        set_trade_control(&mut commands, entity, visible);
                    }
                }
            }
            TradeDisplay::Step(commodity) => {
                let quantity = match session.0.player_trade_order(nation, commodity) {
                    PlayerTradeOrder::Sell(quantity) => quantity,
                    _ => 0,
                };
                let visible = !trade_row_locked(commodity) && quantity > 0 && capacity > 0;
                set_trade_control(&mut commands, entity, visible);
            }
            TradeDisplay::Offer(commodity) => {
                let visible = capacity > 0
                    && !trade_row_locked(commodity)
                    && matches!(
                        session.0.player_trade_order(nation, commodity),
                        PlayerTradeOrder::Sell(quantity) if quantity > 0
                    );
                commands.entity(entity).insert(if visible {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                });
            }
            TradeDisplay::Sell(commodity) => {
                let visible = capacity > 0
                    && !trade_row_locked(commodity)
                    && matches!(
                        session.0.player_trade_order(nation, commodity),
                        PlayerTradeOrder::Sell(quantity) if quantity > 0
                    );
                commands.entity(entity).insert(if visible {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                });
            }
            _ => {}
        }
    }
    for (display, mut visibility) in &mut advisories {
        let TradeDisplay::Advisory(kind) = *display else {
            continue;
        };
        *visibility = if trade_advisory_needed(major, kind) {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
}

fn trade_advisory_needed(major: &MajorNation, kind: TradeAdvisoryKind) -> bool {
    let city = &major.city;
    let economy = &major.economy;
    let building = |slot| {
        i32::from(city.building_type(slot, economy, major.common.owned_region_count() as i32))
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
            stock_and_target(ResourceKind::Lumber)
                < building(CityFacilitySlot::FurnitureFactory) * 2
        }
        TradeAdvisoryKind::Steel => {
            stock_and_target(ResourceKind::Steel) < building(CityFacilitySlot::Metalworks) * 2
        }
    }
}

fn set_trade_control(commands: &mut Commands, entity: Entity, visible: bool) {
    commands.entity(entity).insert(if visible {
        Visibility::Visible
    } else {
        Visibility::Hidden
    });
    if visible {
        commands.entity(entity).remove::<InteractionDisabled>();
    } else {
        commands.entity(entity).insert(InteractionDisabled);
    }
}

fn set_trade_interaction(commands: &mut Commands, entity: Entity, enabled: bool) {
    commands.entity(entity).insert(Visibility::Visible);
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
