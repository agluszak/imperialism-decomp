use super::GameSession;
use super::RetailUiAssets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::retail::{RetailTag, find_descendant};
use crate::AppState;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ActivateOnPress, Button as UiButton};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TradeCardKind {
    Bid,
    Offer,
}

#[derive(Clone)]
struct TradeCardPictures {
    active: Handle<Image>,
    idle: Handle<Image>,
}

#[derive(Component, Clone, Copy, Debug)]
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
    Row(TradeCommodity),
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
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Trade active nation is a major nation");
    session.game.refresh_merchant_capacity(nation);
    session.game.recall_player_trade_orders(nation);
    bind_game_status_display(&mut commands, &mut assets, *root, &children, &tags);

    let (row_font, row_layout, row_line_height, _) = assets
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
        row_line_height,
        assets.palette_color(0x13),
        pictures,
        assets.palette_color(0x37),
        session.game.technology().oil_drilling_available(),
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
    row_line_height: LineHeight,
    row_color: Color,
    pictures: TradePictures,
    gauge_color: Color,
    advanced_trade_unlocked: bool,
) {
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
        commands
            .entity(row)
            .insert((TradeDisplay::Row(binding.commodity), Pickable::IGNORE));
        set_trade_row_visible(
            commands,
            row,
            trade_row_available(advanced_trade_unlocked, binding.commodity),
        );

        let card = find_descendant(row, fourcc!("card"), children, tags);
        let card_pictures = pictures.for_button(binding.commodity, TradeCardKind::Bid);
        let offer = find_descendant(row, fourcc!("offr"), children, tags);
        let offer_pictures = pictures.for_button(binding.commodity, TradeCardKind::Offer);
        bind_trade_card(
            commands,
            card,
            binding.commodity,
            TradeCardKind::Bid,
            card_pictures,
        );
        bind_trade_card(
            commands,
            offer,
            binding.commodity,
            TradeCardKind::Offer,
            offer_pictures,
        );

        for (tag, delta) in [(fourcc!("left"), -1), (fourcc!("rght"), 1)] {
            let step = find_descendant(row, tag, children, tags);
            commands
                .entity(step)
                .insert((
                    ActivateOnPress,
                    TradeAction::Step {
                        commodity: binding.commodity,
                        delta,
                    },
                    TradeDisplay::Step(binding.commodity),
                ))
                .observe(on_trade_activate);
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
        commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0),
                    top: px(0),
                    width: px(0),
                    height: px(0),
                    overflow: Overflow::visible(),
                    ..default()
                },
                Pickable::IGNORE,
                ChildOf(row),
            ))
            .apply_scene(trade_row_overlay(
                binding.commodity,
                row_font.clone(),
                row_layout,
                row_line_height,
                row_color,
            ));
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
    line_height: LineHeight,
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
                template(move |_context| Ok(line_height))
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
                template(move |_context| Ok(line_height))
                TextColor(color)
                Pickable::IGNORE
                template(move |_context| Ok(TradeDisplay::Stock(commodity)))
            ),
        ]
    }
}

fn remember_trade_orders(mut session: ResMut<GameSession>) {
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Trade active nation is a major nation");
    session.game.remember_trade_bids(nation);
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
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Trade active nation is a major nation");
    match *action {
        TradeAction::Card { commodity, kind } => {
            let current = session.game.player_trade_order(nation, commodity);
            let order = match (kind, current) {
                (TradeCardKind::Bid, PlayerTradeOrder::Buy)
                | (TradeCardKind::Offer, PlayerTradeOrder::Sell(_)) => PlayerTradeOrder::None,
                (TradeCardKind::Bid, _) => PlayerTradeOrder::Buy,
                (TradeCardKind::Offer, _) => PlayerTradeOrder::Sell(i16::MAX),
            };
            session
                .game
                .set_player_trade_order(nation, commodity, order);
        }
        TradeAction::Step { commodity, delta } => {
            if matches!(
                session.game.player_trade_order(nation, commodity),
                PlayerTradeOrder::Sell(_)
            ) {
                session
                    .game
                    .step_player_trade_offer(nation, commodity, delta);
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
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Trade active nation is a major nation");
    if !matches!(
        session.game.player_trade_order(nation, commodity),
        PlayerTradeOrder::Sell(_)
    ) {
        return;
    }
    click.propagate(false);
    let capacity = session
        .game
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
            .game
            .set_player_trade_order(nation, commodity, PlayerTradeOrder::None);
        return;
    }
    let quantity = i32::from(x) * i32::from(capacity) / 100 + 1;
    session
        .game
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
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Trade active nation is a major nation");
    let major = session.game.nations().major(nation);
    let capacity = major.economy.capacities.trade_offer;
    for (display, mut text) in &mut texts {
        match *display {
            TradeDisplay::Sell(commodity) => {
                text.0 = match session.game.player_trade_order(nation, commodity) {
                    PlayerTradeOrder::Sell(quantity) => quantity.to_string(),
                    _ => String::new(),
                };
            }
            TradeDisplay::Price(commodity) => {
                text.0 = format_currency(session.game.market().rows[commodity].price);
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
    mut gauges: Query<(&TradeDisplay, &mut Node), Without<ImageNode>>,
) {
    if !session.is_changed() && roots.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Trade active nation is a major nation");
    let capacity = session
        .game
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
        let order = session.game.player_trade_order(nation, *commodity);
        let active = match kind {
            TradeCardKind::Bid => order == PlayerTradeOrder::Buy,
            TradeCardKind::Offer => matches!(order, PlayerTradeOrder::Sell(_)),
        };
        image.image = if active {
            pictures.active.clone()
        } else {
            pictures.idle.clone()
        };
        image.image_mode = NodeImageMode::Stretch;
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
        let quantity = match session.game.player_trade_order(nation, commodity) {
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
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Trade active nation is a major nation");
    let major = session.game.nations().major(nation);
    let capacity = major.economy.capacities.trade_offer;
    let advanced_trade_unlocked = session.game.technology().oil_drilling_available();
    let bid_count = TRADE_ROWS
        .iter()
        .filter(|row| {
            session.game.player_trade_order(nation, row.commodity) == PlayerTradeOrder::Buy
        })
        .count();

    for (entity, display) in &displays {
        match *display {
            TradeDisplay::Row(commodity) => set_trade_row_visible(
                &mut commands,
                entity,
                trade_row_available(advanced_trade_unlocked, commodity),
            ),
            TradeDisplay::Card {
                commodity, kind, ..
            } => {
                let order = session.game.player_trade_order(nation, commodity);
                let active = match kind {
                    TradeCardKind::Bid => order == PlayerTradeOrder::Buy,
                    TradeCardKind::Offer => matches!(order, PlayerTradeOrder::Sell(_)),
                };
                match kind {
                    TradeCardKind::Bid => {
                        let enabled = trade_row_available(advanced_trade_unlocked, commodity)
                            && (active || bid_count < 4);
                        set_trade_interaction(&mut commands, entity, enabled);
                    }
                    TradeCardKind::Offer => {
                        let visible = trade_offer_tab_visible(
                            trade_row_available(advanced_trade_unlocked, commodity),
                            capacity,
                            active,
                            major.city.stockpile[commodity.resource()],
                        );
                        set_trade_control(&mut commands, entity, visible);
                    }
                }
            }
            TradeDisplay::Step(commodity) => {
                let quantity = match session.game.player_trade_order(nation, commodity) {
                    PlayerTradeOrder::Sell(quantity) => quantity,
                    _ => 0,
                };
                let visible = trade_row_available(advanced_trade_unlocked, commodity)
                    && quantity > 0
                    && capacity > 0;
                set_trade_control(&mut commands, entity, visible);
            }
            TradeDisplay::Offer(commodity) => {
                let visible = capacity > 0
                    && trade_row_available(advanced_trade_unlocked, commodity)
                    && matches!(
                        session.game.player_trade_order(nation, commodity),
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
                    && trade_row_available(advanced_trade_unlocked, commodity)
                    && matches!(
                        session.game.player_trade_order(nation, commodity),
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
    let building =
        |slot| i32::from(city.building_type(slot, economy, major.common.owned_region_count()));
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

fn set_trade_row_visible(commands: &mut Commands, entity: Entity, visible: bool) {
    commands
        .entity(entity)
        .entry::<Node>()
        .and_modify(move |mut node| {
            node.display = if visible {
                Display::Flex
            } else {
                Display::None
            };
        });
}

const fn trade_row_available(advanced_trade_unlocked: bool, commodity: TradeCommodity) -> bool {
    advanced_trade_unlocked || !matches!(commodity, TradeCommodity::Oil | TradeCommodity::Fuel)
}

fn trade_card_image(image: Handle<Image>) -> ImageNode {
    ImageNode::new(image).with_mode(NodeImageMode::Stretch)
}

fn bind_trade_card(
    commands: &mut Commands,
    entity: Entity,
    commodity: TradeCommodity,
    kind: TradeCardKind,
    pictures: TradeCardPictures,
) {
    commands
        .entity(entity)
        .insert((
            UiButton,
            ActivateOnPress,
            Pickable::default(),
            ZIndex(1),
            trade_card_image(pictures.idle.clone()),
            TradeAction::Card { commodity, kind },
            TradeDisplay::Card {
                commodity,
                kind,
                pictures,
            },
        ))
        .observe(on_trade_activate);
}

/// Idle `offr` tabs stay shown when merchant capacity is 0: C++ skips
/// `SetTradeOfferSecondaryBitmap` and leaves the DoPostCreate-enabled control.
/// With capacity, C++ hides the tab unless the row is selling or has stockpile.
const fn trade_offer_tab_visible(
    row_available: bool,
    capacity: i16,
    active: bool,
    stockpile: i16,
) -> bool {
    row_available && (capacity == 0 || active || stockpile > 0)
}

fn trade_gauge_width(quantity: i16, capacity: i16) -> f32 {
    if quantity <= 0 || capacity <= 0 {
        0.0
    } else {
        f32::from((i32::from(quantity) * 100 / i32::from(capacity)).clamp(0, 100) as i16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::asset::AssetPlugin;
    use bevy::scene::ScenePlugin;
    use bevy::state::app::StatesPlugin;
    use imperialism_formats::{LegacyGameStateContext, LegacySaveV62, peek_save_header};

    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

    #[derive(Component)]
    struct TestTradeRoot;

    fn fixture_state() -> GameState {
        let selected_nation = peek_save_header(BEGINNING_OF_GAME)
            .and_then(|header| NationId::try_new(header.active_nation))
            .unwrap();
        let mut state =
            LegacySaveV62::parse(BEGINNING_OF_GAME).game_state(LegacyGameStateContext {
                crt_rand_state: 1,
                map_generation_lcg: 0,
                zone_status_lcg: 0,
                selected_nation,
            });
        state.recall_player_trade_orders(MajorNationId::from_nation(selected_nation).unwrap());
        state
    }

    fn spawn_trade_hierarchy(world: &mut World) {
        let root = world.spawn((TestTradeRoot, Node::default())).id();
        for tag in [fourcc!("trad"), fourcc!("mCap"), fourcc!("trea")] {
            world.spawn((RetailTag(tag), Node::default(), ChildOf(root)));
        }
        for (tag, _) in TRADE_ADVISORIES {
            world.spawn((RetailTag(tag), Node::default(), ChildOf(root)));
        }
        for binding in TRADE_ROWS {
            let row = world
                .spawn((RetailTag(binding.tag), Node::default(), ChildOf(root)))
                .id();
            world.spawn((RetailTag(fourcc!("Sell")), Node::default(), ChildOf(row)));
            world.spawn((RetailTag(fourcc!("card")), Node::default(), ChildOf(row)));
            world.spawn((RetailTag(fourcc!("offr")), Node::default(), ChildOf(row)));
            world.spawn((RetailTag(fourcc!("left")), Node::default(), ChildOf(row)));
            world.spawn((
                RetailTag(fourcc!("gree")),
                ImageNode::default(),
                Node::default(),
                ChildOf(row),
            ));
            world.spawn((RetailTag(fourcc!("rght")), Node::default(), ChildOf(row)));
            world.spawn((RetailTag(fourcc!("bar ")), Node::default(), ChildOf(row)));
        }
    }

    fn bind_test_trade(
        mut commands: Commands,
        root: Single<Entity, Added<TestTradeRoot>>,
        children: Query<&Children>,
        tags: Query<&RetailTag>,
    ) {
        let image = Handle::<Image>::default();
        bind_trade_controls(
            &mut commands,
            *root,
            &children,
            &tags,
            TextFont::default(),
            TextLayout::default(),
            LineHeight::default(),
            Color::BLACK,
            TradePictures {
                bid_active: image.clone(),
                bid_idle: image.clone(),
                offer_active: image.clone(),
                offer_idle: image.clone(),
                clothing_bid_active: image.clone(),
                clothing_bid_idle: image.clone(),
                clothing_offer_active: image.clone(),
                clothing_offer_idle: image,
            },
            Color::WHITE,
            false,
        );
    }

    fn activate(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
    }

    #[test]
    fn activating_generated_trade_offer_and_arrow_preserves_controls_and_updates_order() {
        let state = fixture_state();
        let nation = MajorNationId::from_nation(state.turn().active_nation).unwrap();
        let major = state.nations().major(nation);
        let capacity = major.economy.capacities.trade_offer;
        let commodity = TRADE_ROWS
            .into_iter()
            .map(|binding| binding.commodity)
            .find(|commodity| {
                trade_row_available(state.technology().oil_drilling_available(), *commodity)
                    && major.city.stockpile[commodity.resource()].min(capacity) > 1
            })
            .expect("the beginning-of-game fixture has a multi-unit trade offer");
        let mut app = App::new();
        app.add_plugins((
            MinimalPlugins,
            AssetPlugin::default(),
            ScenePlugin,
            StatesPlugin,
        ))
        .insert_state(AppState::Trade)
        .insert_resource(GameSession { game: state })
        .add_systems(
            Update,
            (bind_test_trade, sync_trade_visual, sync_trade_presence).chain(),
        );
        spawn_trade_hierarchy(app.world_mut());
        app.update();

        for commodity in [TradeCommodity::Oil, TradeCommodity::Fuel] {
            let row = app
                .world_mut()
                .query::<(Entity, &TradeDisplay, &Node)>()
                .iter(app.world())
                .find_map(|(entity, display, node)| {
                    matches!(display, TradeDisplay::Row(candidate) if *candidate == commodity)
                        .then_some((entity, node.display))
                })
                .expect("advanced commodity has a generated trade row");
            assert_eq!(row.1, Display::None);
            assert!(
                app.world_mut()
                    .query::<(&TradeAction, &ChildOf, Has<InteractionDisabled>)>()
                    .iter(app.world())
                    .filter(|(action, parent, _)| {
                        parent.parent() == row.0 && matches!(action, TradeAction::Card { .. })
                    })
                    .all(|(_, _, disabled)| disabled),
                "an undiscovered commodity must not retain an actionable card"
            );
        }

        let bid_card = app
            .world_mut()
            .query::<(Entity, &TradeAction, Has<InteractionDisabled>)>()
            .iter(app.world())
            .find_map(|(entity, action, disabled)| match *action {
                TradeAction::Card {
                    commodity: candidate,
                    kind: TradeCardKind::Bid,
                } if candidate == commodity && !disabled => Some(entity),
                _ => None,
            })
            .expect("the generated bid card is enabled");
        activate(&mut app, bid_card);
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .game
                .player_trade_order(nation, commodity),
            PlayerTradeOrder::Buy
        );

        let card = app
            .world_mut()
            .query::<(Entity, &TradeAction, Has<InteractionDisabled>)>()
            .iter(app.world())
            .find_map(|(entity, action, disabled)| match *action {
                TradeAction::Card {
                    commodity: candidate,
                    kind: TradeCardKind::Offer,
                } if candidate == commodity && !disabled => Some(entity),
                _ => None,
            })
            .expect("the generated offer card is enabled");
        assert_eq!(
            app.world().get::<Visibility>(card),
            Some(&Visibility::Visible)
        );
        let offer_node = app.world().get::<Node>(card).unwrap();
        assert_eq!(offer_node.left, Val::Px(163.0));
        assert_eq!(offer_node.width, Val::Px(17.0));
        assert_eq!(offer_node.height, Val::Px(20.0));
        let row = app.world().get::<ChildOf>(card).unwrap().parent();
        for tag in [
            fourcc!("card"),
            fourcc!("offr"),
            fourcc!("left"),
            fourcc!("gree"),
            fourcc!("rght"),
            fourcc!("bar "),
        ] {
            assert!(
                app.world_mut()
                    .query::<(&RetailTag, &ChildOf)>()
                    .iter(app.world())
                    .any(|(candidate, parent)| candidate.0 == tag && parent.parent() == row),
                "generated {tag:?} control was removed from its trade row"
            );
        }
        assert_eq!(
            app.world_mut()
                .query::<&TradeAction>()
                .iter(app.world())
                .filter(|action| matches!(action, TradeAction::Card { .. }))
                .count(),
            TRADE_ROWS.len() * 2
        );

        activate(&mut app, card);
        let PlayerTradeOrder::Sell(quantity) = app
            .world()
            .resource::<GameSession>()
            .game
            .player_trade_order(nation, commodity)
        else {
            panic!("activating the offer card must create a sell order");
        };
        assert!(quantity > 1);

        let left = app
            .world_mut()
            .query::<(Entity, &TradeAction, Has<InteractionDisabled>)>()
            .iter(app.world())
            .find_map(|(entity, action, disabled)| match *action {
                TradeAction::Step {
                    commodity: candidate,
                    delta: -1,
                } if candidate == commodity && !disabled => Some(entity),
                _ => None,
            })
            .expect("the generated left arrow is enabled for the sell order");
        activate(&mut app, left);
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .game
                .player_trade_order(nation, commodity),
            PlayerTradeOrder::Sell(quantity - 1)
        );
    }

    #[test]
    fn idle_offer_tabs_follow_retail_capacity_and_stockpile_gates() {
        assert!(trade_offer_tab_visible(true, 0, false, 0));
        assert!(!trade_offer_tab_visible(true, 4, false, 0));
        assert!(trade_offer_tab_visible(true, 4, false, 2));
        assert!(trade_offer_tab_visible(true, 4, true, 0));
        assert!(!trade_offer_tab_visible(false, 4, false, 2));
    }
}
