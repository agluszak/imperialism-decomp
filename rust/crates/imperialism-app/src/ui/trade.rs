use super::GameSession;
use super::RetailUiAssets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::retail::RetailTree;
use super::retail_amount_bar::{
    AmountBarPixels, TRADE_AMOUNT_BAR, TRADE_BAR_FILL, amount_bar_x_from_normalized,
    trade_amount_bar_click_value, trade_amount_bar_picture,
};
use super::retail_raster::IndexedRasterExt;
use super::retail_raster_text::RetailRasterTextPainter;
use crate::{AppState, RetailAssetsResource, RetailFonts};
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
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

#[derive(Component)]
struct TradeView {
    main: Entity,
    capacity: Entity,
    advisories: Vec<TradeAdvisoryView>,
    rows: Vec<TradeRowView>,
    base: IndexedPicture,
}

struct TradeAdvisoryView {
    kind: TradeAdvisoryKind,
    entity: Entity,
}

struct TradeRowView {
    commodity: TradeCommodity,
    row: Entity,
    bid: TradeCardView,
    offer: TradeCardView,
    decrease: Entity,
    increase: Entity,
    quantity: Entity,
    offer_indicator: Entity,
    gauge: Entity,
    origin: IVec2,
}

struct TradeCardView {
    entity: Entity,
    pictures: TradeCardPictures,
}

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
            (render_trade, render_trade_rasters).run_if(in_state(AppState::Trade)),
        );
    }
}

fn enter_trade_screen(mut commands: Commands, session: Res<GameSession>) {
    let root = if session.game.technology().advanced_production_unlocked() {
        commands.spawn_scene(generated::trade_2010()).id()
    } else {
        commands.spawn_scene(generated::trade_2009()).id()
    };
    commands
        .entity(root)
        .insert((TradeScreen, DespawnOnExit(AppState::Trade)));
}

fn bind_trade_screen(
    mut commands: Commands,
    root: Single<Entity, Added<TradeScreen>>,
    tree: RetailTree,
    nodes: Query<&Node>,
    mut assets: RetailUiAssets,
    mut session: ResMut<GameSession>,
) {
    bind_native_game_screen_nav(
        &mut commands,
        *root,
        &tree,
        fourcc!("topB"),
        Some(fourcc!("tool")),
        true,
    );
    let nation = session.active_major_nation();
    session.game.refresh_merchant_capacity(nation);
    session.game.recall_player_trade_orders(nation);
    bind_game_status_display(&mut commands, &mut assets, *root, &tree);

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
    let (capacity, advisories, rows) = bind_trade_controls(
        &mut commands,
        *root,
        &tree,
        &nodes,
        pictures,
        session.game.technology().advanced_production_unlocked(),
    );
    let palette = *assets.default_dib_palette();
    for row in &rows {
        let picture = trade_amount_bar_picture(AmountBarPixels {
            range: 0,
            current: 0,
            color: TRADE_BAR_FILL,
        });
        let image = assets.add_image(picture.to_keyed_image(&palette, 0x10));
        commands.entity(row.gauge).insert(ImageNode::new(image));
    }
    let base = assets
        .indexed_picture(PictureId::new(2101))
        .expect("retail Trade screen picture must load");
    let image = assets.add_image(base.to_image(&palette));
    let main = tree.find(*root, fourcc!("main"));
    commands.entity(main).insert(ImageNode::new(image));
    commands.entity(*root).insert(TradeView {
        main,
        capacity,
        advisories,
        rows,
        base,
    });
}

fn bind_trade_controls(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    nodes: &Query<&Node>,
    pictures: TradePictures,
    advanced_trade_unlocked: bool,
) -> (Entity, Vec<TradeAdvisoryView>, Vec<TradeRowView>) {
    let selected = tree.find(root, fourcc!("trad"));
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));
    let capacity = tree.find(root, fourcc!("mCap"));
    commands.entity(capacity).insert(InteractionDisabled);
    let advisories = TRADE_ADVISORIES
        .map(|(tag, kind)| TradeAdvisoryView {
            kind,
            entity: tree.find(root, tag),
        })
        .into_iter()
        .collect();

    let rows = TRADE_ROWS
        .map(|binding| {
            let row = tree.find(root, binding.tag);
            commands.entity(row).insert(Pickable::IGNORE);
            set_trade_row_visible(
                commands,
                row,
                trade_row_available(advanced_trade_unlocked, binding.commodity),
            );

            let card = tree.find(row, fourcc!("card"));
            let card_pictures = pictures.for_button(binding.commodity, TradeCardKind::Bid);
            let offer = tree.find(row, fourcc!("offr"));
            let offer_pictures = pictures.for_button(binding.commodity, TradeCardKind::Offer);
            let bid = bind_trade_card(
                commands,
                card,
                binding.commodity,
                TradeCardKind::Bid,
                card_pictures,
            );
            let offer = bind_trade_card(
                commands,
                offer,
                binding.commodity,
                TradeCardKind::Offer,
                offer_pictures,
            );

            let [decrease, increase] =
                [(fourcc!("left"), -1), (fourcc!("rght"), 1)].map(|(tag, delta)| {
                    let step = tree.find(row, tag);
                    commands
                        .entity(step)
                        .insert((
                            ActivateOnPress,
                            TradeAction::Step {
                                commodity: binding.commodity,
                                delta,
                            },
                        ))
                        .observe(on_trade_activate);
                    step
                });

            let quantity = tree.find(row, fourcc!("Sell"));
            let offer_indicator = tree.find(row, fourcc!("gree"));
            let gauge = tree.find(row, fourcc!("bar "));
            commands
                .entity(gauge)
                .insert((
                    TradeAction::Amount(binding.commodity),
                    RelativeCursorPosition::default(),
                ))
                .observe(on_trade_amount_bar_click);
            let node = nodes.get(row).expect("generated trade row has layout");
            let Val::Px(left) = node.left else {
                panic!("generated trade row has a pixel left position");
            };
            let Val::Px(top) = node.top else {
                panic!("generated trade row has a pixel top position");
            };
            TradeRowView {
                commodity: binding.commodity,
                row,
                bid,
                offer,
                decrease,
                increase,
                quantity,
                offer_indicator,
                gauge,
                origin: IVec2::new(left as i32, top as i32),
            }
        })
        .into_iter()
        .collect();
    (capacity, advisories, rows)
}

fn remember_trade_orders(mut session: ResMut<GameSession>) {
    let nation = session.active_major_nation();
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
    let nation = session.active_major_nation();
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
    let nation = session.active_major_nation();
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
    let geometry = TRADE_AMOUNT_BAR.with_segments(capacity);
    let x = amount_bar_x_from_normalized(geometry, normalized.x);
    let quantity = trade_amount_bar_click_value(geometry, x);
    if quantity == 0 {
        session
            .game
            .set_player_trade_order(nation, commodity, PlayerTradeOrder::None);
        return;
    }
    session
        .game
        .set_player_trade_order(nation, commodity, PlayerTradeOrder::Sell(quantity));
}

fn render_trade(
    session: Res<GameSession>,
    view: Single<Ref<TradeView>>,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
    mut images: Query<&mut ImageNode>,
    mut nodes: Query<&mut Node>,
) {
    if !session.is_changed() && !view.is_added() {
        return;
    }
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let capacity = major.economy.capacities.trade_offer;
    texts
        .get_mut(view.capacity)
        .expect("bound trade capacity text must exist")
        .0 = capacity.to_string();
    let advanced_trade_unlocked = session.game.technology().advanced_production_unlocked();
    let bid_count = view
        .rows
        .iter()
        .filter(|row| {
            session.game.player_trade_order(nation, row.commodity) == PlayerTradeOrder::Buy
        })
        .count();

    for row in &view.rows {
        let available = trade_row_available(advanced_trade_unlocked, row.commodity);
        set_trade_row_visible(&mut commands, row.row, available);
        let order = session.game.player_trade_order(nation, row.commodity);
        let bid_active = order == PlayerTradeOrder::Buy;
        let offer_active = matches!(order, PlayerTradeOrder::Sell(_));
        render_trade_card(
            &row.bid,
            TradeCardKind::Bid,
            bid_active,
            &mut images,
            &mut nodes,
        );
        render_trade_card(
            &row.offer,
            TradeCardKind::Offer,
            offer_active,
            &mut images,
            &mut nodes,
        );
        set_trade_interaction(
            &mut commands,
            row.bid.entity,
            available && (bid_active || bid_count < 4),
        );
        set_trade_control(
            &mut commands,
            row.offer.entity,
            trade_offer_tab_visible(
                available,
                capacity,
                offer_active,
                major.city.stockpile[row.commodity.resource()],
            ),
        );
        let quantity = match order {
            PlayerTradeOrder::Sell(quantity) => quantity,
            _ => 0,
        };
        texts
            .get_mut(row.quantity)
            .expect("bound trade quantity text must exist")
            .0 = if quantity > 0 {
            quantity.to_string()
        } else {
            String::new()
        };
        let step_visible = available && quantity > 0 && capacity > 0;
        set_trade_control(&mut commands, row.decrease, step_visible);
        set_trade_control(&mut commands, row.increase, step_visible);
        let offer_visible = capacity > 0 && available && quantity > 0;
        set_trade_visibility(&mut commands, row.quantity, offer_visible);
        set_trade_visibility(&mut commands, row.offer_indicator, offer_visible);
        set_trade_visibility(&mut commands, row.gauge, offer_visible);
    }
    for advisory in &view.advisories {
        set_trade_visibility(
            &mut commands,
            advisory.entity,
            trade_advisory_needed(&session.game, nation, advisory.kind),
        );
    }
}

fn render_trade_card(
    card: &TradeCardView,
    kind: TradeCardKind,
    active: bool,
    images: &mut Query<&mut ImageNode>,
    nodes: &mut Query<&mut Node>,
) {
    let mut image = images
        .get_mut(card.entity)
        .expect("bound trade card image must exist");
    image.image = if active {
        card.pictures.active.clone()
    } else {
        card.pictures.idle.clone()
    };
    image.image_mode = NodeImageMode::Stretch;
    let (left, width) = match (kind, active) {
        (TradeCardKind::Bid, false) => (82.0, 17.0),
        (TradeCardKind::Bid, true) => (82.0, 65.0),
        (TradeCardKind::Offer, false) => (163.0, 17.0),
        (TradeCardKind::Offer, true) => (115.0, 65.0),
    };
    let mut node = nodes
        .get_mut(card.entity)
        .expect("bound trade card node must exist");
    node.left = Val::Px(left);
    node.width = Val::Px(width);
    node.height = Val::Px(20.0);
}

fn render_trade_rasters(
    session: Res<GameSession>,
    view: Single<Ref<TradeView>>,
    retail: Res<RetailAssetsResource>,
    fonts: Res<RetailFonts>,
    font_assets: Res<Assets<Font>>,
    mut images: ResMut<Assets<Image>>,
    image_nodes: Query<&ImageNode>,
) {
    if !session.is_changed() && !view.is_added() {
        return;
    }
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let mut text = RetailRasterTextPainter::from_preset(
        &fonts,
        &font_assets,
        RetailTextStylePreset {
            font_family: 2,
            face_flags: 0,
            point_size: 14,
            alignment: -1,
        },
    )
    .expect("retail Trade custom-drawing text style");
    let mut picture = view.base.clone();
    for row in &view.rows {
        let stock = match major.city.stockpile[row.commodity.resource()] {
            0 => "--".to_owned(),
            stock => stock.to_string(),
        };
        text.draw_right(
            &mut picture,
            row.origin.x + 238,
            row.origin.y + 12,
            &format_currency(session.game.market().rows[row.commodity].price),
            0x13,
        );
        text.draw_right(
            &mut picture,
            row.origin.x + 300,
            row.origin.y + 12,
            &stock,
            0x13,
        );
    }
    let main = image_nodes
        .get(view.main)
        .expect("bound trade screen image must exist");
    if let Some(mut image) = images.get_mut(&main.image) {
        *image = picture.to_image(retail.assets().default_dib_palette());
    }

    let capacity = major.economy.capacities.trade_offer;
    let geometry = TRADE_AMOUNT_BAR.with_segments(capacity);
    for row in &view.rows {
        let quantity = match session.game.player_trade_order(nation, row.commodity) {
            PlayerTradeOrder::Sell(quantity) => quantity,
            _ => 0,
        };
        let picture = trade_amount_bar_picture(AmountBarPixels {
            range: geometry.span(quantity),
            current: geometry.span(quantity),
            color: TRADE_BAR_FILL,
        });
        let gauge = image_nodes
            .get(row.gauge)
            .expect("bound trade gauge image must exist");
        if let Some(mut image) = images.get_mut(&gauge.image) {
            *image = picture.to_keyed_image(retail.assets().default_dib_palette(), 0x10);
        }
    }
}

fn trade_advisory_needed(
    state: &GameState,
    nation: MajorNationId,
    kind: TradeAdvisoryKind,
) -> bool {
    let major = state.nations().major(nation);
    let city = &major.city;
    let economy = &major.economy;
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
            trade_input_short(state, nation, TransportAllocation::COTTON_AND_WOOL)
        }
        TradeAdvisoryKind::Timber => trade_input_short(state, nation, TransportAllocation::TIMBER),
        TradeAdvisoryKind::Coal => trade_input_short(state, nation, TransportAllocation::COAL),
        TradeAdvisoryKind::Iron => trade_input_short(state, nation, TransportAllocation::IRON),
        TradeAdvisoryKind::Oil => trade_input_short(state, nation, TransportAllocation::OIL),
        TradeAdvisoryKind::Fabric => trade_input_short(state, nation, TransportAllocation::FABRIC),
        TradeAdvisoryKind::Lumber => trade_input_short(state, nation, TransportAllocation::LUMBER),
        TradeAdvisoryKind::Steel => trade_input_short(state, nation, TransportAllocation::STEEL),
    }
}

fn trade_input_short(
    state: &GameState,
    nation: MajorNationId,
    allocation: TransportAllocation,
) -> bool {
    let Some(required) = state.transport_requirement(nation, allocation) else {
        return false;
    };
    let major = state.nations().major(nation);
    let (primary, secondary) = allocation.resources();
    let on_hand = |resource| {
        i32::from(major.city.stockpile[resource])
            + i32::from(major.economy.need_target_by_type[resource])
    };
    on_hand(primary) + secondary.map_or(0, on_hand) < i32::from(required)
}

fn set_trade_control(commands: &mut Commands, entity: Entity, visible: bool) {
    set_trade_visibility(commands, entity, visible);
    if visible {
        commands.entity(entity).remove::<InteractionDisabled>();
    } else {
        commands.entity(entity).insert(InteractionDisabled);
    }
}

fn set_trade_visibility(commands: &mut Commands, entity: Entity, visible: bool) {
    commands.entity(entity).insert(if visible {
        Visibility::Visible
    } else {
        Visibility::Hidden
    });
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
) -> TradeCardView {
    commands
        .entity(entity)
        .insert((
            UiButton,
            ActivateOnPress,
            Pickable::default(),
            ZIndex(1),
            trade_card_image(pictures.idle.clone()),
            TradeAction::Card { commodity, kind },
        ))
        .observe(on_trade_activate);
    TradeCardView { entity, pictures }
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

#[cfg(test)]
mod tests {
    use super::super::retail::RetailTag;
    use super::*;
    use crate::ui::test_support::beginning_of_game;
    use bevy::asset::AssetPlugin;
    use bevy::scene::ScenePlugin;
    use bevy::state::app::StatesPlugin;

    #[derive(Component)]
    struct TestTradeRoot;

    fn fixture_state() -> GameState {
        let mut state = beginning_of_game();
        state.recall_player_trade_orders(
            MajorNationId::from_nation(state.turn().active_nation).unwrap(),
        );
        state
    }

    fn spawn_trade_hierarchy(world: &mut World) -> Entity {
        let root = world.spawn((TestTradeRoot, Node::default())).id();
        world.spawn((RetailTag(fourcc!("trad")), Node::default(), ChildOf(root)));
        world.spawn((RetailTag(fourcc!("mCap")), Text::default(), ChildOf(root)));
        world.spawn((RetailTag(fourcc!("trea")), Node::default(), ChildOf(root)));
        for (tag, _) in TRADE_ADVISORIES {
            world.spawn((RetailTag(tag), Node::default(), ChildOf(root)));
        }
        for binding in TRADE_ROWS {
            let row = world
                .spawn((
                    RetailTag(binding.tag),
                    Node {
                        left: Val::Px(0.0),
                        top: Val::Px(0.0),
                        ..default()
                    },
                    ChildOf(root),
                ))
                .id();
            world.spawn((RetailTag(fourcc!("Sell")), Text::default(), ChildOf(row)));
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
        root
    }

    fn bind_test_trade(
        mut commands: Commands,
        root: Single<Entity, Added<TestTradeRoot>>,
        tree: RetailTree,
        nodes: Query<&Node>,
    ) {
        let image = Handle::<Image>::default();
        let (capacity, advisories, rows) = bind_trade_controls(
            &mut commands,
            *root,
            &tree,
            &nodes,
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
            false,
        );
        commands.entity(*root).insert(TradeView {
            main: *root,
            capacity,
            advisories,
            rows,
            base: IndexedPicture {
                width: 0,
                height: 0,
                pixels: Vec::new(),
            },
        });
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
                trade_row_available(
                    state.technology().advanced_production_unlocked(),
                    *commodity,
                ) && major.city.stockpile[commodity.resource()].min(capacity) > 1
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
        .insert_resource(GameSession::new(state))
        .add_systems(Update, (bind_test_trade, render_trade).chain());
        let root = spawn_trade_hierarchy(app.world_mut());
        app.update();

        for commodity in [TradeCommodity::Oil, TradeCommodity::Fuel] {
            let row = app
                .world()
                .get::<TradeView>(root)
                .expect("trade root has a semantic view")
                .rows
                .iter()
                .find(|row| row.commodity == commodity)
                .map(|row| (row.row, app.world().get::<Node>(row.row).unwrap().display))
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
