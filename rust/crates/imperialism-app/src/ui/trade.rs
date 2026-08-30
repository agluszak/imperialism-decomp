use super::GameSession;
use super::RetailUiAssets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::retail::{AmountBarParts, RetailTree, Step};
use super::retail_amount_bar::{
    TRADE_BAR_HEIGHT, amount_bar_x_from_normalized, trade_amount_bar_click_value,
    trade_amount_bar_geometry,
};
use crate::AppState;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, Button as UiButton};
use imperialism_core::*;
use imperialism_formats::*;

const TRADE_ROW_TAGS: TradeCommodityTable<FourCc> = TradeCommodityTable::from_array([
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
]);

#[derive(Clone, Copy)]
enum TradeAdvisory {
    Food,
    Input(TransportAllocation),
}

const TRADE_ADVISORIES: [(FourCc, TradeAdvisory); 10] = [
    (fourcc!("food"), TradeAdvisory::Food),
    (
        fourcc!("cott"),
        TradeAdvisory::Input(TransportAllocation::COTTON_AND_WOOL),
    ),
    (
        fourcc!("wool"),
        TradeAdvisory::Input(TransportAllocation::COTTON_AND_WOOL),
    ),
    (
        fourcc!("timb"),
        TradeAdvisory::Input(TransportAllocation::TIMBER),
    ),
    (
        fourcc!("coal"),
        TradeAdvisory::Input(TransportAllocation::COAL),
    ),
    (
        fourcc!("iron"),
        TradeAdvisory::Input(TransportAllocation::IRON),
    ),
    (
        fourcc!("oil "),
        TradeAdvisory::Input(TransportAllocation::OIL),
    ),
    (
        fourcc!("fabr"),
        TradeAdvisory::Input(TransportAllocation::FABRIC),
    ),
    (
        fourcc!("lumb"),
        TradeAdvisory::Input(TransportAllocation::LUMBER),
    ),
    (
        fourcc!("stee"),
        TradeAdvisory::Input(TransportAllocation::STEEL),
    ),
];

/// Retail picture for a trade card state.
fn trade_card_picture(commodity: TradeCommodity, kind: TradeCardKind, active: bool) -> PictureId {
    let base = if commodity == TradeCommodity::Clothing {
        PictureId::new(2125)
    } else {
        PictureId::new(2111)
    };
    base.offset(match (kind, active) {
        (TradeCardKind::Bid, true) => 0,
        (TradeCardKind::Bid, false) => 1,
        (TradeCardKind::Offer, true) => 2,
        (TradeCardKind::Offer, false) => 3,
    })
}

#[derive(Component)]
struct TradeScreen;

#[derive(Component)]
struct TradeView {
    capacity: Entity,
    advisories: [Entity; TRADE_ADVISORIES.len()],
    rows: TradeCommodityTable<TradeRowView>,
}

#[derive(Clone, Copy)]
struct TradeRowView {
    bid: Entity,
    offer: Entity,
    decrease: Entity,
    increase: Entity,
    quantity: Entity,
    offer_indicator: Entity,
    gauge: Entity,
    gauge_fill: Entity,
    gauge_limit: Entity,
    price: Entity,
    stock: Entity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TradeCardKind {
    Bid,
    Offer,
}

pub(crate) struct TradePlugin;

impl Plugin for TradePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::Trade),
            (enter_trade_screen, bind_trade_screen).chain(),
        )
        .add_systems(OnExit(AppState::Trade), remember_trade_orders)
        .add_systems(Update, render_trade.run_if(in_state(AppState::Trade)));
    }
}

fn enter_trade_screen(mut commands: Commands, mut session: ResMut<GameSession>) {
    let nation = session.active_major_nation();
    session.game.refresh_merchant_capacity(nation);
    session.game.recall_player_trade_orders(nation);
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
    amount_bars: Query<&AmountBarParts>,
    session: Res<GameSession>,
    mut assets: RetailUiAssets,
) {
    let root = *root;
    bind_native_game_screen_nav(
        &mut commands,
        root,
        &tree,
        fourcc!("topB"),
        Some(fourcc!("tool")),
        true,
        AppState::Trade,
    );
    bind_game_status_display(&mut commands, &mut assets, root, &tree);

    let capacity = tree.find(root, fourcc!("mCap"));
    commands.entity(capacity).insert(InteractionDisabled);
    let advisories = TRADE_ADVISORIES.map(|(tag, _)| tree.find(root, tag));
    let advanced = session.game.technology().advanced_production_unlocked();
    let text_style = assets.text_style(RetailTextStylePreset::explicit(2, 0, 14, -1));
    let text_color = assets.palette_color(0x13);
    let rows = TRADE_ROW_TAGS.map(|commodity, tag| {
        let row = tree.find(root, tag);
        if !advanced && matches!(commodity, TradeCommodity::Oil | TradeCommodity::Fuel) {
            commands.entity(row).insert(Visibility::Hidden);
        }
        bind_trade_row(
            &mut commands,
            &tree,
            row,
            commodity,
            &text_style,
            text_color,
            &amount_bars,
        )
    });
    commands.entity(root).insert(TradeView {
        capacity,
        advisories,
        rows,
    });
}

fn bind_trade_row(
    commands: &mut Commands,
    tree: &RetailTree,
    row: Entity,
    commodity: TradeCommodity,
    text_style: &(TextFont, TextLayout, LineHeight, bool),
    text_color: Color,
    amount_bars: &Query<&AmountBarParts>,
) -> TradeRowView {
    commands.entity(row).insert(Pickable::IGNORE);

    let card = tree.find(row, fourcc!("card"));
    let offer = tree.find(row, fourcc!("offr"));
    let bid = bind_trade_card(commands, card, commodity, TradeCardKind::Bid);
    let offer = bind_trade_card(commands, offer, commodity, TradeCardKind::Offer);

    let [decrease, increase] = [(fourcc!("left"), -1), (fourcc!("rght"), 1)].map(|(tag, delta)| {
        let step = tree.find(row, tag);
        commands.entity(step).observe(
            move |step_event: On<Step>,
                  disabled: Query<Has<InteractionDisabled>>,
                  mut session: ResMut<GameSession>| {
                if disabled.get(step_event.entity).unwrap_or(false) {
                    return;
                }
                let nation = session.active_major_nation();
                session
                    .game
                    .step_player_trade_offer(nation, commodity, delta);
            },
        );
        step
    });

    let quantity = tree.find(row, fourcc!("Sell"));
    let (font, layout, line_height, underline) = text_style;
    assert!(!underline, "retail Trade Sell counter is not underlined");
    commands
        .entity(quantity)
        .insert((font.clone(), *layout, *line_height, TextColor(text_color)));
    let offer_indicator = tree.find(row, fourcc!("gree"));
    let gauge = tree.find(row, fourcc!("bar "));
    commands.entity(gauge).observe(
        move |mut click: On<Pointer<Click>>, mut session: ResMut<GameSession>| {
            let Some(position) = click.hit.position else {
                return;
            };
            let nation = session.active_major_nation();
            if !matches!(
                session.game.player_trade_order(nation, commodity),
                PlayerTradeOrder::Sell(_)
            ) {
                return;
            }
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
            click.propagate(false);
            let geometry = trade_amount_bar_geometry(capacity);
            let x = amount_bar_x_from_normalized(geometry, position.x);
            let quantity = trade_amount_bar_click_value(geometry, x);
            if quantity == 0 {
                session
                    .game
                    .set_player_trade_order(nation, commodity, PlayerTradeOrder::None);
                return;
            }
            session.game.set_player_trade_order(
                nation,
                commodity,
                PlayerTradeOrder::Sell(quantity),
            );
        },
    );
    let price = spawn_trade_row_text(commands, row, 180.0, 58.0, text_style, text_color);
    let stock = spawn_trade_row_text(commands, row, 238.0, 62.0, text_style, text_color);
    let gauge_parts = amount_bars
        .get(gauge)
        .expect("bound trade amount bar must exist");
    TradeRowView {
        bid,
        offer,
        decrease,
        increase,
        quantity,
        offer_indicator,
        gauge,
        gauge_fill: gauge_parts.fill,
        gauge_limit: gauge_parts.limit,
        price,
        stock,
    }
}

fn spawn_trade_row_text(
    commands: &mut Commands,
    row: Entity,
    left: f32,
    width: f32,
    text_style: &(TextFont, TextLayout, LineHeight, bool),
    color: Color,
) -> Entity {
    let (font, layout, line_height, underline) = text_style;
    assert!(!underline, "retail Trade row text is not underlined");
    commands
        .spawn((
            Text::default(),
            font.clone(),
            *layout,
            *line_height,
            TextColor(color),
            Node {
                position_type: PositionType::Absolute,
                left: px(left),
                top: px(0),
                width: px(width),
                height: px(14),
                ..default()
            },
            Pickable::IGNORE,
            ZIndex(1),
            ChildOf(row),
        ))
        .id()
}

fn remember_trade_orders(mut session: ResMut<GameSession>) {
    let nation = session.active_major_nation();
    session.game.remember_trade_bids(nation);
}

fn render_trade(
    session: Res<GameSession>,
    view: Single<Ref<TradeView>>,
    mut assets: RetailUiAssets,
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
    let bid_count = view
        .rows
        .iter()
        .filter(|(commodity, _)| {
            session.game.player_trade_order(nation, *commodity) == PlayerTradeOrder::Buy
        })
        .count();

    for (commodity, row) in &view.rows {
        let order = session.game.player_trade_order(nation, commodity);
        let bid_active = order == PlayerTradeOrder::Buy;
        let offer_active = matches!(order, PlayerTradeOrder::Sell(_));
        render_trade_card(
            row.bid,
            assets.picture(trade_card_picture(
                commodity,
                TradeCardKind::Bid,
                bid_active,
            )),
            TradeCardKind::Bid,
            bid_active,
            &mut images,
            &mut nodes,
        );
        render_trade_card(
            row.offer,
            assets.picture(trade_card_picture(
                commodity,
                TradeCardKind::Offer,
                offer_active,
            )),
            TradeCardKind::Offer,
            offer_active,
            &mut images,
            &mut nodes,
        );
        // C++ `TTradeCluster::DoControlAction`: idle `card` tabs stay shown while
        // `fieldEc < 4`, otherwise `Show(0)`. Opening with `merchantCapacity == 0`
        // forces `fieldEc = 5`, which hides every non-selected bid tab.
        set_trade_visibility(
            &mut commands,
            row.bid,
            trade_bid_tab_visible(capacity, bid_active, bid_count),
        );
        set_trade_visibility(
            &mut commands,
            row.offer,
            trade_offer_tab_visible(
                capacity,
                offer_active,
                major.city.stockpile[commodity.resource()],
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
        let selling = quantity > 0 && capacity > 0;
        set_trade_visibility(&mut commands, row.decrease, selling);
        set_trade_visibility(&mut commands, row.increase, selling);
        set_trade_visibility(&mut commands, row.quantity, selling);
        set_trade_visibility(&mut commands, row.offer_indicator, selling);
        set_trade_visibility(&mut commands, row.gauge, selling);
        let geometry = trade_amount_bar_geometry(capacity);
        let stock = major.city.stockpile[commodity.resource()];
        let stock_marker = geometry.span(capacity.saturating_sub(stock));
        let offer_marker =
            (i32::from(TRADE_BAR_HEIGHT) * i32::from(quantity) / i32::from(capacity.max(1))) as i16;
        let mut stock_node = nodes
            .get_mut(row.gauge_fill)
            .expect("bound trade amount bar stock marker");
        stock_node.left = Val::Px(f32::from(stock_marker.saturating_sub(1)));
        let mut offer_node = nodes
            .get_mut(row.gauge_limit)
            .expect("bound trade amount bar offer marker");
        offer_node.left = Val::Px(f32::from(offer_marker.saturating_sub(1)));
        set_trade_visibility(&mut commands, row.gauge_fill, stock_marker > 0);
        set_trade_visibility(&mut commands, row.gauge_limit, offer_marker > 0);
        texts
            .get_mut(row.price)
            .expect("bound trade price text must exist")
            .0 = format_currency(session.game.market().rows[commodity].price);
        texts
            .get_mut(row.stock)
            .expect("bound trade stock text must exist")
            .0 = match major.city.stockpile[commodity.resource()] {
            0 => "--".to_owned(),
            stock => stock.to_string(),
        };
    }
    for ((_, rule), entity) in TRADE_ADVISORIES.iter().zip(view.advisories) {
        set_trade_visibility(
            &mut commands,
            entity,
            trade_advisory_needed(&session.game, nation, *rule),
        );
    }
}

fn render_trade_card(
    entity: Entity,
    picture: Handle<Image>,
    kind: TradeCardKind,
    active: bool,
    images: &mut Query<&mut ImageNode>,
    nodes: &mut Query<&mut Node>,
) {
    let mut image = images
        .get_mut(entity)
        .expect("bound trade card image must exist");
    image.image = picture;
    let mut node = nodes
        .get_mut(entity)
        .expect("bound trade card node must exist");
    node.width = px(if active { 65 } else { 17 });
    if kind == TradeCardKind::Offer {
        node.left = px(if active { 115 } else { 163 });
    }
}

fn trade_advisory_needed(state: &GameState, nation: MajorNationId, rule: TradeAdvisory) -> bool {
    let major = state.nations().major(nation);
    let city = &major.city;
    let economy = &major.economy;
    match rule {
        TradeAdvisory::Food => {
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
        TradeAdvisory::Input(allocation) => trade_input_short(state, nation, allocation),
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

fn set_trade_visibility(commands: &mut Commands, entity: Entity, visible: bool) {
    commands.entity(entity).insert(if visible {
        Visibility::Visible
    } else {
        Visibility::Hidden
    });
}

/// Idle buy tabs follow retail `fieldEc` / merchant-capacity gating.
const fn trade_bid_tab_visible(capacity: i16, active: bool, bid_count: usize) -> bool {
    active || (capacity > 0 && bid_count < 4)
}

fn bind_trade_card(
    commands: &mut Commands,
    entity: Entity,
    commodity: TradeCommodity,
    kind: TradeCardKind,
) -> Entity {
    commands
        .entity(entity)
        .entry::<Node>()
        .and_modify(move |mut node| {
            node.left = px(match kind {
                TradeCardKind::Bid => 82,
                TradeCardKind::Offer => 163,
            });
            node.width = px(17);
            node.height = px(20);
        });
    commands
        .entity(entity)
        .entry::<ImageNode>()
        .and_modify(|mut image| image.image_mode = NodeImageMode::Stretch);
    commands
        .entity(entity)
        .insert((UiButton, Pickable::default(), ZIndex(1)))
        .observe(
            move |activate: On<Activate>,
                  disabled: Query<Has<InteractionDisabled>>,
                  visibility: Query<&Visibility>,
                  mut session: ResMut<GameSession>| {
                if disabled.get(activate.entity).unwrap_or(false) {
                    return;
                }
                // C++ `TView::Show(0)` clears actionability; hidden buy tabs must not toggle.
                if visibility.get(activate.entity).ok() == Some(&Visibility::Hidden) {
                    return;
                }
                let nation = session.active_major_nation();
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
            },
        );
    entity
}

/// Idle `offr` tabs stay shown when merchant capacity is 0: C++ skips
/// `SetTradeOfferSecondaryBitmap` and leaves the DoPostCreate-enabled control.
/// With capacity, C++ hides the tab unless the row is selling or has stockpile.
const fn trade_offer_tab_visible(capacity: i16, active: bool, stockpile: i16) -> bool {
    capacity == 0 || active || stockpile > 0
}

#[cfg(test)]
mod tests {
    use super::super::retail::{RetailTag, Step};
    use super::super::retail_sideways_arrow::RetailSidewaysArrow;
    use super::*;
    use crate::ui::RetailUiPlugin;
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
        for (_, tag) in &TRADE_ROW_TAGS {
            let row = world
                .spawn((
                    RetailTag(*tag),
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
            world.spawn((
                RetailTag(fourcc!("left")),
                RetailSidewaysArrow,
                Pickable::default(),
                Node::default(),
                ChildOf(row),
            ));
            world.spawn((
                RetailTag(fourcc!("gree")),
                ImageNode::default(),
                Node::default(),
                ChildOf(row),
            ));
            world.spawn((
                RetailTag(fourcc!("rght")),
                RetailSidewaysArrow,
                Pickable::default(),
                Node::default(),
                ChildOf(row),
            ));
            let fill = world.spawn(Node::default()).id();
            let limit = world.spawn(Node::default()).id();
            world.spawn((
                RetailTag(fourcc!("bar ")),
                Node::default(),
                AmountBarParts { fill, limit },
                ChildOf(row),
            ));
        }
        root
    }

    fn bind_test_trade(
        mut commands: Commands,
        root: Single<Entity, Added<TestTradeRoot>>,
        tree: RetailTree,
        amount_bars: Query<&AmountBarParts>,
        session: Res<GameSession>,
    ) {
        let capacity = tree.find(*root, fourcc!("mCap"));
        let advisories = TRADE_ADVISORIES.map(|(tag, _)| tree.find(*root, tag));
        let text_style = (
            TextFont::default(),
            TextLayout::justify(Justify::Right),
            LineHeight::Px(14.0),
            false,
        );
        let advanced = session.game.technology().advanced_production_unlocked();
        let rows = TRADE_ROW_TAGS.map(|commodity, tag| {
            let row = tree.find(*root, tag);
            if !advanced && matches!(commodity, TradeCommodity::Oil | TradeCommodity::Fuel) {
                commands.entity(row).insert(Visibility::Hidden);
            }
            bind_trade_row(
                &mut commands,
                &tree,
                row,
                commodity,
                &text_style,
                Color::BLACK,
                &amount_bars,
            )
        });
        commands.entity(*root).insert(TradeView {
            capacity,
            advisories,
            rows,
        });
    }

    fn activate(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
    }

    fn step(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Step { entity });
        app.world_mut().flush();
        app.update();
    }

    #[test]
    fn trade_cards_and_arrows_update_the_player_order() {
        let state = fixture_state();
        let nation = MajorNationId::from_nation(state.turn().active_nation).unwrap();
        let major = state.nations().major(nation);
        let capacity = major.economy.capacities.trade_offer;
        let commodity = TRADE_ROW_TAGS
            .iter()
            .map(|(commodity, _)| commodity)
            .find(|commodity| {
                !matches!(commodity, TradeCommodity::Oil | TradeCommodity::Fuel)
                    && major.city.stockpile[commodity.resource()].min(capacity) > 1
            })
            .expect("the beginning-of-game fixture has a multi-unit trade offer");
        let mut app = App::new();
        app.add_plugins((
            MinimalPlugins,
            AssetPlugin::default(),
            ScenePlugin,
            StatesPlugin,
            RetailUiPlugin,
        ))
        .insert_state(AppState::Trade)
        .insert_resource(GameSession::new(state))
        .add_systems(Update, bind_test_trade);
        let root = spawn_trade_hierarchy(app.world_mut());
        app.update();

        for commodity in [TradeCommodity::Oil, TradeCommodity::Fuel] {
            let tag = TRADE_ROW_TAGS[commodity];
            let row = app
                .world_mut()
                .query::<(Entity, &RetailTag)>()
                .iter(app.world())
                .find(|(_, candidate)| candidate.0 == tag)
                .map(|(entity, _)| entity)
                .expect("generated trade row keeps its recovered tag");
            assert_eq!(
                app.world().get::<Visibility>(row),
                Some(&Visibility::Hidden),
                "advanced-production row must be hidden before the technology unlocks"
            );
        }

        let row = app
            .world()
            .get::<TradeView>(root)
            .expect("trade root has a semantic view")
            .rows[commodity];

        activate(&mut app, row.bid);
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .game
                .player_trade_order(nation, commodity),
            PlayerTradeOrder::Buy
        );

        activate(&mut app, row.offer);
        let PlayerTradeOrder::Sell(quantity) = app
            .world()
            .resource::<GameSession>()
            .game
            .player_trade_order(nation, commodity)
        else {
            panic!("activating the offer card must create a sell order");
        };
        assert!(quantity > 1);

        step(&mut app, row.decrease);
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
        assert!(trade_offer_tab_visible(0, false, 0));
        assert!(!trade_offer_tab_visible(4, false, 0));
        assert!(trade_offer_tab_visible(4, false, 2));
        assert!(trade_offer_tab_visible(4, true, 0));
    }

    #[test]
    fn idle_bid_tabs_follow_retail_four_bid_and_capacity_gates() {
        assert!(trade_bid_tab_visible(4, false, 0));
        assert!(trade_bid_tab_visible(4, false, 3));
        assert!(!trade_bid_tab_visible(4, false, 4));
        assert!(trade_bid_tab_visible(4, true, 4));
        assert!(!trade_bid_tab_visible(0, false, 0));
        assert!(trade_bid_tab_visible(0, true, 1));
    }

    #[test]
    fn hidden_idle_bid_tabs_do_not_accept_activation_at_the_four_bid_cap() {
        let state = fixture_state();
        let nation = MajorNationId::from_nation(state.turn().active_nation).unwrap();
        let bids = [
            TradeCommodity::Cotton,
            TradeCommodity::Wool,
            TradeCommodity::Timber,
            TradeCommodity::Coal,
        ];
        let other = TradeCommodity::Iron;
        let mut app = App::new();
        app.add_plugins((
            MinimalPlugins,
            AssetPlugin::default(),
            ScenePlugin,
            StatesPlugin,
            RetailUiPlugin,
        ))
        .insert_state(AppState::Trade)
        .insert_resource(GameSession::new(state))
        .add_systems(Update, bind_test_trade);
        let root = spawn_trade_hierarchy(app.world_mut());
        app.update();

        let rows = app
            .world()
            .get::<TradeView>(root)
            .expect("trade root has a semantic view")
            .rows;
        let bid = |commodity: TradeCommodity| rows[commodity].bid;

        for commodity in bids {
            activate(&mut app, bid(commodity));
            assert_eq!(
                app.world()
                    .resource::<GameSession>()
                    .game
                    .player_trade_order(nation, commodity),
                PlayerTradeOrder::Buy
            );
        }

        // Mirror `render_trade`'s retail projection without loading picture assets.
        let capacity = app
            .world()
            .resource::<GameSession>()
            .game
            .nations()
            .major(nation)
            .economy
            .capacities
            .trade_offer;
        let bid_count = bids.len();
        for (commodity, _) in &TRADE_ROW_TAGS {
            let active = app
                .world()
                .resource::<GameSession>()
                .game
                .player_trade_order(nation, commodity)
                == PlayerTradeOrder::Buy;
            let visible = trade_bid_tab_visible(capacity, active, bid_count);
            app.world_mut()
                .entity_mut(bid(commodity))
                .insert(if visible {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                });
        }

        assert_eq!(
            app.world().get::<Visibility>(bid(other)),
            Some(&Visibility::Hidden)
        );
        activate(&mut app, bid(other));
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .game
                .player_trade_order(nation, other),
            PlayerTradeOrder::None,
            "hidden idle buy tabs must not become a fifth bid"
        );

        activate(&mut app, bid(bids[0]));
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .game
                .player_trade_order(nation, bids[0]),
            PlayerTradeOrder::None
        );
        let bid_count = bids.len() - 1;
        for (commodity, _) in &TRADE_ROW_TAGS {
            let active = app
                .world()
                .resource::<GameSession>()
                .game
                .player_trade_order(nation, commodity)
                == PlayerTradeOrder::Buy;
            let visible = trade_bid_tab_visible(capacity, active, bid_count);
            app.world_mut()
                .entity_mut(bid(commodity))
                .insert(if visible {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                });
        }
        assert_eq!(
            app.world().get::<Visibility>(bid(other)),
            Some(&Visibility::Visible)
        );
        activate(&mut app, bid(other));
        assert_eq!(
            app.world()
                .resource::<GameSession>()
                .game
                .player_trade_order(nation, other),
            PlayerTradeOrder::Buy
        );
    }
}
