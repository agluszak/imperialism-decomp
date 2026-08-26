use super::GameSession;
use super::RetailUiAssets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::retail::RetailTree;
use super::retail_amount_bar::{
    TRADE_AMOUNT_BAR, TRADE_BAR_FILL, amount_bar_x_from_normalized, trade_amount_bar_click_value,
};
use crate::AppState;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ActivateOnPress, Button as UiButton};
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
    fn for_button(
        &self,
        commodity: TradeCommodity,
        kind: TradeCardKind,
        active: bool,
    ) -> &Handle<Image> {
        let clothing = commodity == TradeCommodity::Clothing;
        match (kind, clothing, active) {
            (TradeCardKind::Bid, false, true) => &self.bid_active,
            (TradeCardKind::Bid, false, false) => &self.bid_idle,
            (TradeCardKind::Offer, false, true) => &self.offer_active,
            (TradeCardKind::Offer, false, false) => &self.offer_idle,
            (TradeCardKind::Bid, true, true) => &self.clothing_bid_active,
            (TradeCardKind::Bid, true, false) => &self.clothing_bid_idle,
            (TradeCardKind::Offer, true, true) => &self.clothing_offer_active,
            (TradeCardKind::Offer, true, false) => &self.clothing_offer_idle,
        }
    }
}

#[derive(Component)]
struct TradeScreen;

#[derive(Component)]
struct TradeView {
    capacity: Entity,
    advisories: [(TradeAdvisoryKind, Entity); TRADE_ADVISORIES.len()],
    rows: TradeCommodityTable<TradeRowView>,
    pictures: TradePictures,
}

struct TradeRowView {
    row: Entity,
    bid: Entity,
    offer: Entity,
    decrease: Entity,
    increase: Entity,
    quantity: Entity,
    offer_indicator: Entity,
    gauge: Entity,
    gauge_fill: Entity,
    price: Entity,
    stock: Entity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TradeCardKind {
    Bid,
    Offer,
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
    );
    bind_game_status_display(&mut commands, &mut assets, root, &tree);

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
    let selected = tree.find(root, fourcc!("trad"));
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));
    let capacity = tree.find(root, fourcc!("mCap"));
    commands.entity(capacity).insert(InteractionDisabled);
    let advisories = TRADE_ADVISORIES.map(|(tag, kind)| (kind, tree.find(root, tag)));
    let advanced = session.game.technology().advanced_production_unlocked();
    let text_style = assets
        .text_style(RetailTextStylePreset {
            font_family: 2,
            face_flags: 0,
            point_size: 14,
            alignment: -1,
        })
        .expect("retail Trade row text style");
    let text_color = assets.palette_color(0x13);
    let gauge_color = assets.palette_color(TRADE_BAR_FILL);
    let rows = TRADE_ROW_TAGS.map(|commodity, tag| {
        let row = bind_trade_row(
            &mut commands,
            &tree,
            root,
            commodity,
            tag,
            &pictures,
            &text_style,
            text_color,
            gauge_color,
        );
        set_trade_row_visible(
            &mut commands,
            row.row,
            trade_row_available(advanced, commodity),
        );
        row
    });
    commands.entity(root).insert(TradeView {
        capacity,
        advisories,
        rows,
        pictures,
    });
}

fn bind_trade_row(
    commands: &mut Commands,
    tree: &RetailTree,
    root: Entity,
    commodity: TradeCommodity,
    tag: FourCc,
    pictures: &TradePictures,
    text_style: &(TextFont, TextLayout, LineHeight, bool),
    text_color: Color,
    gauge_color: Color,
) -> TradeRowView {
    let row = tree.find(root, tag);
    commands.entity(row).insert(Pickable::IGNORE);

    let card = tree.find(row, fourcc!("card"));
    let offer = tree.find(row, fourcc!("offr"));
    let bid = bind_trade_card(
        commands,
        card,
        commodity,
        TradeCardKind::Bid,
        pictures.for_button(commodity, TradeCardKind::Bid, false),
    );
    let offer = bind_trade_card(
        commands,
        offer,
        commodity,
        TradeCardKind::Offer,
        pictures.for_button(commodity, TradeCardKind::Offer, false),
    );

    let [decrease, increase] = [(fourcc!("left"), -1), (fourcc!("rght"), 1)].map(|(tag, delta)| {
        let step = tree.find(row, tag);
        commands
            .entity(step)
            .insert((ActivateOnPress, TradeAction::Step { commodity, delta }))
            .observe(on_trade_activate);
        step
    });

    let quantity = tree.find(row, fourcc!("Sell"));
    let offer_indicator = tree.find(row, fourcc!("gree"));
    let gauge = tree.find(row, fourcc!("bar "));
    commands
        .entity(gauge)
        .insert((
            TradeAction::Amount(commodity),
            RelativeCursorPosition::default(),
        ))
        .observe(on_trade_amount_bar_click);
    let gauge_fill = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(0),
                top: px(0),
                width: px(0),
                height: percent(100),
                ..default()
            },
            BackgroundColor(gauge_color),
            Pickable::IGNORE,
            ChildOf(gauge),
        ))
        .id();
    let price = spawn_trade_row_text(commands, row, 180.0, 58.0, text_style, text_color);
    let stock = spawn_trade_row_text(commands, row, 238.0, 62.0, text_style, text_color);
    TradeRowView {
        row,
        bid,
        offer,
        decrease,
        increase,
        quantity,
        offer_indicator,
        gauge,
        gauge_fill,
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
            view.pictures
                .for_button(commodity, TradeCardKind::Bid, bid_active),
            TradeCardKind::Bid,
            bid_active,
            &mut images,
            &mut nodes,
        );
        render_trade_card(
            row.offer,
            view.pictures
                .for_button(commodity, TradeCardKind::Offer, offer_active),
            TradeCardKind::Offer,
            offer_active,
            &mut images,
            &mut nodes,
        );
        set_trade_interaction(&mut commands, row.bid, bid_active || bid_count < 4);
        set_trade_control(
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
        let step_visible = quantity > 0 && capacity > 0;
        set_trade_control(&mut commands, row.decrease, step_visible);
        set_trade_control(&mut commands, row.increase, step_visible);
        let offer_visible = capacity > 0 && quantity > 0;
        set_trade_visibility(&mut commands, row.quantity, offer_visible);
        set_trade_visibility(&mut commands, row.offer_indicator, offer_visible);
        set_trade_visibility(&mut commands, row.gauge, offer_visible);
        nodes
            .get_mut(row.gauge_fill)
            .expect("bound trade gauge fill must exist")
            .width = px(TRADE_AMOUNT_BAR.with_segments(capacity).span(quantity));
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
    for &(kind, entity) in &view.advisories {
        set_trade_visibility(
            &mut commands,
            entity,
            trade_advisory_needed(&session.game, nation, kind),
        );
    }
}

fn render_trade_card(
    entity: Entity,
    picture: &Handle<Image>,
    kind: TradeCardKind,
    active: bool,
    images: &mut Query<&mut ImageNode>,
    nodes: &mut Query<&mut Node>,
) {
    let mut image = images
        .get_mut(entity)
        .expect("bound trade card image must exist");
    image.image = picture.clone();
    let mut node = nodes
        .get_mut(entity)
        .expect("bound trade card node must exist");
    node.width = px(if active { 65 } else { 17 });
    if kind == TradeCardKind::Offer {
        node.left = px(if active { 115 } else { 163 });
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
    idle_picture: &Handle<Image>,
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
        .insert((
            UiButton,
            ActivateOnPress,
            Pickable::default(),
            ZIndex(1),
            trade_card_image(idle_picture.clone()),
            TradeAction::Card { commodity, kind },
        ))
        .observe(on_trade_activate);
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
        session: Res<GameSession>,
    ) {
        let image = Handle::<Image>::default();
        let pictures = TradePictures {
            bid_active: image.clone(),
            bid_idle: image.clone(),
            offer_active: image.clone(),
            offer_idle: image.clone(),
            clothing_bid_active: image.clone(),
            clothing_bid_idle: image.clone(),
            clothing_offer_active: image.clone(),
            clothing_offer_idle: image,
        };
        let capacity = tree.find(*root, fourcc!("mCap"));
        let advisories = TRADE_ADVISORIES.map(|(tag, kind)| (kind, tree.find(*root, tag)));
        let text_style = (
            TextFont::default(),
            TextLayout::justify(Justify::Right),
            LineHeight::Px(14.0),
            false,
        );
        let advanced = session.game.technology().advanced_production_unlocked();
        let rows = TRADE_ROW_TAGS.map(|commodity, tag| {
            let row = bind_trade_row(
                &mut commands,
                &tree,
                *root,
                commodity,
                tag,
                &pictures,
                &text_style,
                Color::BLACK,
                Color::WHITE,
            );
            set_trade_row_visible(
                &mut commands,
                row.row,
                trade_row_available(advanced, commodity),
            );
            row
        });
        commands.entity(*root).insert(TradeView {
            capacity,
            advisories,
            rows,
            pictures,
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
        let commodity = TRADE_ROW_TAGS
            .iter()
            .map(|(commodity, _)| commodity)
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
            let row_entity = app
                .world()
                .get::<TradeView>(root)
                .expect("trade root has a semantic view")
                .rows[commodity]
                .row;
            assert_eq!(
                app.world().get::<Node>(row_entity).unwrap().display,
                Display::None
            );
        }

        let bound_row = &app
            .world()
            .get::<TradeView>(root)
            .expect("trade root has a semantic view")
            .rows[commodity];
        assert_eq!(
            app.world().get::<Text>(bound_row.price).unwrap().0,
            format_currency(
                app.world().resource::<GameSession>().game.market().rows[commodity].price
            )
        );
        assert_eq!(
            app.world().get::<Text>(bound_row.stock).unwrap().0,
            app.world()
                .resource::<GameSession>()
                .game
                .nations()
                .major(nation)
                .city
                .stockpile[commodity.resource()]
            .to_string()
        );
        assert!(app.world().get::<ImageNode>(bound_row.gauge).is_none());
        assert_eq!(
            app.world().get::<Node>(bound_row.gauge_fill).unwrap().width,
            px(0)
        );

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
            TradeCommodity::LENGTH * 2
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
        let gauge_fill = app.world().get::<TradeView>(root).unwrap().rows[commodity].gauge_fill;
        assert_eq!(
            app.world().get::<Node>(gauge_fill).unwrap().width,
            px(TRADE_AMOUNT_BAR.with_segments(capacity).span(quantity))
        );

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
        assert!(trade_offer_tab_visible(0, false, 0));
        assert!(!trade_offer_tab_visible(4, false, 0));
        assert!(trade_offer_tab_visible(4, false, 2));
        assert!(trade_offer_tab_visible(4, true, 0));
    }
}
