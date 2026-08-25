use super::GameSession;
use super::RetailUiAssets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
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
    commodity: TradeCommodity,
}

const TRADE_ROWS: [TradeRowBinding; 17] = [
    TradeRowBinding {
        commodity: TradeCommodity::Cotton,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Wool,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Timber,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Coal,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Iron,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Horses,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Oil,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Food,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Fabric,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Lumber,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Paper,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Steel,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Fuel,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Clothing,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Furniture,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Hardware,
    },
    TradeRowBinding {
        commodity: TradeCommodity::Arms,
    },
];

#[derive(Clone, Copy)]
struct TradeRowControls {
    row: Entity,
    sell: Entity,
    card: Entity,
    offr: Entity,
    left: Entity,
    rght: Entity,
    gree: Entity,
    bar: Entity,
}

fn trade_row(
    row: Entity,
    sell: Entity,
    card: Entity,
    offr: Entity,
    left: Entity,
    rght: Entity,
    gree: Entity,
    bar: Entity,
) -> TradeRowControls {
    TradeRowControls {
        row,
        sell,
        card,
        offr,
        left,
        rght,
        gree,
        bar,
    }
}

fn trade_2009_rows(ui: generated::Trade2009) -> [TradeRowControls; 17] {
    [
        trade_row(
            ui.rs0,
            ui.rs0_sell,
            ui.rs0_card,
            ui.rs0_offr,
            ui.rs0_left,
            ui.rs0_rght,
            ui.rs0_gree,
            ui.rs0_bar,
        ),
        trade_row(
            ui.rs1,
            ui.rs1_sell,
            ui.rs1_card,
            ui.rs1_offr,
            ui.rs1_left,
            ui.rs1_rght,
            ui.rs1_gree,
            ui.rs1_bar,
        ),
        trade_row(
            ui.rs2,
            ui.rs2_sell,
            ui.rs2_card,
            ui.rs2_offr,
            ui.rs2_left,
            ui.rs2_rght,
            ui.rs2_gree,
            ui.rs2_bar,
        ),
        trade_row(
            ui.rs3,
            ui.rs3_sell,
            ui.rs3_card,
            ui.rs3_offr,
            ui.rs3_left,
            ui.rs3_rght,
            ui.rs3_gree,
            ui.rs3_bar,
        ),
        trade_row(
            ui.rs4,
            ui.rs4_sell,
            ui.rs4_card,
            ui.rs4_offr,
            ui.rs4_left,
            ui.rs4_rght,
            ui.rs4_gree,
            ui.rs4_bar,
        ),
        trade_row(
            ui.rs5,
            ui.rs5_sell,
            ui.rs5_card,
            ui.rs5_offr,
            ui.rs5_left,
            ui.rs5_rght,
            ui.rs5_gree,
            ui.rs5_bar,
        ),
        trade_row(
            ui.rs6,
            ui.rs6_sell,
            ui.rs6_card,
            ui.rs6_offr,
            ui.rs6_left,
            ui.rs6_rght,
            ui.rs6_gree,
            ui.rs6_bar,
        ),
        trade_row(
            ui.ma0,
            ui.ma0_sell,
            ui.ma0_card,
            ui.ma0_offr,
            ui.ma0_left,
            ui.ma0_rght,
            ui.ma0_gree,
            ui.ma0_bar,
        ),
        trade_row(
            ui.ma1,
            ui.ma1_sell,
            ui.ma1_card,
            ui.ma1_offr,
            ui.ma1_left,
            ui.ma1_rght,
            ui.ma1_gree,
            ui.ma1_bar,
        ),
        trade_row(
            ui.ma2,
            ui.ma2_sell,
            ui.ma2_card,
            ui.ma2_offr,
            ui.ma2_left,
            ui.ma2_rght,
            ui.ma2_gree,
            ui.ma2_bar,
        ),
        trade_row(
            ui.ma3,
            ui.ma3_sell,
            ui.ma3_card,
            ui.ma3_offr,
            ui.ma3_left,
            ui.ma3_rght,
            ui.ma3_gree,
            ui.ma3_bar,
        ),
        trade_row(
            ui.ma4,
            ui.ma4_sell,
            ui.ma4_card,
            ui.ma4_offr,
            ui.ma4_left,
            ui.ma4_rght,
            ui.ma4_gree,
            ui.ma4_bar,
        ),
        trade_row(
            ui.ma5,
            ui.ma5_sell,
            ui.ma5_card,
            ui.ma5_offr,
            ui.ma5_left,
            ui.ma5_rght,
            ui.ma5_gree,
            ui.ma5_bar,
        ),
        trade_row(
            ui.gd0,
            ui.gd0_sell,
            ui.gd0_card,
            ui.gd0_offr,
            ui.gd0_left,
            ui.gd0_rght,
            ui.gd0_gree,
            ui.gd0_bar,
        ),
        trade_row(
            ui.gd1,
            ui.gd1_sell,
            ui.gd1_card,
            ui.gd1_offr,
            ui.gd1_left,
            ui.gd1_rght,
            ui.gd1_gree,
            ui.gd1_bar,
        ),
        trade_row(
            ui.gd2,
            ui.gd2_sell,
            ui.gd2_card,
            ui.gd2_offr,
            ui.gd2_left,
            ui.gd2_rght,
            ui.gd2_gree,
            ui.gd2_bar,
        ),
        trade_row(
            ui.gd3,
            ui.gd3_sell,
            ui.gd3_card,
            ui.gd3_offr,
            ui.gd3_left,
            ui.gd3_rght,
            ui.gd3_gree,
            ui.gd3_bar,
        ),
    ]
}

fn trade_2010_rows(ui: generated::Trade2010) -> [TradeRowControls; 17] {
    [
        trade_row(
            ui.rs0,
            ui.rs0_sell,
            ui.rs0_card,
            ui.rs0_offr,
            ui.rs0_left,
            ui.rs0_rght,
            ui.rs0_gree,
            ui.rs0_bar,
        ),
        trade_row(
            ui.rs1,
            ui.rs1_sell,
            ui.rs1_card,
            ui.rs1_offr,
            ui.rs1_left,
            ui.rs1_rght,
            ui.rs1_gree,
            ui.rs1_bar,
        ),
        trade_row(
            ui.rs2,
            ui.rs2_sell,
            ui.rs2_card,
            ui.rs2_offr,
            ui.rs2_left,
            ui.rs2_rght,
            ui.rs2_gree,
            ui.rs2_bar,
        ),
        trade_row(
            ui.rs3,
            ui.rs3_sell,
            ui.rs3_card,
            ui.rs3_offr,
            ui.rs3_left,
            ui.rs3_rght,
            ui.rs3_gree,
            ui.rs3_bar,
        ),
        trade_row(
            ui.rs4,
            ui.rs4_sell,
            ui.rs4_card,
            ui.rs4_offr,
            ui.rs4_left,
            ui.rs4_rght,
            ui.rs4_gree,
            ui.rs4_bar,
        ),
        trade_row(
            ui.rs5,
            ui.rs5_sell,
            ui.rs5_card,
            ui.rs5_offr,
            ui.rs5_left,
            ui.rs5_rght,
            ui.rs5_gree,
            ui.rs5_bar,
        ),
        trade_row(
            ui.rs6,
            ui.rs6_sell,
            ui.rs6_card,
            ui.rs6_offr,
            ui.rs6_left,
            ui.rs6_rght,
            ui.rs6_gree,
            ui.rs6_bar,
        ),
        trade_row(
            ui.ma0,
            ui.ma0_sell,
            ui.ma0_card,
            ui.ma0_offr,
            ui.ma0_left,
            ui.ma0_rght,
            ui.ma0_gree,
            ui.ma0_bar,
        ),
        trade_row(
            ui.ma1,
            ui.ma1_sell,
            ui.ma1_card,
            ui.ma1_offr,
            ui.ma1_left,
            ui.ma1_rght,
            ui.ma1_gree,
            ui.ma1_bar,
        ),
        trade_row(
            ui.ma2,
            ui.ma2_sell,
            ui.ma2_card,
            ui.ma2_offr,
            ui.ma2_left,
            ui.ma2_rght,
            ui.ma2_gree,
            ui.ma2_bar,
        ),
        trade_row(
            ui.ma3,
            ui.ma3_sell,
            ui.ma3_card,
            ui.ma3_offr,
            ui.ma3_left,
            ui.ma3_rght,
            ui.ma3_gree,
            ui.ma3_bar,
        ),
        trade_row(
            ui.ma4,
            ui.ma4_sell,
            ui.ma4_card,
            ui.ma4_offr,
            ui.ma4_left,
            ui.ma4_rght,
            ui.ma4_gree,
            ui.ma4_bar,
        ),
        trade_row(
            ui.ma5,
            ui.ma5_sell,
            ui.ma5_card,
            ui.ma5_offr,
            ui.ma5_left,
            ui.ma5_rght,
            ui.ma5_gree,
            ui.ma5_bar,
        ),
        trade_row(
            ui.gd0,
            ui.gd0_sell,
            ui.gd0_card,
            ui.gd0_offr,
            ui.gd0_left,
            ui.gd0_rght,
            ui.gd0_gree,
            ui.gd0_bar,
        ),
        trade_row(
            ui.gd1,
            ui.gd1_sell,
            ui.gd1_card,
            ui.gd1_offr,
            ui.gd1_left,
            ui.gd1_rght,
            ui.gd1_gree,
            ui.gd1_bar,
        ),
        trade_row(
            ui.gd2,
            ui.gd2_sell,
            ui.gd2_card,
            ui.gd2_offr,
            ui.gd2_left,
            ui.gd2_rght,
            ui.gd2_gree,
            ui.gd2_bar,
        ),
        trade_row(
            ui.gd3,
            ui.gd3_sell,
            ui.gd3_card,
            ui.gd3_offr,
            ui.gd3_left,
            ui.gd3_rght,
            ui.gd3_gree,
            ui.gd3_bar,
        ),
    ]
}

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

const TRADE_ADVISORY_KINDS: [TradeAdvisoryKind; 10] = [
    TradeAdvisoryKind::Food,
    TradeAdvisoryKind::Textile,
    TradeAdvisoryKind::Textile,
    TradeAdvisoryKind::Timber,
    TradeAdvisoryKind::Coal,
    TradeAdvisoryKind::Iron,
    TradeAdvisoryKind::Oil,
    TradeAdvisoryKind::Fabric,
    TradeAdvisoryKind::Lumber,
    TradeAdvisoryKind::Steel,
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
    Capacity,
    Advisory(TradeAdvisoryKind),
}

#[derive(Component, Clone, Copy)]
struct TradeGaugeVisual(TradeCommodity);

#[derive(Component)]
struct TradeScreenVisual {
    base: IndexedPicture,
    rows: [(TradeCommodity, IVec2); TRADE_ROWS.len()],
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
            (
                sync_trade_text,
                sync_trade_screen_picture,
                sync_trade_cards,
                sync_trade_gauges,
                sync_trade_presence,
            )
                .run_if(in_state(AppState::Trade)),
        );
    }
}

fn enter_trade_screen(mut commands: Commands, session: Res<GameSession>) {
    if session.game.technology().advanced_production_unlocked() {
        let ui = generated::spawn_trade_2010(&mut commands);
        commands
            .entity(ui.root)
            .insert((TradeScreen, ui, DespawnOnExit(AppState::Trade)));
    } else {
        let ui = generated::spawn_trade_2009(&mut commands);
        commands
            .entity(ui.root)
            .insert((TradeScreen, ui, DespawnOnExit(AppState::Trade)));
    }
}

fn bind_trade_screen(
    mut commands: Commands,
    trade_2009: Option<Single<&generated::Trade2009, Added<TradeScreen>>>,
    trade_2010: Option<Single<&generated::Trade2010, Added<TradeScreen>>>,
    nodes: Query<&Node>,
    mut assets: RetailUiAssets,
    mut session: ResMut<GameSession>,
) {
    if let Some(ui) = trade_2009 {
        let ui = **ui;
        bind_trade_screen_ui(
            &mut commands,
            &nodes,
            &mut assets,
            &mut session,
            ui.main,
            ui.trad,
            ui.tran,
            ui.city,
            ui.dipl,
            ui.end,
            ui.quer,
            ui.seas,
            ui.trea,
            ui.mcap,
            [
                ui.food, ui.cott, ui.wool, ui.timb, ui.coal, ui.iron, ui.oil, ui.fabr, ui.lumb,
                ui.stee,
            ],
            trade_2009_rows(ui),
        );
    } else if let Some(ui) = trade_2010 {
        let ui = **ui;
        bind_trade_screen_ui(
            &mut commands,
            &nodes,
            &mut assets,
            &mut session,
            ui.main,
            ui.trad,
            ui.tran,
            ui.city,
            ui.dipl,
            ui.end,
            ui.quer,
            ui.seas,
            ui.trea,
            ui.mcap,
            [
                ui.food, ui.cott, ui.wool, ui.timb, ui.coal, ui.iron, ui.oil, ui.fabr, ui.lumb,
                ui.stee,
            ],
            trade_2010_rows(ui),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn bind_trade_screen_ui(
    commands: &mut Commands,
    nodes: &Query<&Node>,
    assets: &mut RetailUiAssets,
    session: &mut GameSession,
    main: Entity,
    trad: Entity,
    tran: Entity,
    city: Entity,
    dipl: Entity,
    end: Entity,
    quer: Entity,
    seas: Entity,
    trea: Entity,
    mcap: Entity,
    advisories: [Entity; 10],
    rows: [TradeRowControls; 17],
) {
    bind_native_game_screen_nav(commands, trad, tran, city, dipl, Some(end), Some(quer));
    let nation = session.active_major_nation();
    session.game.refresh_merchant_capacity(nation);
    session.game.recall_player_trade_orders(nation);
    bind_game_status_display(commands, assets, seas, trea);

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
        commands,
        trad,
        mcap,
        advisories,
        rows,
        pictures,
        session.game.technology().advanced_production_unlocked(),
    );
    let palette = *assets.default_dib_palette();
    for (binding, row) in TRADE_ROWS.into_iter().zip(rows) {
        let picture = trade_amount_bar_picture(AmountBarPixels {
            range: 0,
            current: 0,
            color: TRADE_BAR_FILL,
        });
        let image = assets.add_image(picture.to_keyed_image(&palette, 0x10));
        commands
            .entity(row.bar)
            .insert((ImageNode::new(image), TradeGaugeVisual(binding.commodity)));
    }
    let rows = core::array::from_fn(|index| {
        let node = nodes
            .get(rows[index].row)
            .expect("generated trade row has layout");
        let Val::Px(left) = node.left else {
            panic!("generated trade row has a pixel left position");
        };
        let Val::Px(top) = node.top else {
            panic!("generated trade row has a pixel top position");
        };
        (
            TRADE_ROWS[index].commodity,
            IVec2::new(left as i32, top as i32),
        )
    });
    let base = assets
        .indexed_picture(PictureId::new(2101))
        .expect("retail Trade screen picture must load");
    let image = assets.add_image(base.to_image(&palette));
    commands
        .entity(main)
        .insert((ImageNode::new(image), TradeScreenVisual { base, rows }));
}

fn bind_trade_controls(
    commands: &mut Commands,
    trad: Entity,
    mcap: Entity,
    advisories: [Entity; 10],
    rows: [TradeRowControls; 17],
    pictures: TradePictures,
    advanced_trade_unlocked: bool,
) {
    commands.entity(trad).insert((Checked, InteractionDisabled));
    commands
        .entity(mcap)
        .insert((TradeDisplay::Capacity, InteractionDisabled));
    for (advisory, kind) in advisories.into_iter().zip(TRADE_ADVISORY_KINDS) {
        commands
            .entity(advisory)
            .insert(TradeDisplay::Advisory(kind));
    }

    for (binding, row) in TRADE_ROWS.into_iter().zip(rows) {
        commands
            .entity(row.row)
            .insert((TradeDisplay::Row(binding.commodity), Pickable::IGNORE));
        set_trade_row_visible(
            commands,
            row.row,
            trade_row_available(advanced_trade_unlocked, binding.commodity),
        );

        let card_pictures = pictures.for_button(binding.commodity, TradeCardKind::Bid);
        let offer_pictures = pictures.for_button(binding.commodity, TradeCardKind::Offer);
        bind_trade_card(
            commands,
            row.card,
            binding.commodity,
            TradeCardKind::Bid,
            card_pictures,
        );
        bind_trade_card(
            commands,
            row.offr,
            binding.commodity,
            TradeCardKind::Offer,
            offer_pictures,
        );

        for (step, delta) in [(row.left, -1), (row.rght, 1)] {
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

        commands
            .entity(row.sell)
            .insert(TradeDisplay::Sell(binding.commodity));
        commands
            .entity(row.gree)
            .insert(TradeDisplay::Offer(binding.commodity));
        commands
            .entity(row.bar)
            .insert((
                TradeAction::Amount(binding.commodity),
                TradeDisplay::Offer(binding.commodity),
                RelativeCursorPosition::default(),
            ))
            .observe(on_trade_amount_bar_click);
    }
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

fn sync_trade_text(
    session: Res<GameSession>,
    roots: Query<(), Added<TradeScreen>>,
    mut texts: Query<(&TradeDisplay, &mut Text)>,
) {
    if !session.is_changed() && roots.is_empty() {
        return;
    }
    let nation = session.active_major_nation();
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
            TradeDisplay::Capacity => text.0 = capacity.to_string(),
            _ => {}
        }
    }
}

fn sync_trade_screen_picture(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    fonts: Res<RetailFonts>,
    font_assets: Res<Assets<Font>>,
    mut images: ResMut<Assets<Image>>,
    roots: Query<(), Added<TradeScreen>>,
    screens: Query<(&TradeScreenVisual, &ImageNode)>,
) {
    if !session.is_changed() && roots.is_empty() {
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
    for (screen, image_node) in &screens {
        let mut picture = screen.base.clone();
        for &(commodity, origin) in &screen.rows {
            let stock = match major.city.stockpile[commodity.resource()] {
                0 => "--".to_owned(),
                stock => stock.to_string(),
            };
            text.draw_right(
                &mut picture,
                origin.x + 238,
                origin.y + 12,
                &format_currency(session.game.market().rows[commodity].price),
                0x13,
            );
            text.draw_right(&mut picture, origin.x + 300, origin.y + 12, &stock, 0x13);
        }
        if let Some(mut image) = images.get_mut(&image_node.image) {
            *image = picture.to_image(retail.assets().default_dib_palette());
        }
    }
}

fn sync_trade_cards(
    session: Res<GameSession>,
    roots: Query<(), Added<TradeScreen>>,
    mut cards: Query<(&TradeDisplay, &mut ImageNode, &mut Node)>,
) {
    if !session.is_changed() && roots.is_empty() {
        return;
    }
    let nation = session.active_major_nation();
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
}

fn sync_trade_gauges(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    roots: Query<(), Added<TradeScreen>>,
    gauges: Query<(&TradeGaugeVisual, &ImageNode)>,
) {
    if !session.is_changed() && roots.is_empty() {
        return;
    }
    let nation = session.active_major_nation();
    let capacity = session
        .game
        .nations()
        .major(nation)
        .economy
        .capacities
        .trade_offer;
    for (gauge, image_node) in &gauges {
        let commodity = gauge.0;
        let quantity = match session.game.player_trade_order(nation, commodity) {
            PlayerTradeOrder::Sell(quantity) => quantity,
            _ => 0,
        };
        let geometry = TRADE_AMOUNT_BAR.with_segments(capacity);
        let picture = trade_amount_bar_picture(AmountBarPixels {
            range: geometry.span(quantity),
            current: geometry.span(quantity),
            color: TRADE_BAR_FILL,
        });
        if let Some(mut image) = images.get_mut(&image_node.image) {
            *image = picture.to_keyed_image(retail.assets().default_dib_palette(), 0x10);
        }
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
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let capacity = major.economy.capacities.trade_offer;
    let advanced_trade_unlocked = session.game.technology().advanced_production_unlocked();
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
        *visibility = if trade_advisory_needed(&session.game, nation, kind) {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
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

#[cfg(test)]
mod tests {
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

    fn spawn_child(world: &mut World, parent: Entity) -> Entity {
        world.spawn((Node::default(), ChildOf(parent))).id()
    }

    fn spawn_trade_row(world: &mut World, parent: Entity) -> TradeRowControls {
        let row = spawn_child(world, parent);
        TradeRowControls {
            row,
            sell: spawn_child(world, row),
            card: spawn_child(world, row),
            offr: world
                .spawn((
                    Node {
                        left: Val::Px(163.0),
                        width: Val::Px(17.0),
                        height: Val::Px(20.0),
                        ..default()
                    },
                    ChildOf(row),
                ))
                .id(),
            left: spawn_child(world, row),
            rght: spawn_child(world, row),
            gree: world
                .spawn((ImageNode::default(), Node::default(), ChildOf(row)))
                .id(),
            bar: spawn_child(world, row),
        }
    }

    #[derive(Component)]
    struct TestTradeBindings {
        trad: Entity,
        mcap: Entity,
        advisories: [Entity; 10],
        rows: [TradeRowControls; 17],
    }

    fn spawn_trade_hierarchy(world: &mut World) {
        let root = world.spawn((TestTradeRoot, Node::default())).id();
        let trad = spawn_child(world, root);
        let mcap = spawn_child(world, root);
        let advisories = [(); 10].map(|_| spawn_child(world, root));
        let rows = [(); 17].map(|_| spawn_trade_row(world, root));
        world.entity_mut(root).insert(TestTradeBindings {
            trad,
            mcap,
            advisories,
            rows,
        });
    }

    fn bind_test_trade(
        mut commands: Commands,
        bindings: Single<&TestTradeBindings, Added<TestTradeRoot>>,
    ) {
        let image = Handle::<Image>::default();
        bind_trade_controls(
            &mut commands,
            bindings.trad,
            bindings.mcap,
            bindings.advisories,
            bindings.rows,
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
        .add_systems(
            Update,
            (bind_test_trade, sync_trade_cards, sync_trade_presence).chain(),
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
        assert!(
            app.world()
                .get::<TradeAction>(card)
                .is_some_and(|action| matches!(
                    action,
                    TradeAction::Card {
                        kind: TradeCardKind::Offer,
                        ..
                    }
                )),
            "generated offer card kept its TradeAction"
        );
        let mut has_step = |delta| {
            app.world_mut()
                .query::<(&TradeAction, &ChildOf)>()
                .iter(app.world())
                .any(|(action, parent)| {
                    parent.parent() == row
                        && matches!(
                            action,
                            TradeAction::Step {
                                delta: candidate,
                                ..
                            } if *candidate == delta
                        )
                })
        };
        assert!(
            has_step(-1),
            "generated left control was removed from its trade row"
        );
        assert!(
            has_step(1),
            "generated right control was removed from its trade row"
        );
        assert!(
            app.world_mut()
                .query::<(&TradeDisplay, &ChildOf)>()
                .iter(app.world())
                .any(|(display, parent)| {
                    parent.parent() == row && matches!(display, TradeDisplay::Offer(_))
                }),
            "generated offer display was removed from its trade row"
        );
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
