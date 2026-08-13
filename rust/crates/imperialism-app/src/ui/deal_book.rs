use super::GameSession;
use super::RetailUiAssets;
use super::format_currency;
use super::game_shell::project_date_and_treasury;
use super::generated;
use super::retail::{RetailTag, find_descendant};
use crate::AppState;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::{InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ActivateOnPress, Button as UiButton};
use imperialism_core::*;
use imperialism_formats::*;

const HISTORY_BACKGROUND: i16 = 0x2260;
const CATEGORY_BACKGROUND: i16 = 0x2263;
const TAB_STRIP_BASE: i16 = 0x2266;
const FLAG_ATLAS: i16 = 680;
const COMMODITY_ICON_BASE: i16 = 700;
const PAGE_LEFT: f32 = 65.0;
const PAGE_RIGHT: f32 = 314.0;
const PAGE_TOP: f32 = 89.0;
const PAGE_OFFSCREEN: f32 = 1000.0;
const PAGE_WIDTH: f32 = 240.0;
const LINE_HEIGHT: f32 = 30.0;
const TAB_ROW_HEIGHT: f32 = 25.0;
const TAB_STRIP_HEIGHT: f32 = 423.0;
const ICON_WIDTH: f32 = 32.0;
const ICON_HEIGHT: f32 = 24.0;
const TEXT_INSET: f32 = 40.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DealBookMode {
    History,
    Category { commodity: TradeCommodity, tab: u8 },
}

#[derive(Clone, Copy)]
struct DealBookHosts {
    main: Entity,
    sold: Entity,
    bought: Entity,
    tsol: Entity,
    tbou: Entity,
    titl: Entity,
    rtil: Entity,
    mark: Entity,
    lcor: Entity,
    rcor: Entity,
    tabs: Entity,
    highlight: Entity,
}

#[derive(Clone)]
struct DealBookPictures {
    history: Handle<Image>,
    category: Handle<Image>,
    tab_empty: Handle<Image>,
    tab_filled: Handle<Image>,
    flags: Handle<Image>,
    commodities: [Handle<Image>; ResourceKind::LENGTH],
}

#[derive(Clone)]
struct DealBookFonts {
    body: TextFont,
    body_layout: TextLayout,
    body_line_height: LineHeight,
    heading: TextFont,
    heading_layout: TextLayout,
    heading_line_height: LineHeight,
    heading_center: TextLayout,
    color: Color,
}

#[derive(Component)]
struct DealBookRoot;

#[derive(Component)]
struct DealBookScreen {
    mode: DealBookMode,
    page: u16,
    hosts: DealBookHosts,
    pictures: DealBookPictures,
    fonts: DealBookFonts,
    oil_drilling: bool,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum DealBookAction {
    History,
    PreviousPage,
    NextPage,
    Close,
}

pub(crate) struct DealBookPlugin;

impl Plugin for DealBookPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::DealBook),
            (spawn_deal_book, bind_deal_book).chain(),
        )
        .add_observer(on_deal_book_activate)
        .add_observer(on_deal_book_tabs_click)
        .add_systems(
            Update,
            (hover_deal_book_tabs, sync_deal_book)
                .chain()
                .run_if(in_state(AppState::DealBook)),
        );
    }
}

fn spawn_deal_book(mut commands: Commands) {
    let root = commands.spawn_scene(generated::flagview_8800()).id();
    commands
        .entity(root)
        .insert((DealBookRoot, DespawnOnExit(AppState::DealBook)));
}

fn bind_deal_book(
    mut commands: Commands,
    root: Single<Entity, Added<DealBookRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let root = *root;
    let oil_drilling = session.0.technology().oil_drilling_available();
    let tab_base = if oil_drilling {
        TAB_STRIP_BASE + 1
    } else {
        TAB_STRIP_BASE
    };
    let pictures = DealBookPictures {
        history: assets
            .picture(PictureId::new(HISTORY_BACKGROUND))
            .expect("retail deal-book history background must load"),
        category: assets
            .picture(PictureId::new(CATEGORY_BACKGROUND))
            .expect("retail deal-book category background must load"),
        tab_empty: assets
            .picture(PictureId::new(tab_base + 4))
            .expect("retail deal-book empty tab strip must load"),
        tab_filled: assets
            .picture(PictureId::new(tab_base))
            .expect("retail deal-book filled tab strip must load"),
        flags: transparent_picture(&mut assets, PictureId::new(FLAG_ATLAS)),
        commodities: std::array::from_fn(|index| {
            transparent_picture(
                &mut assets,
                PictureId::new(COMMODITY_ICON_BASE + index as i16),
            )
        }),
    };
    let (body, body_layout, body_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -1,
        })
        .expect("retail deal-book body text style");
    let (heading, heading_layout, heading_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 14,
            alignment: -1,
        })
        .expect("retail deal-book heading text style");
    let fonts = DealBookFonts {
        body,
        body_layout,
        body_line_height,
        heading,
        heading_layout,
        heading_line_height,
        heading_center: TextLayout::justify(Justify::Center),
        color: Color::BLACK,
    };

    let main = find_descendant(root, fourcc!("main"), &children, &tags);
    let sold = find_descendant(root, fourcc!("sold"), &children, &tags);
    let bought = find_descendant(root, fourcc!("boug"), &children, &tags);
    let tsol = find_descendant(root, fourcc!("tsol"), &children, &tags);
    let tbou = find_descendant(root, fourcc!("tbou"), &children, &tags);
    let tabs = find_descendant(root, fourcc!("tabs"), &children, &tags);
    let mark = find_descendant(root, fourcc!("mark"), &children, &tags);
    let lcor = find_descendant(root, fourcc!("lcor"), &children, &tags);
    let rcor = find_descendant(root, fourcc!("rcor"), &children, &tags);

    commands.entity(tabs).insert((
        ImageNode::new(pictures.tab_empty.clone()),
        RelativeCursorPosition::default(),
    ));
    let highlight = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(0.0),
                top: Val::Px(0.0),
                width: Val::Px(31.0),
                height: Val::Px(TAB_ROW_HEIGHT),
                ..default()
            },
            ImageNode {
                image: pictures.tab_filled.clone(),
                rect: Some(Rect::new(0.0, 0.0, 31.0, TAB_ROW_HEIGHT)),
                ..default()
            },
            Visibility::Hidden,
            Pickable::IGNORE,
            ChildOf(tabs),
        ))
        .id();
    commands
        .entity(find_descendant(root, fourcc!("end "), &children, &tags))
        .insert((DealBookAction::Close, ActivateOnPress))
        .remove::<InteractionDisabled>();
    commands
        .entity(find_descendant(root, fourcc!("quer"), &children, &tags))
        .insert(InteractionDisabled);
    project_date_and_treasury(&mut commands, &mut assets, root, &children, &tags, &session);
    commands
        .entity(mark)
        .insert((DealBookAction::History, ActivateOnPress));
    commands.entity(lcor).insert((
        UiButton,
        DealBookAction::PreviousPage,
        ActivateOnPress,
        Visibility::Hidden,
        InteractionDisabled,
    ));
    commands.entity(rcor).insert((
        UiButton,
        DealBookAction::NextPage,
        ActivateOnPress,
        Visibility::Hidden,
        InteractionDisabled,
    ));

    commands.entity(root).insert(DealBookScreen {
        mode: DealBookMode::History,
        page: 0,
        hosts: DealBookHosts {
            main,
            sold,
            bought,
            tsol,
            tbou,
            titl: find_descendant(root, fourcc!("titL"), &children, &tags),
            rtil: find_descendant(root, fourcc!("rtil"), &children, &tags),
            mark,
            lcor,
            rcor,
            tabs,
            highlight,
        },
        pictures,
        fonts,
        oil_drilling,
    });
}

fn on_deal_book_activate(
    activate: On<Activate>,
    actions: Query<&DealBookAction>,
    mut screens: Query<&mut DealBookScreen>,
    session: Res<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    if *action == DealBookAction::Close {
        next_state.set(AppState::StrategicMap);
        return;
    }
    let Ok(mut screen) = screens.single_mut() else {
        return;
    };
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Deal Book requires an active major nation");
    let last_page = match screen.mode {
        DealBookMode::History => session.0.deal_book_history(nation).last_page_index(),
        DealBookMode::Category { commodity, .. } => session
            .0
            .deal_book_category(nation, commodity)
            .last_page_index(),
    };
    match *action {
        DealBookAction::History => {
            if screen.mode != DealBookMode::History {
                screen.mode = DealBookMode::History;
                screen.page = 0;
            }
        }
        DealBookAction::PreviousPage => {
            screen.page = screen.page.saturating_sub(1);
        }
        DealBookAction::NextPage => {
            screen.page = (screen.page + 1).min(last_page);
        }
        DealBookAction::Close => {}
    }
}

fn on_deal_book_tabs_click(
    mut click: On<Pointer<Click>>,
    tabs: Query<&RelativeCursorPosition>,
    mut screens: Query<&mut DealBookScreen>,
) {
    let Ok(mut screen) = screens.single_mut() else {
        return;
    };
    if tabs.get(click.entity).is_err() && click.entity != screen.hosts.tabs {
        return;
    }
    let Ok(cursor) = tabs.get(screen.hosts.tabs) else {
        return;
    };
    let Some(row) = tab_row(cursor, screen.oil_drilling) else {
        return;
    };
    let Some(commodity) = deal_book_tab_commodity(screen.oil_drilling, row) else {
        return;
    };
    click.propagate(false);
    screen.mode = DealBookMode::Category {
        commodity,
        tab: row,
    };
    screen.page = 0;
}

fn hover_deal_book_tabs(
    screens: Query<&DealBookScreen>,
    tabs: Query<&RelativeCursorPosition>,
    mut highlights: Query<(&mut Node, &mut ImageNode, &mut Visibility)>,
) {
    let Ok(screen) = screens.single() else {
        return;
    };
    let Ok(cursor) = tabs.get(screen.hosts.tabs) else {
        return;
    };
    let row = tab_row(cursor, screen.oil_drilling).or(match screen.mode {
        DealBookMode::History => None,
        DealBookMode::Category { tab, .. } => Some(tab),
    });
    let Ok((mut node, mut image, mut visibility)) = highlights.get_mut(screen.hosts.highlight)
    else {
        return;
    };
    let Some(row) = row else {
        *visibility = Visibility::Hidden;
        return;
    };
    let top = f32::from(row) * TAB_ROW_HEIGHT;
    node.top = Val::Px(top);
    image.rect = Some(Rect::new(0.0, top, 31.0, top + TAB_ROW_HEIGHT));
    *visibility = Visibility::Visible;
}

fn tab_row(cursor: &RelativeCursorPosition, oil_drilling: bool) -> Option<u8> {
    let normalized = cursor.normalized.filter(|_| cursor.cursor_over())?;
    let y = (normalized.y + 0.5) * TAB_STRIP_HEIGHT;
    if y < 0.0 {
        return None;
    }
    let row = (y / TAB_ROW_HEIGHT).floor() as i32;
    let count = i32::from(deal_book_tab_count(oil_drilling));
    (row >= 0 && row < count).then_some(row as u8)
}

#[allow(clippy::too_many_arguments)]
fn sync_deal_book(
    mut commands: Commands,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    screens: Query<&DealBookScreen, Changed<DealBookScreen>>,
    children: Query<&Children>,
    mut nodes: Query<&mut Node>,
    mut texts: Query<&mut Text>,
    mut pictures: Query<&mut ImageNode>,
    mut visibilities: Query<&mut Visibility>,
) {
    let Ok(screen) = screens.single() else {
        return;
    };
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Deal Book requires an active major nation");
    let last_page = match screen.mode {
        DealBookMode::History => project_history(
            &mut commands,
            &mut assets,
            &session.0,
            nation,
            screen,
            &children,
            &mut nodes,
            &mut texts,
            &mut pictures,
            &mut visibilities,
        ),
        DealBookMode::Category { commodity, .. } => project_category(
            &mut commands,
            &mut assets,
            &session.0,
            nation,
            commodity,
            screen,
            &children,
            &mut nodes,
            &mut texts,
            &mut pictures,
            &mut visibilities,
        ),
    };
    let page = screen.page.min(last_page);
    set_page_button(
        &mut commands,
        &mut visibilities,
        screen.hosts.lcor,
        page > 0,
    );
    set_page_button(
        &mut commands,
        &mut visibilities,
        screen.hosts.rcor,
        page < last_page && last_page != 0,
    );
}

#[allow(clippy::too_many_arguments)]
fn project_history(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    state: &GameState,
    nation: MajorNationId,
    screen: &DealBookScreen,
    children: &Query<&Children>,
    nodes: &mut Query<&mut Node>,
    texts: &mut Query<&mut Text>,
    pictures: &mut Query<&mut ImageNode>,
    visibilities: &mut Query<&mut Visibility>,
) -> u16 {
    place_page(nodes, screen.hosts.sold, PAGE_LEFT, PAGE_TOP);
    place_page(nodes, screen.hosts.bought, PAGE_RIGHT, PAGE_TOP);
    place_page(nodes, screen.hosts.tsol, PAGE_OFFSCREEN, PAGE_OFFSCREEN);
    place_page(nodes, screen.hosts.tbou, PAGE_OFFSCREEN, PAGE_OFFSCREEN);
    set_picture(pictures, screen.hosts.main, screen.pictures.history.clone());
    commands
        .entity(screen.hosts.mark)
        .insert(InteractionDisabled);
    let sold_title = assets
        .string(0x2740, 0x19)
        .expect("retail deal-book sold title must load");
    let bought_title = assets
        .string(0x2740, 0x1a)
        .expect("retail deal-book bought title must load");
    set_text(texts, screen.hosts.titl, sold_title);
    set_text(texts, screen.hosts.rtil, bought_title);

    let history = state.deal_book_history(nation);
    let sold_pages = history.sold_pages();
    let bought_pages = history.bought_pages();
    let last_page = history.last_page_index();
    let page = usize::from(screen.page.min(last_page));
    clear_host(commands, screen.hosts.sold, children);
    clear_host(commands, screen.hosts.bought, children);
    if page < sold_pages.len() {
        set_visible(visibilities, screen.hosts.sold, true);
        spawn_history_rows(
            commands,
            assets,
            state,
            screen,
            screen.hosts.sold,
            &sold_pages[page],
        );
    } else {
        set_visible(visibilities, screen.hosts.sold, false);
    }
    if page < bought_pages.len() {
        set_visible(visibilities, screen.hosts.bought, true);
        spawn_history_rows(
            commands,
            assets,
            state,
            screen,
            screen.hosts.bought,
            &bought_pages[page],
        );
    } else {
        set_visible(visibilities, screen.hosts.bought, false);
    }
    last_page
}

#[allow(clippy::too_many_arguments)]
fn project_category(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    state: &GameState,
    nation: MajorNationId,
    commodity: TradeCommodity,
    screen: &DealBookScreen,
    children: &Query<&Children>,
    nodes: &mut Query<&mut Node>,
    texts: &mut Query<&mut Text>,
    pictures: &mut Query<&mut ImageNode>,
    visibilities: &mut Query<&mut Visibility>,
) -> u16 {
    place_page(nodes, screen.hosts.tsol, PAGE_LEFT, PAGE_TOP);
    place_page(nodes, screen.hosts.tbou, PAGE_RIGHT, PAGE_TOP);
    place_page(nodes, screen.hosts.sold, PAGE_OFFSCREEN, PAGE_OFFSCREEN);
    place_page(nodes, screen.hosts.bought, PAGE_OFFSCREEN, PAGE_OFFSCREEN);
    set_picture(
        pictures,
        screen.hosts.main,
        screen.pictures.category.clone(),
    );
    commands
        .entity(screen.hosts.mark)
        .remove::<InteractionDisabled>();
    let template = get_string(assets, 0x2741, 3);
    let commodity_name = get_string(assets, 0x2711, commodity.resource() as i16);
    set_text(
        texts,
        screen.hosts.titl,
        fill_brackets(&template, &[&commodity_name]),
    );
    set_text(
        texts,
        screen.hosts.rtil,
        category_date(assets, state.turn().economic_turn),
    );

    let category = state.deal_book_category(nation, commodity);
    let sell_pages = category.sell_pages();
    let buy_pages = category.buy_pages();
    let last_page = category.last_page_index();
    let page = usize::from(screen.page.min(last_page));
    clear_host(commands, screen.hosts.tsol, children);
    clear_host(commands, screen.hosts.tbou, children);
    if page < sell_pages.len() {
        set_visible(visibilities, screen.hosts.tsol, true);
        spawn_category_rows(
            commands,
            assets,
            state,
            screen,
            screen.hosts.tsol,
            &sell_pages[page],
        );
    } else {
        set_visible(visibilities, screen.hosts.tsol, false);
    }
    if page < buy_pages.len() {
        set_visible(visibilities, screen.hosts.tbou, true);
        spawn_category_rows(
            commands,
            assets,
            state,
            screen,
            screen.hosts.tbou,
            &buy_pages[page],
        );
    } else {
        set_visible(visibilities, screen.hosts.tbou, false);
    }
    last_page
}

fn spawn_history_rows(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    state: &GameState,
    screen: &DealBookScreen,
    host: Entity,
    rows: &[DealBookHistoryRow],
) {
    let mut y = 0.0;
    for row in rows {
        match row {
            DealBookHistoryRow::CommodityHeader {
                commodity,
                market_price,
            } => {
                spawn_commodity_header(
                    commands,
                    assets,
                    screen,
                    host,
                    y,
                    commodity.resource(),
                    *market_price,
                );
                y += LINE_HEIGHT;
            }
            DealBookHistoryRow::Deal(deal) => {
                spawn_text_row(
                    commands,
                    screen,
                    host,
                    y,
                    TEXT_INSET,
                    PAGE_WIDTH - TEXT_INSET,
                    false,
                    format_deal_line(assets, state, *deal),
                );
                y += LINE_HEIGHT;
            }
            DealBookHistoryRow::AidHeading => {
                spawn_text_row(
                    commands,
                    screen,
                    host,
                    y,
                    0.0,
                    PAGE_WIDTH,
                    true,
                    get_string(assets, 0x2741, 7),
                );
                y += LINE_HEIGHT;
            }
            DealBookHistoryRow::AidHeader {
                resource,
                market_price,
            } => {
                spawn_commodity_header(commands, assets, screen, host, y, *resource, *market_price);
                y += LINE_HEIGHT;
            }
            DealBookHistoryRow::AidLine(line) => {
                let name = nation_name(state, line.nation);
                spawn_text_row(
                    commands,
                    screen,
                    host,
                    y,
                    0.0,
                    PAGE_WIDTH,
                    false,
                    format!("{name}: {}", format_currency(line.amount)),
                );
                y += LINE_HEIGHT;
            }
            DealBookHistoryRow::Totals(totals) => {
                spawn_totals(commands, assets, screen, host, y, *totals);
                y += totals.height() as f32;
            }
        }
    }
}

fn spawn_category_rows(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    state: &GameState,
    screen: &DealBookScreen,
    host: Entity,
    rows: &[DealBookCategoryRow],
) {
    let mut y = 0.0;
    for row in rows {
        match row {
            DealBookCategoryRow::Header => {
                let group = if host == screen.hosts.tsol { 1 } else { 2 };
                spawn_text_row(
                    commands,
                    screen,
                    host,
                    y,
                    0.0,
                    PAGE_WIDTH,
                    true,
                    get_string(assets, 0x2741, group),
                );
            }
            DealBookCategoryRow::FallbackHeader => {
                spawn_text_row(
                    commands,
                    screen,
                    host,
                    y,
                    0.0,
                    PAGE_WIDTH,
                    true,
                    get_string(assets, 0x2741, 4),
                );
            }
            DealBookCategoryRow::Offer(offer) => {
                spawn_offer_row(commands, assets, state, screen, host, y, offer);
            }
            DealBookCategoryRow::Bid(bid) => {
                spawn_bid_row(commands, state, screen, host, y, *bid);
            }
        }
        y += LINE_HEIGHT;
    }
}

fn spawn_commodity_header(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    screen: &DealBookScreen,
    host: Entity,
    y: f32,
    resource: ResourceKind,
    market_price: i32,
) {
    let name = get_string(assets, 0x2711, resource as i16);
    spawn_icon(
        commands,
        screen.pictures.commodities[resource as usize].clone(),
        None,
        host,
        0.0,
        y,
    );
    spawn_text_row(
        commands,
        screen,
        host,
        y,
        TEXT_INSET,
        PAGE_WIDTH - TEXT_INSET,
        true,
        format!("{name} {}", format_currency(market_price)),
    );
}

fn spawn_offer_row(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    state: &GameState,
    screen: &DealBookScreen,
    host: Entity,
    y: f32,
    offer: &DealBookOfferRow,
) {
    let name = nation_name(state, offer.nation);
    let text = if offer.amount == 1 {
        fill_brackets(&get_string(assets, 0x2740, 7), &[&name])
    } else {
        fill_brackets(
            &get_string(assets, 0x2740, 8),
            &[&name, &offer.amount.to_string()],
        )
    };
    spawn_text_row(commands, screen, host, y, 0.0, PAGE_WIDTH, false, text);
    for (index, bidder) in offer.bidder_nations.iter().take(7).enumerate() {
        let left = index as f32 * ICON_WIDTH;
        spawn_icon(
            commands,
            screen.pictures.flags.clone(),
            Some(flag_rect(*bidder)),
            host,
            left,
            y,
        );
    }
}

fn spawn_bid_row(
    commands: &mut Commands,
    state: &GameState,
    screen: &DealBookScreen,
    host: Entity,
    y: f32,
    bid: DealBookBidRow,
) {
    spawn_icon(
        commands,
        screen.pictures.flags.clone(),
        Some(flag_rect(bid.nation)),
        host,
        0.0,
        y,
    );
    spawn_text_row(
        commands,
        screen,
        host,
        y,
        TEXT_INSET,
        PAGE_WIDTH - TEXT_INSET,
        false,
        nation_name(state, bid.nation),
    );
}

fn spawn_totals(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    screen: &DealBookScreen,
    host: Entity,
    y: f32,
    totals: DealBookTotals,
) {
    spawn_text_at(
        commands,
        screen,
        host,
        8.0,
        y + 4.0,
        PAGE_WIDTH - 16.0,
        true,
        get_string(assets, 0x2740, 0x17),
    );
    spawn_totals_line(
        commands,
        assets,
        screen,
        host,
        y + 30.0,
        0x18,
        totals.budget_pool_base,
        false,
    );
    spawn_totals_line(
        commands,
        assets,
        screen,
        host,
        y + 42.0,
        0x19,
        totals.budget_pool_delta,
        true,
    );
    spawn_totals_line(
        commands,
        assets,
        screen,
        host,
        y + 54.0,
        0x1d,
        -totals.military_expenses,
        true,
    );
    spawn_totals_line(
        commands,
        assets,
        screen,
        host,
        y + 66.0,
        0x1a,
        totals.aid_total,
        false,
    );
    let mut value_y = 66.0;
    if totals.pressure_counter > 0 {
        value_y = 78.0;
        let template = get_string(assets, 0x2740, 0x1c);
        spawn_text_at(
            commands,
            screen,
            host,
            8.0,
            y + value_y,
            116.0,
            false,
            fill_brackets(&template, &[&totals.escalation_counter.to_string()]),
        );
        spawn_text_at(
            commands,
            screen,
            host,
            totals_value_x(-totals.pending_commitment_cost),
            y + value_y,
            100.0,
            false,
            format_currency(-totals.pending_commitment_cost),
        );
    }
    let remaining_y = value_y + 14.0;
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(8.0),
            top: Val::Px(y + remaining_y),
            width: Val::Px(PAGE_WIDTH - 16.0),
            height: Val::Px(1.0),
            ..default()
        },
        BackgroundColor(Color::BLACK),
        Pickable::IGNORE,
        ChildOf(host),
    ));
    spawn_text_at(
        commands,
        screen,
        host,
        totals_value_x(totals.remaining),
        y + remaining_y + 12.0,
        100.0,
        false,
        format_currency(totals.remaining),
    );
    let balance_y = remaining_y + 24.0;
    spawn_text_at(
        commands,
        screen,
        host,
        8.0,
        y + balance_y,
        116.0,
        false,
        fill_brackets(&get_string(assets, 0x2740, 0x1b), &[""]),
    );
    spawn_text_at(
        commands,
        screen,
        host,
        128.0,
        y + balance_y,
        100.0,
        false,
        format_currency(totals.diplomacy_budget_base / 100),
    );
}

#[allow(clippy::too_many_arguments)]
fn spawn_totals_line(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    screen: &DealBookScreen,
    host: Entity,
    y: f32,
    string_index: i16,
    value: i32,
    shift_negative: bool,
) {
    spawn_text_at(
        commands,
        screen,
        host,
        8.0,
        y,
        116.0,
        false,
        get_string(assets, 0x2740, string_index),
    );
    let x = if shift_negative {
        totals_value_x(value)
    } else {
        128.0
    };
    spawn_text_at(
        commands,
        screen,
        host,
        x,
        y,
        100.0,
        false,
        format_currency(value),
    );
}

fn totals_value_x(value: i32) -> f32 {
    if value < 0 { 124.0 } else { 128.0 }
}

fn spawn_icon(
    commands: &mut Commands,
    image: Handle<Image>,
    rect: Option<Rect>,
    host: Entity,
    left: f32,
    top: f32,
) {
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(left),
            top: Val::Px(top),
            width: Val::Px(ICON_WIDTH),
            height: Val::Px(ICON_HEIGHT),
            ..default()
        },
        ImageNode {
            image,
            rect,
            ..default()
        },
        Pickable::IGNORE,
        ChildOf(host),
    ));
}

#[allow(clippy::too_many_arguments)]
fn spawn_text_row(
    commands: &mut Commands,
    screen: &DealBookScreen,
    host: Entity,
    y: f32,
    left: f32,
    width: f32,
    heading: bool,
    value: String,
) {
    spawn_text_at(commands, screen, host, left, y, width, heading, value);
}

#[allow(clippy::too_many_arguments)]
fn spawn_text_at(
    commands: &mut Commands,
    screen: &DealBookScreen,
    host: Entity,
    left: f32,
    top: f32,
    width: f32,
    heading: bool,
    value: String,
) {
    let (font, layout, line_height) = if heading {
        (
            screen.fonts.heading.clone(),
            if left == 0.0 && width == PAGE_WIDTH {
                screen.fonts.heading_center
            } else {
                screen.fonts.heading_layout
            },
            screen.fonts.heading_line_height,
        )
    } else {
        (
            screen.fonts.body.clone(),
            screen.fonts.body_layout,
            screen.fonts.body_line_height,
        )
    };
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(left),
            top: Val::Px(top),
            width: Val::Px(width),
            height: Val::Px(LINE_HEIGHT),
            ..default()
        },
        Text::new(value),
        font,
        layout,
        line_height,
        TextColor(screen.fonts.color),
        Pickable::IGNORE,
        ChildOf(host),
    ));
}

fn format_deal_line(
    assets: &mut RetailUiAssets,
    state: &GameState,
    deal: DealBookDealLine,
) -> String {
    let counterparty = nation_name(state, deal.counterparty);
    let commodity = get_string(assets, 0x2711, deal.commodity.resource() as i16);
    if deal.amount != 0 {
        let amount = deal.amount.to_string();
        if deal.unit_price != deal.market_price {
            let template = get_string(
                assets,
                0x2740,
                if deal.kind == DealBookEntryKind::Offer {
                    0x12
                } else {
                    0x13
                },
            );
            fill_brackets(
                &template,
                &[
                    &amount,
                    &commodity,
                    &counterparty,
                    &format_currency(deal.unit_price),
                ],
            )
        } else {
            let template = get_string(
                assets,
                0x2740,
                if deal.kind == DealBookEntryKind::Offer {
                    0x14
                } else {
                    0x15
                },
            );
            fill_brackets(&template, &[&amount, &commodity, &counterparty])
        }
    } else if deal.uses_navy_status_text() {
        let mut text = fill_brackets(&get_string(assets, 0x2740, 0x1f), &[&counterparty]);
        let status = match deal.unit_price {
            -123_456 => 0x21,
            -123_457 => 0x20,
            _ => 0x23,
        };
        text.push(' ');
        text.push_str(&get_string(assets, 0x2740, status));
        text
    } else {
        fill_brackets(
            &get_string(assets, 0x2740, 0x16),
            &[&counterparty, &commodity],
        )
    }
}

fn get_string(assets: &RetailUiAssets, group: i16, offset: i16) -> String {
    assets
        .string(group, offset + 1)
        .unwrap_or_else(|_| panic!("retail string {group:#x}:{offset} must load"))
}

fn category_date(assets: &RetailUiAssets, economic_turn: i32) -> String {
    let season = get_string(assets, 10_000, (economic_turn % 4) as i16);
    format!("{season} {}", 1815 + economic_turn / 4)
}

fn nation_name(state: &GameState, nation: NationId) -> String {
    state
        .nations()
        .display_name(nation)
        .unwrap_or("")
        .to_owned()
}

fn fill_brackets(template: &str, args: &[&str]) -> String {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '[' {
            let mut scan = index + 1;
            while scan < chars.len() && chars[scan] != ']' && !chars[scan].is_ascii_digit() {
                scan += 1;
            }
            if scan < chars.len() && chars[scan].is_ascii_digit() {
                let slot = (chars[scan] as u8 - b'0') as usize;
                if slot >= 1 && slot <= args.len() {
                    out.push_str(args[slot - 1]);
                }
                while scan < chars.len() && chars[scan] != ']' {
                    scan += 1;
                }
                index = scan.saturating_add(1);
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

fn flag_rect(nation: NationId) -> Rect {
    let left = f32::from(nation.get()) * ICON_WIDTH;
    Rect::new(left, 0.0, left + ICON_WIDTH, ICON_HEIGHT)
}

fn place_page(nodes: &mut Query<&mut Node>, entity: Entity, left: f32, top: f32) {
    let Ok(mut node) = nodes.get_mut(entity) else {
        return;
    };
    node.left = Val::Px(left);
    node.top = Val::Px(top);
    node.overflow = Overflow::clip();
}

fn set_text(texts: &mut Query<&mut Text>, entity: Entity, value: String) {
    if let Ok(mut text) = texts.get_mut(entity) {
        *text = Text::new(value);
    }
}

fn set_picture(pictures: &mut Query<&mut ImageNode>, entity: Entity, image: Handle<Image>) {
    if let Ok(mut picture) = pictures.get_mut(entity) {
        picture.image = image;
    }
}

fn set_visible(visibilities: &mut Query<&mut Visibility>, entity: Entity, visible: bool) {
    if let Ok(mut visibility) = visibilities.get_mut(entity) {
        *visibility = if visible {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
    }
}

fn set_page_button(
    commands: &mut Commands,
    visibilities: &mut Query<&mut Visibility>,
    entity: Entity,
    enabled: bool,
) {
    set_visible(visibilities, entity, enabled);
    if enabled {
        commands.entity(entity).remove::<InteractionDisabled>();
    } else {
        commands.entity(entity).insert(InteractionDisabled);
    }
}

fn clear_host(commands: &mut Commands, host: Entity, children: &Query<&Children>) {
    let Ok(children) = children.get(host) else {
        return;
    };
    for child in children.iter() {
        commands.entity(child).despawn();
    }
}

fn transparent_picture(assets: &mut RetailUiAssets, picture_id: PictureId) -> Handle<Image> {
    let indexed = assets
        .indexed_picture(picture_id)
        .expect("retail deal-book picture must have indexed pixels");
    assets
        .transformed_picture(picture_id, |image| {
            apply_palette_index_transparency(image, &indexed);
        })
        .expect("retail deal-book picture must load")
}

fn apply_palette_index_transparency(image: &mut Image, indexed: &IndexedPicture) {
    let width = image.width() as usize;
    let height = image.height() as usize;
    let Some(pixels) = image.data.as_mut() else {
        return;
    };
    if width == 0
        || height == 0
        || indexed.width as usize != width
        || indexed.height as usize != height
        || pixels.len() != width * height * 4
        || indexed.pixels.len() != width * height
    {
        return;
    }
    for (pixel, &palette_index) in pixels.chunks_exact_mut(4).zip(&indexed.pixels) {
        if palette_index == 0x10 {
            pixel[3] = 0;
        }
    }
}
