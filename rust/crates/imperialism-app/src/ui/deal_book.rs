use super::GameSession;
use super::RetailUiAssets;
use super::fill_brackets;
use super::format_currency;
use super::game_shell::bind_game_status_display;
use super::generated;
use super::retail::{RetailPressedOverlay, RetailTree};
use super::retail_raster::IndexedRasterExt;
use super::retail_resources::ResourceKindRetailResources;
use super::session::{apply_turn_stop, clear_return_to};
use crate::{AppState, RetailAssetsResource, ReturnTo};
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::{InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ActivateOnPress, Button as UiButton};
use imperialism_core::*;
use imperialism_formats::*;

const HISTORY_BACKGROUND: PictureId = PictureId::new(0x2260);
const CATEGORY_BACKGROUND: PictureId = PictureId::new(0x2263);
const TAB_STRIP_BASE: PictureId = PictureId::new(0x2266);
const FLAG_ATLAS: PictureId = PictureId::new(0x21fb);
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
    Category(TradeCommodity),
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum DealBookHost {
    Sold,
    Bought,
    SoldByCategory,
    BoughtByCategory,
}

#[derive(Component)]
struct DealBookBackground;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum DealBookTitle {
    Left,
    Right,
}

#[derive(Component)]
struct DealBookTabs;

#[derive(Component)]
struct DealBookTabVisual {
    empty: IndexedPicture,
    filled: IndexedPicture,
    shown_row: Option<u8>,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum DealBookPageButton {
    Previous,
    Next,
}

#[derive(Component)]
struct DealBookHistory;

#[derive(Clone)]
struct DealBookPictures {
    history: Handle<Image>,
    category: Handle<Image>,
    flags: Handle<Image>,
    commodities: ResourceTable<Handle<Image>>,
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
    body_color: Color,
    heading_color: Color,
}

#[derive(Component)]
struct DealBookRoot;

#[derive(Component)]
struct DealBookScreen {
    mode: DealBookMode,
    page: u16,
    pictures: DealBookPictures,
    fonts: DealBookFonts,
    advanced_production_unlocked: bool,
}

pub(crate) struct DealBookPlugin;

impl Plugin for DealBookPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::DealBook),
            (spawn_deal_book, bind_deal_book).chain(),
        )
        .add_systems(OnExit(AppState::DealBook), clear_return_to)
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
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    mut images: Query<&mut ImageNode>,
) {
    let root = *root;
    let advanced_production_unlocked = session.game.technology().advanced_production_unlocked();
    let tab_base = if advanced_production_unlocked {
        TAB_STRIP_BASE.offset(1)
    } else {
        TAB_STRIP_BASE
    };
    let empty_tabs = assets.indexed_picture(tab_base.offset(4));
    let filled_tabs = assets.indexed_picture(tab_base);
    let pictures = DealBookPictures {
        history: assets.picture(HISTORY_BACKGROUND),
        category: assets.picture(CATEGORY_BACKGROUND),
        flags: assets.transparent_picture(FLAG_ATLAS, 0x10),
        commodities: ResourceTable::from_array(std::array::from_fn(|index| {
            let kind = ResourceKind::from_index(index as u8).expect("resource table index");
            assets.transparent_picture(kind.material_picture(), 0x10)
        })),
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
        // TDealLine initializes the QuickDraw fill color to palette 0 after
        // installing its descriptor; its visible glyphs are black.
        body_color: Color::BLACK,
        heading_color: Color::BLACK,
    };
    // Mac titL is family 0 / 18pt. The generator only emits shipped fonts (modes 1-3),
    // and TDealBookPicture::Startup does not restyle titL on Windows.
    let (title_font, title_layout, title_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 0,
            face_flags: 0,
            point_size: 18,
            alignment: 1,
        })
        .expect("retail deal-book title text style");
    commands.entity(tree.find(root, fourcc!("titL"))).insert((
        title_font,
        title_layout,
        title_line_height,
        TextColor(Color::BLACK),
    ));

    let tabs = tree.find(root, fourcc!("tabs"));
    let palette = *assets.default_dib_palette();
    let tab_image = assets
        .add_image(paint_deal_tab_control(&empty_tabs, &filled_tabs, None).to_image(&palette));
    commands
        .entity(tabs)
        .insert((
            DealBookTabs,
            DealBookTabVisual {
                empty: empty_tabs,
                filled: filled_tabs,
                shown_row: None,
            },
            ImageNode::new(tab_image),
            RelativeCursorPosition::default(),
        ))
        .observe(on_deal_book_tabs_click);
    commands
        .entity(tree.find(root, fourcc!("end ")))
        .insert(ActivateOnPress)
        .remove::<InteractionDisabled>()
        .observe(on_deal_book_close);
    commands
        .entity(tree.find(root, fourcc!("quer")))
        .insert(InteractionDisabled);
    bind_game_status_display(&mut commands, &mut assets, root, &tree);
    let mark = tree.find(root, fourcc!("mark"));
    commands
        .entity(mark)
        .insert((DealBookHistory, ActivateOnPress, RetailPressedOverlay))
        .observe(on_deal_book_history);
    // `mark` is a TPictureButton: picture 8812 is its hilite bitmap, not an
    // always-visible icon. TDealBookPicture enables its input only in category
    // mode; RetailPressedOverlay supplies TPictureButton::HiliteState's paint.
    images
        .get_mut(mark)
        .expect("retail deal-book mark picture must load")
        .color
        .set_alpha(0.0);
    commands
        .entity(tree.find(root, fourcc!("lcor")))
        .insert((
            UiButton,
            DealBookPageButton::Previous,
            ActivateOnPress,
            Visibility::Hidden,
            InteractionDisabled,
        ))
        .observe(on_deal_book_page);
    commands
        .entity(tree.find(root, fourcc!("rcor")))
        .insert((
            UiButton,
            DealBookPageButton::Next,
            ActivateOnPress,
            Visibility::Hidden,
            InteractionDisabled,
        ))
        .observe(on_deal_book_page);
    commands
        .entity(tree.find(root, fourcc!("main")))
        .insert(DealBookBackground);
    commands
        .entity(tree.find(root, fourcc!("sold")))
        .insert(DealBookHost::Sold);
    commands
        .entity(tree.find(root, fourcc!("boug")))
        .insert(DealBookHost::Bought);
    commands
        .entity(tree.find(root, fourcc!("tsol")))
        .insert(DealBookHost::SoldByCategory);
    commands
        .entity(tree.find(root, fourcc!("tbou")))
        .insert(DealBookHost::BoughtByCategory);
    commands
        .entity(tree.find(root, fourcc!("titL")))
        .insert(DealBookTitle::Left);
    commands
        .entity(tree.find(root, fourcc!("rtil")))
        .insert(DealBookTitle::Right);

    commands.entity(root).insert(DealBookScreen {
        mode: DealBookMode::History,
        page: 0,
        pictures,
        fonts,
        advanced_production_unlocked,
    });
}

fn on_deal_book_close(
    _activate: On<Activate>,
    return_state: Option<Res<ReturnTo>>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if let Some(return_state) = return_state.as_deref() {
        next_state.set(return_state.0);
        return;
    }
    let stop = session.game.close_turn_deal_book();
    apply_turn_stop(stop, &mut next_state);
}

fn on_deal_book_history(_activate: On<Activate>, mut screens: Query<&mut DealBookScreen>) {
    let Ok(mut screen) = screens.single_mut() else {
        return;
    };
    if screen.mode != DealBookMode::History {
        screen.mode = DealBookMode::History;
        screen.page = 0;
    }
}

fn on_deal_book_page(
    activate: On<Activate>,
    buttons: Query<&DealBookPageButton>,
    mut screens: Query<&mut DealBookScreen>,
    session: Res<GameSession>,
) {
    let Ok(button) = buttons.get(activate.entity) else {
        return;
    };
    let Ok(mut screen) = screens.single_mut() else {
        return;
    };
    match *button {
        DealBookPageButton::Previous => {
            screen.page = screen.page.saturating_sub(1);
        }
        DealBookPageButton::Next => {
            let last_page = deal_book_last_page(&screen, &session);
            screen.page = (screen.page + 1).min(last_page);
        }
    }
}

fn deal_book_last_page(screen: &DealBookScreen, session: &GameSession) -> u16 {
    let nation = session.active_major_nation();
    match screen.mode {
        DealBookMode::History => session.game.deal_book_history(nation).last_page_index(),
        DealBookMode::Category(commodity) => session
            .game
            .deal_book_category(nation, commodity)
            .last_page_index(),
    }
}

fn on_deal_book_tabs_click(
    mut click: On<Pointer<Click>>,
    tabs: Query<&RelativeCursorPosition, With<DealBookTabs>>,
    mut screens: Query<&mut DealBookScreen>,
) {
    let Ok(mut screen) = screens.single_mut() else {
        return;
    };
    let Ok(cursor) = tabs.get(click.entity) else {
        return;
    };
    let Some(commodity) = tab_row(cursor, screen.advanced_production_unlocked) else {
        return;
    };
    click.propagate(false);
    screen.mode = DealBookMode::Category(commodity);
    screen.page = 0;
}

fn paint_deal_tab_control(
    empty: &IndexedPicture,
    filled: &IndexedPicture,
    selected_row: Option<u8>,
) -> IndexedPicture {
    let mut picture = empty.clone();
    let Some(row) = selected_row else {
        return picture;
    };
    let top = i32::from(row) * TAB_ROW_HEIGHT as i32;
    let width = picture.width as i32;
    let height = picture.height as i32;
    if top >= height {
        return picture;
    }
    let bottom = (top + TAB_ROW_HEIGHT as i32).min(height);
    picture.copy_rect(
        filled,
        IRect::new(0, top, width, bottom),
        IVec2::new(0, top),
    );
    picture
}

fn hover_deal_book_tabs(
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    screen: Option<Single<&DealBookScreen>>,
    mut tabs: Query<
        (&RelativeCursorPosition, &mut DealBookTabVisual, &ImageNode),
        With<DealBookTabs>,
    >,
) {
    let Some(screen) = screen else {
        return;
    };
    let Ok((cursor, mut visual, image_node)) = tabs.single_mut() else {
        return;
    };
    let shown = tab_row(cursor, screen.advanced_production_unlocked)
        .or(match screen.mode {
            DealBookMode::History => None,
            DealBookMode::Category(commodity) => Some(commodity),
        })
        .and_then(|commodity| deal_book_tab_index(screen.advanced_production_unlocked, commodity));
    if visual.shown_row == shown {
        return;
    }
    visual.shown_row = shown;
    if let Some(mut image) = images.get_mut(&image_node.image) {
        *image = paint_deal_tab_control(&visual.empty, &visual.filled, shown)
            .to_image(retail.assets().default_dib_palette());
    }
}

fn tab_row(
    cursor: &RelativeCursorPosition,
    advanced_production_unlocked: bool,
) -> Option<TradeCommodity> {
    let normalized = cursor.normalized.filter(|_| cursor.cursor_over())?;
    let y = (normalized.y + 0.5) * TAB_STRIP_HEIGHT;
    if y < 0.0 {
        return None;
    }
    let row = (y / TAB_ROW_HEIGHT).floor() as i32;
    let count = i32::from(deal_book_tab_count(advanced_production_unlocked));
    (row >= 0 && row < count)
        .then(|| u8::try_from(row).expect("retail deal-book tab row fits in u8"))
        .and_then(|row| deal_book_tab_commodity(advanced_production_unlocked, row))
}

#[allow(clippy::too_many_arguments)]
fn sync_deal_book(
    mut commands: Commands,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    screen: Option<Single<&DealBookScreen, Changed<DealBookScreen>>>,
    children: Query<&Children>,
    hosts: Query<(Entity, &DealBookHost)>,
    titles: Query<(Entity, &DealBookTitle)>,
    background: Option<Single<Entity, With<DealBookBackground>>>,
    history: Option<Single<Entity, With<DealBookHistory>>>,
    page_buttons: Query<(Entity, &DealBookPageButton)>,
    mut nodes: Query<&mut Node>,
    mut texts: Query<&mut Text>,
    mut pictures: Query<&mut ImageNode>,
    mut visibilities: Query<&mut Visibility>,
) {
    let Some(screen) = screen else {
        return;
    };
    let Some(&background) = background.as_deref() else {
        return;
    };
    let Some(&history) = history.as_deref() else {
        return;
    };
    let nation = session.active_major_nation();
    let last_page = match screen.mode {
        DealBookMode::History => project_history(
            &mut commands,
            &mut assets,
            &session.game,
            nation,
            *screen,
            &hosts,
            &titles,
            background,
            history,
            &children,
            &mut nodes,
            &mut texts,
            &mut pictures,
            &mut visibilities,
        ),
        DealBookMode::Category(commodity) => project_category(
            &mut commands,
            &mut assets,
            &session.game,
            nation,
            commodity,
            *screen,
            &hosts,
            &titles,
            background,
            history,
            &children,
            &mut nodes,
            &mut texts,
            &mut pictures,
            &mut visibilities,
        ),
    };
    let page = screen.page.min(last_page);
    for (entity, button) in &page_buttons {
        let enabled = match *button {
            DealBookPageButton::Previous => page > 0,
            DealBookPageButton::Next => page < last_page && last_page != 0,
        };
        set_page_button(&mut commands, &mut visibilities, entity, enabled);
    }
}

fn deal_book_host(hosts: &Query<(Entity, &DealBookHost)>, kind: DealBookHost) -> Entity {
    hosts
        .iter()
        .find_map(|(entity, host)| (*host == kind).then_some(entity))
        .expect("deal-book host is bound")
}

fn deal_book_title(titles: &Query<(Entity, &DealBookTitle)>, which: DealBookTitle) -> Entity {
    titles
        .iter()
        .find_map(|(entity, title)| (*title == which).then_some(entity))
        .expect("deal-book title is bound")
}

#[allow(clippy::too_many_arguments)]
fn project_history(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    state: &GameState,
    nation: MajorNationId,
    screen: &DealBookScreen,
    hosts: &Query<(Entity, &DealBookHost)>,
    titles: &Query<(Entity, &DealBookTitle)>,
    background: Entity,
    history: Entity,
    children: &Query<&Children>,
    nodes: &mut Query<&mut Node>,
    texts: &mut Query<&mut Text>,
    pictures: &mut Query<&mut ImageNode>,
    visibilities: &mut Query<&mut Visibility>,
) -> u16 {
    let sold = deal_book_host(hosts, DealBookHost::Sold);
    let bought = deal_book_host(hosts, DealBookHost::Bought);
    place_page(nodes, sold, PAGE_LEFT, PAGE_TOP);
    place_page(nodes, bought, PAGE_RIGHT, PAGE_TOP);
    place_page(
        nodes,
        deal_book_host(hosts, DealBookHost::SoldByCategory),
        PAGE_OFFSCREEN,
        PAGE_OFFSCREEN,
    );
    place_page(
        nodes,
        deal_book_host(hosts, DealBookHost::BoughtByCategory),
        PAGE_OFFSCREEN,
        PAGE_OFFSCREEN,
    );
    set_picture(pictures, background, screen.pictures.history.clone());
    commands.entity(history).insert(InteractionDisabled);
    let sold_title = assets.ui_string(0x2740, 0x19);
    let bought_title = assets.ui_string(0x2740, 0x1a);
    set_text(
        texts,
        deal_book_title(titles, DealBookTitle::Left),
        sold_title,
    );
    set_text(
        texts,
        deal_book_title(titles, DealBookTitle::Right),
        bought_title,
    );

    let history_rows = state.deal_book_history(nation);
    let sold_pages = history_rows.sold_pages();
    let bought_pages = history_rows.bought_pages();
    let last_page = history_rows.last_page_index();
    let page = usize::from(screen.page.min(last_page));
    clear_host(commands, sold, children);
    clear_host(commands, bought, children);
    if page < sold_pages.len() {
        set_visible(visibilities, sold, true);
        spawn_history_rows(commands, assets, state, screen, sold, &sold_pages[page]);
    } else {
        set_visible(visibilities, sold, false);
    }
    if page < bought_pages.len() {
        set_visible(visibilities, bought, true);
        spawn_history_rows(commands, assets, state, screen, bought, &bought_pages[page]);
    } else {
        set_visible(visibilities, bought, false);
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
    hosts: &Query<(Entity, &DealBookHost)>,
    titles: &Query<(Entity, &DealBookTitle)>,
    background: Entity,
    history: Entity,
    children: &Query<&Children>,
    nodes: &mut Query<&mut Node>,
    texts: &mut Query<&mut Text>,
    pictures: &mut Query<&mut ImageNode>,
    visibilities: &mut Query<&mut Visibility>,
) -> u16 {
    let sold = deal_book_host(hosts, DealBookHost::SoldByCategory);
    let bought = deal_book_host(hosts, DealBookHost::BoughtByCategory);
    place_page(nodes, sold, PAGE_LEFT, PAGE_TOP);
    place_page(nodes, bought, PAGE_RIGHT, PAGE_TOP);
    place_page(
        nodes,
        deal_book_host(hosts, DealBookHost::Sold),
        PAGE_OFFSCREEN,
        PAGE_OFFSCREEN,
    );
    place_page(
        nodes,
        deal_book_host(hosts, DealBookHost::Bought),
        PAGE_OFFSCREEN,
        PAGE_OFFSCREEN,
    );
    set_picture(pictures, background, screen.pictures.category.clone());
    commands.entity(history).remove::<InteractionDisabled>();
    let template = assets.get_string(0x2741, 3);
    let commodity_name = assets.string(commodity.resource().name_string());
    set_text(
        texts,
        deal_book_title(titles, DealBookTitle::Left),
        fill_brackets(&template, &[&commodity_name]),
    );
    set_text(
        texts,
        deal_book_title(titles, DealBookTitle::Right),
        category_date(assets, state.turn().economic_turn),
    );

    let category = state.deal_book_category(nation, commodity);
    let sell_pages = category.sell_pages();
    let buy_pages = category.buy_pages();
    let last_page = category.last_page_index();
    let page = usize::from(screen.page.min(last_page));
    clear_host(commands, sold, children);
    clear_host(commands, bought, children);
    if page < sell_pages.len() {
        set_visible(visibilities, sold, true);
        spawn_category_rows(
            commands,
            assets,
            state,
            screen,
            sold,
            DealBookHost::SoldByCategory,
            &sell_pages[page],
        );
    } else {
        set_visible(visibilities, sold, false);
    }
    if page < buy_pages.len() {
        set_visible(visibilities, bought, true);
        spawn_category_rows(
            commands,
            assets,
            state,
            screen,
            bought,
            DealBookHost::BoughtByCategory,
            &buy_pages[page],
        );
    } else {
        set_visible(visibilities, bought, false);
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
                    assets.get_string(0x2741, 7),
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
    host_kind: DealBookHost,
    rows: &[DealBookCategoryRow],
) {
    let mut y = 0.0;
    for row in rows {
        match row {
            DealBookCategoryRow::Header => {
                let group = match host_kind {
                    DealBookHost::SoldByCategory => 1,
                    DealBookHost::BoughtByCategory => 2,
                    DealBookHost::Sold | DealBookHost::Bought => {
                        panic!("category headers are only spawned on category hosts")
                    }
                };
                spawn_text_row(
                    commands,
                    screen,
                    host,
                    y,
                    0.0,
                    PAGE_WIDTH,
                    true,
                    assets.get_string(0x2741, group),
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
                    assets.get_string(0x2741, 4),
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
    let name = assets.string(resource.name_string());
    spawn_icon(
        commands,
        screen.pictures.commodities[resource].clone(),
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
        fill_brackets(
            &assets.get_string(0x2740, 7),
            &[&name],
        )
    } else {
        fill_brackets(
            &assets.get_string(0x2740, 8),
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
        assets.get_string(0x2740, 0x17),
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
        let template = assets.get_string(0x2740, 0x1c);
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
        fill_brackets(
            &assets.get_string(0x2740, 0x1b),
            &[""],
        ),
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
        false, assets.get_string(0x2740, string_index as u16),
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
        TextColor(if heading {
            screen.fonts.heading_color
        } else {
            screen.fonts.body_color
        }),
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
    let commodity = assets.string(deal.commodity.resource().name_string());
    if deal.amount != 0 {
        let amount = deal.amount.to_string();
        if deal.unit_price != deal.market_price {
            let template = assets.get_string(0x2740, if deal.kind == DealBookEntryKind::Offer {
                        0x12
                    } else {
                        0x13
                    });
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
            let template = assets.get_string(0x2740, if deal.kind == DealBookEntryKind::Offer {
                        0x14
                    } else {
                        0x15
                    });
            fill_brackets(&template, &[&amount, &commodity, &counterparty])
        }
    } else if deal.uses_navy_status_text() {
        let mut text = fill_brackets(
            &assets.get_string(0x2740, 0x1f),
            &[&counterparty],
        );
        let status = match deal.unit_price {
            -123_456 => 0x21,
            -123_457 => 0x20,
            _ => 0x23,
        };
        text.push(' ');
        text.push_str(&assets.get_string(0x2740, status));
        text
    } else {
        fill_brackets(
            &assets.get_string(0x2740, 0x16),
            &[&counterparty, &commodity],
        )
    }
}

fn category_date(assets: &RetailUiAssets, economic_turn: i32) -> String {
    let season = assets.get_string(10_000, (economic_turn % 4) as u16);
    format!("{season} {}", 1815 + economic_turn / 4)
}

fn nation_name(state: &GameState, nation: NationId) -> String {
    state
        .nations()
        .display_name(nation)
        .unwrap_or("")
        .to_owned()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::retail_raster::indexed_picture;

    #[test]
    fn deal_tab_control_draw_overlays_the_filled_band_at_the_selected_row() {
        let empty = indexed_picture(31, 75, 1);
        let filled = indexed_picture(31, 75, 2);
        let none = paint_deal_tab_control(&empty, &filled, None);
        assert_eq!(none.pixels, empty.pixels);
        let selected = paint_deal_tab_control(&empty, &filled, Some(1));
        let width = 31usize;
        let row = TAB_ROW_HEIGHT as usize;
        assert!(
            selected.pixels[..width * row]
                .iter()
                .all(|&pixel| pixel == 1)
        );
        assert!(
            selected.pixels[width * row..width * 2 * row]
                .iter()
                .all(|&pixel| pixel == 2)
        );
        assert!(
            selected.pixels[width * 2 * row..]
                .iter()
                .all(|&pixel| pixel == 1)
        );
    }
}
