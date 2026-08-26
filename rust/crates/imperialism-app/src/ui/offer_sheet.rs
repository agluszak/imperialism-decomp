use super::fill_brackets;
use super::format_currency;
use super::game_shell::bind_game_status_display;
use super::generated;
use super::hover_help::{HoverHelpBarStyle, bind_hover_help_bar, get_string};
use super::linger::{bind_linger_dialog, spawn_linger_dialog};
use super::retail::{RetailTree, RetailUiAssets};
use super::session::{GameSession, apply_turn_stop};
use crate::AppState;
use bevy::input_focus::AutoFocus;
use bevy::prelude::*;
use bevy::text::{EditableText, EditableTextFilter, TextCursorStyle};
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::{Activate, ActivateOnPress, SelectAllOnFocus};
use imperialism_core::*;
use imperialism_formats::{PictureId, RetailTextStylePreset, fourcc};

const COMMODITY_ICON_BASE: i16 = 700;
const OFFER_STRING_GROUP: i16 = 0x2740;

#[derive(Component)]
struct OfferSheetRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum OfferSheetAction {
    Accept,
    Reject,
}

#[derive(Component)]
struct PurchaseAmountField;

#[derive(Component)]
struct StopBuyingToggle;

#[derive(Component)]
struct OfferSheetNotice;

#[derive(Component)]
struct OfferSheetNoticeBody(String);

pub(crate) struct OfferSheetPlugin;

impl Plugin for OfferSheetPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::OfferSheet),
            (
                enter_offer_sheet_phase,
                spawn_offer_sheet,
                bind_offer_sheet,
                pose_offer_sheet,
            )
                .chain(),
        )
        .add_systems(
            Update,
            pose_offer_sheet
                .run_if(in_state(AppState::OfferSheet).and_then(resource_changed::<GameSession>)),
        )
        .add_systems(
            Update,
            bind_offer_sheet_notice.run_if(in_state(AppState::OfferSheet)),
        );
    }
}

fn enter_offer_sheet_phase(session: Res<GameSession>) {
    assert!(
        session.game.pending_trade_offer().is_some(),
        "Offer Sheet requires a core trade continuation"
    );
}

fn spawn_offer_sheet(mut commands: Commands) {
    let root = commands.spawn_scene(generated::flagview_8500()).id();
    commands
        .entity(root)
        .insert((OfferSheetRoot, DespawnOnExit(AppState::OfferSheet)));
}

fn bind_offer_sheet(
    mut commands: Commands,
    root: Option<Single<Entity, Added<OfferSheetRoot>>>,
    tree: RetailTree,
    mut nodes: Query<&mut Node>,
    mut assets: RetailUiAssets,
) {
    let Some(root) = root else {
        return;
    };
    let root = *root;
    bind_offer_sheet_controls(&mut commands, root, &tree);
    bind_offer_sheet_text(&mut commands, &mut assets, root, &tree);
    for tag in [
        fourcc!("ForM"),
        fourcc!("tabs"),
        fourcc!("quer"),
        fourcc!("done"),
    ] {
        commands
            .entity(tree.find(root, tag))
            .insert(InteractionDisabled);
    }
    let curs = tree.find(root, fourcc!("curs"));
    bind_hover_help_bar(
        &mut commands,
        &mut assets,
        curs,
        &mut nodes
            .get_mut(curs)
            .expect("offer-sheet hover-help bar has Node"),
        HoverHelpBarStyle::MAIN_MENU,
    );
    bind_game_status_display(&mut commands, &mut assets, root, &tree);
}

fn bind_offer_sheet_text(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let text_style = |assets: &mut RetailUiAssets, alignment| {
        assets
            .text_style(RetailTextStylePreset {
                font_family: 0,
                face_flags: 0,
                point_size: 12,
                alignment,
            })
            .expect("retail offer-sheet text style")
    };
    let (body, center, body_height, _) = text_style(assets, 1);
    commands.entity(tree.find(root, fourcc!("offe"))).insert((
        body.clone(),
        center,
        body_height,
        TextColor(Color::BLACK),
    ));
    let (body, right, body_height, _) = text_style(assets, -1);
    commands.entity(tree.find(root, fourcc!("purT"))).insert((
        body.clone(),
        right,
        body_height,
        TextColor(Color::BLACK),
    ));
    let (body, left, body_height, _) = text_style(assets, -2);
    for tag in [fourcc!("unit"), fourcc!("noof")] {
        commands.entity(tree.find(root, tag)).insert((
            body.clone(),
            left,
            body_height,
            TextColor(Color::BLACK),
        ));
    }
    let (number, center, number_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 0,
            face_flags: 0,
            point_size: 14,
            alignment: 1,
        })
        .expect("retail offer-sheet number text style");
    for tag in [fourcc!("purc"), fourcc!("mCap")] {
        commands.entity(tree.find(root, tag)).insert((
            number.clone(),
            center,
            number_height,
            TextColor(Color::BLACK),
        ));
    }
    commands.entity(tree.find(root, fourcc!("info"))).insert((
        Text::new(get_string(assets, OFFER_STRING_GROUP, 9)),
        body,
        TextLayout::justify(Justify::Center),
        body_height,
        TextColor(assets.palette_color(0x28)),
        TextShadow {
            offset: Vec2::new(1.0, 1.0),
            color: assets.palette_color(0xd2),
        },
    ));
}

fn bind_offer_sheet_controls(commands: &mut Commands, root: Entity, tree: &RetailTree) {
    let accept = tree.find(root, fourcc!("acce"));
    let reject = tree.find(root, fourcc!("reje"));
    let purc = tree.find(root, fourcc!("purc"));
    let nomo = tree.find(root, fourcc!("nomo"));
    commands
        .entity(accept)
        .insert((OfferSheetAction::Accept, ActivateOnPress))
        .remove::<InteractionDisabled>()
        .observe(on_offer_sheet_activate);
    commands
        .entity(reject)
        .insert((OfferSheetAction::Reject, ActivateOnPress))
        .remove::<InteractionDisabled>()
        .observe(on_offer_sheet_activate);
    commands
        .entity(nomo)
        .insert(StopBuyingToggle)
        .remove::<(Checked, InteractionDisabled)>();
    commands.entity(purc).insert((
        PurchaseAmountField,
        SelectAllOnFocus,
        AutoFocus,
        TextCursorStyle::default(),
        EditableTextFilter::new(|character| character.is_ascii_digit() || character == '-'),
        EditableText {
            max_characters: Some(6),
            allow_newlines: false,
            ..EditableText::new(String::new())
        },
    ));
}

fn pose_offer_sheet(
    mut commands: Commands,
    root: Option<Single<Entity, With<OfferSheetRoot>>>,
    tree: RetailTree,
    mut amounts: Query<&mut EditableText, With<PurchaseAmountField>>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let Some(root) = root else {
        return;
    };
    let offer = session
        .game
        .pending_trade_offer()
        .expect("OfferSheet requires pending trade offer");
    apply_offer_sheet_pose(
        &mut commands,
        &mut assets,
        *root,
        &tree,
        &mut amounts,
        &session,
        offer,
    );
}

#[allow(clippy::too_many_arguments)]
fn apply_offer_sheet_pose(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    amounts: &mut Query<&mut EditableText, With<PurchaseAmountField>>,
    session: &GameSession,
    offer: PendingTradeOffer,
) {
    let offering = session
        .game
        .nations()
        .display_name(offer.seller)
        .unwrap_or("")
        .to_owned();
    let commodity = get_string(
        assets,
        0x2711,
        i16::from(offer.commodity.resource().retail()),
    );
    let amount = offer.amount.to_string();
    let price = format_currency(i32::from(offer.price));
    set_text(
        commands,
        tree.find(root, fourcc!("offe")),
        fill_brackets(
            &get_string(assets, OFFER_STRING_GROUP, 0xc),
            &[&offering, &amount, &commodity, &price],
        ),
    );
    set_text(
        commands,
        tree.find(root, fourcc!("purT")),
        get_string(assets, OFFER_STRING_GROUP, 0xe),
    );
    set_text(
        commands,
        tree.find(root, fourcc!("unit")),
        get_string(assets, OFFER_STRING_GROUP, 0xf),
    );
    set_text(
        commands,
        tree.find(root, fourcc!("noof")),
        fill_brackets(&get_string(assets, OFFER_STRING_GROUP, 0xf), &[&commodity]),
    );

    let nation = session.active_major_nation();
    set_text(
        commands,
        tree.find(root, fourcc!("mCap")),
        session
            .game
            .nations()
            .major(nation)
            .economy
            .capacities
            .available_merchant
            .to_string(),
    );

    if let Ok(mut editable) = amounts.single_mut() {
        *editable = EditableText {
            max_characters: Some(6),
            allow_newlines: false,
            ..EditableText::new(offer.amount.to_string())
        };
    }

    if let Ok(icon) = assets.transparent_picture(
        PictureId::new(COMMODITY_ICON_BASE + i16::from(offer.commodity.resource().retail())),
        0x10,
    ) {
        commands
            .entity(tree.find(root, fourcc!("icon")))
            .insert(ImageNode::new(icon));
    }

    commands
        .entity(tree.find(root, fourcc!("nomo")))
        .remove::<Checked>();
}

fn set_text(commands: &mut Commands, entity: Entity, value: String) {
    commands.entity(entity).insert(Text::new(value));
}

#[allow(clippy::too_many_arguments)]
fn on_offer_sheet_activate(
    activate: On<Activate>,
    actions: Query<&OfferSheetAction>,
    amount: Option<Single<&EditableText, With<PurchaseAmountField>>>,
    stop_buying: Option<Single<Has<Checked>, With<StopBuyingToggle>>>,
    notices: Query<(), With<OfferSheetNotice>>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
    assets: RetailUiAssets,
) {
    if !notices.is_empty() {
        return;
    }
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let offer = session
        .game
        .pending_trade_offer()
        .expect("OfferSheet requires pending trade offer");
    let stop_buying = stop_buying.is_some_and(|flag| *flag);
    let amount = match action {
        OfferSheetAction::Reject => 0,
        OfferSheetAction::Accept => {
            let Some(amount) =
                amount.and_then(|editable| editable.value().to_string().parse::<i16>().ok())
            else {
                spawn_offer_quantity_error(
                    &mut commands,
                    get_string(&assets, OFFER_STRING_GROUP, 0x10),
                );
                return;
            };
            if amount < 0 || amount > offer.amount {
                spawn_offer_quantity_error(
                    &mut commands,
                    get_string(&assets, OFFER_STRING_GROUP, 0x10),
                );
                return;
            }
            amount
        }
    };
    match session.game.answer_trade_offer(amount, stop_buying) {
        TurnStop::TradeOffer => {}
        stop => apply_turn_stop(stop, &mut next_state),
    }
}

fn spawn_offer_quantity_error(commands: &mut Commands, body: String) {
    spawn_linger_dialog(
        commands,
        (OfferSheetNotice, OfferSheetNoticeBody(body)),
        AppState::OfferSheet,
    );
}

fn bind_offer_sheet_notice(
    mut commands: Commands,
    notice: Option<Single<(Entity, &OfferSheetNoticeBody), Added<OfferSheetNotice>>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    let Some(notice) = notice else {
        return;
    };
    let (root, body) = notice.into_inner();
    let linger = bind_linger_dialog(&mut commands, root, &tree);
    linger.set_body(&mut commands, &mut assets, &body.0);
    commands
        .entity(linger.okay)
        .insert(ActivateOnPress)
        .remove::<InteractionDisabled>();
}

#[cfg(test)]
mod tests {
    use super::super::retail::RetailTag;
    use super::*;
    use crate::ui::test_support::beginning_of_game_parts;
    use bevy::state::app::StatesPlugin;
    use indexmap::IndexMap;

    fn fixture_state() -> GameState {
        let mut parts = beginning_of_game_parts();
        let buyer =
            MajorNationId::from_nation(parts.turn.active_nation).expect("active nation is a major");
        let seller = MajorNationId::new(if buyer.get() == 0 { 1 } else { 0 });
        let majors = MajorNationTable::from_fn(|nation| {
            let mut major = parts.nations.major(nation).clone();
            major.city.ship_order_count_by_type[ShipType::Trader] = 2;
            major.city.ship_order_count_by_type[ShipType::Paddlewheeler] = 1;
            major.city.ship_order_count_by_type[ShipType::Freighter] = 1;
            major.city.stockpile[ResourceKind::Clothing] = 10;
            major.city.stockpile[ResourceKind::Timber] = 12;
            major.common.treasury = 20_000;
            if nation == buyer {
                major.economy.remembered_trade_offers_by_resource[ResourceKind::Clothing] = -1;
                major.economy.remembered_trade_offers_by_resource[ResourceKind::Timber] = 5;
            }
            if nation == seller {
                major.economy.remembered_trade_offers_by_resource[ResourceKind::Clothing] = 4;
            }
            major
        });
        parts.nations = Nations::new(majors, IndexMap::new());
        GameState::from_parts(parts)
    }

    fn test_app(state: GameState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(StatesPlugin)
            .insert_resource(GameSession::new(state))
            .insert_state(AppState::OfferSheet)
            .add_systems(OnEnter(AppState::OfferSheet), enter_offer_sheet_phase)
            .add_systems(
                OnEnter(AppState::OfferSheet),
                (spawn_test_offer_sheet, bind_test_offer_sheet).chain(),
            );
        app
    }

    fn spawn_test_offer_sheet(mut commands: Commands) {
        let root = commands
            .spawn((
                OfferSheetRoot,
                Node::default(),
                DespawnOnExit(AppState::OfferSheet),
            ))
            .id();
        commands.spawn((RetailTag(fourcc!("acce")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("reje")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("purc")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("nomo")), Node::default(), ChildOf(root)));
    }

    fn bind_test_offer_sheet(
        mut commands: Commands,
        root: Option<Single<Entity, Added<OfferSheetRoot>>>,
        tree: RetailTree,
    ) {
        let Some(root) = root else {
            return;
        };
        bind_offer_sheet_controls(&mut commands, *root, &tree);
    }

    #[test]
    fn entering_the_offer_sheet_binds_a_pending_offer() {
        let mut state = fixture_state();
        let TradeProgress::Offer(_) = state.begin_trade_phase() else {
            panic!("beginning-of-game fixture must produce a pending offer");
        };
        let mut app = test_app(state);
        app.update();
        assert!(
            app.world()
                .resource::<GameSession>()
                .game
                .pending_trade_offer()
                .is_some()
        );
        let bound = app
            .world_mut()
            .query::<&OfferSheetAction>()
            .iter(app.world())
            .copied()
            .collect::<Vec<_>>();
        assert!(bound.contains(&OfferSheetAction::Accept));
        assert!(bound.contains(&OfferSheetAction::Reject));
    }
}
