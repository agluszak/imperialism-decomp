use super::fill_brackets;
use super::format_currency;
use super::game_shell::bind_game_status_display;
use super::generated;
use super::linger::{bind_linger_dialog, spawn_linger_dialog};
use super::retail::{RetailTree, RetailUiAssets};
use super::retail_resources::ResourceKindRetailResources;
use super::session::{GameSession, apply_turn_stop};
use crate::AppState;
use bevy::input_focus::AutoFocus;
use bevy::prelude::*;
use bevy::text::{EditableText, EditableTextFilter, TextCursorStyle};
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::{Activate, SelectAllOnFocus};
use imperialism_core::*;
use imperialism_formats::fourcc;

const OFFER_STRING_GROUP: u16 = 0x2740;

#[derive(Component)]
struct OfferSheetRoot;

#[derive(Component)]
struct OfferSheetView {
    offer: Entity,
    purchase_title: Entity,
    unit: Entity,
    no_offer: Entity,
    merchant_capacity: Entity,
    amount: Entity,
    icon: Entity,
    stop_buying: Entity,
}

#[derive(Component)]
struct OfferSheetNotice(String);

pub(crate) struct OfferSheetPlugin;

impl Plugin for OfferSheetPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::OfferSheet),
            (enter_offer_sheet_phase, spawn_offer_sheet, bind_offer_sheet).chain(),
        )
        .add_systems(
            Update,
            render_offer_sheet.run_if(in_state(AppState::OfferSheet)),
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
    mut assets: RetailUiAssets,
) {
    let Some(root) = root else {
        return;
    };
    let root = *root;
    let view = bind_offer_sheet_controls(&mut commands, root, &tree);
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
    // HoverHelpBar + recovered curs / offe/purT/unit/noof/purc/mCap/info styles
    // come from codegen / Windows deltas (including STR# 0x2740 index 10 on info).
    bind_game_status_display(&mut commands, &mut assets, root, &tree);
    commands.entity(root).insert(view);
}

fn bind_offer_sheet_controls(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
) -> OfferSheetView {
    let accept = tree.find(root, fourcc!("acce"));
    let reject = tree.find(root, fourcc!("reje"));
    let purc = tree.find(root, fourcc!("purc"));
    let nomo = tree.find(root, fourcc!("nomo"));
    commands.entity(accept).remove::<InteractionDisabled>();
    commands.entity(reject).remove::<InteractionDisabled>();
    bind_offer_answer(commands, accept, true);
    bind_offer_answer(commands, reject, false);
    commands
        .entity(nomo)
        .remove::<(Checked, InteractionDisabled)>();
    commands.entity(purc).insert((
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
    let view = OfferSheetView {
        offer: tree.find(root, fourcc!("offe")),
        purchase_title: tree.find(root, fourcc!("purT")),
        unit: tree.find(root, fourcc!("unit")),
        no_offer: tree.find(root, fourcc!("noof")),
        merchant_capacity: tree.find(root, fourcc!("mCap")),
        amount: purc,
        icon: tree.find(root, fourcc!("icon")),
        stop_buying: nomo,
    };
    for entity in [
        view.offer,
        view.purchase_title,
        view.unit,
        view.no_offer,
        view.merchant_capacity,
    ] {
        commands.entity(entity).insert(Text::default());
    }
    commands.entity(view.icon).insert(ImageNode::default());
    view
}

fn render_offer_sheet(
    views: Query<Ref<OfferSheetView>>,
    mut commands: Commands,
    mut amounts: Query<&mut EditableText>,
    mut texts: Query<&mut Text>,
    mut images: Query<&mut ImageNode>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    checked: Query<(), With<Checked>>,
) {
    let Ok(view) = views.single() else {
        return;
    };
    if !session.is_changed() && !view.is_added() {
        return;
    }
    let Some(offer) = session.game.pending_trade_offer() else {
        return;
    };
    let offering = session
        .game
        .nations()
        .display_name(offer.seller)
        .unwrap_or("")
        .to_owned();
    let commodity = assets.string(offer.commodity.resource().name_string());
    let amount = offer.amount.to_string();
    let price = format_currency(i32::from(offer.price));
    texts.get_mut(view.offer).expect("bound offer text").0 = fill_brackets(
        &assets.get_string(OFFER_STRING_GROUP, 0xc),
        &[&offering, &amount, &commodity, &price],
    );
    texts
        .get_mut(view.purchase_title)
        .expect("bound purchase title")
        .0 = assets.get_string(OFFER_STRING_GROUP, 0xe);
    texts.get_mut(view.unit).expect("bound unit label").0 =
        assets.get_string(OFFER_STRING_GROUP, 0xf);
    texts
        .get_mut(view.no_offer)
        .expect("bound no-offer label")
        .0 = fill_brackets(&assets.get_string(OFFER_STRING_GROUP, 0xf), &[&commodity]);

    let nation = session.active_major_nation();
    texts
        .get_mut(view.merchant_capacity)
        .expect("bound merchant capacity")
        .0 = session
        .game
        .nations()
        .major(nation)
        .economy
        .capacities
        .available_merchant
        .to_string();

    if let Ok(mut editable) = amounts.get_mut(view.amount) {
        *editable = EditableText {
            max_characters: Some(6),
            allow_newlines: false,
            ..EditableText::new(offer.amount.to_string())
        };
    }
    images.get_mut(view.icon).expect("bound offer icon").image =
        assets.keyed_picture(offer.commodity.resource().material_picture(), 0x10);
    if checked.get(view.stop_buying).is_ok() {
        commands.entity(view.stop_buying).remove::<Checked>();
    }
}

#[allow(clippy::too_many_arguments)]
fn bind_offer_answer(commands: &mut Commands, button: Entity, accept: bool) {
    commands.entity(button).observe(
        move |_: On<Activate>,
              views: Query<&OfferSheetView>,
              amounts: Query<&EditableText>,
              stop_buying: Query<Has<Checked>>,
              notices: Query<(), With<OfferSheetNotice>>,
              mut session: ResMut<GameSession>,
              mut next_state: ResMut<NextState<AppState>>,
              mut commands: Commands,
              assets: RetailUiAssets| {
            if !notices.is_empty() {
                return;
            }
            let Ok(view) = views.single() else {
                return;
            };
            let offer = session
                .game
                .pending_trade_offer()
                .expect("OfferSheet requires pending trade offer");
            let stop_buying = stop_buying.get(view.stop_buying).unwrap_or(false);
            let amount = if accept {
                let Some(amount) = amounts
                    .get(view.amount)
                    .ok()
                    .and_then(|editable| editable.value().to_string().parse::<i16>().ok())
                else {
                    spawn_offer_quantity_error(
                        &mut commands,
                        assets.get_string(OFFER_STRING_GROUP, 0x10),
                    );
                    return;
                };
                if amount < 0 || amount > offer.amount {
                    spawn_offer_quantity_error(
                        &mut commands,
                        assets.get_string(OFFER_STRING_GROUP, 0x10),
                    );
                    return;
                }
                amount
            } else {
                0
            };
            match session.game.answer_trade_offer(amount, stop_buying) {
                TurnStop::TradeOffer => {}
                stop => apply_turn_stop(stop, &mut next_state),
            }
        },
    );
}

fn spawn_offer_quantity_error(commands: &mut Commands, body: String) {
    spawn_linger_dialog(commands, OfferSheetNotice(body), AppState::OfferSheet);
}

fn bind_offer_sheet_notice(
    mut commands: Commands,
    notice: Option<Single<(Entity, &OfferSheetNotice), Added<OfferSheetNotice>>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    let Some(notice) = notice else {
        return;
    };
    let (root, body) = notice.into_inner();
    let linger = bind_linger_dialog(&mut commands, root, &tree);
    linger.set_body(&mut commands, &mut assets, &body.0);
    commands.entity(linger.okay).remove::<InteractionDisabled>();
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
        for tag in [
            fourcc!("acce"),
            fourcc!("reje"),
            fourcc!("purc"),
            fourcc!("nomo"),
            fourcc!("offe"),
            fourcc!("purT"),
            fourcc!("unit"),
            fourcc!("noof"),
            fourcc!("mCap"),
            fourcc!("icon"),
        ] {
            let mut entity = commands.spawn((RetailTag(tag), Node::default(), ChildOf(root)));
            if tag != fourcc!("icon") && tag != fourcc!("purc") && tag != fourcc!("nomo") {
                entity.insert(Text::default());
            }
            if tag == fourcc!("icon") {
                entity.insert(ImageNode::default());
            }
        }
    }

    fn bind_test_offer_sheet(
        mut commands: Commands,
        root: Option<Single<Entity, Added<OfferSheetRoot>>>,
        tree: RetailTree,
    ) {
        let Some(root) = root else {
            return;
        };
        let view = bind_offer_sheet_controls(&mut commands, *root, &tree);
        commands.entity(*root).insert(view);
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
        let view = app
            .world_mut()
            .query::<&OfferSheetView>()
            .iter(app.world())
            .next()
            .expect("offer sheet binds a semantic view");
        assert_ne!(view.amount, view.stop_buying);
    }
}
