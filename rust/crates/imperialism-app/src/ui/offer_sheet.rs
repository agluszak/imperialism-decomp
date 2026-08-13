use super::format_currency;
use super::game_shell::project_date_and_treasury;
use super::generated;
use super::hover_help::{HoverHelpBarStyle, bind_hover_help_bar, get_string};
use super::random_setup::GameSession;
use super::retail::{ModalDialog, RetailTag, RetailUiAssets, find_descendant};
use crate::AppState;
use bevy::input_focus::AutoFocus;
use bevy::input_focus::tab_navigation::TabGroup;
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

#[derive(Component)]
struct OfferSheetScreen {
    posed: Option<PendingTradeOffer>,
    posed_amount: i16,
    purc: Entity,
    nomo: Entity,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum OfferSheetAction {
    Accept,
    Reject,
}

#[derive(Component)]
struct PurchaseAmountField;

#[derive(Component)]
struct OfferSheetNotice;

#[derive(Component)]
struct OfferSheetNoticeBody(String);

#[derive(Resource)]
struct PendingOfferQuantityError;

#[derive(Component)]
struct OfferSheetNoticeClose(Entity);

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
            (
                pose_offer_sheet,
                spawn_offer_quantity_error,
                bind_offer_sheet_notice,
            )
                .chain()
                .run_if(in_state(AppState::OfferSheet)),
        )
        .add_observer(on_offer_sheet_activate)
        .add_observer(on_offer_sheet_notice_activate);
    }
}

fn enter_offer_sheet_phase(
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if session.0.pending_trade_offer().is_some() {
        return;
    }
    if session.0.begin_trade_phase() == TradeProgress::Complete {
        next_state.set(AppState::StrategicMap);
    }
}

fn spawn_offer_sheet(mut commands: Commands, session: Res<GameSession>) {
    if session.0.pending_trade_offer().is_none() {
        return;
    }
    let root = commands.spawn_scene(generated::flagview_8500()).id();
    commands
        .entity(root)
        .insert((OfferSheetRoot, DespawnOnExit(AppState::OfferSheet)));
}

fn bind_offer_sheet(
    mut commands: Commands,
    root: Option<Single<Entity, Added<OfferSheetRoot>>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut nodes: Query<&mut Node>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let Some(root) = root else {
        return;
    };
    let root = *root;
    bind_offer_sheet_controls(&mut commands, root, &children, &tags, &session);
    for tag in [
        fourcc!("ForM"),
        fourcc!("tabs"),
        fourcc!("quer"),
        fourcc!("done"),
    ] {
        commands
            .entity(find_descendant(root, tag, &children, &tags))
            .insert(InteractionDisabled);
    }
    let curs = find_descendant(root, fourcc!("curs"), &children, &tags);
    bind_hover_help_bar(
        &mut commands,
        &mut assets,
        curs,
        &mut nodes
            .get_mut(curs)
            .expect("offer-sheet hover-help bar has Node"),
        HoverHelpBarStyle::MAIN_MENU,
    );
    project_date_and_treasury(&mut commands, &mut assets, root, &children, &tags, &session);
}

fn bind_offer_sheet_controls(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    session: &GameSession,
) {
    let offer = session
        .0
        .pending_trade_offer()
        .expect("Offer Sheet bind requires a pending trade offer");
    let accept = find_descendant(root, fourcc!("acce"), children, tags);
    let reject = find_descendant(root, fourcc!("reje"), children, tags);
    let purc = find_descendant(root, fourcc!("purc"), children, tags);
    let nomo = find_descendant(root, fourcc!("nomo"), children, tags);
    commands
        .entity(accept)
        .insert((OfferSheetAction::Accept, ActivateOnPress))
        .remove::<InteractionDisabled>();
    commands
        .entity(reject)
        .insert((OfferSheetAction::Reject, ActivateOnPress))
        .remove::<InteractionDisabled>();
    commands
        .entity(nomo)
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
            ..EditableText::new(offer.amount.to_string())
        },
    ));
    commands.entity(root).insert(OfferSheetScreen {
        posed: None,
        posed_amount: offer.amount,
        purc,
        nomo,
    });
}

#[allow(clippy::too_many_arguments)]
fn pose_offer_sheet(
    mut commands: Commands,
    mut screens: Query<&mut OfferSheetScreen, With<OfferSheetRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut amounts: Query<&mut EditableText, With<PurchaseAmountField>>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    roots: Query<Entity, With<OfferSheetRoot>>,
) {
    let Some(offer) = session.0.pending_trade_offer() else {
        return;
    };
    let Ok(root) = roots.single() else {
        return;
    };
    let Ok(mut screen) = screens.single_mut() else {
        return;
    };
    if screen.posed == Some(offer) {
        return;
    }
    screen.posed = Some(offer);
    screen.posed_amount = offer.amount;
    let purc = screen.purc;
    apply_offer_sheet_pose(
        &mut commands,
        &mut assets,
        root,
        &children,
        &tags,
        &mut amounts,
        purc,
        &session,
        offer,
    );
}

#[allow(clippy::too_many_arguments)]
fn apply_offer_sheet_pose(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    amounts: &mut Query<&mut EditableText, With<PurchaseAmountField>>,
    purc: Entity,
    session: &GameSession,
    offer: PendingTradeOffer,
) {
    let offering = session
        .0
        .nations()
        .display_name(offer.seller)
        .unwrap_or("")
        .to_owned();
    let commodity = get_string(assets, 0x2711, offer.commodity as i16);
    let amount = offer.amount.to_string();
    let price = format_currency(i32::from(offer.price));
    set_text(
        commands,
        find_descendant(root, fourcc!("offe"), children, tags),
        fill_brackets(
            &get_string(assets, OFFER_STRING_GROUP, 0xc),
            &[&offering, &amount, &commodity, &price],
        ),
    );
    set_text(
        commands,
        find_descendant(root, fourcc!("purT"), children, tags),
        get_string(assets, OFFER_STRING_GROUP, 0xe),
    );
    set_text(
        commands,
        find_descendant(root, fourcc!("unit"), children, tags),
        get_string(assets, OFFER_STRING_GROUP, 0xf),
    );
    set_text(
        commands,
        find_descendant(root, fourcc!("noof"), children, tags),
        fill_brackets(&get_string(assets, OFFER_STRING_GROUP, 0xf), &[&commodity]),
    );

    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Offer Sheet requires an active major nation");
    set_text(
        commands,
        find_descendant(root, fourcc!("mCap"), children, tags),
        session
            .0
            .nations()
            .major(nation)
            .economy
            .capacities
            .available_merchant
            .to_string(),
    );

    if let Ok(mut editable) = amounts.get_mut(purc) {
        *editable = EditableText {
            max_characters: Some(6),
            allow_newlines: false,
            ..EditableText::new(offer.amount.to_string())
        };
    }

    if let Ok(icon) = assets.picture(PictureId::new(COMMODITY_ICON_BASE + offer.commodity as i16)) {
        commands
            .entity(find_descendant(root, fourcc!("icon"), children, tags))
            .insert(ImageNode::new(icon));
    }

    commands
        .entity(find_descendant(root, fourcc!("nomo"), children, tags))
        .remove::<Checked>();
    project_date_and_treasury(commands, assets, root, children, tags, session);
}

fn set_text(commands: &mut Commands, entity: Entity, value: String) {
    commands.entity(entity).insert(Text::new(value));
}

#[allow(clippy::too_many_arguments)]
fn on_offer_sheet_activate(
    activate: On<Activate>,
    actions: Query<&OfferSheetAction>,
    screens: Query<&OfferSheetScreen>,
    amounts: Query<&EditableText, With<PurchaseAmountField>>,
    checked: Query<Has<Checked>>,
    notices: Query<(), With<OfferSheetNotice>>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    if !notices.is_empty() {
        return;
    }
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let Ok(screen) = screens.single() else {
        return;
    };
    let stop_buying = checked.get(screen.nomo).unwrap_or(false);
    let amount = match action {
        OfferSheetAction::Reject => 0,
        OfferSheetAction::Accept => {
            let Some(amount) = amounts
                .get(screen.purc)
                .ok()
                .and_then(|editable| editable.value().to_string().parse::<i16>().ok())
            else {
                commands.insert_resource(PendingOfferQuantityError);
                return;
            };
            if amount < 0 || amount > screen.posed_amount {
                commands.insert_resource(PendingOfferQuantityError);
                return;
            }
            amount
        }
    };
    match session.0.reply_to_trade_offer(amount, stop_buying) {
        TradeProgress::Complete => next_state.set(AppState::StrategicMap),
        TradeProgress::Offer(_) => {}
    }
}

fn spawn_offer_quantity_error(
    mut commands: Commands,
    pending: Option<Res<PendingOfferQuantityError>>,
    assets: RetailUiAssets,
) {
    if pending.is_none() {
        return;
    }
    commands.remove_resource::<PendingOfferQuantityError>();
    let root = commands.spawn_scene(generated::linger_2020()).id();
    commands.entity(root).insert((
        OfferSheetNotice,
        OfferSheetNoticeBody(get_string(&assets, OFFER_STRING_GROUP, 0x10)),
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::OfferSheet),
    ));
}

fn bind_offer_sheet_notice(
    mut commands: Commands,
    notice: Option<Single<(Entity, &OfferSheetNoticeBody), Added<OfferSheetNotice>>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
) {
    let Some(notice) = notice else {
        return;
    };
    let (root, body) = notice.into_inner();
    let info = find_descendant(root, fourcc!("info"), &children, &tags);
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail offer-sheet notice body style");
    commands.entity(info).insert((
        Text::new(body.0.clone()),
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(0)),
    ));
    let okay = find_descendant(root, fourcc!("okay"), &children, &tags);
    commands
        .entity(okay)
        .insert((OfferSheetNoticeClose(root), ActivateOnPress))
        .remove::<InteractionDisabled>();
}

fn on_offer_sheet_notice_activate(
    activate: On<Activate>,
    closes: Query<&OfferSheetNoticeClose>,
    mut commands: Commands,
) {
    let Ok(close) = closes.get(activate.entity) else {
        return;
    };
    commands.entity(close.0).despawn();
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

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::state::app::StatesPlugin;
    use imperialism_formats::{LegacyGameStateContext, LegacySaveV62, peek_save_header};

    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

    fn fixture_state() -> GameState {
        let selected_nation = peek_save_header(BEGINNING_OF_GAME)
            .and_then(|header| NationId::try_new(header.active_nation))
            .unwrap_or(NationId::new(0));
        LegacySaveV62::parse(BEGINNING_OF_GAME).game_state(LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 0,
            selected_nation,
        })
    }

    fn test_app(state: GameState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(StatesPlugin)
            .insert_resource(GameSession(state))
            .insert_state(AppState::OfferSheet)
            .add_systems(OnEnter(AppState::OfferSheet), enter_offer_sheet_phase)
            .add_systems(
                OnEnter(AppState::OfferSheet),
                (spawn_test_offer_sheet, bind_test_offer_sheet).chain(),
            )
            .add_observer(on_offer_sheet_activate);
        app
    }

    fn spawn_test_offer_sheet(mut commands: Commands, session: Res<GameSession>) {
        if session.0.pending_trade_offer().is_none() {
            return;
        }
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
        children: Query<&Children>,
        tags: Query<&RetailTag>,
        session: Res<GameSession>,
    ) {
        let Some(root) = root else {
            return;
        };
        bind_offer_sheet_controls(&mut commands, *root, &children, &tags, &session);
    }

    #[test]
    fn entering_the_offer_sheet_either_binds_a_pending_offer_or_leaves() {
        let mut app = test_app(fixture_state());
        app.update();
        let pending = app
            .world()
            .resource::<GameSession>()
            .0
            .pending_trade_offer();
        if pending.is_some() {
            let bound = app
                .world_mut()
                .query::<&OfferSheetAction>()
                .iter(app.world())
                .copied()
                .collect::<Vec<_>>();
            assert!(bound.contains(&OfferSheetAction::Accept));
            assert!(bound.contains(&OfferSheetAction::Reject));
            let reject = app
                .world_mut()
                .query_filtered::<Entity, With<OfferSheetAction>>()
                .iter(app.world())
                .find(|entity| {
                    app.world().get::<OfferSheetAction>(*entity) == Some(&OfferSheetAction::Reject)
                })
                .expect("reject is bound");
            app.world_mut()
                .commands()
                .trigger(Activate { entity: reject });
            app.world_mut().flush();
            app.update();
        } else {
            assert_eq!(
                app.world().resource::<State<AppState>>().get(),
                &AppState::StrategicMap
            );
        }
    }

    #[test]
    fn fill_brackets_expands_numbered_slots() {
        assert_eq!(
            fill_brackets(
                "[1] offers [2] [3] at [4]",
                &["Spain", "4", "clothing", "$10"]
            ),
            "Spain offers 4 clothing at $10"
        );
    }
}
