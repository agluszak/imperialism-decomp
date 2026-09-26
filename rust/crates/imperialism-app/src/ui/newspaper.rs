use super::GamePreferences;
use super::fill_brackets;
use super::generated;
use super::linger::{bind_linger_dialog, spawn_linger_dialog};
use super::retail::{RetailTree, RetailUiAssets};
use super::session::{GameSession, apply_turn_stop};
use super::window::{bind_modal_keys, dismiss_on_activate, spawn_modal_window};
use crate::media::RetailAudioAssets;
use crate::{AppState, RetailAssetsResource};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Activate;
use imperialism_core::*;
use imperialism_formats::{
    NewsTable, PictureId, RetailTextStylePreset, SoundId, StringGroup, fourcc,
};
use std::collections::VecDeque;

const COLUMN_X: [f32; 3] = [24.0, 226.0, 428.0];
const COLUMN_WIDTH: f32 = 188.0;
const STORY_TOP: f32 = 80.0;
const STORY_HEIGHT: f32 = 396.0;

#[derive(Component)]
struct NewspaperRoot;

pub(crate) struct NewspaperPlugin;

impl Plugin for NewspaperPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::Newspaper),
            (spawn_newspaper, bind_newspaper, queue_newspaper_notices).chain(),
        )
        .add_systems(
            Update,
            (
                spawn_newspaper_notice_if_pending,
                bind_status_prompt_notice,
                bind_turn_summary_notice,
            )
                .chain()
                .run_if(in_state(AppState::Newspaper)),
        );
    }
}

/// Modal notices retail shows over the newspaper
/// (`THelpMgr::HandlePostDispatchTurnStateEventUpdates`), in dispatch order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum NewspaperNotice {
    StatusPrompt(PendingStatusPrompt),
    TurnSummary(PreviousTurnSummary),
}

#[derive(Resource, Default)]
struct NewspaperNotices(VecDeque<NewspaperNotice>);

#[derive(Component)]
struct NewspaperNoticeDialog;

#[derive(Component)]
struct StatusPromptNotice(PendingStatusPrompt);

#[derive(Component)]
struct TurnSummaryNotice(PreviousTurnSummary);

fn queue_newspaper_notices(mut commands: Commands, session: Res<GameSession>) {
    commands.insert_resource(NewspaperNotices(newspaper_notices(&session.game)));
}

fn newspaper_notices(state: &GameState) -> VecDeque<NewspaperNotice> {
    let mut notices: VecDeque<NewspaperNotice> = state
        .pending()
        .status_prompts
        .iter()
        .copied()
        .map(NewspaperNotice::StatusPrompt)
        .collect();
    if let Some(nation) = MajorNationId::from_nation(state.turn().active_nation)
        && let Some(summary) = state.previous_turn_summary(nation)
    {
        notices.push_back(NewspaperNotice::TurnSummary(summary));
    }
    notices
}

fn spawn_newspaper_notice_if_pending(
    mut commands: Commands,
    notices: Option<Res<NewspaperNotices>>,
    existing: Query<(), With<NewspaperNoticeDialog>>,
) {
    let Some(notice) = notices.as_deref().and_then(|notices| notices.0.front()) else {
        return;
    };
    if !existing.is_empty() {
        return;
    }
    match notice {
        NewspaperNotice::StatusPrompt(prompt) => {
            let (modal, _window) = spawn_modal_window(&mut commands, generated::minister_9480());
            commands.entity(modal).insert((
                NewspaperNoticeDialog,
                StatusPromptNotice(*prompt),
                DespawnOnExit(AppState::Newspaper),
            ));
        }
        NewspaperNotice::TurnSummary(summary) => {
            let modal = spawn_linger_dialog(
                &mut commands,
                TurnSummaryNotice(summary.clone()),
                AppState::Newspaper,
            );
            commands.entity(modal).insert(NewspaperNoticeDialog);
        }
    }
}

fn on_newspaper_notice_dismiss(_activate: On<Activate>, mut notices: ResMut<NewspaperNotices>) {
    notices
        .0
        .pop_front()
        .expect("newspaper notice dismissal requires a pending notice");
}

const MINISTER_REWARD_COAT: PictureId = PictureId::new(0x251c);
const MINISTER_REWARD_GOLD: PictureId = PictureId::new(0x252a);
const MINISTER_MESSAGE_GOLD: PictureId = PictureId::new(0x24cd);
const TURN_OVERLAY_TEXT: StringGroup = StringGroup::new(0x273a);
const MINISTER_TITLES: StringGroup = StringGroup::new(0x2749);
const RESOURCE_NAMES: StringGroup = StringGroup::new(0x2716);

/// `TViewMgr::BuildAndShowTurnOverlayByMode` case table: body text, `rewa` picture,
/// and the dialog context word that selects the `DLOG` gold plate.
fn status_prompt_presentation(
    assets: &RetailUiAssets,
    state: &GameState,
    nation: MajorNationId,
    prompt: PendingStatusPrompt,
) -> (String, PictureId, i16) {
    let mode = prompt.kind as usize as u16;
    let payload = prompt.payload;
    let plain = |assets: &RetailUiAssets| assets.string(TURN_OVERLAY_TEXT.entry(mode));
    let templated = |assets: &RetailUiAssets, argument: &str| {
        fill_brackets(&assets.string(TURN_OVERLAY_TEXT.entry(mode)), &[argument])
    };
    let nation_name = |payload: i16| {
        u8::try_from(payload)
            .ok()
            .and_then(NationId::try_new)
            .and_then(|nation| state.nations().display_name(nation))
            .unwrap_or_default()
            .to_owned()
    };
    let city_name = |payload: i16| {
        u16::try_from(payload)
            .ok()
            .and_then(ProvinceId::try_new)
            .map(|province| state.map().provinces[province].name.clone())
            .unwrap_or_default()
    };
    let mode_picture = PictureId::new(0x2508).offset(payload_mode(mode));
    match prompt.kind {
        PendingActionKind::NavyGrowthReward => {
            let ship_name = assets.string(RESOURCE_NAMES.entry(payload_mode_from(payload)));
            let picture = match payload {
                8 => PictureId::new(0x2515),
                9 => PictureId::new(0x2516),
                0xc => PictureId::new(0x2517),
                _ => PictureId::new(0x2508),
            };
            (templated(assets, &ship_name), picture, 1)
        }
        PendingActionKind::ArmyGrowthReward => {
            let general = state.technology().selected_capability_slots[nation]
                [ArmyUnitCategory::Generals]
                .retail();
            let picture = match general {
                0x1c => PictureId::new(0x2518),
                0x1d => PictureId::new(0x2519),
                _ => PictureId::new(0x2509),
            };
            (plain(assets), picture, 1)
        }
        PendingActionKind::ShipyardIronworkingUpgrade
        | PendingActionKind::ConquestMonumentArmory => (plain(assets), mode_picture, 1),
        PendingActionKind::ConqueredCapitalArmoryUpgrade => (
            templated(assets, &nation_name(payload)),
            PictureId::new(0x250e),
            1,
        ),
        PendingActionKind::ColonyMonumentMerchantCapacity => (
            templated(assets, &nation_name(payload)),
            PictureId::new(0x2512),
            1,
        ),
        PendingActionKind::OverseasDeveloperReward => (plain(assets), PictureId::new(0x250a), 0),
        PendingActionKind::AnnexedGreatPowerCapitalExpansion
        | PendingActionKind::CouncilLeadMonument => (plain(assets), mode_picture, 0),
        PendingActionKind::VillageDevelopment | PendingActionKind::TownDevelopment => {
            (templated(assets, &city_name(payload)), mode_picture, 2)
        }
        PendingActionKind::UniversityExpansion => {
            let picture = if payload == -1 {
                PictureId::new(0x251a)
            } else {
                PictureId::new(0x250f)
            };
            (plain(assets), picture, 2)
        }
        PendingActionKind::RailyardExpansion => (plain(assets), PictureId::new(0x2510), 2),
    }
}

fn payload_mode(mode: u16) -> i16 {
    i16::try_from(mode).expect("pending action kind index fits a retail word")
}

fn payload_mode_from(payload: i16) -> u16 {
    u16::try_from(payload).unwrap_or_default()
}

/// `RunNationInfoModalAndReturnNonCancel` reward-dialog sound per prompt kind.
fn status_prompt_sound(kind: PendingActionKind) -> SoundId {
    const OVERLAY_SFX: [u16; 13] = [
        0xbcc, 0xbcd, 0xbce, 0xbcf, 0xbd0, 0xbc2, 0xbd2, 0xbd3, 0xbd5, 0xbd6, 0xbd7, 0xbd7, 0xbd9,
    ];
    SoundId::new(OVERLAY_SFX[kind as usize])
}

fn bind_status_prompt_notice(
    mut commands: Commands,
    notice: Option<Single<(Entity, &StatusPromptNotice), Added<StatusPromptNotice>>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    mut audio: RetailAudioAssets,
) {
    let Some(notice) = notice else {
        return;
    };
    let (root, notice) = notice.into_inner();
    let prompt = notice.0;
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("newspaper requires an active major nation");
    let (body, reward, context) =
        status_prompt_presentation(&assets, &session.game, nation, prompt);
    let gold = assets.picture(MINISTER_REWARD_GOLD.offset(context));
    commands
        .entity(tree.find(root, fourcc!("DLOG")))
        .insert(ImageNode::new(gold));
    let reward = assets.picture(reward);
    commands
        .entity(tree.find(root, fourcc!("rewa")))
        .insert(ImageNode::new(reward));
    let coat = assets.picture(MINISTER_REWARD_COAT.offset(i16::from(nation.get())));
    commands
        .entity(tree.find(root, fourcc!("coat")))
        .insert(ImageNode::new(coat));
    let (font, layout, line_height, _) =
        assets.text_style(RetailTextStylePreset::explicit(1, 0, 12, 0));
    commands.entity(tree.find(root, fourcc!("info"))).insert((
        Text::new(body.replace('\r', "\n")),
        Label,
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(0)),
    ));
    let okay = tree.find(root, fourcc!("okay"));
    dismiss_on_activate(&mut commands, okay, root);
    bind_modal_keys(&mut commands, root, Some(okay), None);
    commands
        .entity(okay)
        .remove::<InteractionDisabled>()
        .observe(on_newspaper_notice_dismiss);
    audio.play(&mut commands, status_prompt_sound(prompt.kind));
}

/// `TGreatPower::BuildGreatPowerTurnMessageSummaryAndDispatch` text composition.
fn turn_summary_text(assets: &RetailUiAssets, summary: &PreviousTurnSummary) -> String {
    let mut text = assets.string(MINISTER_TITLES.entry(9));
    for entry in &summary.entries {
        let (order_kind, payload, count) = match *entry {
            TurnSummary::MilitaryRecruit {
                unit_type, count, ..
            } => (3, i16::from(unit_type.retail()), count),
            TurnSummary::Retail {
                order_kind,
                payload,
                flags,
                ..
            } => (order_kind, payload, flags),
        };
        let entry_index = payload_mode_from(payload);
        let plural = count > 1;
        let entry_text = match order_kind {
            0 | 1 => assets.get_string(if plural { 0x271a } else { 0x2716 }, entry_index),
            2 => assets.get_string(if plural { 0x2748 } else { 0x2718 }, entry_index),
            3 => {
                if plural {
                    fill_brackets(
                        &assets.get_string(0x2747, 1),
                        &[&assets.get_string(0x2717, entry_index)],
                    )
                } else if payload == 0x2508 {
                    assets.get_string(0x2744, 2)
                } else if (0x1b..=0x1d).contains(&payload) {
                    assets.get_string(0x2744, 0)
                } else {
                    fill_brackets(
                        &assets.get_string(0x2747, 0),
                        &[&assets.get_string(0x2717, entry_index)],
                    )
                }
            }
            _ => String::new(),
        };
        text.push('\n');
        text.push_str("     ");
        text.push_str(&count.to_string());
        text.push(' ');
        text.push_str(&entry_text);
    }
    if let Some(capacity) = summary.aid_capacity {
        text.push_str("\n\n");
        text.push_str(&fill_brackets(
            &assets.get_string(0x2739, 1),
            &[&capacity.to_string()],
        ));
    }
    text
}

fn bind_turn_summary_notice(
    mut commands: Commands,
    notice: Option<Single<(Entity, &TurnSummaryNotice), Added<TurnSummaryNotice>>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    mut audio: RetailAudioAssets,
) {
    let Some(notice) = notice else {
        return;
    };
    let (root, notice) = notice.into_inner();
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("newspaper requires an active major nation");
    let linger = bind_linger_dialog(&mut commands, root, &tree);
    // `ModalMessage(text, pos, overlayMode = 2)`: title `0x2749[3]` filled with `0x2749[2]`.
    let title = fill_brackets(
        &assets.string(MINISTER_TITLES.entry(3)),
        &[&assets.string(MINISTER_TITLES.entry(2))],
    );
    linger.set_title(&mut commands, &mut assets, title);
    let body = turn_summary_text(&assets, &notice.0);
    linger.set_body(&mut commands, &mut assets, body);
    let gold = assets.picture(MINISTER_MESSAGE_GOLD.offset(2 * 2));
    commands
        .entity(tree.find(root, fourcc!("DLOG")))
        .insert(ImageNode::new(gold));
    let coat = assets.picture(MINISTER_REWARD_COAT.offset(i16::from(nation.get())));
    commands.entity(linger.coat).insert(ImageNode::new(coat));
    commands
        .entity(linger.okay)
        .remove::<InteractionDisabled>()
        .observe(on_newspaper_notice_dismiss);
    commands.entity(linger.cancel).insert(Visibility::Hidden);
    audio.play(&mut commands, SoundId::new(0xbcb));
}

fn spawn_newspaper(mut commands: Commands) {
    let root = commands.spawn_scene(generated::flagview_8451()).id();
    commands
        .entity(root)
        .insert((NewspaperRoot, DespawnOnExit(AppState::Newspaper)));
}

fn bind_newspaper(
    mut commands: Commands,
    root: Single<Entity, Added<NewspaperRoot>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
) {
    let root = *root;
    commands
        .entity(tree.find(root, fourcc!("date")))
        .insert(Text::new(project_newspaper_date(
            &assets,
            session.game.turn().economic_turn,
        )));
    commands
        .entity(tree.find(root, fourcc!("spec")))
        .insert(Text::new(newspaper_spec_text(&assets, &session.game)));
    fill_newspaper_stories(
        &mut commands,
        &mut assets,
        root,
        &tree,
        &session.game,
        retail.assets().news_table(),
    );
    commands
        .entity(tree.find(root, fourcc!("end ")))
        .observe(on_newspaper_activate);
}

fn project_newspaper_date(assets: &RetailUiAssets, economic_turn: i32) -> String {
    let season = assets.get_string(10_000, (economic_turn % 4) as u16);
    format!("{season}, {}", 1815 + economic_turn / 4)
}

fn newspaper_spec_text(assets: &RetailUiAssets, state: &GameState) -> String {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("newspaper requires an active major nation");
    let (template, value) = match state.turn().economic_turn % 4 {
        0 => (
            assets.get_string(0x275e, 0),
            state
                .nations()
                .major(nation)
                .economy
                .escalation_counter
                .to_string(),
        ),
        1 => {
            let sum = (0..TradeCommodity::LENGTH)
                .map(|index| {
                    let commodity = TradeCommodity::from_retail(index as i16)
                        .expect("market index is a retail trade commodity");
                    let row = &state.market().rows[commodity];
                    row.price - row.previous_price
                })
                .sum::<i32>();
            let change = sum / TradeCommodity::LENGTH as i32;
            (
                assets.get_string(0x275e, 1),
                if change > 0 {
                    format!("+{change}")
                } else {
                    change.to_string()
                },
            )
        }
        2 => (
            assets.get_string(0x275e, 2),
            state.newspaper_commodity_power(nation).to_string(),
        ),
        3 => (
            assets.get_string(0x275e, 3),
            state.newspaper_military_power(nation).to_string(),
        ),
        _ => unreachable!("economic turn modulo four is in range"),
    };
    fill_brackets(&template, &[&value])
}

fn fill_newspaper_stories(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
    news: &NewsTable,
) {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("newspaper requires an active major nation");
    let Some(page) = state.news().pages[nation].as_ref() else {
        return;
    };
    let main = tree.find(root, fourcc!("main"));
    let (feature_font, feature_layout, feature_line, _) =
        assets.text_style(RetailTextStylePreset::explicit(2, 0, 14, 2));
    let (event_font, event_layout, event_line, _) =
        assets.text_style(RetailTextStylePreset::explicit(2, 1, 14, 2));
    let (body_font, body_layout, body_line, _) =
        assets.text_style(RetailTextStylePreset::explicit(2, 0, 12, 2));

    let columns = COLUMN_X.map(|left| {
        commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(left),
                    top: Val::Px(STORY_TOP),
                    width: Val::Px(COLUMN_WIDTH),
                    height: Val::Px(STORY_HEIGHT),
                    flex_direction: FlexDirection::Column,
                    ..default()
                },
                ChildOf(main),
            ))
            .id()
    });
    for (column, stories) in page.stories.iter().enumerate() {
        for story in stories.iter().flatten() {
            let tokens = story_tokens(assets, state, story);
            let token_refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
            let headline = fill_brackets(news.headline(story.template_index), &token_refs);
            let body = fill_brackets(news.body(story.template_index), &token_refs);
            if story.feature {
                spawn_story_text(
                    commands,
                    columns[column],
                    headline,
                    feature_font.clone(),
                    feature_layout,
                    feature_line,
                );
            } else {
                spawn_story_text(
                    commands,
                    columns[column],
                    headline,
                    event_font.clone(),
                    event_layout,
                    event_line,
                );
            }
            spawn_story_text(
                commands,
                columns[column],
                body,
                body_font.clone(),
                body_layout,
                body_line,
            );
        }
    }
}

fn spawn_story_text(
    commands: &mut Commands,
    parent: Entity,
    text: String,
    font: TextFont,
    layout: TextLayout,
    line_height: LineHeight,
) {
    commands.spawn((
        Node {
            width: Val::Percent(100.0),
            padding: UiRect::all(Val::Px(4.0)),
            flex_shrink: 0.0,
            ..default()
        },
        Text::new(text),
        font,
        layout,
        line_height,
        TextColor(Color::BLACK),
        ChildOf(parent),
    ));
}

fn story_tokens(assets: &RetailUiAssets, state: &GameState, story: &NewsStory) -> [String; 4] {
    std::array::from_fn(|index| match &story.arguments[index] {
        NewsArgument::NationMask { nations } => format_nation_names(assets, state, nations, false),
        NewsArgument::NationList { nations } => format_nation_names(assets, state, nations, true),
        NewsArgument::Province { province } => state.map().provinces[*province].name.clone(),
        NewsArgument::Zone { ordinal } => state.ocean().zones
            [usize::try_from(*ordinal).expect("newspaper ocean-zone ordinal is nonnegative")]
        .zone()
        .display_name
        .clone(),
        NewsArgument::Empty => String::new(),
    })
}

fn format_nation_names(
    assets: &RetailUiAssets,
    state: &GameState,
    nations: &NationTable<bool>,
    string_group: bool,
) -> String {
    let mut names = Vec::new();
    for nation in NationId::all() {
        if !nations[nation] {
            continue;
        }
        if string_group {
            names.push(assets.get_string(0x2711, u16::from(nation.get())));
        } else if let Some(name) = state.nations().display_name(nation) {
            names.push(name.to_owned());
        }
    }
    join_with_conjunction(assets, &names, string_group)
}

fn join_with_conjunction(assets: &RetailUiAssets, names: &[String], list_and: bool) -> String {
    match names.len() {
        0 => String::new(),
        1 => names[0].clone(),
        2 => {
            let conjunction = if list_and {
                " and ".to_owned()
            } else {
                assets.get_string(0x275e, 4)
            };
            format!("{}{}{}", names[0], conjunction, names[1])
        }
        _ => {
            let conjunction = if list_and {
                " and ".to_owned()
            } else {
                assets.get_string(0x275e, 4)
            };
            let mut out = String::new();
            for (index, name) in names.iter().enumerate() {
                if index == 0 {
                    out.push_str(name);
                } else if index == names.len() - 1 {
                    out.push_str(&conjunction);
                    out.push_str(name);
                } else {
                    out.push_str(", ");
                    out.push_str(name);
                }
            }
            out
        }
    }
}

fn on_newspaper_activate(
    _activate: On<Activate>,
    mut session: ResMut<GameSession>,
    preferences: Res<GamePreferences>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let stop = session
        .game
        .close_newspaper(preferences.music_volume() != 0);
    apply_turn_stop(stop, &mut next_state);
}
