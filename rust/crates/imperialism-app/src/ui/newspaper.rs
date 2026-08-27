use super::GamePreferences;
use super::fill_brackets;
use super::generated;
use super::retail::{RetailTree, RetailUiAssets};
use super::session::{GameSession, apply_turn_stop};
use crate::{AppState, RetailAssetsResource};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::{NewsTable, RetailTextStylePreset, fourcc};

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
            (spawn_newspaper, bind_newspaper).chain(),
        );
    }
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
        .insert(ActivateOnPress)
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
    let (feature_font, feature_layout, feature_line, _) = assets
        .text_style(RetailTextStylePreset::explicit(2, 0, 14, 2))
        .expect("newspaper feature headline style");
    let (event_font, event_layout, event_line, _) = assets
        .text_style(RetailTextStylePreset::explicit(2, 1, 14, 2))
        .expect("newspaper event headline style");
    let (body_font, body_layout, body_line, _) = assets
        .text_style(RetailTextStylePreset::explicit(2, 0, 12, 2))
        .expect("newspaper body style");

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
