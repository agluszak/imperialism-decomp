use super::fill_brackets;
use super::generated;
use super::hover_help::get_string;
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

#[derive(Component)]
struct NewspaperRoot;

#[derive(Component, Clone, Copy)]
enum NewspaperDisplay {
    Date,
    Spec,
}

pub(crate) struct NewspaperPlugin;

impl Plugin for NewspaperPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::Newspaper),
            (spawn_newspaper, bind_newspaper).chain(),
        )
        .add_systems(
            Update,
            project_newspaper_chrome
                .run_if(in_state(AppState::Newspaper).and_then(resource_exists::<GameSession>)),
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
    bind_newspaper_chrome(&mut commands, root, &tree);
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

fn bind_newspaper_chrome(commands: &mut Commands, root: Entity, tree: &RetailTree) {
    commands
        .entity(tree.find(root, fourcc!("date")))
        .insert((NewspaperDisplay::Date, Text::default()));
    commands
        .entity(tree.find(root, fourcc!("spec")))
        .insert((NewspaperDisplay::Spec, Text::default()));
}

fn project_newspaper_chrome(
    session: Res<GameSession>,
    added: Query<(), Added<NewspaperDisplay>>,
    assets: RetailUiAssets,
    mut displays: Query<(&NewspaperDisplay, &mut Text)>,
) {
    if super::projection_idle(&session, !added.is_empty()) {
        return;
    }
    let date = project_newspaper_date(&assets, session.game.turn().economic_turn);
    let spec = newspaper_spec_text(&assets, &session.game);
    for (display, mut text) in &mut displays {
        text.0 = match display {
            NewspaperDisplay::Date => date.clone(),
            NewspaperDisplay::Spec => spec.clone(),
        };
    }
}

fn project_newspaper_date(assets: &RetailUiAssets, economic_turn: i32) -> String {
    let season = get_string(assets, 10_000, (economic_turn % 4) as i16);
    format!("{season}, {}", 1815 + economic_turn / 4)
}

fn newspaper_spec_text(assets: &RetailUiAssets, state: &GameState) -> String {
    // FIXME: `TNewspaperView::StuffValues` switches on `economicTurn % 4`: 0 escalation,
    // 1 `GetMarketChange()`, 2/3 comparative-power rows. Only season 0 is implemented.
    // The opening paper is turn 1 after `AdvanceSeason`, so retail shows market change.
    if state.turn().economic_turn % 4 != 0 {
        return String::new();
    }
    let nation = NationId::as_major(state.turn().active_nation)
        .expect("newspaper requires an active major nation");
    let template = get_string(assets, 0x275e, 0);
    fill_brackets(
        &template,
        &[&state
            .nations()
            .major(nation)
            .economy
            .escalation_counter
            .to_string()],
    )
}

fn fill_newspaper_stories(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
    news: &NewsTable,
) {
    let nation = NationId::as_major(state.turn().active_nation)
        .expect("newspaper requires an active major nation");
    let Some(page) = state.news().pages[nation].as_ref() else {
        return;
    };
    let main = tree.find(root, fourcc!("main"));
    let (feature_font, feature_layout, feature_line, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 14,
            alignment: 2,
        })
        .expect("newspaper feature headline style");
    let (event_font, event_layout, event_line, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 1,
            point_size: 14,
            alignment: 2,
        })
        .expect("newspaper event headline style");
    let (body_font, body_layout, body_line, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 12,
            alignment: 2,
        })
        .expect("newspaper body style");

    for (column, stories) in page.stories.iter().enumerate() {
        let mut y = STORY_TOP;
        for story in stories.iter().flatten() {
            let tokens = story_tokens(assets, state, story);
            let token_refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
            let headline = fill_brackets(news.headline(story.template_index), &token_refs);
            let body = fill_brackets(news.body(story.template_index), &token_refs);
            if story.feature {
                y += spawn_story_text(
                    commands,
                    main,
                    column,
                    y,
                    headline,
                    feature_font.clone(),
                    feature_layout,
                    feature_line,
                );
            } else {
                y += spawn_story_text(
                    commands,
                    main,
                    column,
                    y,
                    headline,
                    event_font.clone(),
                    event_layout,
                    event_line,
                );
            }
            y += spawn_story_text(
                commands,
                main,
                column,
                y,
                body,
                body_font.clone(),
                body_layout,
                body_line,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_story_text(
    commands: &mut Commands,
    parent: Entity,
    column: usize,
    y: f32,
    text: String,
    font: TextFont,
    layout: TextLayout,
    line_height: LineHeight,
) -> f32 {
    let lines = text.lines().count().max(1) as f32;
    let height = match line_height {
        LineHeight::Px(px) => px * lines + 8.0,
        LineHeight::RelativeToFont(scale) => 16.0 * scale * lines + 8.0,
    };
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(COLUMN_X[column]),
            top: Val::Px(y),
            width: Val::Px(COLUMN_WIDTH),
            height: Val::Px(height),
            overflow: Overflow::clip(),
            ..default()
        },
        Text::new(text),
        font,
        layout,
        line_height,
        TextColor(Color::BLACK),
        ChildOf(parent),
    ));
    height
}

fn story_tokens(assets: &RetailUiAssets, state: &GameState, story: &NewsStory) -> [String; 4] {
    std::array::from_fn(|index| match &story.arguments[index] {
        NewsArgument::NationMask { nations } => format_nation_names(assets, state, nations, false),
        NewsArgument::NationList { nations } => format_nation_names(assets, state, nations, true),
        _ => String::new(),
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
            names.push(get_string(assets, 0x2711, i16::from(nation.retail_slot())));
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
                get_string(assets, 0x275e, 4)
            };
            format!("{}{}{}", names[0], conjunction, names[1])
        }
        _ => {
            let conjunction = if list_and {
                " and ".to_owned()
            } else {
                get_string(assets, 0x275e, 4)
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
    mut next_state: ResMut<NextState<AppState>>,
) {
    let stop = session.game.close_newspaper();
    apply_turn_stop(stop, &mut next_state);
}
