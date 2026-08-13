use super::generated;
use super::hover_help::get_string;
use super::retail::{RetailTag, RetailUiAssets, find_descendant};
use super::session::GameSession;
use crate::{AppState, RetailAssetsResource};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::{NewsTable, RetailAssets, RetailTextStylePreset, fourcc};

const COLUMN_X: [f32; 3] = [24.0, 226.0, 428.0];
const COLUMN_WIDTH: f32 = 188.0;
const STORY_TOP: f32 = 80.0;

#[derive(Component)]
struct NewspaperRoot;

#[derive(Component, Clone, Copy)]
struct NewspaperAction;

pub(crate) struct NewspaperPlugin;

impl Plugin for NewspaperPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::Newspaper),
            (spawn_newspaper, bind_newspaper).chain(),
        )
        .add_observer(on_newspaper_activate.run_if(in_state(AppState::Newspaper)));
    }
}

pub(crate) fn enter_newspaper(
    session: &mut GameState,
    assets: &RetailAssets,
    _commands: &mut Commands,
    next_state: &mut NextState<AppState>,
) {
    session.start_newspaper_phase(assets.news_table().story_ids());
    next_state.set(AppState::Newspaper);
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
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
) {
    let root = *root;
    fill_newspaper_chrome(
        &mut commands,
        &mut assets,
        root,
        &children,
        &tags,
        &session.0,
    );
    fill_newspaper_stories(
        &mut commands,
        &mut assets,
        root,
        &children,
        &tags,
        &session.0,
        retail.assets().news_table(),
    );
    commands
        .entity(find_descendant(root, fourcc!("end "), &children, &tags))
        .insert((NewspaperAction, ActivateOnPress));
}

fn fill_newspaper_chrome(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    state: &GameState,
) {
    let date = project_newspaper_date(assets, state.turn().economic_turn);
    commands
        .entity(find_descendant(root, fourcc!("date"), children, tags))
        .insert(Text::new(date));

    let spec = newspaper_spec_text(assets, state);
    commands
        .entity(find_descendant(root, fourcc!("spec"), children, tags))
        .insert(Text::new(spec));
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
    let nation = MajorNationId::from_nation(state.turn().active_nation)
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
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    state: &GameState,
    news: &NewsTable,
) {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("newspaper requires an active major nation");
    let Some(page) = state.news().pages[nation].as_ref() else {
        return;
    };
    let main = find_descendant(root, fourcc!("main"), children, tags);
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
            names.push(get_string(assets, 0x2711, i16::from(nation.get())));
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

fn on_newspaper_activate(
    activate: On<Activate>,
    actions: Query<&NewspaperAction>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if actions.get(activate.entity).is_err() {
        return;
    }
    session.0.finish_newspaper_phase();
    next_state.set(AppState::StrategicMap);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::state::app::StatesPlugin;

    #[test]
    fn unrelated_activation_before_a_game_does_not_require_a_session() {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(StatesPlugin)
            .insert_state(AppState::MainMenu)
            .add_plugins(NewspaperPlugin);
        let unrelated = app.world_mut().spawn_empty().id();

        app.world_mut()
            .commands()
            .trigger(Activate { entity: unrelated });
        app.world_mut().flush();
    }
}
