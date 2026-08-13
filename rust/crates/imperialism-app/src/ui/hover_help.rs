use super::retail::{RetailTag, RetailUiAssets, find_descendant};
use bevy::picking::hover::DirectlyHovered;
use bevy::prelude::*;
use imperialism_formats::{FourCc, RetailTextStylePreset};

/// Hover-help string shown in the screen's info bar while this control is the cursor hit.
///
/// Retail stores this on `TView::hoverHelpText58` after `SetHoverHelpText`. `TView::DoSetCursor`
/// then forwards it to `g_pCursorControlPanel` (`TInfoBarText::SetTextAndLayoutRect`).
#[derive(Component, Clone, Debug, Eq, PartialEq)]
pub(crate) struct HoverHelpText(pub String);

/// The retail `curs` / `hot!` info-bar control that displays hover-help text.
#[derive(Component)]
pub(crate) struct HoverHelpBar;

/// Last control whose hover-help was applied, matching `TInfoBarText::layoutRectA4`.
#[derive(Component, Default)]
struct HoverHelpSource(Option<Entity>);

#[derive(Clone, Copy)]
pub(crate) struct HoverHelpBarStyle {
    point_size: i32,
    text_palette: u8,
    shadow_palette: u8,
}

impl HoverHelpBarStyle {
    /// `TViewMgr::HandleTurnEventDialogFactorySlotF8` restyles `curs` to 14pt theme `0x2b6c`
    /// (palette `0x28`) with shadow theme `0x2b6b` (palette `0xd2`).
    pub(crate) const MAIN_MENU: Self = Self {
        point_size: 14,
        text_palette: 0x28,
        shadow_palette: 0xd2,
    };

    /// `TSetupRandomMapPicture::DoPostCreate` restyles `hot!` through
    /// `InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c)`: 12pt, text palette `0xd2`,
    /// shadow palette `0x28`.
    pub(crate) const RANDOM_SETUP: Self = Self {
        point_size: 12,
        text_palette: 0xd2,
        shadow_palette: 0x28,
    };
}

pub(crate) fn register_hover_help(app: &mut App) {
    app.add_systems(Update, sync_hover_help_bar);
}

pub(crate) fn bind_hover_help_bar(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    bar: Entity,
    node: &mut Node,
    style: HoverHelpBarStyle,
) {
    let (font, layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: style.point_size,
            alignment: 1,
        })
        .expect("retail hover-help bar text style");
    let text_color = assets.palette_color(style.text_palette);
    let shadow_color = assets.palette_color(style.shadow_palette);
    commands.entity(bar).insert((
        HoverHelpBar,
        HoverHelpSource::default(),
        Text::new(""),
        font,
        layout,
        TextColor(text_color),
        TextShadow {
            offset: Vec2::new(1.0, 1.0),
            color: shadow_color,
        },
    ));
    node.flex_direction = FlexDirection::Column;
    node.justify_content = JustifyContent::Center;
    node.overflow = Overflow::clip();
}

pub(crate) fn bind_hover_help_texts(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    texts: impl IntoIterator<Item = (FourCc, String)>,
) {
    for (tag, text) in texts {
        commands
            .entity(find_descendant(root, tag, children, tags))
            .insert((HoverHelpText(text), DirectlyHovered::default()));
    }
}

/// `TSimMgr::GetString`: adds one before the direct `LoadStringA` lookup.
pub(crate) fn get_string(assets: &RetailUiAssets, group: i16, offset: i16) -> String {
    assets
        .string(group, offset + 1)
        .expect("retail hover-help string")
}

/// `LoadUiStringResourceByGroupAndIndex`: direct `LoadStringA` group/index.
pub(crate) fn ui_string(assets: &RetailUiAssets, group: i16, index: i16) -> String {
    assets
        .string(group, index)
        .expect("retail hover-help string")
}

fn sync_hover_help_bar(
    sources: Query<(Entity, &HoverHelpText, &DirectlyHovered)>,
    changed: Query<(), (With<HoverHelpText>, Changed<DirectlyHovered>)>,
    mut bars: Query<(&mut Text, &mut HoverHelpSource), With<HoverHelpBar>>,
) {
    if changed.is_empty() {
        return;
    }
    let Some((entity, help)) = sources
        .iter()
        .find(|(_, _, hovered)| hovered.get())
        .map(|(entity, help, _)| (entity, help.0.as_str()))
    else {
        return;
    };
    for (mut text, mut source) in &mut bars {
        if source.0 == Some(entity) {
            continue;
        }
        source.0 = Some(entity);
        text.0 = help.to_owned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::fourcc;

    fn app() -> App {
        let mut app = App::new();
        app.add_systems(Update, sync_hover_help_bar);
        app
    }

    fn spawn_bar_and_source(app: &mut App, text: &str) -> (Entity, Entity) {
        let bar = app
            .world_mut()
            .spawn((HoverHelpBar, HoverHelpSource::default(), Text::new("stale")))
            .id();
        let source = app
            .world_mut()
            .spawn((HoverHelpText(text.to_owned()), DirectlyHovered(false)))
            .id();
        (bar, source)
    }

    #[test]
    fn directly_hovered_control_replaces_info_bar_text() {
        let mut app = app();
        let (bar, source) = spawn_bar_and_source(&mut app, "Start a new Random Game");
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "stale");

        app.world_mut()
            .entity_mut(source)
            .insert(DirectlyHovered(true));
        app.update();
        assert_eq!(
            app.world().get::<Text>(bar).unwrap().0,
            "Start a new Random Game"
        );
    }

    #[test]
    fn empty_hover_help_clears_the_info_bar() {
        let mut app = app();
        let (bar, source) = spawn_bar_and_source(&mut app, "");
        app.world_mut()
            .entity_mut(source)
            .insert(DirectlyHovered(true));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "");
    }

    #[test]
    fn a_new_directly_hovered_control_replaces_the_info_bar_text() {
        let mut app = app();
        let (bar, first) = spawn_bar_and_source(&mut app, "Random");
        let second = app
            .world_mut()
            .spawn((HoverHelpText("Quit".to_owned()), DirectlyHovered(false)))
            .id();
        app.world_mut()
            .entity_mut(first)
            .insert(DirectlyHovered(true));
        app.update();
        app.world_mut()
            .entity_mut(first)
            .insert(DirectlyHovered(false));
        app.world_mut()
            .entity_mut(second)
            .insert(DirectlyHovered(true));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "Quit");
    }

    #[test]
    fn leaving_a_help_control_keeps_the_previous_info_bar_text() {
        let mut app = app();
        let (bar, source) = spawn_bar_and_source(&mut app, "Quit");
        app.world_mut()
            .entity_mut(source)
            .insert(DirectlyHovered(true));
        app.update();
        app.world_mut()
            .entity_mut(source)
            .insert(DirectlyHovered(false));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "Quit");
    }

    #[test]
    fn bind_hover_help_texts_attaches_help_and_direct_hover() {
        #[derive(Component)]
        struct Root;

        let mut app = App::new();
        app.add_systems(
            Update,
            (
                |mut commands: Commands| {
                    let root = commands.spawn((Root, Node::default())).id();
                    commands.spawn((RetailTag(fourcc!("rand")), Node::default(), ChildOf(root)));
                },
                |mut commands: Commands,
                 root: Single<Entity, Added<Root>>,
                 children: Query<&Children>,
                 tags: Query<&RetailTag>| {
                    bind_hover_help_texts(
                        &mut commands,
                        *root,
                        &children,
                        &tags,
                        [(fourcc!("rand"), "Start a new Random Game".to_owned())],
                    );
                },
            )
                .chain(),
        );
        app.update();

        let mut query = app
            .world_mut()
            .query::<(&HoverHelpText, &DirectlyHovered, &RetailTag)>();
        let (help, hovered, tag) = query.single(app.world()).unwrap();
        assert_eq!(tag.0, fourcc!("rand"));
        assert_eq!(help.0, "Start a new Random Game");
        assert!(!hovered.get());
    }
}
