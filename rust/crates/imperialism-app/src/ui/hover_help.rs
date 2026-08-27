use super::retail::{RetailTree, RetailUiAssets};
use bevy::picking::hover::DirectlyHovered;
use bevy::prelude::*;
use imperialism_formats::{FourCc, RetailTextStylePreset};

/// Hover-help string shown in the screen's info bar while this control is the cursor hit.
///
/// Retail stores this on `TView::hoverHelpText58` after `SetHoverHelpText`. `TView::DoSetCursor`
/// then forwards it to `g_pCursorControlPanel` (`TInfoBarText::SetTextAndLayoutRect`).
#[derive(Component, Clone, Debug, Eq, PartialEq)]
#[require(DirectlyHovered)]
pub(crate) struct HoverHelpText(pub String);

/// The retail `curs` / `hot!` info-bar control that displays hover-help text.
#[derive(Component)]
pub(crate) struct HoverHelpBar;

#[derive(Clone, Copy)]
pub(crate) struct HoverHelpBarStyle {
    point_size: i32,
    alignment: i32,
    text_palette: u8,
    shadow_palette: u8,
}

impl HoverHelpBarStyle {
    /// `TViewMgr::HandleTurnEventDialogFactorySlotF8` restyles `curs` to 14pt theme `0x2b6c`
    /// (palette `0x28`) with shadow theme `0x2b6b` (palette `0xd2`).
    pub(crate) const MAIN_MENU: Self = Self {
        point_size: 14,
        alignment: 1,
        text_palette: 0x28,
        shadow_palette: 0xd2,
    };

    /// `TSetupRandomMapPicture::DoPostCreate` restyles `hot!` through
    /// `InitializeMapHintTextStyleAndThemeFlags(0x2b6b, 0x2b6c)`: 12pt, text palette `0xd2`,
    /// shadow palette `0x28`.
    pub(crate) const RANDOM_SETUP: Self = Self {
        point_size: 12,
        alignment: 1,
        text_palette: 0xd2,
        shadow_palette: 0x28,
    };

    /// `TCitySiteView::DoPostCreate` restyles `curs` through
    /// `InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67)`: 12pt right-aligned,
    /// text palette `0x28`, shadow palette `0`.
    pub(crate) const CITY_SITE: Self = Self {
        point_size: 12,
        alignment: -1,
        text_palette: 0x28,
        shadow_palette: 0,
    };

    /// `TTacticalBattleView::DoPostCreate` uses the same recovered 12pt right-aligned
    /// `InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67)` style.
    pub(crate) const TACTICAL: Self = Self {
        point_size: 12,
        alignment: -1,
        text_palette: 0x28,
        shadow_palette: 0,
    };

    /// `TGamePreferencesPicture::DoPostCreate` restyles `curs` through
    /// `InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67)`: 12pt, text palette `0x28`,
    /// shadow palette `0`.
    pub(crate) const PREFERENCES: Self = Self {
        point_size: 12,
        alignment: 1,
        text_palette: 0x28,
        shadow_palette: 0,
    };
}

pub(crate) fn register_hover_help(app: &mut App) {
    app.add_systems(
        Update,
        (sync_hover_help_bar, sync_hover_help_accessible_labels),
    );
}

pub(crate) fn bind_hover_help_bar(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    bar: Entity,
    node: &mut Node,
    style: HoverHelpBarStyle,
) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset::explicit(
            1,
            0,
            style.point_size,
            style.alignment,
        ))
        .expect("retail hover-help bar text style");
    let text_color = assets.palette_color(style.text_palette);
    let shadow_color = assets.palette_color(style.shadow_palette);
    commands.entity(bar).insert((
        HoverHelpBar,
        Text::new(""),
        font,
        layout,
        line_height,
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
    tree: &RetailTree,
    texts: impl IntoIterator<Item = (FourCc, String)>,
) {
    for (tag, text) in texts {
        commands
            .entity(tree.find(root, tag))
            .insert(HoverHelpText(text));
    }
}

#[allow(clippy::type_complexity)]
fn sync_hover_help_bar(
    sources: Query<(&HoverHelpText, &DirectlyHovered)>,
    changed: Query<
        (),
        (
            With<HoverHelpText>,
            Or<(Changed<DirectlyHovered>, Changed<HoverHelpText>)>,
        ),
    >,
    mut bars: Query<&mut Text, With<HoverHelpBar>>,
) {
    if changed.is_empty() {
        return;
    }
    let Some(help) = sources
        .iter()
        .find_map(|(help, hovered)| hovered.get().then_some(help.0.as_str()))
    else {
        return;
    };
    for mut text in &mut bars {
        text.0 = help.to_owned();
    }
}

fn sync_hover_help_accessible_labels(
    mut commands: Commands,
    sources: Query<(Entity, &HoverHelpText), Changed<HoverHelpText>>,
) {
    for (entity, help) in &sources {
        if help.0.is_empty() {
            commands.entity(entity).remove::<AccessibleLabel>();
        } else {
            commands
                .entity(entity)
                .insert(AccessibleLabel::new(help.0.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let mut app = App::new();
        app.add_systems(Update, sync_hover_help_bar);
        app
    }

    fn spawn_bar_and_source(app: &mut App, text: &str) -> (Entity, Entity) {
        let bar = app
            .world_mut()
            .spawn((HoverHelpBar, Text::new("stale")))
            .id();
        let source = app.world_mut().spawn(HoverHelpText(text.to_owned())).id();
        (bar, source)
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
        let second = app.world_mut().spawn(HoverHelpText("Quit".to_owned())).id();
        app.world_mut()
            .entity_mut(first)
            .insert(DirectlyHovered(true));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "Random");
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
    fn changing_help_on_the_same_hovered_control_updates_the_bar() {
        let mut app = app();
        let (bar, source) = spawn_bar_and_source(&mut app, "civilian date");
        app.world_mut()
            .entity_mut(source)
            .insert(DirectlyHovered(true));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "civilian date");
        app.world_mut()
            .entity_mut(source)
            .insert(HoverHelpText("army date".to_owned()));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "army date");
    }
}
