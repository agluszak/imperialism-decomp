use super::generated::{self, Linger2020};
use super::retail::RetailUiAssets;
use super::window::{DismissWindow, ModalCancel, ModalDefault, ModalWindow};
use crate::AppState;
use bevy::prelude::*;
use imperialism_formats::RetailTextStylePreset;

pub struct LingerControls {
    pub title: Entity,
    pub body: Entity,
    pub okay: Entity,
    pub cancel: Entity,
    pub coat: Entity,
}

pub fn spawn_linger_dialog(
    commands: &mut Commands,
    extra: impl Bundle,
    screen: AppState,
) -> Linger2020 {
    let ui = generated::spawn_linger_2020(commands);
    commands
        .entity(ui.root)
        .insert((extra, ui, ModalWindow, DespawnOnExit(screen)));
    ui
}

pub fn bind_linger_dialog(commands: &mut Commands, ui: Linger2020) -> LingerControls {
    let controls = LingerControls {
        title: ui.titl,
        body: ui.info,
        okay: ui.okay,
        cancel: ui.cncl,
        coat: ui.coat,
    };
    commands
        .entity(controls.okay)
        .insert((ModalDefault, DismissWindow));
    commands
        .entity(controls.cancel)
        .insert((ModalCancel, DismissWindow));
    controls
}

impl LingerControls {
    pub fn set_body(
        &self,
        commands: &mut Commands,
        assets: &mut RetailUiAssets,
        text: impl AsRef<str>,
    ) {
        insert_linger_text(commands, assets, self.body, text.as_ref(), 0);
    }

    pub fn set_title(
        &self,
        commands: &mut Commands,
        assets: &mut RetailUiAssets,
        text: impl AsRef<str>,
    ) {
        insert_linger_text(commands, assets, self.title, text.as_ref(), 1);
    }
}

fn insert_linger_text(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    entity: Entity,
    text: &str,
    alignment: i32,
) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment,
        })
        .expect("retail linger dialog text style");
    commands.entity(entity).insert((
        Text::new(text.to_owned()),
        Label,
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(0)),
    ));
}
