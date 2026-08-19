use super::generated;
use super::retail::{RetailTree, RetailUiAssets};
use super::window::{DismissWindow, ModalCancel, ModalDefault, ModalWindow};
use crate::AppState;
use bevy::prelude::*;
use imperialism_formats::{RetailTextStylePreset, fourcc};

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
) -> Entity {
    let root = commands.spawn_scene(generated::linger_2020()).id();
    commands
        .entity(root)
        .insert((extra, ModalWindow, DespawnOnExit(screen)));
    root
}

pub fn bind_linger_dialog(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
) -> LingerControls {
    let controls = LingerControls {
        title: tree.find(root, fourcc!("titl")),
        body: tree.find(root, fourcc!("info")),
        okay: tree.find(root, fourcc!("okay")),
        cancel: tree.find(root, fourcc!("cncl")),
        coat: tree.find(root, fourcc!("coat")),
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
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(0)),
    ));
}
