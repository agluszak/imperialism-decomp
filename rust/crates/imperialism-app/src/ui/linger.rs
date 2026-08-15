use super::generated;
use super::retail::{ModalDialog, RetailTag, RetailUiAssets, find_descendant};
use crate::AppState;
use bevy::input_focus::tab_navigation::TabGroup;
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
    z_index: i32,
) -> Entity {
    let root = commands.spawn_scene(generated::linger_2020()).id();
    commands.entity(root).insert((
        extra,
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(z_index),
        Pickable::default(),
        DespawnOnExit(screen),
    ));
    root
}

pub fn bind_linger_dialog(
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) -> LingerControls {
    LingerControls {
        title: find_descendant(root, fourcc!("titl"), children, tags),
        body: find_descendant(root, fourcc!("info"), children, tags),
        okay: find_descendant(root, fourcc!("okay"), children, tags),
        cancel: find_descendant(root, fourcc!("cncl"), children, tags),
        coat: find_descendant(root, fourcc!("coat"), children, tags),
    }
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
