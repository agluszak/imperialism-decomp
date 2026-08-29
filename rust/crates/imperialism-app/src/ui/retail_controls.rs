//! Semantic Bevy scene helpers for recovered retail control classes.
//! Referenced from generated BSN scenes via `retail::*` glob imports.

use super::hover_help::HoverHelpBar;
use super::retail::{
    retail_madness_picture, retail_picture, retail_picture_swap, retail_pressed_overlay_picture,
    retail_radio_text_fill,
};
use super::retail_page_corner::RetailPageCorner;
use super::retail_sideways_arrow::{RetailSidewaysArrow, RetailSidewaysArrowHilite};
use super::retail_transport_gauge::retail_transport_gauge;
use super::window::CaptionedWindow;
use bevy::prelude::*;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition, ScrollPosition};
use bevy::ui_widgets::{Button, Checkbox, RadioButton, RadioGroup, ScrollArea};
fn picture_swap_ids(picture_id: i16) -> (i16, i16) {
    (picture_id, picture_id + 1)
}

fn checkbox_swap_ids(picture_id: i16) -> (i16, i16) {
    (picture_id & !1, picture_id | 1)
}

fn retail_checked(state: bool) -> impl Scene {
    let checked = state.then(|| bsn! { Checked });
    bsn! {
        {checked}
    }
}

pub fn retail_disabled(enabled: bool) -> impl Scene {
    let disabled = (!enabled).then(|| bsn! { InteractionDisabled });
    bsn! {
        {disabled}
    }
}

fn picture_button_enabled(state: bool, enabled: bool) -> bool {
    // TPictureButton / T2PictureButton treat a non-zero state as enabled.
    enabled || state
}

/// Stock release-activated picture button (`TControl`, `TClickZone`, ...).
pub fn retail_picture_button(picture_id: i16, state: bool, enabled: bool) -> impl Scene {
    let (idle, active) = picture_swap_ids(picture_id);
    let enabled = picture_button_enabled(state, enabled);
    bsn! {
        Button
        retail_picture_swap(idle, active)
        retail_disabled(enabled)
    }
}

/// `TPictureButton` with a transparent pressed overlay bitmap.
pub fn retail_picture_button_overlay(picture_id: i16, state: bool, enabled: bool) -> impl Scene {
    let (idle, overlay) = picture_swap_ids(picture_id);
    let enabled = picture_button_enabled(state, enabled);
    bsn! {
        Button
        retail_picture(idle)
        retail_pressed_overlay_picture(overlay)
        retail_disabled(enabled)
    }
}

/// `TRadioPictureButton` and similar checked picture swaps.
pub fn retail_radio_picture_button(picture_id: i16, state: bool, enabled: bool) -> impl Scene {
    let (idle, active) = picture_swap_ids(picture_id);
    bsn! {
        Button
        RadioButton
        retail_picture_swap(idle, active)
        retail_checked(state)
        retail_disabled(enabled)
    }
}

/// `TCzechBox` checkbox skin.
pub fn retail_checkbox(picture_id: i16, state: bool, enabled: bool) -> impl Scene {
    let (idle, active) = checkbox_swap_ids(picture_id);
    bsn! {
        Checkbox
        retail_picture_swap(idle, active)
        retail_checked(state)
        retail_disabled(enabled)
    }
}

/// Toggle that keeps a single static bitmap (`TToggleButton` variant).
pub fn retail_toggle_picture(picture_id: i16, state: bool, enabled: bool) -> impl Scene {
    bsn! {
        Checkbox
        retail_picture(picture_id)
        retail_checked(state)
        retail_disabled(enabled)
    }
}

/// `TMadnessButton` multi-frame CzechBox skin.
pub fn retail_madness_checkbox(base: i16, state: bool, enabled: bool) -> impl Scene {
    bsn! {
        Checkbox
        retail_madness_picture(base)
        retail_checked(state)
        retail_disabled(enabled)
    }
}

/// Headless `TRadioText` option row.
pub fn retail_radio_text(state: bool, enabled: bool) -> impl Scene {
    bsn! {
        RadioButton
        retail_radio_text_fill()
        retail_checked(state)
        retail_disabled(enabled)
    }
}

/// `TRadioTextCluster` container.
pub fn retail_radio_cluster() -> impl Scene {
    bsn! {
        RadioGroup
    }
}

/// Canvas views that track the cursor (`TCitySiteView`, ...).
pub fn retail_pointer_canvas(enabled: bool) -> impl Scene {
    bsn! {
        RelativeCursorPosition
        retail_disabled(enabled)
    }
}

/// Recovered vertical scroll area shell.
pub fn retail_scroll_area(enabled: bool) -> impl Scene {
    bsn! {
        ScrollArea
        ScrollPosition::default()
        Node {
            overflow: Overflow::scroll_y(),
        }
        Pickable
        retail_disabled(enabled)
    }
}

/// Hover-help caption host (`TInfoBarText`).
pub fn retail_hover_help_bar() -> impl Scene {
    bsn! {
        template(|_context| Ok(HoverHelpBar))
        Text("")
        Node {
            flex_direction: FlexDirection::Column,
            justify_content: JustifyContent::Center,
            overflow: Overflow::clip(),
        }
    }
}

/// Captioned modal shell (`TWindow` with title chrome).
pub fn retail_captioned_window() -> impl Scene {
    bsn! {
        template(|_context| Ok(CaptionedWindow))
    }
}

/// `TSidewaysArrow` with press-repeat and hilite (`TUpDownPictureButton` art).
pub fn retail_sideways_arrow(picture_id: i16, enabled: bool) -> impl Scene {
    let (idle, active) = picture_swap_ids(picture_id);
    bsn! {
        RetailSidewaysArrow
        RetailSidewaysArrowHilite
        Pickable
        retail_picture_swap(idle, active)
        retail_disabled(enabled)
    }
}

/// `TRightLeftView`: repeat without pressed hilite.
pub fn retail_right_left_arrow(picture_id: i16, enabled: bool) -> impl Scene {
    let (idle, active) = picture_swap_ids(picture_id);
    bsn! {
        RetailSidewaysArrow
        Pickable
        retail_picture_swap(idle, active)
        retail_disabled(enabled)
    }
}

/// `TPageCorner` triangular picking with stock button activation.
pub fn retail_page_corner(corner: RetailPageCorner, state: bool, enabled: bool) -> impl Scene {
    bsn! {
        template(move |_context| Ok(corner))
        Pickable { should_block_lower: false, is_hoverable: true }
        Button
        retail_checked(state)
        retail_disabled(enabled)
    }
}

/// `TTransportPicture` bitmap plus recovered gauge overlay.
pub fn retail_transport_picture(picture_id: i16, owner_left: i32, enabled: bool) -> impl Scene {
    bsn! {
        retail_picture(picture_id)
        retail_transport_gauge(owner_left)
        retail_disabled(enabled)
    }
}
