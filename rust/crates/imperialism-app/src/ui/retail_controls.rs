//! Semantic Bevy scene helpers for recovered retail control classes.

use super::retail::{
    retail_madness_picture, retail_picture, retail_picture_swap, retail_pressed_overlay_picture,
    retail_radio_text_fill,
};
use super::hover_help::HoverHelpBar;
use super::retail_page_corner::RetailPageCorner;
use super::retail_sideways_arrow::{RetailSidewaysArrow, RetailSidewaysArrowHilite};
use super::window::CaptionedWindow;
use bevy::prelude::*;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition, ScrollPosition};
use bevy::ui_widgets::{Button, Checkbox, RadioButton, RadioGroup, ScrollArea};

/// Stock release-activated picture button (`TControl`, `TClickZone`, ...).
pub fn retail_picture_button(idle: i16, active: i16) -> impl Scene {
    bsn! {
        Button
        retail_picture_swap(idle, active)
    }
}

/// `TPictureButton` with a transparent pressed overlay bitmap.
pub fn retail_picture_button_overlay(idle: i16, overlay: i16) -> impl Scene {
    bsn! {
        Button
        retail_picture(idle)
        retail_pressed_overlay_picture(overlay)
    }
}

/// `TTextPictureButton` / `TUpDownPictureButton` picture swap on a button.
pub fn retail_picture_swap_button(idle: i16, active: i16) -> impl Scene {
    bsn! {
        Button
        retail_picture_swap(idle, active)
    }
}

/// `TRadioPictureButton` and similar checked picture swaps.
pub fn retail_radio_picture_button(idle: i16, active: i16) -> impl Scene {
    bsn! {
        Button
        RadioButton
        retail_picture_swap(idle, active)
    }
}

/// `TCzechBox` / `TToggleButton` checkbox skin.
pub fn retail_checkbox(idle: i16, active: i16) -> impl Scene {
    bsn! {
        Checkbox
        retail_picture_swap(idle, active)
    }
}

/// Toggle that keeps a single static bitmap (`TToggleButton` variant).
pub fn retail_toggle_picture(picture_id: i16) -> impl Scene {
    bsn! {
        Checkbox
        retail_picture(picture_id)
    }
}

/// `TMadnessButton` multi-frame CzechBox skin.
pub fn retail_madness_checkbox(base: i16) -> impl Scene {
    bsn! {
        Checkbox
        retail_madness_picture(base)
    }
}

/// Headless `TRadioText` option row.
pub fn retail_radio_text() -> impl Scene {
    bsn! {
        RadioButton
        retail_radio_text_fill()
    }
}

/// `TRadioTextCluster` container.
pub fn retail_radio_cluster() -> impl Scene {
    bsn! {
        RadioGroup
    }
}

/// Canvas views that track the cursor (`TCitySiteView`, ...).
pub fn retail_pointer_canvas() -> impl Scene {
    bsn! {
        RelativeCursorPosition
    }
}

/// Recovered vertical scroll area shell.
pub fn retail_scroll_area() -> impl Scene {
    bsn! {
        ScrollArea
        ScrollPosition::default()
        Node {
            overflow: Overflow::scroll_y(),
        }
        Pickable
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
pub fn retail_sideways_arrow(idle: i16, active: i16) -> impl Scene {
    bsn! {
        RetailSidewaysArrow
        RetailSidewaysArrowHilite
        Pickable
        retail_picture_swap(idle, active)
    }
}

/// Runtime `TRightLeftView` replacement: repeat without pressed hilite.
pub fn retail_right_left_arrow(idle: i16, active: i16) -> impl Scene {
    bsn! {
        RetailSidewaysArrow
        Pickable
        retail_picture_swap(idle, active)
    }
}

/// `TPageCorner` triangular picking with stock button activation.
pub fn retail_page_corner(corner: RetailPageCorner) -> impl Scene {
    bsn! {
        template(move |_context| Ok(corner))
        Pickable { should_block_lower: false, is_hoverable: true }
        Button
    }
}

/// Apply recovered enabled/input-gate flags to interactive controls.
pub fn retail_interaction_state(checked: bool, disabled: bool) -> impl Scene {
    let checked = checked.then(|| bsn! { Checked });
    let disabled = disabled.then(|| bsn! { InteractionDisabled });
    bsn! {
        {checked}
        {disabled}
    }
}
