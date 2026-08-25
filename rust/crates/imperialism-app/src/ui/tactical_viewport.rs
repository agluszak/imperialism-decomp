//! Recovered `TTacticalBattleView` pixel geometry shared by land and naval battles.
//!
//! Land maps `(row, column)` onto `TacticalHex`; navy maps it onto a linear tile index.
//! Gameplay and presentation stay in the battle screens.

use bevy::prelude::{IRect, IVec2};
use bevy::ui::RelativeCursorPosition;

/// Retail setters 0x5a6830 / 0x5a6860.
pub(in crate::ui) const TACTICAL_TILE_WIDTH_PX: i32 = 0x32;
pub(in crate::ui) const TACTICAL_TILE_ROW_HEIGHT_PX: i32 = 0x1e;
/// `TTacticalBattleView::ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset` grows the tile up by 0x14.
pub(in crate::ui) const UNIT_SPRITE_LIFT_PX: i32 = 0x14;
pub(in crate::ui) const BATTLEFIELD_WIDTH_PX: i32 = 575;
pub(in crate::ui) const BATTLEFIELD_HEIGHT_PX: i32 = 450;

/// Visible hex rows in the 450px battlefield (`frameHeight / tileRowHeight`).
pub(in crate::ui) const TACTICAL_VIEWPORT_ROWS: i32 =
    BATTLEFIELD_HEIGHT_PX / TACTICAL_TILE_ROW_HEIGHT_PX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::ui) struct TacticalViewport {
    pub columns: i32,
    pub rows: i32,
    pub origin: IVec2,
}

impl TacticalViewport {
    pub fn new(columns: i32, rows: i32, origin: IVec2) -> Self {
        Self {
            columns,
            rows,
            origin,
        }
    }

    pub fn land(column_count: i32, origin_x: i32) -> Self {
        Self::new(
            column_count,
            TACTICAL_VIEWPORT_ROWS,
            IVec2::new(origin_x, 0),
        )
    }

    pub fn navy(origin: IVec2) -> Self {
        let columns = imperialism_core::NavyBattle::tile_stride();
        Self::new(
            columns,
            imperialism_core::NavyBattle::tile_count() / columns,
            origin,
        )
    }

    pub fn cell_rect(&self, row: i32, column: i32) -> IRect {
        let mut x = column * TACTICAL_TILE_WIDTH_PX - self.origin.x;
        if row & 1 != 0 {
            x += TACTICAL_TILE_WIDTH_PX / 2;
        }
        let y = row * TACTICAL_TILE_ROW_HEIGHT_PX - self.origin.y;
        IRect::new(
            x,
            y,
            x + TACTICAL_TILE_WIDTH_PX,
            y + TACTICAL_TILE_ROW_HEIGHT_PX,
        )
    }

    pub fn unit_rect(&self, row: i32, column: i32) -> IRect {
        let cell = self.cell_rect(row, column);
        IRect::new(
            cell.min.x,
            cell.min.y - UNIT_SPRITE_LIFT_PX,
            cell.max.x,
            cell.max.y,
        )
    }

    pub fn cell_at(&self, point: IVec2) -> Option<(i32, i32)> {
        if self.columns <= 0 || self.rows <= 0 {
            return None;
        }
        let row = ((point.y + self.origin.y) / TACTICAL_TILE_ROW_HEIGHT_PX).clamp(0, self.rows - 1);
        let mut col = self.origin.x + point.x;
        if row & 1 != 0 {
            col -= TACTICAL_TILE_WIDTH_PX / 2;
        }
        col /= TACTICAL_TILE_WIDTH_PX;
        Some((row, col.clamp(0, self.columns - 1)))
    }

    /// `TTacticalBattleView::MakeTileVisible` on X; navy uses the same 2-cell margin on Y.
    pub fn center_on(&mut self, row: i32, column: i32) {
        self.origin.x = snap_origin(
            self.origin.x,
            column,
            TACTICAL_TILE_WIDTH_PX,
            BATTLEFIELD_WIDTH_PX,
            self.max_origin_x(),
        );
        self.origin.y = snap_origin(
            self.origin.y,
            row,
            TACTICAL_TILE_ROW_HEIGHT_PX,
            BATTLEFIELD_HEIGHT_PX,
            self.max_origin_y(),
        );
    }

    pub fn max_origin_x(&self) -> i32 {
        ((self.columns + 1) * TACTICAL_TILE_WIDTH_PX - BATTLEFIELD_WIDTH_PX).max(0)
    }

    pub fn max_origin_y(&self) -> i32 {
        (self.rows * TACTICAL_TILE_ROW_HEIGHT_PX - BATTLEFIELD_HEIGHT_PX).max(0)
    }
}

pub(in crate::ui) fn battlefield_cursor_pixel(
    cursor: &RelativeCursorPosition,
) -> Option<(i32, i32)> {
    let position = cursor.normalized.filter(|_| cursor.cursor_over())?;
    Some((
        ((position.x + 0.5) * BATTLEFIELD_WIDTH_PX as f32).floor() as i32,
        ((position.y + 0.5) * BATTLEFIELD_HEIGHT_PX as f32).floor() as i32,
    ))
}

pub(in crate::ui) fn rect_xywh(rect: IRect) -> (i32, i32, i32, i32) {
    (
        rect.min.x,
        rect.min.y,
        rect.max.x - rect.min.x,
        rect.max.y - rect.min.y,
    )
}

fn snap_origin(current: i32, index: i32, cell: i32, viewport: i32, max_origin: i32) -> i32 {
    let first_visible = current / cell;
    let last_visible = first_visible + viewport / cell;
    if index >= first_visible + 2 && index <= last_visible - 2 {
        return current;
    }
    let centered = (index * cell - viewport / 2).clamp(0, max_origin);
    centered / cell * cell
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_pixel_round_trip_uses_retail_stagger() {
        let viewport = TacticalViewport::new(16, TACTICAL_VIEWPORT_ROWS, IVec2::new(100, 0));
        let (x, y, width, height) = rect_xywh(viewport.cell_rect(2, 4));
        let center = IVec2::new(x + width / 2, y + height / 2);
        assert_eq!(viewport.cell_at(center), Some((2, 4)));
        let (ox, oy, ow, oh) = rect_xywh(viewport.cell_rect(3, 4));
        assert_eq!(
            ox,
            4 * TACTICAL_TILE_WIDTH_PX + TACTICAL_TILE_WIDTH_PX / 2 - 100
        );
        assert_eq!(
            viewport.cell_at(IVec2::new(ox + ow / 2, oy + oh / 2)),
            Some((3, 4))
        );
    }

    #[test]
    fn navy_origin_y_shifts_row_lookup() {
        let viewport = TacticalViewport::navy(IVec2::new(0, 60));
        let (x, y, width, height) = rect_xywh(viewport.cell_rect(2, 4));
        assert_eq!(y, 2 * TACTICAL_TILE_ROW_HEIGHT_PX - 60);
        assert_eq!(
            viewport.cell_at(IVec2::new(x + width / 2, y + height / 2)),
            Some((2, 4))
        );
        let (ox, oy, ow, oh) = rect_xywh(viewport.cell_rect(3, 4));
        assert_eq!(ox, 4 * TACTICAL_TILE_WIDTH_PX + TACTICAL_TILE_WIDTH_PX / 2);
        assert_eq!(oy, 3 * TACTICAL_TILE_ROW_HEIGHT_PX - 60);
        assert_eq!(
            viewport.cell_at(IVec2::new(ox + ow / 2, oy + oh / 2)),
            Some((3, 4))
        );
    }

    #[test]
    fn center_on_snaps_land_x_and_is_a_no_op_for_navy_x() {
        let mut land = TacticalViewport::land(20, 0);
        land.center_on(4, 14);
        assert_eq!(land.origin.x % TACTICAL_TILE_WIDTH_PX, 0);
        assert_eq!(land.origin, IVec2::new(400, 0));
        land.center_on(4, 10);
        assert_eq!(land.origin.x, 400);

        let mut navy = TacticalViewport::navy(IVec2::ZERO);
        navy.center_on(20, 2);
        assert_eq!(navy.origin.x, 0);
        assert_eq!(navy.origin.y % TACTICAL_TILE_ROW_HEIGHT_PX, 0);
        assert_eq!(navy.origin.y, 360);
        navy.center_on(16, 2);
        assert_eq!(navy.origin.y, 360);
    }
}
