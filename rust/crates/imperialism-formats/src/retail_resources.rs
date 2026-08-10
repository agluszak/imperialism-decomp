//! Imperialism-specific resource payload decoding.
//!
//! PE traversal belongs to `pelite`; this module only understands the payload formats the game
//! stores inside those resources.

use crate::{DibPalette, Rgb};

/// Palette indexes from a retail 1-bpp or 8-bpp bitmap resource.
///
/// Rows are normalized to top-to-bottom order and contain exactly `width`
/// indexes, with DIB row padding and 1-bpp packing removed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedPicture {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum RetailResourceDecodeError {
    #[error("invalid resource payload: {0}")]
    Invalid(String),
    #[error("unsupported resource payload: {0}")]
    Unsupported(String),
}

pub(super) fn bitmap_resource_to_bmp(dib: &[u8]) -> Result<Vec<u8>, RetailResourceDecodeError> {
    let header_size = usize::try_from(read_u32(dib, 0, "DIB header size")?)
        .map_err(|_| invalid("DIB header size does not fit usize"))?;
    let (bit_count, palette_entries, extra_masks) = if header_size == 12 {
        let bit_count = read_u16(dib, 10, "BITMAPCOREHEADER bit count")?;
        let colors = palette_count(bit_count, 0)?;
        (bit_count, colors, 0usize)
    } else if header_size >= 40 {
        require_range(dib, 0, header_size, "DIB header")?;
        let bit_count = read_u16(dib, 14, "BITMAPINFOHEADER bit count")?;
        let compression = read_u32(dib, 16, "BITMAPINFOHEADER compression")?;
        let colors_used = read_u32(dib, 32, "BITMAPINFOHEADER colors used")?;
        let colors = palette_count(bit_count, colors_used)?;
        let masks = usize::from(header_size == 40 && compression == 3) * 12;
        (bit_count, colors, masks)
    } else {
        return Err(RetailResourceDecodeError::Unsupported(format!(
            "DIB header size {header_size}"
        )));
    };
    let palette_stride = if header_size == 12 { 3usize } else { 4usize };
    let palette_bytes = palette_entries
        .checked_mul(palette_stride)
        .ok_or_else(|| invalid("DIB palette size overflow"))?;
    let dib_pixel_offset = header_size
        .checked_add(extra_masks)
        .and_then(|value| value.checked_add(palette_bytes))
        .ok_or_else(|| invalid("DIB pixel offset overflow"))?;
    if dib_pixel_offset > dib.len() {
        return Err(invalid("DIB palette extends past resource payload"));
    }
    let file_size = dib
        .len()
        .checked_add(14)
        .ok_or_else(|| invalid("BMP file size overflow"))?;
    let file_size = u32::try_from(file_size).map_err(|_| invalid("BMP exceeds 4 GiB"))?;
    let pixel_offset = u32::try_from(dib_pixel_offset + 14)
        .map_err(|_| invalid("BMP pixel offset exceeds 4 GiB"))?;

    let mut bmp = Vec::with_capacity(file_size as usize);
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&file_size.to_le_bytes());
    bmp.extend_from_slice(&0u16.to_le_bytes());
    bmp.extend_from_slice(&0u16.to_le_bytes());
    bmp.extend_from_slice(&pixel_offset.to_le_bytes());
    bmp.extend_from_slice(dib);
    debug_assert_eq!(bmp.len(), file_size as usize);
    let _ = bit_count;
    Ok(bmp)
}

pub(super) fn bitmap_resource_to_indexed_picture(
    dib: &[u8],
) -> Result<IndexedPicture, RetailResourceDecodeError> {
    let header_size = usize::try_from(read_u32(dib, 0, "DIB header size")?)
        .map_err(|_| invalid("DIB header size does not fit usize"))?;
    let (width, height, bottom_up, planes, bit_count, compression, palette_entries) =
        if header_size == 12 {
            require_range(dib, 0, header_size, "BITMAPCOREHEADER")?;
            let width = u32::from(read_u16(dib, 4, "BITMAPCOREHEADER width")?);
            let height = u32::from(read_u16(dib, 6, "BITMAPCOREHEADER height")?);
            let planes = read_u16(dib, 8, "BITMAPCOREHEADER planes")?;
            let bit_count = read_u16(dib, 10, "BITMAPCOREHEADER bit count")?;
            (
                width,
                height,
                true,
                planes,
                bit_count,
                0,
                palette_count(bit_count, 0)?,
            )
        } else if header_size >= 40 {
            require_range(dib, 0, header_size, "BITMAPINFOHEADER")?;
            let signed_width = read_i32(dib, 4, "BITMAPINFOHEADER width")?;
            if signed_width <= 0 {
                return Err(invalid(format!(
                    "BITMAPINFOHEADER width {signed_width} is not positive"
                )));
            }
            let signed_height = read_i32(dib, 8, "BITMAPINFOHEADER height")?;
            if signed_height == 0 {
                return Err(invalid("BITMAPINFOHEADER height is zero"));
            }
            let planes = read_u16(dib, 12, "BITMAPINFOHEADER planes")?;
            let bit_count = read_u16(dib, 14, "BITMAPINFOHEADER bit count")?;
            let compression = read_u32(dib, 16, "BITMAPINFOHEADER compression")?;
            let colors_used = read_u32(dib, 32, "BITMAPINFOHEADER colors used")?;
            (
                signed_width as u32,
                signed_height.unsigned_abs(),
                signed_height > 0,
                planes,
                bit_count,
                compression,
                palette_count(bit_count, colors_used)?,
            )
        } else {
            return Err(RetailResourceDecodeError::Unsupported(format!(
                "DIB header size {header_size}"
            )));
        };

    if width == 0 || height == 0 {
        return Err(invalid("indexed DIB dimensions are empty"));
    }
    if planes != 1 {
        return Err(invalid(format!("indexed DIB plane count {planes}")));
    }
    if bit_count != 1 && bit_count != 8 {
        return Err(RetailResourceDecodeError::Unsupported(format!(
            "indexed DIB bit count {bit_count}"
        )));
    }
    if compression != 0 {
        return Err(RetailResourceDecodeError::Unsupported(format!(
            "indexed DIB compression {compression}"
        )));
    }

    let palette_stride = if header_size == 12 { 3usize } else { 4usize };
    let palette_bytes = palette_entries
        .checked_mul(palette_stride)
        .ok_or_else(|| invalid("DIB palette size overflow"))?;
    let pixel_offset = header_size
        .checked_add(palette_bytes)
        .ok_or_else(|| invalid("DIB pixel offset overflow"))?;
    let width_usize =
        usize::try_from(width).map_err(|_| invalid("DIB width does not fit usize"))?;
    let height_usize =
        usize::try_from(height).map_err(|_| invalid("DIB height does not fit usize"))?;
    let row_bits = width_usize
        .checked_mul(usize::from(bit_count))
        .ok_or_else(|| invalid("DIB row bit count overflow"))?;
    let row_stride = row_bits
        .checked_add(31)
        .map(|bits| bits / 32 * 4)
        .ok_or_else(|| invalid("DIB row stride overflow"))?;
    let stored_bytes = row_stride
        .checked_mul(height_usize)
        .ok_or_else(|| invalid("DIB pixel data size overflow"))?;
    require_range(dib, pixel_offset, stored_bytes, "indexed DIB pixels")?;

    let pixel_count = width_usize
        .checked_mul(height_usize)
        .ok_or_else(|| invalid("indexed picture pixel count overflow"))?;
    let mut pixels = Vec::with_capacity(pixel_count);
    for top_row in 0..height_usize {
        let stored_row = if bottom_up {
            height_usize - top_row - 1
        } else {
            top_row
        };
        let row_start = pixel_offset + stored_row * row_stride;
        let row = &dib[row_start..row_start + row_stride];
        match bit_count {
            8 => pixels.extend_from_slice(&row[..width_usize]),
            1 => {
                for x in 0..width_usize {
                    pixels.push((row[x / 8] >> (7 - x % 8)) & 1);
                }
            }
            _ => unreachable!(),
        }
    }

    Ok(IndexedPicture {
        width,
        height,
        pixels,
    })
}

/// Decodes the 256 RGB entries used by the retail default indexed-DIB palette.
///
/// The application obtains this from the named `950.BMP` resource. It is a
/// `BITMAPINFOHEADER` 8-bit DIB, so this intentionally does not try to become
/// a general image decoder.
pub(super) fn bitmap_palette_rgb(dib: &[u8]) -> Result<DibPalette, RetailResourceDecodeError> {
    let header_size = usize::try_from(read_u32(dib, 0, "DIB header size")?)
        .map_err(|_| invalid("DIB header size does not fit usize"))?;
    if header_size < 40 {
        return Err(RetailResourceDecodeError::Unsupported(format!(
            "default palette DIB header size {header_size}"
        )));
    }
    require_range(dib, 0, header_size, "DIB header")?;
    let bit_count = read_u16(dib, 14, "BITMAPINFOHEADER bit count")?;
    if bit_count != 8 {
        return Err(RetailResourceDecodeError::Unsupported(format!(
            "default palette DIB bit count {bit_count}"
        )));
    }
    let compression = read_u32(dib, 16, "BITMAPINFOHEADER compression")?;
    let palette_start = header_size
        .checked_add(usize::from(header_size == 40 && compression == 3) * 12)
        .ok_or_else(|| invalid("DIB palette offset overflow"))?;
    let palette_bytes = 256usize
        .checked_mul(4)
        .ok_or_else(|| invalid("DIB palette size overflow"))?;
    require_range(dib, palette_start, palette_bytes, "default DIB palette")?;

    let mut colors = [Rgb::default(); 256];
    for (index, color) in colors.iter_mut().enumerate() {
        let offset = palette_start + index * 4;
        let bgr = &dib[offset..offset + 3];
        *color = Rgb::from_bgr(bgr[0], bgr[1], bgr[2]);
    }
    Ok(DibPalette::new(colors))
}

fn palette_count(bit_count: u16, colors_used: u32) -> Result<usize, RetailResourceDecodeError> {
    if colors_used != 0 {
        return usize::try_from(colors_used)
            .map_err(|_| invalid("DIB color count does not fit usize"));
    }
    if bit_count <= 8 {
        return 1usize
            .checked_shl(u32::from(bit_count))
            .ok_or_else(|| invalid("DIB palette count overflow"));
    }
    Ok(0)
}

fn read_u16(bytes: &[u8], offset: usize, label: &str) -> Result<u16, RetailResourceDecodeError> {
    let raw = bytes
        .get(offset..checked_add(offset, 2, label)?)
        .ok_or_else(|| invalid(format!("truncated {label}")))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize, label: &str) -> Result<u32, RetailResourceDecodeError> {
    let raw = bytes
        .get(offset..checked_add(offset, 4, label)?)
        .ok_or_else(|| invalid(format!("truncated {label}")))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_i32(bytes: &[u8], offset: usize, label: &str) -> Result<i32, RetailResourceDecodeError> {
    let raw = bytes
        .get(offset..checked_add(offset, 4, label)?)
        .ok_or_else(|| invalid(format!("truncated {label}")))?;
    Ok(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn require_range(
    bytes: &[u8],
    offset: usize,
    length: usize,
    label: &str,
) -> Result<(), RetailResourceDecodeError> {
    let end = checked_add(offset, length, label)?;
    if end > bytes.len() {
        return Err(invalid(format!("truncated {label}")));
    }
    Ok(())
}

fn checked_add(left: usize, right: usize, label: &str) -> Result<usize, RetailResourceDecodeError> {
    left.checked_add(right)
        .ok_or_else(|| invalid(format!("{label} offset overflow")))
}

fn invalid(message: impl Into<String>) -> RetailResourceDecodeError {
    RetailResourceDecodeError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_an_indexed_dib_without_changing_its_payload() {
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes());
        dib.extend_from_slice(&2i32.to_le_bytes());
        dib.extend_from_slice(&2i32.to_le_bytes());
        dib.extend_from_slice(&1u16.to_le_bytes());
        dib.extend_from_slice(&8u16.to_le_bytes());
        dib.extend_from_slice(&0u32.to_le_bytes());
        dib.extend_from_slice(&8u32.to_le_bytes());
        dib.extend_from_slice(&0i32.to_le_bytes());
        dib.extend_from_slice(&0i32.to_le_bytes());
        dib.extend_from_slice(&2u32.to_le_bytes());
        dib.extend_from_slice(&0u32.to_le_bytes());
        dib.extend_from_slice(&[0, 0, 0, 0, 0, 0, 255, 0]);
        dib.extend_from_slice(&[0, 1, 0, 0, 1, 0, 0, 0]);

        let bmp = bitmap_resource_to_bmp(&dib).unwrap();

        assert_eq!(&bmp[..2], b"BM");
        assert_eq!(u32::from_le_bytes(bmp[10..14].try_into().unwrap()), 62);
        assert_eq!(&bmp[14..], dib);
    }

    #[test]
    fn decodes_the_rgbquad_default_palette_entries() {
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1u16.to_le_bytes());
        dib.extend_from_slice(&8u16.to_le_bytes());
        dib.extend_from_slice(&0u32.to_le_bytes());
        dib.extend_from_slice(&4u32.to_le_bytes());
        dib.extend_from_slice(&0i32.to_le_bytes());
        dib.extend_from_slice(&0i32.to_le_bytes());
        dib.extend_from_slice(&0u32.to_le_bytes());
        dib.extend_from_slice(&0u32.to_le_bytes());
        for index in 0..256u16 {
            let value = index as u8;
            dib.extend_from_slice(&[value, value.wrapping_add(1), value.wrapping_add(2), 0]);
        }

        let palette = bitmap_palette_rgb(&dib).unwrap();

        assert_eq!(palette[0], Rgb::new(2, 1, 0));
        assert_eq!(palette[0x16], Rgb::new(0x18, 0x17, 0x16));
    }
}
