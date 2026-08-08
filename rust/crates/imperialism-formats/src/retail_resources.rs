//! Imperialism-specific resource payload decoding.
//!
//! PE traversal belongs to `pelite`; this module only understands the payload formats the game
//! stores inside those resources.

use crate::{DibPalette, Rgb};

#[derive(Debug, thiserror::Error)]
pub(super) enum RetailResourceDecodeError {
    #[error("invalid resource payload: {0}")]
    Invalid(String),
    #[error("unsupported resource payload: {0}")]
    Unsupported(String),
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct DecodedStringResource {
    pub(super) id: u32,
    pub(super) text: String,
}

pub(super) fn decode_string_table_block(
    block: u32,
    bytes: &[u8],
) -> Result<Vec<DecodedStringResource>, RetailResourceDecodeError> {
    if block == 0 {
        return Err(invalid("STRING block id is zero"));
    }

    let mut strings = Vec::with_capacity(16);
    let mut offset = 0usize;
    for index in 0..16u32 {
        let length = usize::from(read_u16(bytes, offset, "STRING entry length")?);
        offset = checked_add(offset, 2, "STRING entry length")?;
        let byte_length = length
            .checked_mul(2)
            .ok_or_else(|| invalid("STRING entry byte length overflow"))?;
        let end = checked_add(offset, byte_length, "STRING entry text")?;
        let encoded = bytes
            .get(offset..end)
            .ok_or_else(|| invalid("truncated STRING entry text"))?;
        let code_units = encoded
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let text = String::from_utf16(&code_units)
            .map_err(|_| invalid("STRING entry contains invalid UTF-16"))?;
        let id = (block - 1)
            .checked_mul(16)
            .and_then(|base| base.checked_add(index))
            .ok_or_else(|| invalid("STRING id overflow"))?;
        strings.push(DecodedStringResource { id, text });
        offset = end;
    }
    if offset != bytes.len() {
        return Err(invalid("trailing bytes after 16 STRING entries"));
    }
    Ok(strings)
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
    fn decodes_runtime_string_ids_without_the_historical_plus_sixteen_error() {
        let mut block = Vec::new();
        for index in 0..16u16 {
            let value = if index == 10 { "Introductory" } else { "" };
            let encoded = value.encode_utf16().collect::<Vec<_>>();
            block.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
            for unit in encoded {
                block.extend_from_slice(&unit.to_le_bytes());
            }
        }

        let strings = decode_string_table_block(1305, &block).unwrap();

        assert_eq!(strings[10].id, 20_874);
        assert_eq!(strings[10].text, "Introductory");
    }

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
