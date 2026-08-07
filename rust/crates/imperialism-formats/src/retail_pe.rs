use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::ops::Range;

const DIRECTORY_BIT: u32 = 0x8000_0000;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceIdentifier {
    Numeric(u32),
    Named(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeResourceEntry {
    pub resource_type: ResourceIdentifier,
    pub name: ResourceIdentifier,
    pub language: u32,
    data: Range<usize>,
}

impl PeResourceEntry {
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeResourceFile {
    bytes: Vec<u8>,
    resources: Vec<PeResourceEntry>,
}

impl PeResourceFile {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, PeResourceError> {
        let resources = parse_resources(&bytes)?;
        Ok(Self { bytes, resources })
    }

    pub fn resources(&self) -> &[PeResourceEntry] {
        &self.resources
    }

    pub fn payload<'a>(&'a self, entry: &PeResourceEntry) -> &'a [u8] {
        &self.bytes[entry.data.clone()]
    }

    pub fn find(
        &self,
        resource_type: &ResourceIdentifier,
        name: &ResourceIdentifier,
        language: u32,
    ) -> Option<&PeResourceEntry> {
        self.resources.iter().find(|entry| {
            &entry.resource_type == resource_type
                && &entry.name == name
                && entry.language == language
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedStringResource {
    pub id: u32,
    pub block: u32,
    pub index: u8,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeResourceError {
    Invalid(String),
    Unsupported(String),
}

impl fmt::Display for PeResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid PE resource file: {message}"),
            Self::Unsupported(message) => {
                write!(formatter, "unsupported PE resource file: {message}")
            }
        }
    }
}

impl Error for PeResourceError {}

pub fn decode_string_table_block(
    block: u32,
    bytes: &[u8],
) -> Result<Vec<DecodedStringResource>, PeResourceError> {
    if block == 0 {
        return Err(invalid("STRING block id must be nonzero"));
    }
    let mut offset = 0usize;
    let mut strings = Vec::with_capacity(16);
    for index in 0..16u8 {
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
        strings.push(DecodedStringResource {
            id: (block - 1)
                .checked_mul(16)
                .and_then(|base| base.checked_add(u32::from(index)))
                .ok_or_else(|| invalid("STRING id overflow"))?,
            block,
            index,
            text,
        });
        offset = end;
    }
    if offset != bytes.len() {
        return Err(invalid("trailing bytes after 16 STRING entries"));
    }
    Ok(strings)
}

pub fn bitmap_resource_to_bmp(dib: &[u8]) -> Result<Vec<u8>, PeResourceError> {
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
        return Err(PeResourceError::Unsupported(format!(
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

fn palette_count(bit_count: u16, colors_used: u32) -> Result<usize, PeResourceError> {
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

fn parse_resources(bytes: &[u8]) -> Result<Vec<PeResourceEntry>, PeResourceError> {
    if bytes.get(0..2) != Some(b"MZ") {
        return Err(invalid("missing DOS MZ signature"));
    }
    let pe_offset = usize_from_u32(read_u32(bytes, 0x3c, "PE header offset")?)?;
    if bytes.get(pe_offset..checked_add(pe_offset, 4, "PE signature")?) != Some(b"PE\0\0") {
        return Err(invalid("missing PE signature"));
    }
    let coff = checked_add(pe_offset, 4, "COFF header")?;
    let section_count = usize::from(read_u16(bytes, coff + 2, "section count")?);
    let optional_size = usize::from(read_u16(bytes, coff + 16, "optional header size")?);
    let optional = checked_add(coff, 20, "optional header")?;
    require_range(bytes, optional, optional_size, "optional header")?;
    let magic = read_u16(bytes, optional, "optional header magic")?;
    let resource_directory_offset = match magic {
        0x10b => 112usize,
        0x20b => 128usize,
        other => {
            return Err(PeResourceError::Unsupported(format!(
                "optional header magic 0x{other:x}"
            )));
        }
    };
    if optional_size < resource_directory_offset + 8 {
        return Err(invalid("optional header has no resource data directory"));
    }
    let resource_rva = read_u32(
        bytes,
        optional + resource_directory_offset,
        "resource directory RVA",
    )?;
    if resource_rva == 0 {
        return Ok(Vec::new());
    }
    let sections_offset = checked_add(optional, optional_size, "section table")?;
    let sections = parse_sections(bytes, sections_offset, section_count)?;
    let resource_base = rva_to_offset(resource_rva, &sections, bytes.len())?;
    let mut resources = Vec::new();
    parse_directory(
        bytes,
        resource_base,
        resource_base,
        &sections,
        DirectoryLevel::Type,
        None,
        None,
        &mut resources,
    )?;
    Ok(resources)
}

#[derive(Clone, Copy)]
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

fn parse_sections(
    bytes: &[u8],
    offset: usize,
    count: usize,
) -> Result<Vec<Section>, PeResourceError> {
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let entry = offset
            .checked_add(
                index
                    .checked_mul(40)
                    .ok_or_else(|| invalid("section table offset overflow"))?,
            )
            .ok_or_else(|| invalid("section table offset overflow"))?;
        require_range(bytes, entry, 40, "section header")?;
        sections.push(Section {
            virtual_size: read_u32(bytes, entry + 8, "section virtual size")?,
            virtual_address: read_u32(bytes, entry + 12, "section virtual address")?,
            raw_size: read_u32(bytes, entry + 16, "section raw size")?,
            raw_offset: read_u32(bytes, entry + 20, "section raw offset")?,
        });
    }
    Ok(sections)
}

fn rva_to_offset(
    rva: u32,
    sections: &[Section],
    file_len: usize,
) -> Result<usize, PeResourceError> {
    for section in sections {
        let extent = section.virtual_size.max(section.raw_size);
        let Some(end) = section.virtual_address.checked_add(extent) else {
            continue;
        };
        if section.virtual_address <= rva && rva < end {
            let delta = rva - section.virtual_address;
            if delta >= section.raw_size {
                return Err(invalid("resource RVA points into an unbacked section tail"));
            }
            let offset = section
                .raw_offset
                .checked_add(delta)
                .ok_or_else(|| invalid("resource file offset overflow"))?;
            let offset = usize_from_u32(offset)?;
            if offset > file_len {
                return Err(invalid("resource file offset is past end of file"));
            }
            return Ok(offset);
        }
    }
    Err(invalid(format!("resource RVA 0x{rva:x} is unmapped")))
}

#[derive(Clone, Copy)]
enum DirectoryLevel {
    Type,
    Name,
    Language,
}

#[allow(clippy::too_many_arguments)]
fn parse_directory(
    bytes: &[u8],
    resource_base: usize,
    directory: usize,
    sections: &[Section],
    level: DirectoryLevel,
    resource_type: Option<ResourceIdentifier>,
    name: Option<ResourceIdentifier>,
    resources: &mut Vec<PeResourceEntry>,
) -> Result<(), PeResourceError> {
    require_range(bytes, directory, 16, "resource directory")?;
    let named = usize::from(read_u16(bytes, directory + 12, "named resource count")?);
    let numeric = usize::from(read_u16(bytes, directory + 14, "numeric resource count")?);
    let count = named
        .checked_add(numeric)
        .ok_or_else(|| invalid("resource entry count overflow"))?;
    let entries = checked_add(directory, 16, "resource directory entries")?;
    require_range(
        bytes,
        entries,
        count
            .checked_mul(8)
            .ok_or_else(|| invalid("resource directory size overflow"))?,
        "resource directory entries",
    )?;

    for index in 0..count {
        let entry = entries + index * 8;
        let identifier = parse_identifier(
            bytes,
            resource_base,
            read_u32(bytes, entry, "resource identifier")?,
        )?;
        let target = read_u32(bytes, entry + 4, "resource target")?;
        match level {
            DirectoryLevel::Type | DirectoryLevel::Name => {
                if target & DIRECTORY_BIT == 0 {
                    return Err(invalid("resource type/name entry points to a data leaf"));
                }
                let child = relative_offset(resource_base, target & !DIRECTORY_BIT)?;
                match level {
                    DirectoryLevel::Type => parse_directory(
                        bytes,
                        resource_base,
                        child,
                        sections,
                        DirectoryLevel::Name,
                        Some(identifier),
                        None,
                        resources,
                    )?,
                    DirectoryLevel::Name => parse_directory(
                        bytes,
                        resource_base,
                        child,
                        sections,
                        DirectoryLevel::Language,
                        resource_type.clone(),
                        Some(identifier),
                        resources,
                    )?,
                    DirectoryLevel::Language => unreachable!(),
                }
            }
            DirectoryLevel::Language => {
                if target & DIRECTORY_BIT != 0 {
                    return Err(invalid("resource language entry points to a subdirectory"));
                }
                let language = match identifier {
                    ResourceIdentifier::Numeric(value) => value,
                    ResourceIdentifier::Named(_) => {
                        return Err(PeResourceError::Unsupported(
                            "named resource language".to_owned(),
                        ));
                    }
                };
                let data_entry = relative_offset(resource_base, target)?;
                require_range(bytes, data_entry, 16, "resource data entry")?;
                let data_rva = read_u32(bytes, data_entry, "resource data RVA")?;
                let size = usize_from_u32(read_u32(bytes, data_entry + 4, "resource size")?)?;
                let data_offset = rva_to_offset(data_rva, sections, bytes.len())?;
                let data_end = checked_add(data_offset, size, "resource payload")?;
                if data_end > bytes.len() {
                    return Err(invalid("resource payload extends past end of file"));
                }
                resources.push(PeResourceEntry {
                    resource_type: resource_type
                        .clone()
                        .ok_or_else(|| invalid("resource leaf has no type"))?,
                    name: name
                        .clone()
                        .ok_or_else(|| invalid("resource leaf has no name"))?,
                    language,
                    data: data_offset..data_end,
                });
            }
        }
    }
    Ok(())
}

fn parse_identifier(
    bytes: &[u8],
    resource_base: usize,
    raw: u32,
) -> Result<ResourceIdentifier, PeResourceError> {
    if raw & DIRECTORY_BIT == 0 {
        return Ok(ResourceIdentifier::Numeric(raw));
    }
    let offset = relative_offset(resource_base, raw & !DIRECTORY_BIT)?;
    let length = usize::from(read_u16(bytes, offset, "resource name length")?);
    let start = checked_add(offset, 2, "resource name")?;
    let byte_length = length
        .checked_mul(2)
        .ok_or_else(|| invalid("resource name length overflow"))?;
    let end = checked_add(start, byte_length, "resource name")?;
    let encoded = bytes
        .get(start..end)
        .ok_or_else(|| invalid("truncated resource name"))?;
    let code_units = encoded
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let name = String::from_utf16(&code_units)
        .map_err(|_| invalid("resource name contains invalid UTF-16"))?;
    Ok(ResourceIdentifier::Named(name))
}

fn relative_offset(base: usize, relative: u32) -> Result<usize, PeResourceError> {
    base.checked_add(usize_from_u32(relative)?)
        .ok_or_else(|| invalid("resource-relative offset overflow"))
}

fn read_u16(bytes: &[u8], offset: usize, label: &str) -> Result<u16, PeResourceError> {
    let raw = bytes
        .get(offset..checked_add(offset, 2, label)?)
        .ok_or_else(|| invalid(format!("truncated {label}")))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize, label: &str) -> Result<u32, PeResourceError> {
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
) -> Result<(), PeResourceError> {
    let end = checked_add(offset, length, label)?;
    if end > bytes.len() {
        return Err(invalid(format!("truncated {label}")));
    }
    Ok(())
}

fn checked_add(left: usize, right: usize, label: &str) -> Result<usize, PeResourceError> {
    left.checked_add(right)
        .ok_or_else(|| invalid(format!("{label} offset overflow")))
}

fn usize_from_u32(value: u32) -> Result<usize, PeResourceError> {
    usize::try_from(value).map_err(|_| invalid("32-bit offset does not fit usize"))
}

fn invalid(message: impl Into<String>) -> PeResourceError {
    PeResourceError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_named_bitmap_pe() -> Vec<u8> {
        const PE_OFFSET: usize = 0x80;
        const OPTIONAL_OFFSET: usize = PE_OFFSET + 24;
        const SECTION_OFFSET: usize = OPTIONAL_OFFSET + 224;
        const RESOURCE_OFFSET: usize = 0x200;
        const RESOURCE_RVA: u32 = 0x1000;
        const PAYLOAD_OFFSET: usize = 0x90;

        let mut bytes = vec![0u8; 0x400];
        bytes[..2].copy_from_slice(b"MZ");
        write_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        write_u16(&mut bytes, PE_OFFSET + 4, 0x14c);
        write_u16(&mut bytes, PE_OFFSET + 6, 1);
        write_u16(&mut bytes, PE_OFFSET + 20, 224);
        write_u16(&mut bytes, OPTIONAL_OFFSET, 0x10b);
        write_u32(&mut bytes, OPTIONAL_OFFSET + 112, RESOURCE_RVA);
        write_u32(&mut bytes, OPTIONAL_OFFSET + 116, 0x200);
        bytes[SECTION_OFFSET..SECTION_OFFSET + 8].copy_from_slice(b".rsrc\0\0\0");
        write_u32(&mut bytes, SECTION_OFFSET + 8, 0x200);
        write_u32(&mut bytes, SECTION_OFFSET + 12, RESOURCE_RVA);
        write_u32(&mut bytes, SECTION_OFFSET + 16, 0x200);
        write_u32(&mut bytes, SECTION_OFFSET + 20, RESOURCE_OFFSET as u32);

        let base = RESOURCE_OFFSET;
        write_u16(&mut bytes, base + 14, 1);
        write_u32(&mut bytes, base + 16, 2);
        write_u32(&mut bytes, base + 20, DIRECTORY_BIT | 0x18);

        write_u16(&mut bytes, base + 0x18 + 12, 1);
        write_u32(&mut bytes, base + 0x18 + 16, DIRECTORY_BIT | 0x70);
        write_u32(&mut bytes, base + 0x18 + 20, DIRECTORY_BIT | 0x30);

        write_u16(&mut bytes, base + 0x30 + 14, 1);
        write_u32(&mut bytes, base + 0x30 + 16, 1033);
        write_u32(&mut bytes, base + 0x30 + 20, 0x48);

        write_u32(
            &mut bytes,
            base + 0x48,
            RESOURCE_RVA + PAYLOAD_OFFSET as u32,
        );
        write_u32(&mut bytes, base + 0x48 + 4, 4);

        let name = "4500.BMP".encode_utf16().collect::<Vec<_>>();
        write_u16(&mut bytes, base + 0x70, name.len() as u16);
        for (index, unit) in name.into_iter().enumerate() {
            write_u16(&mut bytes, base + 0x72 + index * 2, unit);
        }
        bytes[base + PAYLOAD_OFFSET..base + PAYLOAD_OFFSET + 4].copy_from_slice(&[1, 2, 3, 4]);
        bytes
    }

    #[test]
    fn parses_named_resource_slots_and_preserves_payload_bytes() {
        let pe = PeResourceFile::parse(synthetic_named_bitmap_pe()).unwrap();

        assert_eq!(pe.resources().len(), 1);
        let entry = &pe.resources()[0];
        assert_eq!(entry.resource_type, ResourceIdentifier::Numeric(2));
        assert_eq!(entry.name, ResourceIdentifier::Named("4500.BMP".to_owned()));
        assert_eq!(entry.language, 1033);
        assert_eq!(entry.size(), 4);
        assert_eq!(pe.payload(entry), [1, 2, 3, 4]);
    }

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
    fn rejects_truncated_pe_headers() {
        let error = PeResourceFile::parse(b"MZ".to_vec()).unwrap_err();
        assert!(error.to_string().contains("truncated PE header offset"));
    }
}
