//! Class-semantic checks on generated retail input wiring.

#[cfg(test)]
mod tests {
    use super::super::generated;

    fn source() -> &'static str {
        include_str!("generated.rs")
    }

    fn node_chunk(source: &str, view: &str, tag: &str) -> String {
        let view_start = source
            .find(&format!("pub fn {view}()"))
            .unwrap_or_else(|| panic!("missing generated view {view}"));
        let view_body = &source[view_start..];
        let next_fn = view_body.find("\npub fn ").unwrap_or(view_body.len());
        let view_body = &view_body[..next_fn];
        let tag = format!("retail_node(fourcc!(\"{tag}\")");
        let start = view_body
            .find(&tag)
            .unwrap_or_else(|| panic!("{view} missing {tag}"));
        let rest = &view_body[start..];
        let end = rest
            .find("\n                            ),")
            .unwrap_or_else(|| {
                rest.find("\n                                ),")
                    .unwrap_or(rest.len())
            });
        rest[..end].to_string()
    }

    #[test]
    fn sideways_arrows_press_repeat_instead_of_release_button() {
        let chunk = node_chunk(source(), "transport_2014", "left");
        assert!(chunk.contains("RetailSidewaysArrow"), "{chunk}");
        assert!(!chunk.contains("Button"), "{chunk}");
    }

    #[test]
    fn page_corners_use_triangular_picking_not_rectangular_button() {
        let chunk = node_chunk(source(), "diplo_1352", "lcor");
        assert!(
            chunk.contains("template(|_context| Ok(RetailPageCorner::Left)"),
            "{chunk}"
        );
        assert!(!chunk.contains("Button"), "{chunk}");
    }

    #[test]
    fn ordinary_picture_buttons_still_release_activate() {
        let chunk = node_chunk(source(), "diplo_1352", "okay");
        assert!(chunk.contains("Button"), "{chunk}");
        assert!(!chunk.contains("RetailSidewaysArrow"), "{chunk}");
    }

    #[test]
    fn transport_gauge_structure_comes_from_rust_helpers() {
        let transport = source();
        let start = transport.find("pub fn transport_2014()").unwrap();
        let body = &transport[start..];
        let end = body.find("\npub fn ").unwrap_or(body.len());
        let body = &body[..end];
        assert!(body.contains("transport_gauge_remainder("));
        assert!(body.contains("transport_gauge_track_left("));
        assert!(!body.contains("width: px(113."));
        let _ = generated::transport_2014;
    }
}
