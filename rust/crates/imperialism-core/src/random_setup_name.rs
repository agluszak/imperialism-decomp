use crate::{RetailLcg, mapped_flavor_text};

/// Retail country-name edit limit used by Random Setup (`coun`).
pub const COUNTRY_NAME_MAX_CHARS: usize = 12;

/// Generates the English random-setup fallback text used by the retail default
/// language context (nation table slot 6, mapped-flavor variant 2).
///
/// The caller owns the shared zone/status LCG. Retail generates the default
/// planet seed and then the fallback country name from the same stream, so this
/// function deliberately leaves the resulting state in `rng`.
/// Profile `CountryName` remains a caller-provided override after this fallback.
pub fn generate_english_random_setup_name(rng: &mut RetailLcg) -> String {
    mapped_flavor_text::generate_english_name(rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_native_seed_one_default_setup_names() {
        let mut rng = RetailLcg::from_state(1);

        assert_eq!(generate_english_random_setup_name(&mut rng), "Woopnist");
        assert_eq!(rng.state(), 1_153_135_800);
        assert_eq!(generate_english_random_setup_name(&mut rng), "Purtast");
    }
}
