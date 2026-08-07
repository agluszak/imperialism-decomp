use crate::RngState;
use serde::{Deserialize, Serialize};

const VC5_CRT_RAND_MULTIPLIER: u32 = 214_013;
const VC5_CRT_RAND_ADDEND: u32 = 2_531_011;
const RETAIL_MAP_LCG_MULTIPLIER: u32 = 0x015a_4e35;
const RETAIL_MAP_LCG_ADDEND: u32 = 1;

/// The map-generation and zone-status generator used by retail. Each domain
/// owns an independent state even though both use this transition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RetailLcg(u32);

impl RetailLcg {
    pub const fn from_state(state: u32) -> Self {
        Self(state)
    }

    pub const fn state(self) -> u32 {
        self.0
    }

    /// Advances exactly once and returns the new full 32-bit state.
    pub fn advance(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(RETAIL_MAP_LCG_MULTIPLIER)
            .wrapping_add(RETAIL_MAP_LCG_ADDEND);
        self.0
    }

    /// Extracts the retail 15-bit sample without consuming another draw.
    pub const fn current_sample_15(self) -> u32 {
        (self.0 >> 12) & 0x7fff
    }

    /// Advances exactly once, then extracts bits 12..26 of that new state.
    pub fn next_sample_15(&mut self) -> u32 {
        self.advance();
        self.current_sample_15()
    }
}

/// Hashes the scenario/tuning bytes exactly as VC5 did before seeding the map
/// or zone LCG. Retail `char` is signed, and every arithmetic operation wraps
/// in the recovered 32-bit machine code.
pub fn hash_retail_scenario_tag(bytes: &[u8]) -> i32 {
    const NADA_TAG: i32 = 0x6e61_6461;

    bytes
        .iter()
        .take_while(|byte| **byte != 0)
        .fold(NADA_TAG, |seed, byte| {
            let signed_byte = i32::from(*byte as i8);
            (seed >> 16)
                .wrapping_add(seed.wrapping_mul(2))
                .wrapping_add(signed_byte)
        })
}

impl RngState {
    /// Mirrors VC5 libcmt's `srand`: the supplied value becomes the complete
    /// thread-local CRT random state without an eager transition.
    pub fn seed_crt(&mut self, seed: u32) {
        self.crt_rand = seed;
    }

    /// Mirrors the `rand.obj` shipped with VC5 libcmt. The object updates a
    /// 32-bit LCG state and returns bits 16..30 of the new state.
    pub fn next_crt_rand(&mut self) -> i32 {
        self.crt_rand = self
            .crt_rand
            .wrapping_mul(VC5_CRT_RAND_MULTIPLIER)
            .wrapping_add(VC5_CRT_RAND_ADDEND);
        ((self.crt_rand >> 16) & 0x7fff) as i32
    }

    /// Consumes one draw from only the authoritative map-generation stream.
    pub fn next_map_generation_sample_15(&mut self) -> u32 {
        let mut rng = RetailLcg::from_state(self.map_generation);
        let sample = rng.next_sample_15();
        self.map_generation = rng.state();
        sample
    }

    /// Consumes one draw from only the authoritative zone-status stream.
    pub fn next_zone_status_sample_15(&mut self) -> u32 {
        let mut rng = RetailLcg::from_state(self.zone_status);
        let sample = rng.next_sample_15();
        self.zone_status = rng.state();
        sample
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(crt_rand: u32) -> RngState {
        RngState {
            crt_rand,
            map_generation: 0x1122_3344,
            zone_status: 0x5566_7788,
        }
    }

    #[test]
    fn reproduces_the_vc5_seed_one_sequence() {
        let mut rng = state(0);
        rng.seed_crt(1);
        let actual: Vec<i32> = (0..8).map(|_| rng.next_crt_rand()).collect();
        assert_eq!(
            actual,
            vec![41, 18_467, 6_334, 26_500, 19_169, 15_724, 11_478, 29_358]
        );
        assert_eq!(rng.crt_rand, 1_924_036_713);
        assert_eq!(rng.map_generation, 0x1122_3344);
        assert_eq!(rng.zone_status, 0x5566_7788);
    }

    #[test]
    fn wraps_the_full_unsigned_state_before_extracting_the_result() {
        let mut rng = state(u32::MAX);
        assert_eq!(rng.next_crt_rand(), 35);
        assert_eq!(rng.crt_rand, 2_316_998);
    }

    #[test]
    fn retail_lcg_advances_before_extracting_bits_12_through_26() {
        let mut rng = RetailLcg::from_state(0x1122_3344);
        assert_eq!(rng.next_sample_15(), 6_581);
        assert_eq!(rng.state(), 0x419b_5515);
        assert_eq!(rng.next_sample_15(), 30_576);
        assert_eq!(rng.state(), 0xe777_035a);
    }

    #[test]
    fn map_and_zone_draws_do_not_consume_each_others_streams() {
        let mut rng = state(0xaabb_ccdd);
        let original_crt = rng.crt_rand;
        let original_zone = rng.zone_status;
        assert_eq!(rng.next_map_generation_sample_15(), 6_581);
        assert_eq!(rng.crt_rand, original_crt);
        assert_eq!(rng.zone_status, original_zone);

        assert_eq!(rng.next_zone_status_sample_15(), 18_210);
        assert_eq!(rng.crt_rand, original_crt);
        assert_eq!(rng.map_generation, 0x419b_5515);
    }

    #[test]
    fn scenario_tag_hash_uses_arithmetic_shift_and_signed_bytes() {
        assert_eq!(hash_retail_scenario_tag(b""), 0x6e61_6461);
        assert_eq!(hash_retail_scenario_tag(b"earth"), -869_132_543);
        assert_eq!(hash_retail_scenario_tag(b"earth\0ignored"), -869_132_543);
        assert_eq!(hash_retail_scenario_tag(&[0x80]), -591_186_269);
        assert_eq!(hash_retail_scenario_tag(&[0xff, b'A']), -1_182_381_240);
    }
}
