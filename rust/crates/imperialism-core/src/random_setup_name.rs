use crate::RetailLcg;

/// Retail country-name edit limit used by Random Setup (`coun`).
pub const COUNTRY_NAME_MAX_CHARS: usize = 12;

type Choice = (&'static str, i32);

const SHORT_INITIAL: &[Choice] = &[("A", 5), ("E", 3), ("Ea", 2), ("U", 2), ("Eu", 2)];
const LONG_INITIAL: &[Choice] = &[
    ("H", 24),
    ("W", 22),
    ("N", 16),
    ("B", 11),
    ("K", 10),
    ("S", 10),
    ("M", 10),
    ("P", 10),
    ("C", 9),
    ("F", 8),
    ("Gr", 6),
    ("L", 6),
    ("D", 5),
    ("R", 5),
    ("Br", 4),
    ("Ch", 4),
    ("T", 4),
    ("V", 3),
    ("G", 3),
    ("Cl", 3),
    ("Str", 3),
    ("St", 3),
    ("Sh", 2),
    ("Wh", 2),
    ("Cr", 2),
    ("Sm", 1),
    ("Pl", 1),
    ("Bl", 1),
];
const VOWELS: &[Choice] = &[
    ("o", 97),
    ("e", 90),
    ("a", 83),
    ("i", 62),
    ("oo", 12),
    ("u", 12),
    ("ou", 11),
    ("ea", 8),
];
const CONSONANTS: &[Choice] = &[
    ("t", 12),
    ("r", 8),
    ("ngt", 8),
    ("w", 6),
    ("n", 6),
    ("ns", 5),
    ("lw", 5),
    ("tt", 5),
    ("th", 4),
    ("rw", 4),
    ("d", 4),
    ("ll", 4),
    ("lb", 3),
    ("l", 3),
    ("nw", 3),
    ("mb", 3),
    ("ct", 3),
    ("st", 3),
    ("nst", 3),
    ("pp", 3),
    ("nh", 3),
    ("nt", 3),
    ("nchl", 3),
    ("mm", 2),
    ("ndsw", 2),
    ("lh", 2),
    ("ph", 2),
    ("xt", 2),
    ("v", 2),
    ("rn", 2),
    ("sh", 2),
    ("nn", 2),
    ("ckl", 2),
    ("ckh", 2),
    ("rl", 2),
    ("lth", 2),
    ("tf", 2),
    ("mpst", 2),
    ("g", 2),
    ("yt", 2),
    ("rt", 2),
    ("m", 2),
    ("ldg", 2),
    ("k", 2),
    ("thg", 2),
    ("sw", 2),
    ("dm", 2),
    ("sd", 2),
    ("ng", 2),
    ("sm", 1),
    ("yf", 1),
    ("rh", 1),
    ("thf", 1),
    ("wcr", 1),
    ("b", 1),
    ("rb", 1),
    ("ngsb", 1),
    ("ptf", 1),
    ("rlt", 1),
    ("rk", 1),
    ("mpt", 1),
    ("h", 1),
    ("yw", 1),
    ("bb", 1),
    ("tn", 1),
    ("s", 1),
    ("nds", 1),
    ("rm", 1),
    ("lf", 1),
    ("df", 1),
    ("mst", 1),
    ("rtl", 1),
    ("nd", 1),
    ("rg", 1),
    ("rs", 1),
    ("pl", 1),
    ("mt", 1),
    ("ckw", 1),
    ("ngsg", 1),
    ("ryl", 1),
    ("rbl", 1),
    ("ckn", 1),
    ("lst", 1),
    ("pt", 1),
    ("ngf", 1),
    ("thn", 1),
    ("p", 1),
    ("ch", 1),
    ("pn", 1),
    ("ld", 1),
    ("ls", 1),
    ("nchm", 1),
    ("tst", 1),
    ("md", 1),
    ("yn", 1),
    ("rsm", 1),
    ("psg", 1),
    ("lm", 1),
    ("stm", 1),
    ("dg", 1),
    ("rls", 1),
    ("ghtsbr", 1),
    ("rns", 1),
    ("ngd", 1),
    ("mbl", 1),
    ("lg", 1),
    ("ghg", 1),
];
const CONSONANT_TAIL: &[Choice] = &[
    ("n", 38),
    ("y", 13),
    ("m", 12),
    ("th", 12),
    ("ll", 12),
    ("d", 11),
    ("rth", 10),
    ("r", 8),
    ("st", 7),
    ("rd", 6),
    ("ch", 5),
    ("ng", 5),
    ("ry", 5),
    ("w", 4),
    ("rk", 4),
    ("l", 3),
    ("rn", 3),
    ("ss", 3),
    ("sh", 2),
    ("rs", 2),
    ("s", 2),
    ("tch", 1),
    ("hns", 1),
    ("t", 1),
    ("nk", 1),
    ("cks", 1),
];
const VOWEL_TAIL: &[Choice] = &[("e", 24), ("ia", 3), ("ea", 2)];

const BANNED_SUBSTRINGS: &[&str] = &[
    "Duck",
    "Ship",
    "Bunt",
    "Whole",
    "Ass",
    "Benis",
    "Bagina",
    "Pigg",
    "Dussy",
    "Twit",
    "Bigger",
    "Gook",
    "Kike",
    "Spic",
    "Nasi",
    "Hitman",
    "Dock",
    "Dag",
    "Merde",
    "Scheiss",
    "Chinga",
    "Coger",
    "Tit",
    "Cabron",
    "Maricon",
    "Mierda",
    "Schweinhund",
    "Smegma",
    "Turd",
    "Jism",
    "Fart",
    "Ritch",
    "Feces",
];

/// Generates the English random-setup fallback text used by the retail default
/// language context (nation table slot 6, mapped-flavor variant 2).
///
/// The caller owns the shared zone/status LCG. Retail generates the default
/// planet seed and then the fallback country name from the same stream, so this
/// function deliberately leaves the resulting state in `rng`.
/// Profile `CountryName` remains a caller-provided override after this fallback.
pub fn generate_english_random_setup_name(rng: &mut RetailLcg) -> String {
    loop {
        let candidate = generate_candidate(rng);
        if BANNED_SUBSTRINGS
            .iter()
            .all(|forbidden| !candidate.contains(forbidden))
        {
            return candidate;
        }
    }
}

fn generate_candidate(rng: &mut RetailLcg) -> String {
    let mut flag = flavor_gate_flag(rng, 0xd3, 0xc4);
    let count_weights = if flag {
        [0x33, 0x0a, 0x55, 0x0e, 0x1e, 5, 1, 0]
    } else {
        [0, 8, 2, 5, 0, 0, 0, 0]
    };
    let count_range = if flag { 0xc4 } else { 0x0f };
    let count = count_index(rng.current_sample_15(), &count_weights, count_range) + 3;

    let mut output = String::new();
    if flag {
        output.push_str(pick_weighted(rng, LONG_INITIAL, 0xbc));
    } else {
        output.push_str(pick_weighted(rng, SHORT_INITIAL, 0x0e));
    }

    for _ in 0..count - 2 {
        flag = !flag;
        if flag {
            output.push_str(pick_weighted(rng, CONSONANTS, 0xd6));
        } else {
            output.push_str(pick_weighted(rng, VOWELS, 0x174));
        }
    }

    if flag {
        output.push_str(pick_weighted(rng, VOWEL_TAIL, 0x1d));
    } else {
        output.push_str(pick_weighted(rng, CONSONANT_TAIL, 0xac));
    }
    output
}

fn flavor_gate_flag(rng: &mut RetailLcg, range: u32, threshold: u32) -> bool {
    let sample = rng.next_sample_15();
    let flag = sample % range < threshold;
    rng.advance();
    flag
}

fn pick_weighted(rng: &mut RetailLcg, choices: &'static [Choice], range: u32) -> &'static str {
    let index = choice_index(rng.next_sample_15(), choices, range);
    choices[index].0
}

fn choice_index(sample: u32, choices: &[Choice], range: u32) -> usize {
    let mut remaining = (sample % range) as i32 - choices[0].1;
    let mut index = 0;
    while remaining >= 0 {
        index += 1;
        remaining -= choices[index].1;
    }
    index
}

fn count_index(sample: u32, weights: &[i32], range: u32) -> usize {
    let mut remaining = (sample % range) as i32 - weights[0];
    let mut index = 0;
    while remaining >= 0 {
        index += 1;
        remaining -= weights[index];
    }
    index
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
