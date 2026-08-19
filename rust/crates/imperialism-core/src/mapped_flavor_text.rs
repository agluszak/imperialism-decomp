#![allow(clippy::let_and_return)]

use crate::{NationId, RetailLcg};

// Retail's `GenerateMappedFlavorTextByTableSlot` name grammars. The weighted tables and
// draw order are part of gameplay state because ships, admirals, and generals persist
// these names and share the zone-status RNG with later operations.

const MAJOR_NATION_VARIANTS: [u8; 7] = [0, 9, 16, 14, 17, 8, 2];
const MINOR_NATION_VARIANTS: [u8; 16] = [5, 12, 11, 13, 6, 6, 6, 6, 4, 7, 1, 1, 10, 15, 10, 10];

fn pick_weighted<'a>(
    rng: &mut RetailLcg,
    choices: &'a [(&'a str, u32)],
    range: u32,
    mask: bool,
) -> &'a str {
    let sample = rng.next_sample_15();
    let mut remaining = if mask { sample & range } else { sample % range };
    for &(text, weight) in choices {
        if remaining < weight {
            return text;
        }
        remaining -= weight;
    }
    unreachable!("retail flavor weights cover their draw range")
}

type Choice = (&'static [(&'static str, u32)], u32, bool);

fn append_choice(out: &mut String, rng: &mut RetailLcg, choice: Choice) {
    out.push_str(pick_weighted(rng, choice.0, choice.1, choice.2));
}

fn alternating(
    rng: &mut RetailLcg,
    gate_range: u32,
    threshold: u32,
    false_count: (&[u32], u32),
    true_count: (&[u32], u32),
    start_false: Choice,
    start_true: Choice,
    middle_false: Choice,
    middle_true: Choice,
    end_false: Option<Choice>,
    end_true: Option<Choice>,
) -> String {
    let gate_sample = rng.next_sample_15();
    rng.advance();
    let mut flag = gate_sample % gate_range < threshold;
    let (count_weights, count_range) = if flag { true_count } else { false_count };
    let mut remaining = rng.current_sample_15() % count_range;
    let mut count = 0;
    for &weight in count_weights {
        if remaining < weight {
            break;
        }
        remaining -= weight;
        count += 1;
    }

    let mut out = String::new();
    append_choice(&mut out, rng, if flag { start_true } else { start_false });
    for _ in 0..=count {
        flag = !flag;
        append_choice(&mut out, rng, if flag { middle_true } else { middle_false });
    }
    if let Some(choice) = if flag { end_true } else { end_false } {
        append_choice(&mut out, rng, choice);
    }
    out
}

fn grammar_a(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Kvkvl", 19),
            ("Vkvl", 2),
            ("Kvkw", 4),
            ("Kvkvkvl", 13),
            ("Vkvkvl", 2),
            ("Vkvkvkvl", 1),
            ("Kvl", 1),
        ],
        42,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'K' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("H", 4),
                        ("B", 3),
                        ("Fr", 2),
                        ("St", 1),
                        ("F", 1),
                        ("M", 4),
                        ("P", 1),
                        ("Pf", 1),
                        ("R", 3),
                        ("L", 1),
                        ("Schw", 1),
                        ("W", 4),
                        ("V", 1),
                        ("N", 1),
                        ("Sch", 2),
                        ("G", 2),
                        ("Kr", 1),
                        ("K", 2),
                        ("S", 1),
                        ("D", 1),
                    ],
                    37,
                    false,
                ));
            }
            b'V' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("Au", 1), ("Ei", 1), ("I", 1), ("Ü", 1), ("E", 1)],
                    5,
                    false,
                ));
            }
            b'k' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("mb", 2),
                        ("rl", 2),
                        ("nkf", 1),
                        ("gsb", 1),
                        ("ttg", 1),
                        ("ss", 3),
                        ("hld", 1),
                        ("rrk", 1),
                        ("rch", 1),
                        ("s", 2),
                        ("nh", 2),
                        ("chst", 1),
                        ("ng", 7),
                        ("lst", 1),
                        ("nd", 2),
                        ("g", 1),
                        ("nsb", 1),
                        ("ß", 1),
                        ("nb", 2),
                        ("d", 2),
                        ("lb", 2),
                        ("b", 2),
                        ("ll", 1),
                        ("ttw", 1),
                        ("st", 1),
                        ("ffh", 1),
                        ("nnh", 1),
                        ("rb", 1),
                        ("pp", 1),
                        ("ssl", 1),
                        ("sl", 1),
                        ("sb", 1),
                        ("tzl", 1),
                        ("n", 2),
                        ("tzn", 1),
                        ("bl", 1),
                        ("gb", 1),
                        ("nch", 1),
                        ("tt", 1),
                        ("rst", 1),
                    ],
                    58,
                    false,
                ));
            }
            b'l' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("rg", 9),
                        ("n", 12),
                        ("rt", 2),
                        ("rf", 2),
                        ("m", 3),
                        ("tt", 1),
                        ("dt", 3),
                        ("l", 1),
                        ("r", 1),
                        ("ch", 1),
                        ("nz", 1),
                        ("ln", 1),
                        ("ck", 1),
                    ],
                    38,
                    false,
                ));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("a", 19),
                        ("u", 7),
                        ("e", 28),
                        ("i", 11),
                        ("ü", 3),
                        ("o", 6),
                        ("ei", 8),
                        ("ä", 1),
                        ("eu", 2),
                        ("au", 1),
                        ("ö", 3),
                        ("ie", 2),
                    ],
                    91,
                    false,
                ));
            }
            b'w' => out.push_str("au"),
            _ => {}
        }
    }
    out
}

fn grammar_b(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Kvkvkvkw", 3),
            ("Kvkvl", 12),
            ("Kvl", 1),
            ("Kvkw", 5),
            ("Kvkvkvl", 6),
            ("Vkvkw", 2),
            ("Vkvkvl", 1),
            ("Vkvl", 2),
            ("Kvkvkw", 2),
            ("Vkvkvkvl", 1),
        ],
        35,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'K' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("S", 3),
                        ("Th", 3),
                        ("Kh", 2),
                        ("Sp", 2),
                        ("M", 2),
                        ("K", 7),
                        ("P", 3),
                        ("R", 1),
                        ("Tr", 1),
                        ("Z", 1),
                        ("V", 1),
                        ("L", 1),
                        ("N", 1),
                        ("T", 1),
                    ],
                    29,
                    false,
                ));
            }
            b'V' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("A", 4), ("Ioa", 1), ("I", 1)],
                    6,
                    false,
                ));
            }
            b'k' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("l", 5),
                        ("n", 7),
                        ("k", 3),
                        ("s", 1),
                        ("rt", 2),
                        ("th", 4),
                        ("r", 9),
                        ("nth", 2),
                        ("nn", 1),
                        ("kl", 1),
                        ("mn", 1),
                        ("str", 1),
                        ("st", 2),
                        ("p", 1),
                        ("rg", 3),
                        ("sp", 1),
                        ("rk", 1),
                        ("f", 1),
                        ("ll", 1),
                        ("sv", 1),
                        ("fn", 1),
                        ("x", 1),
                        ("m", 1),
                        ("thr", 1),
                        ("ndr", 1),
                    ],
                    53,
                    false,
                ));
            }
            b'l' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("s", 17), ("n", 5), ("l", 1)],
                    23,
                    false,
                ));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("a", 14),
                        ("o", 25),
                        ("i", 22),
                        ("io", 3),
                        ("eio", 1),
                        ("aiu", 1),
                        ("e", 4),
                    ],
                    70,
                    false,
                ));
            }
            b'w' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("a", 6), ("ia", 2), ("i", 3), ("ai", 1)],
                    12,
                    false,
                ));
            }
            _ => {}
        }
    }
    out
}

fn grammar_c(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Kvj/Gw", 7),
            ("Kvj/Gvl", 10),
            ("Ku/Gvl", 8),
            ("Ku/Gw", 1),
            ("Vj/Gvl", 1),
            ("Ku/Rl", 1),
            ("Kvkvl", 2),
            ("Kvkw", 1),
        ],
        31,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'/' => out.push(' '),
            b'G' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("G", 1),
                        ("H", 3),
                        ("L", 5),
                        ("D", 3),
                        ("R", 1),
                        ("Th", 1),
                        ("Tr", 2),
                        ("Nh", 2),
                        ("T", 2),
                        ("Ng", 1),
                        ("N", 3),
                        ("B", 1),
                        ("Ph", 1),
                        ("M", 1),
                    ],
                    27,
                    false,
                ));
            }
            b'K' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("R", 1),
                        ("Kh", 1),
                        ("Q", 4),
                        ("V", 3),
                        ("G", 1),
                        ("D", 4),
                        ("Ph", 2),
                        ("Nh", 1),
                        ("H", 6),
                        ("S", 2),
                        ("Th", 1),
                        ("N", 2),
                        ("B", 1),
                        ("C", 1),
                    ],
                    30,
                    false,
                ));
            }
            b'R' | b'V' => out.push('A'),
            b'j' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("ch", 1),
                        ("nh", 5),
                        ("n", 5),
                        ("ng", 3),
                        ("m", 2),
                        ("c", 1),
                        ("t", 1),
                    ],
                    18,
                    false,
                ));
            }
            b'k' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("g", 1), ("n", 1), ("ph", 1)],
                    3,
                    false,
                ));
            }
            b'l' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("ng", 8),
                        ("nh", 6),
                        ("t", 1),
                        ("n", 4),
                        ("c", 1),
                        ("y", 1),
                        ("m", 1),
                    ],
                    22,
                    false,
                ));
            }
            b'u' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("ia", 1),
                        ("a", 5),
                        ("ui", 1),
                        ("oai", 1),
                        ("oi", 1),
                        ("o", 1),
                    ],
                    10,
                    false,
                ));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("a", 14),
                        ("u", 2),
                        ("ua", 3),
                        ("o", 9),
                        ("i", 9),
                        ("ie", 2),
                        ("ai", 2),
                    ],
                    41,
                    false,
                ));
            }
            b'w' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("ia", 1),
                        ("oi", 3),
                        ("ai", 2),
                        ("i", 1),
                        ("oa", 1),
                        ("a", 1),
                    ],
                    9,
                    false,
                ));
            }
            _ => {}
        }
    }
    out
}

fn grammar_d(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Vkvkvl", 5),
            ("Vkvl", 6),
            ("Kvkvkw", 4),
            ("Kvkw", 6),
            ("Kvkvl", 6),
            ("Vkvkw", 3),
            ("Kvkvkvl", 3),
            ("Vkvkvkvl", 2),
            ("Vkvkvkw", 2),
            ("Kvkvkvkw", 1),
            ("Kvkvkvkvl", 1),
            ("Vkw", 1),
        ],
        40,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'K' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("K", 2),
                        ("B", 3),
                        ("G", 4),
                        ("Z", 1),
                        ("C", 1),
                        ("M", 2),
                        ("S", 4),
                        ("R", 1),
                        ("F", 1),
                        ("V", 1),
                        ("T", 1),
                    ],
                    21,
                    false,
                ));
            }
            b'V' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("Ü", 1),
                        ("I", 4),
                        ("Yo", 1),
                        ("A", 6),
                        ("E", 1),
                        ("Ya", 1),
                        ("U", 3),
                        ("Ay", 1),
                        ("Ö", 1),
                    ],
                    19,
                    false,
                ));
            }
            b'k' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("sk", 3),
                        ("d", 4),
                        ("zm", 2),
                        ("nd", 1),
                        ("r", 5),
                        ("rs", 1),
                        ("zn", 1),
                        ("zg", 2),
                        ("nk", 2),
                        ("rz", 1),
                        ("m", 3),
                        ("sr", 1),
                        ("ng", 1),
                        ("ld", 1),
                        ("v", 2),
                        ("s", 4),
                        ("h", 3),
                        ("ks", 1),
                        ("lv", 1),
                        ("lg", 1),
                        ("z", 1),
                        ("pr", 2),
                        ("n", 1),
                        ("kk", 1),
                        ("l", 6),
                        ("kh", 1),
                        ("ll", 1),
                        ("dr", 1),
                        ("gl", 1),
                        ("k", 3),
                        ("rd", 1),
                        ("th", 1),
                        ("nt", 1),
                        ("sl", 1),
                        ("kf", 1),
                        ("b", 1),
                        ("ms", 1),
                        ("rk", 1),
                        ("rf", 1),
                    ],
                    67,
                    false,
                ));
            }
            b'l' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("r", 8),
                        ("t", 2),
                        ("k", 4),
                        ("z", 1),
                        ("c", 2),
                        ("n", 3),
                        ("m", 1),
                        ("rt", 1),
                        ("s", 1),
                    ],
                    23,
                    false,
                ));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("ü", 5),
                        ("a", 25),
                        ("i", 17),
                        ("u", 9),
                        ("e", 9),
                        ("o", 2),
                        ("ey", 1),
                        ("ö", 2),
                        ("ay", 1),
                    ],
                    71,
                    false,
                ));
            }
            b'w' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("a", 7),
                        ("e", 3),
                        ("ü", 2),
                        ("öy", 2),
                        ("iye", 2),
                        ("ya", 1),
                    ],
                    17,
                    false,
                ));
            }
            _ => {}
        }
    }
    out
}

fn grammar_e(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Kvkvkvl", 4),
            ("Kvkvl", 8),
            ("Vkvkvl", 3),
            ("Kvkw", 7),
            ("Kvl", 1),
            ("Vkw", 1),
            ("Kvkvkvkw", 5),
            ("Kvkvkw", 5),
            ("Vkvkvkw", 2),
        ],
        36,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'K' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("S", 3),
                        ("P", 3),
                        ("K", 5),
                        ("B", 1),
                        ("Kr", 4),
                        ("Kl", 1),
                        ("Sh", 1),
                        ("N", 2),
                        ("Zl", 1),
                        ("G", 2),
                        ("Gl", 1),
                        ("D", 2),
                        ("R", 2),
                        ("M", 1),
                        ("Sv", 1),
                    ],
                    30,
                    false,
                ));
            }
            b'V' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("A", 2), ("Ye", 1), ("I", 3)],
                    6,
                    false,
                ));
            }
            b'k' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("r", 3),
                        ("t", 3),
                        ("tr", 2),
                        ("zn", 1),
                        ("rd", 1),
                        ("s", 1),
                        ("m", 6),
                        ("lkh", 1),
                        ("tn", 1),
                        ("stk", 1),
                        ("v", 8),
                        ("nk", 3),
                        ("ln", 1),
                        ("rk", 1),
                        ("ch", 2),
                        ("l", 3),
                        ("f", 1),
                        ("n", 5),
                        ("kh", 1),
                        ("rt", 1),
                        ("rl", 1),
                        ("vk", 7),
                        ("nn", 1),
                        ("p", 1),
                        ("sn", 1),
                        ("d", 2),
                        ("tch", 1),
                        ("rdl", 1),
                    ],
                    61,
                    false,
                ));
            }
            b'l' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("v", 7), ("vsk", 3), ("tsk", 3), ("rsk", 2), ("sk", 1)],
                    15,
                    true,
                ));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("a", 14),
                        ("o", 30),
                        ("e", 13),
                        ("u", 4),
                        ("i", 6),
                        ("y", 1),
                        ("ay", 1),
                        ("iye", 2),
                    ],
                    71,
                    false,
                ));
            }
            b'w' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("y", 1),
                        ("ya", 2),
                        ("a", 9),
                        ("yy", 1),
                        ("i", 2),
                        ("o", 2),
                        ("aya", 3),
                    ],
                    20,
                    false,
                ));
            }
            _ => {}
        }
    }
    out
}

fn grammar_f(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Vcvcvcu", 1),
            ("Vcu", 2),
            ("Vcvcu", 1),
            ("Cvcu", 22),
            ("Cvcvcvcu", 5),
            ("Cvcvcu", 16),
            ("Cu", 4),
        ],
        51,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'C' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("L", 2),
                        ("W", 3),
                        ("N", 3),
                        ("P", 10),
                        ("M", 5),
                        ("K", 14),
                        ("H", 10),
                    ],
                    47,
                    false,
                ));
            }
            b'V' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("Oa", 1), ("A", 2), ("Oo", 1)],
                    3,
                    true,
                ));
            }
            b'c' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("w", 1),
                        ("m", 2),
                        ("n", 10),
                        ("p", 14),
                        ("k", 9),
                        ("l", 27),
                        ("h", 13),
                    ],
                    76,
                    false,
                ));
            }
            b'u' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("i", 1),
                        ("ia", 1),
                        ("auea", 1),
                        ("ai", 2),
                        ("auai", 1),
                        ("aui", 1),
                        ("aii", 1),
                        ("oo", 1),
                        ("io", 1),
                        ("oe", 1),
                        ("ua", 3),
                        ("u", 4),
                        ("eaau", 1),
                        ("ou", 1),
                        ("eo", 1),
                        ("ea", 1),
                        ("e", 1),
                        ("oa", 4),
                        ("o", 5),
                        ("au", 2),
                        ("aa", 2),
                        ("a", 14),
                        ("oea", 1),
                    ],
                    51,
                    false,
                ));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("aia", 1),
                        ("ea", 1),
                        ("ae", 1),
                        ("oo", 1),
                        ("ua", 2),
                        ("u", 3),
                        ("ue", 1),
                        ("oe", 1),
                        ("oau", 1),
                        ("ee", 1),
                        ("e", 4),
                        ("i", 3),
                        ("aa", 2),
                        ("aaui", 1),
                        ("aau", 1),
                        ("ai", 5),
                        ("au", 2),
                        ("a", 29),
                        ("o", 12),
                    ],
                    72,
                    false,
                ));
            }
            _ => {}
        }
    }
    out
}

fn grammar_g(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Vj/Gvkw", 4),
            ("Vj/Gvl", 3),
            ("Vj/Gvkvl", 11),
            ("Vkvj/Gvkvl", 1),
            ("Kvl", 5),
            ("Vkvl", 3),
            ("Kvkvl", 9),
            ("Kvkvkw", 1),
            ("Vj/Rkw", 1),
            ("Vj/Gvkvkvl", 6),
            ("Vj/Rkvkvl", 1),
            ("Kvkvkvl", 1),
            ("Kvkw", 3),
            ("Vku/Gvkvkvl", 1),
            ("Kvkvj/Gvkvl", 1),
            ("Vkw", 1),
            ("Vkvkvl", 1),
            ("Vj/Gvkvkvkvl", 1),
        ],
        54,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'/' => out.push(' '),
            b'G' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("R", 1),
                        ("H", 4),
                        ("M", 7),
                        ("Z", 1),
                        ("S", 4),
                        ("Y", 1),
                        ("K", 1),
                        ("T", 1),
                        ("Sh", 1),
                        ("J", 1),
                        ("D", 2),
                        ("L", 1),
                        ("B", 1),
                        ("Q", 2),
                    ],
                    28,
                    false,
                ));
            }
            b'K' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("M", 4),
                        ("J", 3),
                        ("S", 2),
                        ("D", 1),
                        ("R", 2),
                        ("L", 2),
                        ("Dh", 1),
                        ("Q", 1),
                        ("Y", 1),
                        ("F", 1),
                        ("H", 1),
                        ("T", 1),
                    ],
                    20,
                    false,
                ));
            }
            b'R' => {
                out.push_str(pick_weighted(rng, &[("A", 1), ("'A", 1)], 1, true));
            }
            b'V' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("A", 31), ("I", 1), ("'U", 2)],
                    34,
                    false,
                ));
            }
            b'j' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("r", 1), ("l", 15), ("s", 5), ("t", 3), ("sh", 1), ("d", 4)],
                    29,
                    false,
                ));
            }
            b'k' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("mth", 1),
                        ("fr", 1),
                        ("rq", 1),
                        ("shd", 1),
                        ("q", 2),
                        ("rb", 1),
                        ("r", 4),
                        ("mm", 2),
                        ("h", 2),
                        ("d", 3),
                        ("b", 6),
                        ("zr", 1),
                        ("z", 1),
                        ("f", 3),
                        ("yn", 1),
                        ("l", 4),
                        ("wb", 1),
                        ("k", 2),
                        ("fh", 1),
                        ("n", 3),
                        ("dr", 1),
                        ("y", 1),
                        ("rr", 2),
                        ("lw", 1),
                        ("yy", 1),
                        ("sh", 2),
                        ("bh", 1),
                        ("nf", 1),
                        ("dh", 1),
                        ("kk", 1),
                        ("yr", 1),
                        ("sf", 1),
                        ("dm", 1),
                        ("dd", 2),
                        ("nb", 1),
                        ("bb", 1),
                        ("st", 1),
                        ("j", 1),
                    ],
                    62,
                    false,
                ));
            }
            b'l' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("sn", 1),
                        ("q", 3),
                        ("lt", 1),
                        ("v", 1),
                        ("d", 2),
                        ("sh", 1),
                        ("n", 5),
                        ("b", 1),
                        ("h", 17),
                        ("k", 2),
                        ("r", 1),
                        ("wf", 1),
                        ("f", 1),
                        ("m", 2),
                        ("z", 1),
                        ("l", 2),
                        ("s", 1),
                        ("yd", 1),
                    ],
                    44,
                    false,
                ));
            }
            b'u' => {
                out.push_str(pick_weighted(rng, &[("u", 1)], 1, false));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("a", 63),
                        ("i", 14),
                        ("o", 2),
                        ("a'a", 4),
                        ("a'", 1),
                        ("'a", 2),
                        ("u", 10),
                        ("a'i", 2),
                        ("ua", 1),
                    ],
                    99,
                    false,
                ));
            }
            b'w' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("a", 7), ("ua", 1), ("i", 1), ("u'", 1)],
                    10,
                    false,
                ));
            }
            _ => {}
        }
    }
    out
}

fn grammar_h(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Kvkw", 42),
            ("Kvkvl", 40),
            ("Kvkvkw", 8),
            ("Kvkvkvl", 14),
            ("Kvkvkvkvl", 1),
        ],
        105,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'K' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("J", 10),
                        ("X", 13),
                        ("L", 9),
                        ("Zh", 7),
                        ("M", 4),
                        ("B", 4),
                        ("H", 6),
                        ("W", 5),
                        ("T", 8),
                        ("G", 6),
                        ("Ch", 3),
                        ("Sh", 6),
                        ("S", 5),
                        ("K", 2),
                        ("Q", 3),
                        ("F", 4),
                        ("N", 6),
                        ("Y", 4),
                    ],
                    105,
                    false,
                ));
            }
            b'k' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("z", 1),
                        ("nx", 4),
                        ("nzh", 5),
                        ("ngzh", 5),
                        ("x", 4),
                        ("j", 6),
                        ("ngm", 1),
                        ("h", 5),
                        ("ny", 6),
                        ("ch", 1),
                        ("sh", 6),
                        ("ngx", 3),
                        ("l", 6),
                        ("ngsh", 4),
                        ("ngl", 5),
                        ("nqzh", 1),
                        ("zh", 7),
                        ("ngy", 2),
                        ("d", 4),
                        ("nd", 1),
                        ("nq", 2),
                        ("ns", 1),
                        ("w", 2),
                        ("t", 2),
                        ("f", 2),
                        ("ng", 2),
                        ("y", 2),
                        ("nt", 1),
                        ("ngb", 3),
                        ("b", 3),
                        ("ngh", 4),
                        ("nj", 2),
                        ("ngw", 1),
                        ("c", 1),
                        ("nz", 1),
                        ("ngg", 1),
                        ("ngd", 1),
                        ("nsh", 4),
                        ("nw", 1),
                        ("nm", 1),
                        ("nh", 1),
                        ("ngt", 4),
                        ("nch", 1),
                        ("nc", 1),
                        ("ngj", 2),
                        ("m", 2),
                        ("ngp", 1),
                        ("s", 1),
                        ("k", 2),
                    ],
                    129,
                    false,
                ));
            }
            b'l' => {
                out.push_str(pick_weighted(rng, &[("ng", 33), ("n", 22)], 55, false));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("iao", 2),
                        ("i", 32),
                        ("ia", 21),
                        ("a", 52),
                        ("e", 21),
                        ("ei", 6),
                        ("uo", 2),
                        ("u", 19),
                        ("ie", 1),
                        ("ua", 4),
                        ("o", 9),
                        ("ao", 3),
                        ("ai", 6),
                        ("ui", 3),
                        ("iou", 1),
                        ("ou", 1),
                        ("io", 1),
                    ],
                    184,
                    false,
                ));
            }
            b'w' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("uo", 2),
                        ("ou", 14),
                        ("iao", 3),
                        ("e", 2),
                        ("u", 7),
                        ("i", 9),
                        ("a", 1),
                        ("ao", 1),
                        ("ui", 1),
                        ("ai", 3),
                        ("ei", 3),
                        ("o", 1),
                        ("ua", 2),
                        ("ia", 1),
                    ],
                    50,
                    false,
                ));
            }
            _ => {}
        }
    }
    out
}

fn grammar_i(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Kvkvkw", 12),
            ("Vkvkw", 6),
            ("Vkvkvkw", 6),
            ("Kvkw", 13),
            ("Kvkvkvkw", 7),
            ("Vkw", 2),
            ("Kw", 1),
        ],
        47,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'K' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("H", 3),
                        ("M", 3),
                        ("N", 4),
                        ("F", 3),
                        ("S", 2),
                        ("Ch", 1),
                        ("T", 5),
                        ("G", 2),
                        ("K", 6),
                        ("Sh", 3),
                        ("W", 1),
                    ],
                    33,
                    false,
                ));
            }
            b'V' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("Ao", 1),
                        ("A", 1),
                        ("I", 3),
                        ("Ya", 3),
                        ("Ai", 1),
                        ("O", 3),
                        ("E", 1),
                        ("Oi", 1),
                    ],
                    14,
                    false,
                ));
            }
            b'k' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("kk", 1),
                        ("d", 1),
                        ("m", 16),
                        ("r", 5),
                        ("k", 16),
                        ("t", 8),
                        ("w", 5),
                        ("g", 13),
                        ("sh", 6),
                        ("b", 2),
                        ("ch", 4),
                        ("nm", 1),
                        ("n", 5),
                        ("z", 2),
                        ("f", 1),
                        ("s", 2),
                        ("tt", 1),
                        ("h", 1),
                    ],
                    90,
                    false,
                ));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("o", 11),
                        ("ai", 2),
                        ("i", 15),
                        ("a", 30),
                        ("iya", 2),
                        ("ii", 1),
                        ("u", 8),
                        ("oya", 1),
                        ("uo", 2),
                        ("yo", 2),
                        ("aya", 2),
                    ],
                    76,
                    false,
                ));
            }
            b'w' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("o", 5),
                        ("i", 11),
                        ("a", 24),
                        ("e", 3),
                        ("yo", 1),
                        ("u", 1),
                        ("ui", 1),
                        ("ie", 1),
                    ],
                    47,
                    false,
                ));
            }
            _ => {}
        }
    }
    out
}

fn grammar_j(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Kvkw", 16),
            ("Kvkvl", 17),
            ("Vkw", 1),
            ("Vkvl", 5),
            ("Kvl", 1),
        ],
        40,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'K' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("W", 2),
                        ("Ch", 9),
                        ("P", 3),
                        ("M", 1),
                        ("N", 1),
                        ("Kw", 1),
                        ("S", 6),
                        ("K", 8),
                        ("T", 2),
                        ("Hw", 1),
                    ],
                    34,
                    false,
                ));
            }
            b'V' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("Yo", 1), ("U", 3), ("A", 1), ("Ya", 1)],
                    6,
                    false,
                ));
            }
            b'k' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("nd", 3),
                        ("s", 4),
                        ("kp", 1),
                        ("j", 2),
                        ("nj", 4),
                        ("nch", 2),
                        ("n", 2),
                        ("ns", 1),
                        ("g", 1),
                        ("ls", 2),
                        ("nh", 1),
                        ("ngj", 4),
                        ("h", 1),
                        ("r", 1),
                        ("mch", 2),
                        ("ngs", 1),
                        ("ngm", 2),
                        ("lch", 1),
                        ("ng", 1),
                        ("kch", 1),
                        ("ms", 1),
                        ("ch", 1),
                    ],
                    39,
                    false,
                ));
            }
            b'l' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("ng", 8), ("n", 13), ("k", 1), ("l", 1)],
                    23,
                    false,
                ));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("a", 15),
                        ("i", 4),
                        ("o", 20),
                        ("u", 8),
                        ("ya", 2),
                        ("ae", 3),
                        ("yo", 2),
                        ("ou", 1),
                        ("e", 1),
                    ],
                    56,
                    false,
                ));
            }
            b'w' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("o", 3), ("u", 13), ("ae", 1)],
                    17,
                    false,
                ));
            }
            _ => {}
        }
    }
    out
}

fn grammar_k(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Kvkvl", 11),
            ("Vkvl", 10),
            ("Kvkvkvl", 14),
            ("Kvkw", 3),
            ("Vkvkvkvl", 3),
            ("Vkvkw", 6),
            ("Vkvkvkw", 2),
            ("Vkvkvl", 9),
            ("Vkvkvkvkw", 1),
            ("Kvkvkvkvl", 5),
            ("Kvkvkw", 3),
            ("Kvkvkvkw", 2),
            ("Kvl", 3),
            ("Kvkvkvl/Kvkvl", 1),
            ("Vkw", 1),
        ],
        74,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'/' => out.push(' '),
            b'K' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("N", 13),
                        ("K", 7),
                        ("S", 3),
                        ("T", 2),
                        ("Q", 8),
                        ("Y", 1),
                        ("Ch", 1),
                        ("Kh", 1),
                        ("P", 3),
                        ("M", 4),
                    ],
                    43,
                    false,
                ));
            }
            b'V' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("I", 9),
                        ("Ai", 2),
                        ("A", 13),
                        ("Ui", 1),
                        ("E", 1),
                        ("U", 6),
                    ],
                    31,
                    true,
                ));
            }
            b'k' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("ng", 6),
                        ("n", 16),
                        ("k", 10),
                        ("rt", 2),
                        ("dn", 1),
                        ("v", 9),
                        ("l", 13),
                        ("j", 7),
                        ("g", 10),
                        ("rn", 2),
                        ("t", 12),
                        ("h", 1),
                        ("lm", 1),
                        ("p", 3),
                        ("r", 5),
                        ("s", 2),
                        ("ks", 1),
                        ("sh", 2),
                        ("ll", 2),
                        ("rm", 2),
                        ("kch", 1),
                        ("dl", 2),
                        ("kj", 1),
                        ("q", 2),
                        ("kn", 1),
                        ("jj", 2),
                        ("ngn", 1),
                        ("dj", 1),
                        ("kt", 3),
                        ("ts", 1),
                        ("kp", 1),
                        ("ksh", 1),
                        ("m", 5),
                        ("w", 1),
                        ("tt", 1),
                        ("rr", 1),
                    ],
                    132,
                    false,
                ));
            }
            b'l' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("q", 8),
                        ("k", 30),
                        ("t", 14),
                        ("ny", 1),
                        ("nty", 1),
                        ("ntsy", 1),
                        ("tsy", 1),
                        ("n", 1),
                    ],
                    57,
                    false,
                ));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("u", 41),
                        ("a", 48),
                        ("i", 22),
                        ("e", 5),
                        ("ia", 7),
                        ("o", 8),
                        ("aa", 7),
                        ("iu", 4),
                        ("ui", 3),
                        ("ai", 2),
                        ("i'", 1),
                        ("ua", 3),
                        ("uu", 1),
                        ("au", 3),
                        ("ii", 2),
                    ],
                    157,
                    false,
                ));
            }
            b'w' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("a", 11), ("i", 5), ("o", 1), ("u", 1)],
                    18,
                    false,
                ));
            }
            _ => {}
        }
    }
    out
}

fn grammar_l(rng: &mut RetailLcg) -> String {
    let template = pick_weighted(
        rng,
        &[
            ("Kvkw", 13),
            ("Kvkvkw", 21),
            ("Kvkvkvkw", 2),
            ("Vkw", 1),
            ("Vkvkw", 3),
        ],
        40,
        false,
    );
    let mut out = String::new();
    for token in template.bytes() {
        match token {
            b'K' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("M", 8),
                        ("K", 9),
                        ("S", 2),
                        ("P", 1),
                        ("Ch", 1),
                        ("Z", 1),
                        ("L", 2),
                        ("B", 6),
                        ("D", 4),
                        ("W", 2),
                    ],
                    36,
                    false,
                ));
            }
            b'V' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("O", 1), ("A", 1), ("I", 1), ("U", 1)],
                    3,
                    true,
                ));
            }
            b'k' => {
                out.push_str(pick_weighted(
                    rng,
                    &[
                        ("ng", 12),
                        ("l", 12),
                        ("b", 7),
                        ("n", 1),
                        ("z", 1),
                        ("mb", 11),
                        ("m", 2),
                        ("s", 6),
                        ("r", 2),
                        ("shw", 1),
                        ("t", 2),
                        ("d", 1),
                        ("k", 3),
                        ("ts", 1),
                        ("h", 1),
                        ("g", 1),
                        ("kw", 1),
                        ("nd", 3),
                    ],
                    68,
                    false,
                ));
            }
            b'v' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("o", 14), ("a", 25), ("e", 7), ("u", 11), ("i", 7)],
                    63,
                    true,
                ));
            }
            b'w' => {
                out.push_str(pick_weighted(
                    rng,
                    &[("u", 5), ("o", 11), ("a", 14), ("i", 5), ("e", 5)],
                    40,
                    false,
                ));
            }
            _ => {}
        }
    }
    out
}

fn variant_e(rng: &mut RetailLcg) -> String {
    let out = alternating(
        rng,
        211,
        196,
        (&[0, 8, 2, 5, 0, 0, 0, 0], 15),
        (&[51, 10, 85, 14, 30, 5, 1, 0], 196),
        (
            &[("A", 5), ("E", 3), ("Ea", 2), ("U", 2), ("Eu", 2)],
            14,
            false,
        ),
        (
            &[
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
            ],
            188,
            false,
        ),
        (
            &[
                ("o", 97),
                ("e", 90),
                ("a", 83),
                ("i", 62),
                ("oo", 12),
                ("u", 12),
                ("ou", 11),
                ("ea", 8),
            ],
            372,
            false,
        ),
        (
            &[
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
            ],
            214,
            false,
        ),
        Some((
            &[
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
            ],
            172,
            false,
        )),
        Some((&[("e", 24), ("ia", 3), ("ea", 2)], 29, false)),
    );
    out
}

fn random_base(rng: &mut RetailLcg) -> String {
    let out = alternating(
        rng,
        1370,
        963,
        (&[92, 133, 145, 14, 14, 9, 0, 0], 407),
        (&[356, 328, 80, 135, 40, 20, 4, 0], 963),
        (
            &[
                ("A", 98),
                ("O", 85),
                ("E", 66),
                ("Ea", 66),
                ("I", 31),
                ("Au", 19),
                ("Eu", 18),
                ("Oi", 14),
            ],
            390,
            false,
        ),
        (
            &[
                ("L", 128),
                ("M", 115),
                ("R", 108),
                ("H", 91),
                ("S", 81),
                ("V", 79),
                ("C", 50),
                ("G", 48),
                ("Ch", 42),
                ("P", 37),
                ("D", 29),
                ("B", 28),
                ("T", 26),
                ("N", 15),
                ("Pr", 14),
                ("Rh", 13),
                ("Fr", 12),
                ("Cr", 8),
            ],
            924,
            false,
        ),
        (
            &[
                ("a", 369),
                ("e", 354),
                ("i", 223),
                ("o", 219),
                ("oi", 108),
                ("au", 105),
                ("u", 100),
                ("ai", 44),
                ("ou", 40),
                ("ei", 31),
                ("ie", 29),
            ],
            1604,
            false,
        ),
        (
            &[
                ("t", 180),
                ("r", 179),
                ("c", 153),
                ("v", 97),
                ("n", 81),
                ("nn", 73),
                ("gr", 58),
                ("s", 52),
                ("nt", 45),
                ("rn", 43),
                ("lp", 33),
                ("ll", 31),
                ("d", 29),
                ("l", 28),
                ("gn", 25),
                ("rd", 23),
                ("q", 21),
                ("nc", 20),
                ("m", 20),
                ("nd", 19),
                ("ss", 18),
                ("ndr", 16),
                ("rth", 14),
                ("tl", 13),
                ("rm", 12),
                ("rr", 12),
                ("nch", 11),
                ("rs", 10),
                ("y", 9),
                ("yr", 9),
                ("cl", 8),
                ("sn", 8),
                ("sg", 8),
                ("b", 7),
                ("ntr", 7),
                ("z", 7),
                ("mm", 7),
            ],
            1384,
            false,
        ),
        Some((
            &[
                ("s", 160),
                ("f", 96),
                ("rc", 80),
                ("r", 72),
                ("n", 41),
                ("t", 31),
                ("l", 22),
                ("rd", 16),
                ("rn", 15),
                ("ts", 9),
                ("nt", 8),
                ("y", 8),
                ("rr", 8),
                ("rs", 8),
                ("x", 8),
                ("z", 7),
                ("lt", 6),
                ("ys", 6),
                ("c", 6),
                ("rt", 6),
            ],
            610,
            false,
        )),
        Some((
            &[("e", 677), ("i", 14), ("ie", 11), ("oie", 11)],
            704,
            false,
        )),
    );
    out
}

fn variant_c(rng: &mut RetailLcg) -> String {
    let out = alternating(
        rng,
        235,
        197,
        (&[8, 0, 26, 0, 4, 0, 0, 0], 38),
        (&[0, 53, 0, 137, 0, 7, 0, 0], 197),
        (
            &[("A", 16), ("E", 12), ("U", 4), ("O", 2), ("Ao", 2)],
            36,
            false,
        ),
        (
            &[
                ("L", 26),
                ("P", 25),
                ("C", 22),
                ("V", 21),
                ("S", 19),
                ("R", 18),
                ("T", 15),
                ("M", 13),
                ("B", 9),
                ("Tr", 6),
                ("G", 6),
                ("Fr", 5),
                ("F", 4),
                ("N", 3),
            ],
            192,
            false,
        ),
        (
            &[
                ("a", 122),
                ("e", 83),
                ("o", 76),
                ("i", 70),
                ("u", 18),
                ("ie", 13),
            ],
            378,
            false,
        ),
        (
            &[
                ("n", 60),
                ("l", 48),
                ("m", 35),
                ("r", 28),
                ("t", 21),
                ("s", 16),
                ("rd", 16),
                ("c", 16),
                ("nt", 16),
                ("gn", 15),
                ("sc", 13),
                ("z", 12),
                ("v", 12),
                ("mb", 11),
                ("br", 10),
                ("g", 10),
                ("ss", 8),
                ("mp", 7),
                ("d", 6),
                ("st", 6),
                ("nz", 6),
                ("gl", 5),
                ("zz", 5),
                ("ll", 5),
                ("rch", 4),
                ("rn", 4),
                ("lt", 3),
                ("gg", 3),
                ("rb", 3),
                ("cc", 3),
                ("b", 2),
                ("rr", 2),
                ("nn", 2),
                ("mbr", 2),
            ],
            414,
            false,
        ),
        None,
        Some((
            &[("ia", 72), ("a", 62), ("o", 46), ("e", 26), ("i", 19)],
            225,
            false,
        )),
    );
    out
}

fn variant_b(rng: &mut RetailLcg) -> String {
    let out = alternating(
        rng,
        3400,
        3244,
        (&[10, 39, 59, 15, 31, 2, 0, 0], 156),
        (&[394, 745, 575, 925, 273, 313, 19, 0], 3244),
        (&[("O", 93), ("U", 28), ("I", 26), ("A", 8)], 149, false),
        (
            &[
                ("N", 218),
                ("L", 215),
                ("P", 195),
                ("V", 190),
                ("M", 187),
                ("B", 186),
                ("K", 183),
                ("H", 160),
                ("S", 157),
                ("D", 146),
                ("R", 141),
                ("T", 116),
                ("C", 108),
                ("Z", 103),
                ("J", 71),
                ("Br", 70),
                ("Hr", 67),
                ("Kr", 59),
                ("Pr", 58),
                ("St", 53),
                ("Sl", 40),
                ("Tr", 33),
                ("Str", 32),
                ("Kl", 31),
                ("G", 26),
                ("Trn", 22),
                ("Bystr", 22),
                ("Sv", 21),
                ("Sp", 20),
                ("Dr", 18),
                ("Pl", 17),
                ("Zl", 13),
                ("Vr", 12),
                ("Sm", 11),
                ("F", 9),
                ("Zv", 9),
                ("Hn", 8),
                ("Dv", 8),
                ("Ch", 8),
                ("Sk", 8),
                ("Vrb", 8),
                ("Bl", 8),
                ("Trst", 7),
                ("Hl", 7),
                ("Zb", 7),
                ("Kys", 6),
                ("Kv", 5),
                ("Hrnc", 5),
                ("Gr", 5),
                ("Krt", 5),
                ("Vys", 5),
                ("Skl", 4),
                ("Mn", 4),
                ("Zd", 4),
                ("Chr", 4),
            ],
            3134,
            false,
        ),
        (
            &[
                ("o", 1916),
                ("a", 1638),
                ("i", 1038),
                ("e", 987),
                ("u", 478),
            ],
            6002,
            false,
        ),
        (
            &[
                ("v", 552),
                ("c", 376),
                ("n", 341),
                ("l", 317),
                ("vc", 274),
                ("r", 253),
                ("s", 194),
                ("t", 174),
                ("k", 157),
                ("d", 142),
                ("b", 136),
                ("m", 106),
                ("z", 103),
                ("st", 97),
                ("rn", 91),
                ("nsk", 88),
                ("p", 87),
                ("h", 83),
                ("lk", 66),
                ("ch", 55),
                ("vsk", 54),
                ("sk", 53),
                ("ck", 53),
                ("ln", 52),
                ("nc", 49),
                ("zn", 45),
                ("j", 43),
                ("sl", 35),
                ("nk", 35),
                ("tr", 34),
                ("vn", 33),
                ("br", 30),
                ("lc", 29),
                ("dn", 29),
                ("pl", 28),
                ("sn", 26),
                ("dz", 26),
                ("rt", 23),
                ("jn", 21),
                ("ssk", 20),
                ("tn", 20),
                ("cn", 19),
                ("rc", 19),
                ("rsk", 18),
                ("pt", 17),
                ("nn", 17),
                ("bl", 16),
                ("str", 16),
                ("nt", 16),
                ("vk", 16),
                ("dv", 14),
                ("hr", 14),
                ("dr", 14),
                ("dhr", 13),
                ("dl", 13),
                ("rk", 13),
                ("nd", 13),
                ("rv", 12),
                ("rd", 12),
                ("mn", 11),
                ("pr", 10),
                ("bn", 10),
                ("tk", 10),
                ("ls", 8),
                ("rl", 8),
                ("lt", 8),
                ("f", 8),
                ("dk", 8),
                ("dc", 8),
                ("mb", 8),
                ("g", 7),
                ("zm", 6),
                ("mr", 6),
                ("zsk", 6),
                ("rm", 6),
                ("dm", 6),
                ("kr", 6),
                ("tl", 6),
                ("pc", 6),
                ("ndr", 6),
                ("mpl", 6),
                ("mc", 5),
                ("kl", 5),
                ("cht", 5),
                ("hl", 5),
                ("pn", 5),
            ],
            4888,
            false,
        ),
        Some((
            &[
                ("ny", 188),
                ("v", 188),
                ("d", 121),
                ("n", 112),
                ("c", 109),
                ("k", 99),
                ("s", 67),
                ("m", 66),
                ("r", 43),
                ("ky", 26),
                ("l", 24),
                ("lny", 18),
                ("lky", 16),
                ("j", 15),
                ("vsky", 13),
                ("ly", 12),
                ("rny", 11),
                ("ry", 11),
                ("dy", 10),
                ("nky", 9),
                ("chy", 9),
                ("cky", 9),
                ("z", 9),
                ("hy", 8),
                ("zny", 8),
                ("t", 8),
                ("ty", 8),
                ("vy", 6),
                ("nsky", 6),
                ("ch", 6),
                ("b", 6),
                ("by", 5),
                ("st", 4),
                ("ssky", 4),
                ("rsky", 4),
                ("mky", 4),
                ("h", 4),
            ],
            1264,
            false,
        )),
        Some((
            &[("a", 1060), ("e", 818), ("o", 104), ("ou", 45)],
            1999,
            false,
        )),
    );
    out
}

fn variant_a(rng: &mut RetailLcg) -> String {
    let out = alternating(
        rng,
        678,
        586,
        (&[7, 31, 8, 21, 15, 7, 3, 0], 92),
        (&[143, 73, 224, 56, 63, 23, 4, 0], 586),
        (
            &[
                ("A", 44),
                ("O", 15),
                ("E", 12),
                ("I", 11),
                ("U", 4),
                ("Au", 4),
            ],
            89,
            false,
        ),
        (
            &[
                ("C", 46),
                ("B", 43),
                ("M", 40),
                ("S", 38),
                ("H", 34),
                ("P", 33),
                ("R", 31),
                ("J", 26),
                ("G", 26),
                ("L", 25),
                ("D", 21),
                ("T", 20),
                ("K", 20),
                ("N", 19),
                ("W", 19),
                ("F", 16),
                ("Ch", 12),
                ("Gr", 11),
                ("V", 11),
                ("St", 10),
                ("Br", 6),
                ("Tr", 6),
                ("Fr", 6),
                ("Fl", 5),
                ("Y", 5),
                ("Th", 5),
                ("Ph", 4),
                ("Cl", 4),
                ("Sh", 4),
                ("Sp", 4),
                ("Wh", 4),
                ("Pr", 3),
                ("Sc", 3),
                ("Spr", 3),
                ("Pl", 2),
                ("Lyk", 2),
            ],
            567,
            false,
        ),
        (
            &[
                ("a", 335),
                ("e", 260),
                ("o", 215),
                ("i", 199),
                ("u", 63),
                ("ou", 18),
                ("ea", 15),
                ("oo", 14),
                ("ia", 13),
                ("ie", 10),
                ("ua", 9),
                ("ai", 9),
                ("io", 8),
            ],
            1167,
            false,
        ),
        (
            &[
                ("l", 49),
                ("n", 44),
                ("m", 39),
                ("r", 35),
                ("ll", 33),
                ("v", 25),
                ("t", 25),
                ("c", 22),
                ("nc", 21),
                ("s", 20),
                ("nt", 20),
                ("g", 19),
                ("d", 18),
                ("p", 17),
                ("nd", 17),
                ("b", 14),
                ("h", 12),
                ("rr", 11),
                ("rg", 11),
                ("ss", 11),
                ("k", 9),
                ("w", 9),
                ("f", 9),
                ("st", 9),
                ("nn", 9),
                ("rn", 8),
                ("ng", 7),
                ("sh", 7),
                ("rt", 7),
                ("ns", 6),
                ("ch", 6),
                ("bl", 6),
                ("yl", 5),
                ("mp", 5),
                ("tt", 5),
                ("rm", 5),
                ("dg", 5),
                ("rl", 5),
                ("lt", 5),
                ("x", 5),
                ("rs", 4),
                ("rv", 4),
                ("y", 4),
                ("rd", 4),
                ("sk", 4),
                ("br", 4),
                ("ls", 3),
                ("tr", 3),
                ("nv", 3),
                ("ff", 3),
                ("sc", 3),
                ("dd", 3),
                ("tl", 3),
                ("lb", 3),
                ("pp", 3),
                ("nth", 2),
                ("nr", 2),
                ("rwh", 2),
                ("mpl", 2),
                ("cks", 2),
                ("ms", 2),
                ("dl", 2),
                ("nh", 2),
                ("lph", 2),
                ("mm", 2),
                ("wp", 2),
                ("nst", 2),
                ("mpt", 2),
                ("ct", 2),
                ("ld", 2),
                ("nj", 2),
                ("tf", 2),
                ("rb", 2),
                ("sl", 2),
                ("spr", 2),
                ("rk", 2),
                ("rf", 2),
                ("rch", 2),
                ("gg", 2),
                ("ndr", 2),
                ("j", 2),
                ("q", 2),
                ("ttl", 2),
                ("ncr", 1),
                ("ngt", 1),
                ("sn", 1),
                ("lv", 1),
                ("tch", 1),
                ("nb", 1),
                ("hr", 1),
                ("xc", 1),
                ("rpr", 1),
                ("ngl", 1),
                ("lr", 1),
                ("gl", 1),
                ("cr", 1),
                ("yt", 1),
                ("rh", 1),
                ("thf", 1),
                ("cs", 1),
                ("xtr", 1),
                ("mph", 1),
                ("ryl", 1),
                ("lh", 1),
                ("ftw", 1),
                ("ngr", 1),
                ("tn", 1),
                ("nq", 1),
                ("mst", 1),
                ("kr", 1),
                ("mf", 1),
                ("rp", 1),
                ("yw", 1),
                ("rsv", 1),
                ("lymp", 1),
                ("sbr", 1),
                ("wb", 1),
                ("bb", 1),
                ("mpb", 1),
                ("md", 1),
                ("gh", 1),
                ("cl", 1),
                ("kl", 1),
                ("nk", 1),
                ("ck", 1),
                ("rj", 1),
                ("nsw", 1),
                ("sd", 1),
                ("tw", 1),
                ("wst", 1),
                ("lst", 1),
                ("rw", 1),
                ("ngh", 1),
                ("gd", 1),
                ("llf", 1),
                ("ssfr", 1),
                ("hl", 1),
                ("nkl", 1),
                ("ffm", 1),
                ("shm", 1),
                ("z", 1),
                ("ssw", 1),
                ("wkb", 1),
                ("rtf", 1),
                ("nbr", 1),
                ("th", 1),
                ("dn", 1),
                ("sv", 1),
                ("yb", 1),
                ("lyb", 1),
                ("shl", 1),
                ("pl", 1),
                ("db", 1),
                ("wh", 1),
                ("df", 1),
                ("rth", 1),
                ("rtl", 1),
                ("rc", 1),
                ("ntp", 1),
                ("rct", 1),
                ("rdf", 1),
                ("mphr", 1),
            ],
            781,
            false,
        ),
        Some((
            &[
                ("n", 91),
                ("r", 48),
                ("s", 45),
                ("y", 19),
                ("ll", 16),
                ("l", 16),
                ("ng", 12),
                ("sh", 12),
                ("nd", 11),
                ("rt", 11),
                ("m", 11),
                ("t", 10),
                ("d", 10),
                ("nt", 10),
                ("hn", 9),
                ("tt", 9),
                ("ck", 9),
                ("rd", 8),
                ("st", 6),
                ("ty", 6),
                ("x", 6),
                ("rs", 5),
                ("ry", 5),
                ("rk", 5),
                ("rn", 5),
                ("w", 5),
                ("nry", 4),
                ("h", 4),
                ("c", 4),
                ("ns", 4),
                ("wn", 3),
                ("ft", 3),
                ("lt", 3),
                ("th", 3),
                ("ch", 3),
                ("sp", 2),
                ("wk", 2),
                ("rg", 2),
                ("rts", 2),
                ("lf", 2),
                ("v", 2),
                ("nty", 2),
                ("ld", 2),
                ("g", 2),
                ("lk", 2),
                ("rry", 2),
                ("gh", 2),
                ("dy", 2),
                ("tty", 1),
                ("sky", 1),
                ("tch", 1),
                ("k", 1),
                ("rgh", 1),
                ("ss", 1),
                ("p", 1),
                ("rr", 1),
                ("rl", 1),
                ("ws", 1),
                ("ms", 1),
                ("lls", 1),
                ("dd", 1),
                ("ght", 1),
                ("pply", 1),
                ("nk", 1),
            ],
            473,
            false,
        )),
        Some((
            &[
                ("e", 86),
                ("a", 43),
                ("o", 24),
                ("ia", 9),
                ("i", 5),
                ("ue", 3),
                ("oe", 2),
                ("eau", 2),
                ("au", 2),
                ("io", 2),
            ],
            177,
            false,
        )),
    );
    out
}

fn variant_d(rng: &mut RetailLcg) -> String {
    let mut out = alternating(
        rng,
        286,
        253,
        (&[4, 4, 18, 3, 4, 0, 0, 0], 33),
        (&[0, 55, 18, 106, 36, 30, 8, 0], 253),
        (
            &[("A", 16), ("O", 10), ("I", 4), ("E", 1), ("Ao", 1)],
            31,
            true,
        ),
        (
            &[
                ("M", 29),
                ("C", 27),
                ("L", 24),
                ("P", 20),
                ("V", 19),
                ("F", 18),
                ("R", 18),
                ("B", 17),
                ("S", 13),
                ("G", 12),
                ("T", 10),
                ("N", 9),
                ("Tr", 8),
                ("D", 6),
                ("Br", 4),
                ("Ch", 4),
                ("Gr", 3),
                ("Pr", 3),
                ("Sp", 3),
                ("St", 2),
            ],
            248,
            false,
        ),
        (
            &[
                ("a", 161),
                ("o", 137),
                ("e", 136),
                ("i", 95),
                ("ia", 24),
                ("u", 13),
                ("io", 12),
            ],
            575,
            false,
        ),
        (
            &[
                ("n", 86),
                ("r", 67),
                ("v", 34),
                ("l", 30),
                ("s", 27),
                ("t", 22),
                ("c", 18),
                ("m", 15),
                ("ss", 13),
                ("nt", 13),
                ("gn", 13),
                ("g", 13),
                ("d", 12),
                ("nz", 11),
                ("ll", 11),
                ("tt", 9),
                ("st", 9),
                ("rm", 8),
                ("gl", 8),
                ("rt", 8),
                ("nd", 7),
                ("zz", 7),
                ("cc", 6),
                ("gg", 6),
                ("nc", 6),
                ("b", 5),
                ("rn", 5),
                ("nn", 5),
                ("p", 5),
                ("z", 4),
                ("rv", 4),
                ("mp", 4),
                ("f", 4),
                ("sc", 4),
                ("rr", 4),
                ("rd", 3),
                ("rl", 3),
                ("rc", 3),
                ("gr", 3),
                ("dr", 3),
                ("lb", 3),
                ("bb", 2),
                ("str", 2),
                ("rs", 2),
                ("lv", 2),
                ("lm", 2),
                ("ng", 2),
                ("lc", 2),
                ("rg", 2),
                ("rb", 2),
            ],
            538,
            false,
        ),
        None,
        Some((
            &[
                ("o", 72),
                ("a", 65),
                ("e", 30),
                ("i", 20),
                ("ia", 19),
                ("io", 8),
            ],
            208,
            false,
        )),
    );
    if rng.next_sample_15().is_multiple_of(10) && out.chars().count() < 10 {
        if out.ends_with('o') {
            out.insert_str(0, "San ");
        } else if out.ends_with('a') {
            out.insert_str(0, "Santa ");
        }
    }
    out
}

const BANNED: &[&str] = &[
    "Fuck",
    "Shit",
    "Cunt",
    "Whore",
    "Ass",
    "Penis",
    "Vagina",
    "Piss",
    "Pussy",
    "Twat",
    "Nigger",
    "Gook",
    "Kike",
    "Spic",
    "Nazi",
    "Hitler",
    "Cock",
    "Fag",
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
    "Bitch",
    "Feces",
];

fn variant_zero(rng: &mut RetailLcg) -> String {
    let mut out = random_base(rng);
    if out.chars().count() < 9 && rng.next_sample_15().is_multiple_of(10) {
        out.push('-');
        out.push_str(&random_base(rng));
    }
    out
}

fn generate_variant(rng: &mut RetailLcg, variant: u8) -> String {
    loop {
        let out = match variant % 18 {
            0 => variant_zero(rng),
            1 => variant_c(rng),
            2 => variant_e(rng),
            3 => variant_a(rng),
            4 => variant_b(rng),
            5 => grammar_h(rng),
            6 => grammar_k(rng),
            7 => grammar_b(rng),
            8 => variant_d(rng),
            9 => grammar_i(rng),
            10 => grammar_g(rng),
            11 => grammar_f(rng),
            12 => grammar_j(rng),
            13 => grammar_c(rng),
            14 => grammar_e(rng),
            15 => grammar_l(rng),
            16 => grammar_d(rng),
            17 => grammar_a(rng),
            _ => unreachable!(),
        };
        if !should_retry_mapped_flavor_text(&out) {
            return out;
        }
    }
}

fn should_retry_mapped_flavor_text(text: &str) -> bool {
    BANNED.iter().any(|banned| text.contains(banned))
}

pub(crate) fn generate_english_name(rng: &mut RetailLcg) -> String {
    generate_variant(rng, 2)
}

pub(crate) fn generate_ethnic_name(rng: &mut RetailLcg, nation: NationId) -> String {
    let variant = match nation {
        NationId::Major(id) => MAJOR_NATION_VARIANTS[id.get()],
        NationId::Minor(id) => MINOR_NATION_VARIANTS[id.get()],
    };
    generate_variant(rng, variant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_the_retail_banned_word_instead_of_the_sanitized_replacement() {
        assert!(should_retry_mapped_flavor_text("New Hitlerburg"));
        assert!(!should_retry_mapped_flavor_text("Hitman"));
    }
}
