//! Sec-MS-GEC v2 token generation.
//!
//! The token is `<16 hex cs64>-<64 hex digest>`, where the digest is a SHA-256
//! compression over the block layout Edge itself uses: the first seven bytes of
//! the token are folded into a zero padded block and the remainder is hashed as
//! a second block with a length field that includes that first block. A general
//! purpose SHA-256 therefore cannot reproduce it and the compression function is
//! implemented here instead.
//!
//! See <https://github.com/rany2/edge-tts/issues/290#issuecomment-2464956570>.

#![allow(clippy::unreadable_literal)]

const WIN_EPOCH: u64 = 11644473600;
pub(super) const TRUSTED_CLIENT_TOKEN: &str = "6A5AA1D4EAFF4E9FB37E23D68491D6F4";
pub(super) const SEC_MS_GEC_VERSION: &str = "2-130.0.2849.68";

/// SHA-256 initial hash value (FIPS 180-4).
const INITIAL_STATE: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Working state the token's first block is compressed from.
const FIRST_BLOCK_STATE: [u32; 8] = [
    0xFD9FBEA2, 0x91243CE7, 0xBE499094, 0xCD2E1E0A, 0x6C006F49, 0x04BD35AB, 0xFEB0A7E4, 0x03EFFBD2,
];

/// SHA-256 round constants (FIPS 180-4).
const ROUND_CONSTANTS: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

/// Schedule words the first block contributes to its own expansion.
const FIRST_BLOCK_SCHEDULE: [u32; 14] = [
    0xEB24BF9E, 0x1558691F, 0xA0C09EE2, 0x0CFA32BA, 0xA622EE8C, 0xD1DD9491, 0xC0DD25A0, 0xF9E70AB6,
    0xF0C31573, 0x7058CE4E, 0x7188E606, 0x00E5AB33, 0xD258B060, 0x72766564,
];

/// Round constant of the token's first block, which carries the token
/// prefix rather than message data.
const FIRST_BLOCK_CONSTANT: u32 = 0xC9DC06A7;
const FIRST_BLOCK_SIGMA0_ADJUSTMENT: u32 = 0x059C0B80;
const FIRST_BLOCK_SIGMA1_ADJUSTMENT: u32 = 0x000B92C0;

/// Coefficients and offsets of the CS64 digest.
const CS64_COEFFICIENTS: [(u32, u32); 14] = [
    (0xE82E91B1, 0xB32700D0),
    (0x44DE24C6, 0x88DFF51D),
    (0x3BEB65BC, 0x29514038),
    (0xC89C5933, 0xB328CBDF),
    (0x8D1EC211, 0xD405B4D5),
    (0x314EF5D5, 0x26E55F3C),
    (0xE92491B1, 0x607801C6),
    (0xF0A5B9D5, 0x82B2C1FB),
    (0x06064CF3, 0xFA51A3DA),
    (0xDA79FA60, 0x207CC464),
    (0xBED20560, 0x3C3C74F3),
    (0x89F9C9F8, 0xD2D14B61),
    (0x35FA38C6, 0xBB04A2C1),
    (0xCB49E3C6, 0xC5626167),
];
const CS64_FACTOR: u32 = 0x82893933;
const CS64_ADJUSTMENT0: u32 = 0xF2F90B1A;
const CS64_ADJUSTMENT1: u32 = 0x0B1A0000;

const fn first_block_constants() -> [u32; 64] {
    let mut constants = ROUND_CONSTANTS;
    constants[14] = FIRST_BLOCK_CONSTANT;
    constants
}

/// SHA-256 small sigma zero.
fn sigma0(value: u32) -> u32 {
    (value >> 7) ^ (value << 25) ^ (value >> 18) ^ (value << 14) ^ (value >> 3)
}

/// SHA-256 small sigma one.
fn sigma1(value: u32) -> u32 {
    (value >> 17) ^ (value << 15) ^ (value >> 19) ^ (value << 13) ^ (value >> 10)
}

/// Expand the message schedule of a block, resuming at `first_word`.
fn expand_schedule(words: &mut [u32; 64], first_word: usize) {
    for index in first_word..64 {
        words[index] = sigma1(words[index - 2])
            .wrapping_add(words[index - 7])
            .wrapping_add(sigma0(words[index - 15]))
            .wrapping_add(words[index - 16]);
    }
}

/// Run the SHA-256 rounds of a block, resuming at `first_round`.
///
/// The token's first block resumes at round 14 with the prefix replacing
/// the leading rounds, every following block runs all rounds.
fn compress_rounds(
    state: [u32; 8],
    words: &[u32; 64],
    first_round: usize,
    constants: &[u32; 64],
) -> [u32; 8] {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
    for index in first_round..64 {
        let t1 = h
            .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
            .wrapping_add(g ^ (e & (f ^ g)))
            .wrapping_add(constants[index])
            .wrapping_add(words[index]);
        let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
            .wrapping_add((a & b) | (c & (a | b)));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    [a, b, c, d, e, f, g, h]
}

/// State after the token's first block, which only depends on its prefix.
fn first_block_state(prefix: &[u8]) -> [u32; 8] {
    debug_assert!(prefix.len() >= 7);

    let mut words = [0u32; 64];
    words[14] = u32::from_be_bytes([0, prefix[0], prefix[1], prefix[2]]);
    words[15] = u32::from_be_bytes(prefix[3..7].try_into().unwrap());

    for index in 16..30 {
        let mut value = FIRST_BLOCK_SCHEDULE[index - 16];
        let s1 = if index == 16 {
            sigma1(words[index - 2]) ^ FIRST_BLOCK_SIGMA1_ADJUSTMENT
        } else {
            sigma1(words[index - 2])
        };
        value = value.wrapping_add(s1);

        if index >= 21 {
            value = value.wrapping_add(words[index - 7]);
        }
        if index >= 29 {
            let s0 = if index == 29 {
                sigma0(words[index - 15]) ^ FIRST_BLOCK_SIGMA0_ADJUSTMENT
            } else {
                sigma0(words[index - 15])
            };
            value = value.wrapping_add(s0);
        }
        words[index] = value;
    }

    words[30] = sigma1(words[28])
        .wrapping_add(words[23])
        .wrapping_add(sigma0(words[15]))
        .wrapping_add(words[14])
        .wrapping_add(FIRST_BLOCK_CONSTANT)
        .wrapping_sub(ROUND_CONSTANTS[14]);
    expand_schedule(&mut words, 31);

    let working = compress_rounds(FIRST_BLOCK_STATE, &words, 14, &first_block_constants());
    std::array::from_fn(|index| INITIAL_STATE[index].wrapping_add(working[index]))
}

/// Digest of the token data.
fn digest(data: &[u8]) -> [u8; 32] {
    debug_assert!(data.len() >= 7);

    // The first seven bytes are hashed by `first_block_state`, the rest is
    // padded and hashed as message data of the following blocks.
    let length = 57 + data.len();
    let mut padded = Vec::with_capacity(data.len() + 9);
    padded.extend_from_slice(&data[7..]);
    padded.push(0x80);
    padded.resize(padded.len() + (55usize.wrapping_sub(length) % 64), 0);
    padded.extend_from_slice(&(length as u64 * 8).to_be_bytes());

    let mut state = first_block_state(&data[..7]);
    for block in padded.as_chunks::<64>().0 {
        let mut words = [0u32; 64];
        for (index, word) in block.as_chunks::<4>().0.iter().enumerate() {
            words[index] = u32::from_be_bytes(*word);
        }
        expand_schedule(&mut words, 16);

        let working = compress_rounds(state, &words, 0, &ROUND_CONSTANTS);
        for (value, round) in state.iter_mut().zip(working) {
            *value = value.wrapping_add(round);
        }
    }

    let mut digest = [0u8; 32];
    for (chunk, value) in digest.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    digest
}

/// Split data into little-endian 32-bit words, zero-padded to an even count.
fn words_le4_even(data: &[u8]) -> Vec<u32> {
    let mut words: Vec<u32> = data
        .chunks(4)
        .map(|word| {
            let mut buffer = [0u8; 4];
            buffer[..word.len()].copy_from_slice(word);
            u32::from_le_bytes(buffer)
        })
        .collect();
    if !words.len().is_multiple_of(2) {
        words.push(0);
    }
    words
}

/// Compute the two CS64 digest words of the token data.
fn cs64_digest(data: &[u8], digest: &[u8; 32]) -> (u32, u32) {
    let key_a = u32::from_le_bytes(digest[0..4].try_into().unwrap()) | 1;
    let key_b = u32::from_le_bytes(digest[4..8].try_into().unwrap()) | 1;
    let factors = [
        key_a.wrapping_mul(CS64_FACTOR),
        key_b.wrapping_mul(CS64_FACTOR),
    ];

    let mut terms = Vec::with_capacity(CS64_COEFFICIENTS.len() * 2);
    let mut offsets = Vec::with_capacity(CS64_COEFFICIENTS.len() * 2);
    for (index, (coefficient, offset)) in CS64_COEFFICIENTS.iter().enumerate() {
        terms.push(coefficient.wrapping_mul(factors[index % 2]));
        offsets.push(*offset);
    }

    // The token data is prefixed with a zero byte to keep the words even.
    let mut prefixed = Vec::with_capacity(data.len() + 1);
    prefixed.push(0);
    prefixed.extend_from_slice(data);

    for (index, word) in words_le4_even(&prefixed).into_iter().enumerate() {
        let even = index % 2 == 0;
        let mut term = word.wrapping_mul(if even { key_a } else { key_b });
        let mut offset =
            word.rotate_left(16)
                .wrapping_mul(if even { 0xEF0569FB } else { 0xC31713DB });
        if index == 0 {
            term = term.wrapping_add(CS64_ADJUSTMENT0.wrapping_mul(factors[0]));
            offset = offset.wrapping_add(CS64_ADJUSTMENT1);
        }
        terms.push(term);
        offsets.push(offset);
    }

    let mut swap_acc = 0u32;
    let mut swap_last = 0u32;
    let mut state = 0u32;
    let mut acc = 0u32;
    for index in (0..terms.len()).step_by(2) {
        let (x, y) = (terms[index], terms[index + 1]);

        let q = (offsets[index].wrapping_add(x))
            .rotate_left(16)
            .wrapping_mul(0x76F50F34);
        swap_acc =
            swap_acc.wrapping_add(q.rotate_left(16).wrapping_mul(0xC3EFEA97).wrapping_add(q));

        let q = (offsets[index + 1].wrapping_add(y))
            .rotate_left(16)
            .wrapping_mul(0x1881CE3C);
        swap_last = q.rotate_left(16).wrapping_mul(0x35BD1EC9).wrapping_add(q);
        swap_acc = swap_acc.wrapping_add(swap_last);

        state = state.wrapping_mul(key_a).wrapping_add(x);
        state = state.rotate_left(16).wrapping_mul(0xCF98B111);
        state = state.rotate_left(16).wrapping_mul(0x87085B9F);
        state = state.rotate_left(16).wrapping_mul(0x12CEB96D);
        state = state.rotate_left(16).wrapping_mul(0x257E1D83);
        acc = acc.wrapping_add(state);

        let mut value = state.wrapping_mul(key_b).wrapping_add(y);
        value = value.rotate_left(16).wrapping_mul(0xA27416F5);
        value = value.rotate_left(16).wrapping_mul(0xD38396FF);
        state = value
            .rotate_left(16)
            .wrapping_mul(0x7C932B89)
            .rotate_left(16)
            .wrapping_mul(0xBFA49F69);
        acc = acc.wrapping_add(state);
    }

    (swap_last ^ state, swap_acc ^ acc)
}

/// Generate a Sec-MS-GEC token for a Unix timestamp in seconds.
pub(super) fn generate(unix_seconds: u64) -> String {
    // Windows file time, rounded down to the nearest five minutes.
    let ticks = unix_seconds + WIN_EPOCH;
    let ticks = ticks - ticks % 300;
    let token_data = format!("{}{}", ticks * 10_000_000, TRUSTED_CLIENT_TOKEN);

    let digest = digest(token_data.as_bytes());
    let (cs64_first, cs64_second) = cs64_digest(token_data.as_bytes(), &digest);

    let mut cs64 = [0u8; 8];
    cs64[..4].copy_from_slice(&cs64_first.to_le_bytes());
    cs64[4..].copy_from_slice(&cs64_second.to_le_bytes());

    format!("{}-{}", hex::encode_upper(cs64), hex::encode_upper(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tokens of the reference implementation in edge-tts.
    #[test]
    fn matches_reference() {
        let cases: &[(u64, &str)] = &[
            (
                0,
                "52BC7A17B50DFEC9-28C4394775C8751CD2F6859C030C06DB1489ACAB3B3A7651831FC26895177ED6",
            ),
            (
                1,
                "52BC7A17B50DFEC9-28C4394775C8751CD2F6859C030C06DB1489ACAB3B3A7651831FC26895177ED6",
            ),
            (
                299,
                "52BC7A17B50DFEC9-28C4394775C8751CD2F6859C030C06DB1489ACAB3B3A7651831FC26895177ED6",
            ),
            (
                300,
                "F7535A20A262E331-28675BF85C7106BBF20035A78FCB0B6890813EAD5C3B983EF3424931B720BABB",
            ),
            (
                301,
                "F7535A20A262E331-28675BF85C7106BBF20035A78FCB0B6890813EAD5C3B983EF3424931B720BABB",
            ),
            (
                1234567890,
                "BA405D1577B8E0CE-61F01E88539977A1A1E969572D82EECFA45FB1E5DEBD122D6ACBAF0054F959E5",
            ),
            (
                1757000000,
                "F7EC5B6CCB808281-429A288577F29B9CEEF16814E3FC353B2CF7C35357E8D86777622D2EDE4BDECF",
            ),
            (
                1757000123,
                "AD866FE3D19EE432-2E23ED9D64878526DC8E52B9FE8ADB853378B54E3AA04F44BCF182981E209A27",
            ),
            (
                1757999999,
                "E37F7399968814D5-299D8625BE37B779465C14BCB7F97AC44CF41CDAD3D03DA2B170F219E5EB9B5F",
            ),
            (
                2000000000,
                "2D62557F1142BC5D-FD9C30C68FF194A5EE6B45FEFC5E2BA1D1239F88A90569AB55CFFFAA7799F40E",
            ),
            (
                2147483647,
                "96AE288915A09C99-EB52B45DB68387A1383783E40D42BBBD69D4DCCDF2540629BD4E7FB2E3287822",
            ),
            (
                4102444800,
                "DD230DB44FEE2FD7-DA0D4FA797866E36C992FABB81DD2F9DB37EB74D675D63228277003DCD3F9F8C",
            ),
        ];

        for (unix_seconds, expected) in cases {
            assert_eq!(&generate(*unix_seconds), expected);
        }
    }

    /// The token covers a five minute window, so it only changes on its border.
    #[test]
    fn window_is_five_minutes() {
        assert_eq!(generate(1757000123), generate(1757000399));
        assert_ne!(generate(1757000399), generate(1757000400));
    }

    #[test]
    fn token_shape() {
        let token = generate(1757000000);
        let (cs64, digest) = token.split_once('-').expect("token is split by a dash");
        assert_eq!(cs64.len(), 16);
        assert_eq!(digest.len(), 64);
        assert!(token_is_hex(cs64) && token_is_hex(digest));
    }

    fn token_is_hex(value: &str) -> bool {
        value
            .chars()
            .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c))
    }
}
