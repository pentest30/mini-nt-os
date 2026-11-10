//! DEFLATE (RFC 1951), to unpack the ZIP that `fetch-userland` downloads;
//! std only. The output goes to a sink as it comes, the last 32 KiB kept for
//! back-references; codes up to 9 bits decode through a table, longer ones
//! bit by bit. CRC-32 (ISO 3309, as ZIP uses it) checks the result.

use std::io::Write;

/// The window of back-references.
const WINDOW: usize = 32 * 1024;
/// Codes of at most this many bits decode through the table.
const FAST_BITS: u32 = 9;

const LENGTH_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LENGTH_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
/// The order of the code length code lengths in a dynamic block header.
const CODE_LENGTH_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// A running CRC-32.
pub struct Crc32 {
    table: [u32; 256],
    value: u32,
}

impl Crc32 {
    pub fn new() -> Self {
        let mut table = [0u32; 256];
        for (n, entry) in table.iter_mut().enumerate() {
            let mut c = n as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *entry = c;
        }
        Self { table, value: 0xFFFF_FFFF }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.value = self.table[((self.value ^ u32::from(b)) & 0xFF) as usize] ^ (self.value >> 8);
        }
    }

    pub fn value(&self) -> u32 {
        !self.value
    }
}

/// A canonical Huffman code.
struct Huffman {
    /// Codes of each length.
    counts: [u16; 16],
    /// The symbols, by code.
    symbols: Vec<u16>,
    /// For the next `FAST_BITS` input bits (first bit lowest): the symbol
    /// and the code's length, `symbol << 4 | length`; 0 for a longer code.
    fast: Vec<u32>,
}

impl Huffman {
    /// The code of `lengths`, one per symbol (0: unused). Incomplete codes
    /// are allowed (a single distance code); an over-subscribed one is not.
    fn new(lengths: &[u8]) -> Result<Self, String> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            counts[len as usize] += 1;
        }
        counts[0] = 0;
        let mut left: i32 = 1;
        for &count in &counts[1..] {
            left = left * 2 - i32::from(count);
            if left < 0 {
                return Err("deflate: over-subscribed Huffman code".into());
            }
        }
        let mut offsets = [0u16; 16];
        for len in 1..15 {
            offsets[len + 1] = offsets[len] + counts[len];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len != 0 {
                symbols[offsets[len as usize] as usize] = symbol as u16;
                offsets[len as usize] += 1;
            }
        }
        let mut fast = vec![0u32; 1 << FAST_BITS];
        let (mut code, mut index) = (0u32, 0usize);
        for len in 1..=FAST_BITS {
            for _ in 0..counts[len as usize] {
                // Codes are sent first bit highest: the table is indexed by
                // the reversed code.
                let reversed = code.reverse_bits() >> (32 - len);
                let entry = u32::from(symbols[index]) << 4 | len;
                for slot in (reversed as usize..1 << FAST_BITS).step_by(1 << len) {
                    fast[slot] = entry;
                }
                code += 1;
                index += 1;
            }
            code <<= 1;
        }
        Ok(Self { counts, symbols, fast })
    }
}

/// The input bits, first bit of each byte lowest.
struct Bits<'a> {
    input: &'a [u8],
    pos: usize,
    buffer: u64,
    count: u32,
}

impl Bits<'_> {
    /// At least 32 bits in the buffer, as far as the input goes.
    fn refill(&mut self) {
        while self.count <= 56 && self.pos < self.input.len() {
            self.buffer |= u64::from(self.input[self.pos]) << self.count;
            self.pos += 1;
            self.count += 8;
        }
    }

    fn take(&mut self, n: u32) -> Result<u32, String> {
        if self.count < n {
            self.refill();
            if self.count < n {
                return Err("deflate: unexpected end of input".into());
            }
        }
        let value = (self.buffer & ((1u64 << n) - 1)) as u32;
        self.buffer >>= n;
        self.count -= n;
        Ok(value)
    }

    fn decode(&mut self, code: &Huffman) -> Result<u16, String> {
        if self.count < 15 {
            self.refill();
        }
        let entry = code.fast[(self.buffer & ((1 << FAST_BITS) - 1)) as usize];
        if entry != 0 && entry & 0xF <= self.count {
            self.buffer >>= entry & 0xF;
            self.count -= entry & 0xF;
            return Ok((entry >> 4) as u16);
        }
        // Bit by bit: the codes of each length follow those of the shorter ones.
        let (mut value, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            value |= self.take(1)? as i32;
            let count = i32::from(code.counts[len]);
            if value - first < count {
                return Ok(code.symbols[(index + value - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
            value <<= 1;
        }
        Err("deflate: invalid Huffman code".into())
    }
}

/// The decoded bytes: the window, then what the sink has not had yet.
struct Output<W: Write> {
    data: Vec<u8>,
    sink: W,
    crc: Crc32,
    total: u64,
    /// Bytes beyond the window kept before writing them out.
    flush_at: usize,
}

impl<W: Write> Output<W> {
    fn push(&mut self, byte: u8) -> Result<(), String> {
        self.data.push(byte);
        self.total += 1;
        self.maybe_flush()
    }

    fn copy(&mut self, distance: usize, length: usize) -> Result<(), String> {
        if distance == 0 || distance > self.data.len() {
            return Err("deflate: distance beyond the output".into());
        }
        let start = self.data.len() - distance;
        if distance >= length {
            self.data.extend_from_within(start..start + length);
        } else {
            for i in 0..length {
                let byte = self.data[start + i];
                self.data.push(byte);
            }
        }
        self.total += length as u64;
        self.maybe_flush()
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.data.extend_from_slice(bytes);
        self.total += bytes.len() as u64;
        self.maybe_flush()
    }

    fn maybe_flush(&mut self) -> Result<(), String> {
        if self.data.len() >= WINDOW + self.flush_at {
            self.flush(WINDOW)?;
        }
        Ok(())
    }

    /// Writes out all but the last `keep` bytes.
    fn flush(&mut self, keep: usize) -> Result<(), String> {
        let n = self.data.len().saturating_sub(keep);
        self.crc.update(&self.data[..n]);
        self.sink.write_all(&self.data[..n]).map_err(|e| format!("deflate: write: {e}"))?;
        self.data.drain(..n);
        Ok(())
    }
}

/// Decodes the raw DEFLATE stream `input` into `sink`; returns the size and
/// the CRC-32 of the output.
pub fn inflate<W: Write>(input: &[u8], sink: W) -> Result<(u64, u32), String> {
    inflate_flushing(input, sink, 1 << 20)
}

/// [`inflate`], which writes out its output by `flush_at` bytes or more.
fn inflate_flushing<W: Write>(input: &[u8], sink: W, flush_at: usize) -> Result<(u64, u32), String> {
    let mut bits = Bits { input, pos: 0, buffer: 0, count: 0 };
    let mut out =
        Output { data: Vec::with_capacity(WINDOW + flush_at + 258), sink, crc: Crc32::new(), total: 0, flush_at };
    loop {
        let last = bits.take(1)? == 1;
        match bits.take(2)? {
            0 => stored(&mut bits, &mut out)?,
            1 => {
                let mut lengths = [0u8; 288];
                lengths[..144].fill(8);
                lengths[144..256].fill(9);
                lengths[256..280].fill(7);
                lengths[280..].fill(8);
                codes(&mut bits, &mut out, &Huffman::new(&lengths)?, &Huffman::new(&[5; 30])?)?;
            }
            2 => {
                let (literals, distances) = dynamic_codes(&mut bits)?;
                codes(&mut bits, &mut out, &literals, &distances)?;
            }
            _ => return Err("deflate: invalid block type".into()),
        }
        if last {
            break;
        }
    }
    out.flush(0)?;
    Ok((out.total, out.crc.value()))
}

/// A stored block: its length, then its bytes, from the next byte boundary.
fn stored<W: Write>(bits: &mut Bits, out: &mut Output<W>) -> Result<(), String> {
    bits.take(bits.count % 8)?;
    let length = bits.take(16)?;
    if bits.take(16)? != !length & 0xFFFF {
        return Err("deflate: stored block length mismatch".into());
    }
    let mut left = length as usize;
    // Whole bytes still in the bit buffer first.
    while left > 0 && bits.count >= 8 {
        out.push(bits.take(8)? as u8)?;
        left -= 1;
    }
    let end =
        bits.pos.checked_add(left).filter(|&e| e <= bits.input.len()).ok_or("deflate: stored block past the input")?;
    out.extend(&bits.input[bits.pos..end])?;
    bits.pos = end;
    Ok(())
}

/// The two codes of a dynamic block, from its header.
fn dynamic_codes(bits: &mut Bits) -> Result<(Huffman, Huffman), String> {
    let literals = bits.take(5)? as usize + 257;
    let distances = bits.take(5)? as usize + 1;
    let code_lengths = bits.take(4)? as usize + 4;
    if literals > 286 || distances > 30 {
        return Err("deflate: too many codes".into());
    }
    let mut lengths = [0u8; 19];
    for &symbol in &CODE_LENGTH_ORDER[..code_lengths] {
        lengths[symbol] = bits.take(3)? as u8;
    }
    let code_length_code = Huffman::new(&lengths)?;
    let mut lengths = vec![0u8; literals + distances];
    let mut i = 0;
    while i < lengths.len() {
        let symbol = bits.decode(&code_length_code)?;
        let (value, repeat) = match symbol {
            0..=15 => (symbol as u8, 1),
            16 => (*lengths[..i].last().ok_or("deflate: repeat with no length")?, 3 + bits.take(2)? as usize),
            17 => (0, 3 + bits.take(3)? as usize),
            18 => (0, 11 + bits.take(7)? as usize),
            _ => return Err("deflate: invalid code length".into()),
        };
        if i + repeat > lengths.len() {
            return Err("deflate: code lengths overflow".into());
        }
        lengths[i..i + repeat].fill(value);
        i += repeat;
    }
    if lengths[256] == 0 {
        return Err("deflate: no end-of-block code".into());
    }
    Ok((Huffman::new(&lengths[..literals])?, Huffman::new(&lengths[literals..])?))
}

/// The symbols of a Huffman block, up to its end.
fn codes<W: Write>(
    bits: &mut Bits,
    out: &mut Output<W>,
    literals: &Huffman,
    distances: &Huffman,
) -> Result<(), String> {
    loop {
        let symbol = bits.decode(literals)? as usize;
        match symbol {
            0..=255 => out.push(symbol as u8)?,
            256 => return Ok(()),
            257..=285 => {
                let n = symbol - 257;
                let length = usize::from(LENGTH_BASE[n]) + bits.take(u32::from(LENGTH_EXTRA[n]))? as usize;
                let d = bits.decode(distances)? as usize;
                if d >= 30 {
                    return Err("deflate: invalid distance code".into());
                }
                let distance = usize::from(DISTANCE_BASE[d]) + bits.take(u32::from(DISTANCE_EXTRA[d]))? as usize;
                out.copy(distance, length)?;
            }
            _ => return Err("deflate: invalid literal/length code".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(lines: &[&str]) -> Vec<u8> {
        let hex: String = lines.concat();
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }

    fn decoded(input: &[u8], flush_at: usize) -> (Vec<u8>, u64, u32) {
        let mut sink = Vec::new();
        let (size, crc) = inflate_flushing(input, &mut sink, flush_at).expect("a valid stream");
        (sink, size, crc)
    }

    #[test]
    fn crc32_check_value() {
        let mut crc = Crc32::new();
        crc.update(b"123456789");
        assert_eq!(crc.value(), 0xCBF4_3926);
    }

    #[test]
    fn stored_and_fixed_blocks() {
        let stored = unhex(&["011100eeff73746f72656420626c6f636b2064617461"]);
        assert_eq!(decoded(&stored, 1 << 20).0, b"stored block data");
        let fixed = unhex(&["cb48cdc9c957c8402701"]);
        assert_eq!(decoded(&fixed, 1 << 20).0, b"hello hello hello hello");
    }

    /// zlib, raw deflate, level 9, of 60 lines of `the quick brown fox…`.
    const DYNAMIC: &[&str] = &[
        "95d2c70d42311045d156a68409b601510d39f3c9a97a104b6423dde548f33657e7b29cc9f1ba9a6c647ceaee7b99770f",
        "51595f7787b374b7d9492e9f87ede8f59469b7101d7eefdf813507561f7873e0f5413407511fa4e620d507b939c8f541",
        "690e4a7dd0cedaa359fb34eb806635a55dcd6858735a566959a3659d960d5a36d1b099762d346b8f66edd3ac039ab5e5",
        "2fb0bf84fd65eaaf507f4afd19f5e7d45f507f89facbd45fa1fe94fa33eccfb1bfc0fe12f597a9bf42fd29f567d49f53",
        "7f41fd25ea2f537f85fa53eccfb03fc7fe82fa4bd45fa6fe0af5a7d49f517f4efdc53f7f6f",
    ];

    #[test]
    fn dynamic_block() {
        let text: Vec<u8> = (0..60)
            .flat_map(|i| format!("the quick brown fox {} jumps over the lazy dog {}; ", i % 7, i % 13).into_bytes())
            .collect();
        let (out, size, crc) = decoded(&unhex(DYNAMIC), 1 << 20);
        assert_eq!(out, text);
        assert_eq!((size, crc), (2952, 0xB615_11D1));
    }

    /// zlib, raw deflate, level 9, of 1000 bytes of an LCG repeated 40 times.
    const FAR: &[&str] = &[
        "edd38b3f130800077069f2ac361bc9339fdc657974b94b52625e751d72bdc8a3895322b5a244f2b8ce635a9d8a5644b8",
        "ba3ce624f2187ab0ceab30b25298f3d892c7d21a91d2bf707fc0effb3f7c7b09818506c57a5eaf47383afa743223f2e8",
        "17e2c2ca123f3d02a75c4fdec4f94c98f50721fd9f4aa5fdfcc94dc4d6ede90f9e31a9a4852515fee6c22db31bbefc92",
        "66dca21ced58267fe01abdec5d28e78559fcb1232503a224979b0471a7a5afa95ff3bb8f91d389396357bf1ff657ef5e",
        "da5a16a1111c6c1dc4bdf4265cc9395bda56a6f2a9a32fa8e6137dcee843e7bc56d2679f246eb995c59d4c1d1b62f4cc",
        "1941ec60e827d2656accd5f456f5a71e6d5e532f34b55eaeac2578c7dc089cca4b3bc15bcb092eb0e29d6a2cb6b09237",
        "50d86c7a437b7e4ca3bf3d883b105d2bd067eb64a8663d6407745d992f11e6b1d8ab9dfcc7fa1403190b9ecce0f69996",
        "495bddd16195a091feab17ad6e9eab7be9adfc423cf8a3a3ed0e162f37555055d57b90cebf64fc70ffb242771df79460",
        "4baa8821dc1bc1ed750c75a829505a21783c7d56e920a3c7ac59fda4b7514cfde0ebd2fb84ec5571e11b338ea7aaf599",
        "1f382953de5ee1c9678f36b04a8f75f5a93bfa5ba851ee96d8cea9f50bc86de4c4568f9c6dc3de0ff94ee596ddc95f3b",
        "e5681f924a979fa78707728d9d35770993f3c83d8fec2595a407fd8ab1cd91dca17ccf1d056fcdf25dddb344d743060b",
        "32da0d5d0ead6575a792365e3fccac2996fe7a915c2cd3cd5d94c6b9f7c751598a6c6dd46599b4685da20537de69954d",
        "c3614a72d4a9d4a68046c501fd7ac6e20cfe054d5ba3e9867e1389af175f749a1cd962af594d2c54e839ff43a34a7bc2",
        "fb43ade3120ed365aed2408bdbf093b0c26fc7fd388be79b728f09d31c29ff49ff1e7ff27193c392c799fe5943d65d07",
        "250dbb433a765e339874ad932a98b1bff2f8994e6bcaf37869af7edb5a75a29a67b0fb8252ba6e36ddce70811da5ed1a",
        "cb6015ad8b9e8bd3b16f91bd61cd9a56896268d3b3b18b86f32d436f8fe74d7019137b3cc672d80134a6abebfe20d195",
        "5a9fa2655262e492ac3b3653bb7ccd95372f6dbb164acb96a998de0ed1dc97c5d126c853cf1eaad3639fcfdf7767a4a5",
        "e167827bfd5c98ab31e5d9faa5b5beaa3e67fe8cd14fd14e885f3e262aeaed88a05146290f98ed3ebb5fc59bab3a9045",
        "f32e1a1e4f57f09253ce49d735492a253da46e7767f5f1df3b9efbf36d72896f8748c5ff4e6b7f8ebbec595693f072fd",
        "db11eec056b74b01913321cc3dd11d938dc15b18724c96e7ea092da7fa1ad62b9dda4443ca5f1f9fcde89ba84edc6a72",
        "d822de76dace2330cc647ac3a3681ac1deae62b254cdc0e651c5ad84c58273717717ca0b0575963787dc08546b4389b5",
        "22d1e448becf0dbfaea3fcf7494e53efcb9bd6f41694c85169cec78f3c1fcd5afd9816ced0b319dd97dba9367c2fac83",
        "24b73373afa21b4be1bbe6d4e357548daa1558e228aa58acf12437ff75faf55e3cc7733cc7733cc7733cc7733cc7733c",
        "c7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733c",
        "c7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733c",
        "c7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733c",
        "c7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733cc7733c",
        "c7733cc7733cc7733cc7733cc7733cc7733cffdfcfbf01",
    ];

    #[test]
    fn back_references_across_flushes() {
        let mut x: u32 = 12345;
        let block: Vec<u8> = (0..1000)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0x7FFF_FFFF;
                (x >> 16) as u8
            })
            .collect();
        let expected = block.repeat(40);
        // Written out in small pieces: the window stays 32 KiB.
        let (out, size, crc) = decoded(&unhex(FAR), 100);
        assert_eq!((size, crc), (40_000, 0x5EA3_0768));
        assert_eq!(out, expected);
    }

    #[test]
    fn corrupt_streams_are_refused() {
        assert!(inflate(&[0x07], Vec::new()).is_err(), "block type 3");
        assert!(inflate(&[0x01, 0x05, 0x00, 0x00, 0x00], Vec::new()).is_err(), "stored length mismatch");
        assert!(inflate(&[0x01, 0x05, 0x00, 0xFA, 0xFF, b'a'], Vec::new()).is_err(), "stored block past the input");
        let dynamic = unhex(DYNAMIC);
        assert!(inflate(&dynamic[..dynamic.len() / 2], Vec::new()).is_err(), "truncated");
    }
}
