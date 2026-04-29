use std::io::{Read, Write};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidData(&'static str),
    NeedMoreInput,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidData(msg) => write!(f, "{msg}"),
            Self::NeedMoreInput => write!(f, "more input is required"),
        }
    }
}

impl std::error::Error for Error {}

const DEC_L1: &[u16] = &[
    0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff,
];
const POS_L1: &[u16] = &[0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32];
const DEC_L2: &[u16] = &[
    0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff,
];
const POS_L2: &[u16] = &[0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36];
const DEC_HF0: &[u16] = &[
    0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff,
];
const POS_HF0: &[u16] = &[0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33];
const DEC_HF1: &[u16] = &[
    0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff,
];
const POS_HF1: &[u16] = &[0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127];
const DEC_HF2: &[u16] = &[
    0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff,
];
const POS_HF2: &[u16] = &[0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0];
const DEC_HF3: &[u16] = &[0x0800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff];
const POS_HF3: &[u16] = &[0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0];
const DEC_HF4: &[u16] = &[0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff];
const POS_HF4: &[u16] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0];

const SHORT_LEN1: [u8; 16] = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR1: [u8; 15] = [
    0x00, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0,
];
const SHORT_LEN2: [u8; 16] = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR2: [u8; 15] = [
    0x00, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0,
];

pub fn unpack15_encode(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut encoder = Unpack15Encoder::new();
    encoder.encode_member(input)
}

pub fn unpack15_decode(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack15::new();
    decoder.decode_member(input, output_size, false)
}

pub struct Unpack15Encoder {
    bits: BitWriter,
    ch_set: [u16; 256],
    ch_set_c: [u16; 256],
    ch_set_b: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
    ch_set_a: [u16; 256],
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    max_dist3: u32,
    nhfb: u32,
    nlzb: u32,
    num_huf: u32,
    old_dist: [u32; 4],
    old_dist_ptr: usize,
    last_dist: u32,
    last_length: u32,
}

impl Unpack15Encoder {
    pub fn new() -> Self {
        let mut encoder = Self {
            bits: BitWriter::new(),
            ch_set: [0; 256],
            ch_set_c: [0; 256],
            ch_set_b: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
            ch_set_a: [0; 256],
            avr_plc: 0x3500,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            max_dist3: 0x2001,
            nhfb: 0x80,
            nlzb: 0x80,
            num_huf: 0,
            old_dist: [u32::MAX; 4],
            old_dist_ptr: 0,
            last_dist: u32::MAX,
            last_length: 0,
        };
        encoder.init_huff();
        encoder
    }

    #[allow(dead_code)]
    pub fn encode_literals_only(mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.encode_literals_only_member(input)
    }

    #[allow(dead_code)]
    fn encode_literals_only_member(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        self.bits = BitWriter::new();
        let mut pos = 0usize;
        while pos < input.len() {
            let mut flags = 0u8;
            let mut flag_bits = 0usize;
            let mut payloads = Vec::new();
            let mut plan_nhfb = self.nhfb;
            let mut plan_nlzb = self.nlzb;

            while flag_bits < 8 && pos < input.len() {
                let flag = huff_flag_bits(plan_nlzb <= plan_nhfb);
                if flag_bits + flag.len() > 8 {
                    break;
                }
                write_planned_flag_bits(&mut flags, flag_bits, flag);
                payloads.push(EncodedToken::Literal(input[pos]));
                flag_bits += flag.len();
                pos += 1;
                plan_huff_effect(&mut plan_nhfb, &mut plan_nlzb);
            }

            self.emit_flags_byte(flags)?;
            self.emit_payloads(payloads, pos < input.len())?;
        }
        Ok(std::mem::take(&mut self.bits).finish())
    }

    pub fn encode_member(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        self.bits = BitWriter::new();
        let mut pos = 0usize;
        while pos < input.len() {
            let mut flags = 0u8;
            let mut flag_bits = 0usize;
            let mut payloads = Vec::new();
            let mut plan_nhfb = self.nhfb;
            let mut plan_nlzb = self.nlzb;

            while flag_bits < 8 && pos < input.len() {
                if let Some(short_lz) = find_short_lz(input, pos) {
                    if flag_bits + 2 <= 8 {
                        payloads.push(EncodedToken::ShortLz(short_lz));
                        flag_bits += 2;
                        pos += short_lz.length as usize;
                        continue;
                    }
                }
                if let Some(long_lz) = find_long_lz(input, pos) {
                    let flag = long_lz_flag_bits(plan_nlzb > plan_nhfb);
                    if flag_bits + flag.len() <= 8 {
                        write_planned_flag_bits(&mut flags, flag_bits, flag);
                        payloads.push(EncodedToken::LongLz(long_lz));
                        flag_bits += flag.len();
                        pos += long_lz.length as usize;
                        plan_long_lz_effect(&mut plan_nhfb, &mut plan_nlzb);
                        continue;
                    }
                }

                let flag = huff_flag_bits(plan_nlzb <= plan_nhfb);
                if flag_bits + flag.len() > 8 {
                    break;
                }
                write_planned_flag_bits(&mut flags, flag_bits, flag);
                payloads.push(EncodedToken::Literal(input[pos]));
                flag_bits += flag.len();
                pos += 1;
                plan_huff_effect(&mut plan_nhfb, &mut plan_nlzb);
            }

            self.emit_flags_byte(flags)?;
            self.emit_payloads(payloads, pos < input.len())?;
        }
        Ok(std::mem::take(&mut self.bits).finish())
    }

    fn emit_payloads(&mut self, payloads: Vec<EncodedToken>, more_input: bool) -> Result<()> {
        let mut consumed_flag_bits = 0usize;
        let mut decoder_enters_stmode = false;
        for payload in payloads {
            match payload {
                EncodedToken::Literal(byte) => {
                    consumed_flag_bits += huff_flag_bits(self.nlzb <= self.nhfb).len();
                    if consumed_flag_bits == 8 && self.num_huf >= 16 {
                        decoder_enters_stmode = true;
                    }
                    self.emit_literal(byte)?;
                }
                EncodedToken::ShortLz(short_lz) => {
                    consumed_flag_bits += 2;
                    self.emit_short_lz(short_lz)?;
                }
                EncodedToken::LongLz(long_lz) => {
                    consumed_flag_bits += long_lz_flag_bits(self.nlzb > self.nhfb).len();
                    self.emit_long_lz(long_lz)?;
                }
            }
        }

        if decoder_enters_stmode && more_input {
            self.emit_stmode_exit()?;
        }
        Ok(())
    }

    fn emit_flags_byte(&mut self, flags: u8) -> Result<()> {
        let flags_place = self
            .ch_set_c
            .iter()
            .position(|&value| (value >> 8) as u8 == flags)
            .ok_or(Error::InvalidData("RAR 1.3 flag byte is not encodable"))?;
        emit_decode_num(&mut self.bits, flags_place as u32, 5, DEC_HF2, POS_HF2)?;

        let mut cur_flags;
        let mut new_flags_place;
        loop {
            cur_flags = self.ch_set_c[flags_place] as u32;
            new_flags_place = self.n_to_pl_c[(cur_flags & 0xff) as usize] as usize;
            self.n_to_pl_c[(cur_flags & 0xff) as usize] =
                self.n_to_pl_c[(cur_flags & 0xff) as usize].wrapping_add(1);
            cur_flags += 1;
            if cur_flags & 0xff == 0 {
                corr_huff(&mut self.ch_set_c, &mut self.n_to_pl_c);
            } else {
                break;
            }
        }

        self.ch_set_c[flags_place] = self.ch_set_c[new_flags_place];
        self.ch_set_c[new_flags_place] = cur_flags as u16;
        Ok(())
    }

    fn emit_literal(&mut self, byte: u8) -> Result<()> {
        let byte_place = self
            .ch_set
            .iter()
            .position(|&value| (value >> 8) as u8 == byte)
            .ok_or(Error::InvalidData("RAR 1.3 literal is not encodable"))?;

        let (start_pos, dec_tab, pos_tab) = if self.avr_plc > 0x75ff {
            (8, DEC_HF4, POS_HF4)
        } else if self.avr_plc > 0x5dff {
            (6, DEC_HF3, POS_HF3)
        } else if self.avr_plc > 0x35ff {
            (5, DEC_HF2, POS_HF2)
        } else if self.avr_plc > 0x0dff {
            (5, DEC_HF1, POS_HF1)
        } else {
            (4, DEC_HF0, POS_HF0)
        };
        emit_decode_num(
            &mut self.bits,
            byte_place as u32,
            start_pos,
            dec_tab,
            pos_tab,
        )?;

        self.avr_plc += byte_place as u32;
        self.avr_plc -= self.avr_plc >> 8;
        self.nhfb += 16;
        if self.nhfb > 0xff {
            self.nhfb = 0x90;
            self.nlzb >>= 1;
        }
        self.num_huf += 1;

        let idx = byte_place;
        let mut cur_byte;
        let mut new_byte_place;
        loop {
            cur_byte = self.ch_set[idx] as u32;
            new_byte_place = self.n_to_pl[(cur_byte & 0xff) as usize] as usize;
            self.n_to_pl[(cur_byte & 0xff) as usize] =
                self.n_to_pl[(cur_byte & 0xff) as usize].wrapping_add(1);
            cur_byte += 1;
            if cur_byte & 0xff > 0xa1 {
                corr_huff(&mut self.ch_set, &mut self.n_to_pl);
            } else {
                break;
            }
        }

        self.ch_set[idx] = self.ch_set[new_byte_place];
        self.ch_set[new_byte_place] = cur_byte as u16;
        Ok(())
    }

    fn emit_short_lz(&mut self, short_lz: ShortLz) -> Result<()> {
        self.num_huf = 0;
        let length_place = short_lz.length - 2;
        let code_len = if self.avr_ln1 < 37 {
            self.short_len1(length_place as usize)
        } else {
            self.short_len2(length_place as usize)
        };
        let code_byte = if self.avr_ln1 < 37 {
            SHORT_XOR1[length_place as usize]
        } else {
            SHORT_XOR2[length_place as usize]
        };
        self.bits
            .write_bits((code_byte >> (8 - code_len)) as u32, code_len as usize);

        self.avr_ln1 += length_place;
        self.avr_ln1 -= self.avr_ln1 >> 4;

        let distance_value = short_lz.distance - 1;
        let distance_place = self
            .ch_set_a
            .iter()
            .position(|&value| value as u32 == distance_value)
            .ok_or(Error::InvalidData(
                "RAR 1.3 ShortLZ distance is not encodable",
            ))?;
        emit_decode_num(&mut self.bits, distance_place as u32, 5, DEC_HF2, POS_HF2)?;
        if distance_place > 0 {
            let last_distance = self.ch_set_a[distance_place - 1];
            self.ch_set_a[distance_place] = last_distance;
            self.ch_set_a[distance_place - 1] = distance_value as u16;
        }
        self.remember_match(short_lz.distance, short_lz.length);
        Ok(())
    }

    fn emit_long_lz(&mut self, long_lz: LongLz) -> Result<()> {
        self.num_huf = 0;
        self.nlzb += 16;
        if self.nlzb > 0xff {
            self.nlzb = 0x90;
            self.nhfb >>= 1;
        }
        let old_avr2 = self.avr_ln2;

        let length_code = long_lz.length - 3;
        emit_long_lz_length(&mut self.bits, length_code)?;
        self.avr_ln2 += length_code;
        self.avr_ln2 -= self.avr_ln2 >> 5;

        let distance_place = self.long_lz_distance_place(long_lz.distance)?;
        let (start_pos, dec_tab, pos_tab) = if self.avr_plc_b > 0x28ff {
            (5, DEC_HF2, POS_HF2)
        } else if self.avr_plc_b > 0x06ff {
            (5, DEC_HF1, POS_HF1)
        } else {
            (4, DEC_HF0, POS_HF0)
        };
        emit_decode_num(
            &mut self.bits,
            distance_place as u32,
            start_pos,
            dec_tab,
            pos_tab,
        )?;
        self.avr_plc_b += distance_place as u32;
        self.avr_plc_b -= self.avr_plc_b >> 8;

        let idx = distance_place;
        let mut distance;
        let mut new_distance_place;
        loop {
            distance = self.ch_set_b[idx] as u32;
            new_distance_place = self.n_to_pl_b[(distance & 0xff) as usize] as usize;
            self.n_to_pl_b[(distance & 0xff) as usize] =
                self.n_to_pl_b[(distance & 0xff) as usize].wrapping_add(1);
            distance += 1;
            if distance & 0xff == 0 {
                corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
            } else {
                break;
            }
        }

        self.ch_set_b[idx] = self.ch_set_b[new_distance_place];
        self.ch_set_b[new_distance_place] = distance as u16;

        let low_byte = ((long_lz.distance << 1) & 0xff) as u8;
        self.bits.write_bits((low_byte >> 1) as u32, 7);

        let old_avr3 = self.avr_ln3;
        if length_code != 1 && length_code != 4 {
            if length_code == 0 && long_lz.distance <= self.max_dist3 {
                self.avr_ln3 += 1;
                self.avr_ln3 -= self.avr_ln3 >> 8;
            } else if self.avr_ln3 > 0 {
                self.avr_ln3 -= 1;
            }
        }
        if old_avr3 > 0xb0 || (self.avr_plc >= 0x2a00 && old_avr2 < 0x40) {
            self.max_dist3 = 0x7f00;
        } else {
            self.max_dist3 = 0x2001;
        }

        self.remember_match(long_lz.distance, long_lz.length);
        Ok(())
    }

    fn long_lz_distance_place(&self, target_distance: u32) -> Result<usize> {
        let wanted_high = ((target_distance << 1) & 0xff00) as u16;
        self.ch_set_b
            .iter()
            .position(|&value| value & 0xff00 == wanted_high)
            .ok_or(Error::InvalidData(
                "RAR 1.3 LongLZ distance is not encodable",
            ))
    }

    fn emit_stmode_exit(&mut self) -> Result<()> {
        let (start_pos, dec_tab, pos_tab) = if self.avr_plc > 0x75ff {
            (8, DEC_HF4, POS_HF4)
        } else if self.avr_plc > 0x5dff {
            (6, DEC_HF3, POS_HF3)
        } else if self.avr_plc > 0x35ff {
            (5, DEC_HF2, POS_HF2)
        } else if self.avr_plc > 0x0dff {
            (5, DEC_HF1, POS_HF1)
        } else {
            (4, DEC_HF0, POS_HF0)
        };
        emit_decode_num(&mut self.bits, 0, start_pos, dec_tab, pos_tab)?;
        self.bits.write_bits(1, 1);
        self.num_huf = 0;
        Ok(())
    }

    fn init_huff(&mut self) {
        for i in 0..256 {
            self.ch_set[i] = (i as u16) << 8;
            self.ch_set_c[i] = (0u8.wrapping_sub(i as u8) as u16) << 8;
            self.ch_set_b[i] = (i as u16) << 8;
        }
        self.n_to_pl = [0; 256];
        self.n_to_pl_b = [0; 256];
        self.n_to_pl_c = [0; 256];
        for i in 0..256 {
            self.ch_set_a[i] = i as u16;
        }
        corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
    }

    fn remember_match(&mut self, distance: u32, length: u32) {
        self.old_dist[self.old_dist_ptr] = distance;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.last_dist = distance;
    }

    fn short_len1(&self, pos: usize) -> u8 {
        if pos == 1 {
            3
        } else {
            SHORT_LEN1[pos]
        }
    }

    fn short_len2(&self, pos: usize) -> u8 {
        if pos == 3 {
            3
        } else {
            SHORT_LEN2[pos]
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodedToken {
    Literal(u8),
    ShortLz(ShortLz),
    LongLz(LongLz),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShortLz {
    pub distance: u32,
    pub length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongLz {
    pub distance: u32,
    pub length: u32,
}

fn huff_flag_bits(prefer_huff_on_one: bool) -> &'static [bool] {
    if prefer_huff_on_one {
        &[true]
    } else {
        &[false, true]
    }
}

fn long_lz_flag_bits(prefer_long_lz_on_one: bool) -> &'static [bool] {
    if prefer_long_lz_on_one {
        &[true]
    } else {
        &[false, true]
    }
}

fn write_planned_flag_bits(flags: &mut u8, start: usize, bits: &[bool]) {
    for (offset, &bit) in bits.iter().enumerate() {
        if bit {
            *flags |= 1 << (7 - start - offset);
        }
    }
}

fn plan_huff_effect(nhfb: &mut u32, nlzb: &mut u32) {
    *nhfb += 16;
    if *nhfb > 0xff {
        *nhfb = 0x90;
        *nlzb >>= 1;
    }
}

fn plan_long_lz_effect(nhfb: &mut u32, nlzb: &mut u32) {
    *nlzb += 16;
    if *nlzb > 0xff {
        *nlzb = 0x90;
        *nhfb >>= 1;
    }
}

fn find_short_lz(input: &[u8], pos: usize) -> Option<ShortLz> {
    if pos < 2 {
        return None;
    }

    let max_distance = pos.min(256);
    let mut best = ShortLz {
        distance: 0,
        length: 0,
    };
    for distance in 1..=max_distance {
        let mut length = 0usize;
        while length < 10
            && pos + length < input.len()
            && input[pos + length] == input[pos + length - distance]
        {
            length += 1;
        }
        if length >= 3 && length > best.length as usize {
            best = ShortLz {
                distance: distance as u32,
                length: length as u32,
            };
        }
    }

    (best.length >= 3).then_some(best)
}

pub fn find_long_lz(input: &[u8], pos: usize) -> Option<LongLz> {
    if pos < 257 {
        return None;
    }

    let max_distance = pos.min(0x8000);
    let mut best = LongLz {
        distance: 0,
        length: 0,
    };
    for distance in 257..=max_distance {
        let mut length = 0usize;
        while length < 18
            && pos + length < input.len()
            && input[pos + length] == input[pos + length - distance]
        {
            length += 1;
        }
        if length >= 3 && length > best.length as usize {
            best = LongLz {
                distance: distance as u32,
                length: length as u32,
            };
        }
    }

    (best.length >= 3).then_some(best)
}

fn emit_long_lz_length(bits: &mut BitWriter, length_code: u32) -> Result<()> {
    if length_code > 15 {
        return Err(Error::InvalidData(
            "RAR 1.3 LongLZ encoder length is not encodable",
        ));
    }
    bits.write_bits(1, length_code as usize + 1);
    Ok(())
}

fn emit_decode_num(
    bits: &mut BitWriter,
    target: u32,
    start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> Result<()> {
    for len in start_pos as usize..=16 {
        for code in 0..(1u32 << len) {
            let bit_field = code << (16 - len);
            let (decoded, consumed) = simulate_decode_num(bit_field, start_pos, dec_tab, pos_tab);
            if decoded == target && consumed == len {
                bits.write_bits(code, len);
                return Ok(());
            }
        }
    }
    Err(Error::InvalidData(
        "RAR 1.3 DecodeNum value is not encodable",
    ))
}

fn simulate_decode_num(
    bit_field: u32,
    mut start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> (u32, usize) {
    let num = bit_field & 0xfff0;
    let mut i = 0usize;
    while dec_tab[i] as u32 <= num {
        start_pos += 1;
        i += 1;
    }
    (
        ((num - if i > 0 { dec_tab[i - 1] as u32 } else { 0 }) >> (16 - start_pos))
            + pos_tab[start_pos as usize] as u32,
        start_pos as usize,
    )
}

#[derive(Clone)]
pub struct Unpack15 {
    bits: BitReader,
    target: usize,
    output_written: usize,
    window: [u8; 0x10000],
    unp_ptr: usize,
    prev_ptr: usize,
    first_win_done: bool,
    ch_set: [u16; 256],
    ch_set_a: [u16; 256],
    ch_set_b: [u16; 256],
    ch_set_c: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    max_dist3: u32,
    nhfb: u32,
    nlzb: u32,
    num_huf: u32,
    buf60: u32,
    st_mode: bool,
    l_count: u32,
    flag_buf: u32,
    flags_cnt: i32,
    old_dist: [u32; 4],
    old_dist_ptr: usize,
    last_dist: u32,
    last_length: u32,
}

impl Unpack15 {
    pub fn new() -> Self {
        Self {
            bits: BitReader::new(&[]),
            target: 0,
            output_written: 0,
            window: [0; 0x10000],
            unp_ptr: 0,
            prev_ptr: 0,
            first_win_done: false,
            ch_set: [0; 256],
            ch_set_a: [0; 256],
            ch_set_b: [0; 256],
            ch_set_c: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
            avr_plc: 0x3500,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            max_dist3: 0x2001,
            nhfb: 0x80,
            nlzb: 0x80,
            num_huf: 0,
            buf60: 0,
            st_mode: false,
            l_count: 0,
            flag_buf: 0,
            flags_cnt: 0,
            old_dist: [u32::MAX; 4],
            old_dist_ptr: 0,
            last_dist: u32::MAX,
            last_length: 0,
        }
    }

    pub fn decode_member(&mut self, input: &[u8], target: usize, solid: bool) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(target);
        self.decode_member_to(input, target, solid, &mut output)?;
        Ok(output)
    }

    pub fn decode_member_to(
        &mut self,
        input: &[u8],
        target: usize,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        self.init_member(target, solid);
        self.bits = BitReader::new_final(input);
        self.decode_loop(out).map_err(|error| match error {
            Error::NeedMoreInput => Error::InvalidData("RAR 1.3 bitstream is truncated"),
            error => error,
        })
    }

    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        target: usize,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        const INPUT_CHUNK: usize = 64 * 1024;

        self.init_member(target, solid);
        self.bits = BitReader::new(&[]);
        let mut input_done = false;
        let mut buffer = [0u8; INPUT_CHUNK];

        while self.output_written < self.target {
            let checkpoint = self.clone();
            match self.decode_step(out) {
                Ok(()) => {}
                Err(Error::NeedMoreInput) if !input_done => {
                    *self = checkpoint;
                    let read = input
                        .read(&mut buffer)
                        .map_err(|_| Error::InvalidData("RAR 1.3 input read failed"))?;
                    if read == 0 {
                        input_done = true;
                        self.bits.finish();
                    } else {
                        self.bits.append(&buffer[..read]);
                    }
                }
                Err(Error::NeedMoreInput) => {
                    return Err(Error::InvalidData("RAR 1.3 bitstream is truncated"));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn init_member(&mut self, target: usize, solid: bool) {
        self.target = target;
        self.output_written = 0;
        self.flags_cnt = -2;
        self.flag_buf = 0;
        self.st_mode = false;
        self.l_count = 0;

        if !solid {
            self.reset_non_solid();
        }
    }

    fn decode_loop(&mut self, out: &mut impl Write) -> Result<()> {
        if self.target == 0 {
            return Ok(());
        }

        while self.output_written < self.target {
            self.decode_step(out)?;
        }

        Ok(())
    }

    fn decode_step(&mut self, out: &mut impl Write) -> Result<()> {
        if self.flags_cnt == -2 {
            self.get_flags_buf()?;
            self.flags_cnt = 8;
        }

        self.unp_ptr &= 0xffff;
        self.first_win_done |= self.prev_ptr > self.unp_ptr;
        self.prev_ptr = self.unp_ptr;

        if self.st_mode {
            return self.huff_decode(out);
        }

        self.flags_cnt -= 1;
        if self.flags_cnt < 0 {
            self.get_flags_buf()?;
            self.flags_cnt = 7;
        }

        if self.flag_buf & 0x80 != 0 {
            self.flag_buf = (self.flag_buf << 1) & 0xff;
            if self.nlzb > self.nhfb {
                self.long_lz(out)
            } else {
                self.huff_decode(out)
            }
        } else {
            self.flag_buf = (self.flag_buf << 1) & 0xff;
            self.flags_cnt -= 1;
            if self.flags_cnt < 0 {
                self.get_flags_buf()?;
                self.flags_cnt = 7;
            }
            if self.flag_buf & 0x80 != 0 {
                self.flag_buf = (self.flag_buf << 1) & 0xff;
                if self.nlzb > self.nhfb {
                    self.huff_decode(out)
                } else {
                    self.long_lz(out)
                }
            } else {
                self.flag_buf = (self.flag_buf << 1) & 0xff;
                self.short_lz(out)
            }
        }
    }

    fn reset_non_solid(&mut self) {
        self.window = [0; 0x10000];
        self.unp_ptr = 0;
        self.prev_ptr = 0;
        self.first_win_done = false;
        self.avr_plc_b = 0;
        self.avr_ln1 = 0;
        self.avr_ln2 = 0;
        self.avr_ln3 = 0;
        self.num_huf = 0;
        self.buf60 = 0;
        self.avr_plc = 0x3500;
        self.max_dist3 = 0x2001;
        self.nhfb = 0x80;
        self.nlzb = 0x80;
        self.old_dist = [u32::MAX; 4];
        self.old_dist_ptr = 0;
        self.last_dist = u32::MAX;
        self.last_length = 0;
        self.init_huff();
    }

    fn short_lz(&mut self, out: &mut impl Write) -> Result<()> {
        self.num_huf = 0;
        let mut bit_field = self.bits.get_bits()?;
        if self.l_count == 2 {
            self.bits.add_bits(1);
            if bit_field >= 0x8000 {
                self.copy_string(self.last_dist, self.last_length, out)?;
                return Ok(());
            }
            bit_field = (bit_field << 1) & 0xffff;
            self.l_count = 0;
        }

        let bit_byte = (bit_field >> 8) as u8;
        let mut length = 0usize;
        if self.avr_ln1 < 37 {
            while length < SHORT_XOR1.len() {
                let short_len = self.short_len1(length);
                let mask = (!(0xffu16 >> short_len)) as u8;
                if ((bit_byte ^ SHORT_XOR1[length]) & mask) == 0 {
                    break;
                }
                length += 1;
            }
            self.bits.add_bits(self.short_len1(length) as usize);
        } else {
            while length < SHORT_XOR2.len() {
                let short_len = self.short_len2(length);
                let mask = (!(0xffu16 >> short_len)) as u8;
                if ((bit_byte ^ SHORT_XOR2[length]) & mask) == 0 {
                    break;
                }
                length += 1;
            }
            self.bits.add_bits(self.short_len2(length) as usize);
        }

        let mut length = length as u32;
        if length >= 9 {
            if length == 9 {
                self.l_count += 1;
                self.copy_string(self.last_dist, self.last_length, out)?;
                return Ok(());
            }
            if length == 14 {
                self.l_count = 0;
                length = self.decode_num(self.bits.get_bits()?, 3, DEC_L2, POS_L2) + 5;
                let distance = (self.bits.get_bits()? >> 1) | 0x8000;
                self.bits.add_bits(15);
                self.last_length = length;
                self.last_dist = distance;
                self.copy_string(distance, length, out)?;
                return Ok(());
            }

            self.l_count = 0;
            let save_length = length;
            let distance =
                self.old_dist[(self.old_dist_ptr.wrapping_sub((length - 9) as usize)) & 3];
            length = self.decode_num(self.bits.get_bits()?, 2, DEC_L1, POS_L1) + 2;
            if length == 0x101 && save_length == 10 {
                self.buf60 ^= 1;
                return Ok(());
            }
            if distance > 256 {
                length += 1;
            }
            if distance >= self.max_dist3 {
                length += 1;
            }

            self.remember_match(distance, length);
            self.copy_string(distance, length, out)?;
            return Ok(());
        }

        self.l_count = 0;
        self.avr_ln1 += length;
        self.avr_ln1 -= self.avr_ln1 >> 4;

        let distance_place =
            (self.decode_num(self.bits.get_bits()?, 5, DEC_HF2, POS_HF2) & 0xff) as usize;
        let mut distance = self.ch_set_a[distance_place] as u32;
        if distance_place > 0 {
            let last_distance = self.ch_set_a[distance_place - 1];
            self.ch_set_a[distance_place] = last_distance;
            self.ch_set_a[distance_place - 1] = distance as u16;
        }
        length += 2;
        distance += 1;
        self.remember_match(distance, length);
        self.copy_string(distance, length, out)
    }

    fn long_lz(&mut self, out: &mut impl Write) -> Result<()> {
        self.num_huf = 0;
        self.nlzb += 16;
        if self.nlzb > 0xff {
            self.nlzb = 0x90;
            self.nhfb >>= 1;
        }
        let old_avr2 = self.avr_ln2;

        let bit_field = self.bits.get_bits()?;
        let mut length = if self.avr_ln2 >= 122 {
            self.decode_num(bit_field, 3, DEC_L2, POS_L2)
        } else if self.avr_ln2 >= 64 {
            self.decode_num(bit_field, 2, DEC_L1, POS_L1)
        } else if bit_field < 0x100 {
            self.bits.add_bits(16);
            bit_field
        } else {
            let mut length = 0u32;
            while ((bit_field << length) & 0x8000) == 0 {
                length += 1;
            }
            self.bits.add_bits((length + 1) as usize);
            length
        };

        self.avr_ln2 += length;
        self.avr_ln2 -= self.avr_ln2 >> 5;

        let bit_field = self.bits.get_bits()?;
        let distance_place = if self.avr_plc_b > 0x28ff {
            self.decode_num(bit_field, 5, DEC_HF2, POS_HF2)
        } else if self.avr_plc_b > 0x06ff {
            self.decode_num(bit_field, 5, DEC_HF1, POS_HF1)
        } else {
            self.decode_num(bit_field, 4, DEC_HF0, POS_HF0)
        };

        self.avr_plc_b += distance_place;
        self.avr_plc_b -= self.avr_plc_b >> 8;

        let idx = (distance_place & 0xff) as usize;
        let mut distance;
        let mut new_distance_place;
        loop {
            distance = self.ch_set_b[idx] as u32;
            new_distance_place = self.n_to_pl_b[(distance & 0xff) as usize] as usize;
            self.n_to_pl_b[(distance & 0xff) as usize] =
                self.n_to_pl_b[(distance & 0xff) as usize].wrapping_add(1);
            distance += 1;
            if distance & 0xff == 0 {
                corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
            } else {
                break;
            }
        }

        self.ch_set_b[idx] = self.ch_set_b[new_distance_place];
        self.ch_set_b[new_distance_place] = distance as u16;

        distance = ((distance & 0xff00) | (self.bits.get_bits()? >> 8)) >> 1;
        self.bits.add_bits(7);

        let old_avr3 = self.avr_ln3;
        if length != 1 && length != 4 {
            if length == 0 && distance <= self.max_dist3 {
                self.avr_ln3 += 1;
                self.avr_ln3 -= self.avr_ln3 >> 8;
            } else if self.avr_ln3 > 0 {
                self.avr_ln3 -= 1;
            }
        }
        length += 3;
        if distance >= self.max_dist3 {
            length += 1;
        }
        if distance <= 256 {
            length += 8;
        }
        if old_avr3 > 0xb0 || (self.avr_plc >= 0x2a00 && old_avr2 < 0x40) {
            self.max_dist3 = 0x7f00;
        } else {
            self.max_dist3 = 0x2001;
        }

        self.remember_match(distance, length);
        self.copy_string(distance, length, out)
    }

    fn huff_decode(&mut self, out: &mut impl Write) -> Result<()> {
        let bit_field = self.bits.get_bits()?;

        let mut byte_place = if self.avr_plc > 0x75ff {
            self.decode_num(bit_field, 8, DEC_HF4, POS_HF4)
        } else if self.avr_plc > 0x5dff {
            self.decode_num(bit_field, 6, DEC_HF3, POS_HF3)
        } else if self.avr_plc > 0x35ff {
            self.decode_num(bit_field, 5, DEC_HF2, POS_HF2)
        } else if self.avr_plc > 0x0dff {
            self.decode_num(bit_field, 5, DEC_HF1, POS_HF1)
        } else {
            self.decode_num(bit_field, 4, DEC_HF0, POS_HF0)
        } & 0xff;

        if self.st_mode {
            if byte_place == 0 && bit_field > 0x0fff {
                byte_place = 0x100;
            }
            if byte_place == 0 {
                let bit_field = self.bits.get_bits()?;
                self.bits.add_bits(1);
                if bit_field & 0x8000 != 0 {
                    self.num_huf = 0;
                    self.st_mode = false;
                    return Ok(());
                }

                let length = if bit_field & 0x4000 != 0 { 4 } else { 3 };
                self.bits.add_bits(1);
                let mut distance = self.decode_num(self.bits.get_bits()?, 5, DEC_HF2, POS_HF2);
                distance = (distance << 5) | (self.bits.get_bits()? >> 11);
                self.bits.add_bits(5);
                self.copy_string(distance, length, out)?;
                return Ok(());
            }
            byte_place -= 1;
        } else {
            if self.num_huf >= 16 && self.flags_cnt == 0 {
                self.st_mode = true;
            }
            self.num_huf += 1;
        }

        self.avr_plc += byte_place;
        self.avr_plc -= self.avr_plc >> 8;
        self.nhfb += 16;
        if self.nhfb > 0xff {
            self.nhfb = 0x90;
            self.nlzb >>= 1;
        }

        let byte = (self.ch_set[byte_place as usize] >> 8) as u8;
        self.put_byte(byte, out)?;

        let idx = byte_place as usize;
        let mut cur_byte;
        let mut new_byte_place;
        loop {
            cur_byte = self.ch_set[idx] as u32;
            new_byte_place = self.n_to_pl[(cur_byte & 0xff) as usize] as usize;
            self.n_to_pl[(cur_byte & 0xff) as usize] =
                self.n_to_pl[(cur_byte & 0xff) as usize].wrapping_add(1);
            cur_byte += 1;
            if cur_byte & 0xff > 0xa1 {
                corr_huff(&mut self.ch_set, &mut self.n_to_pl);
            } else {
                break;
            }
        }

        self.ch_set[idx] = self.ch_set[new_byte_place];
        self.ch_set[new_byte_place] = cur_byte as u16;
        Ok(())
    }

    fn get_flags_buf(&mut self) -> Result<()> {
        let flags_place = self.decode_num(self.bits.get_bits()?, 5, DEC_HF2, POS_HF2) as usize;
        if flags_place >= self.ch_set_c.len() {
            return Ok(());
        }

        let mut flags;
        let mut new_flags_place;
        loop {
            flags = self.ch_set_c[flags_place] as u32;
            new_flags_place = self.n_to_pl_c[(flags & 0xff) as usize] as usize;
            self.n_to_pl_c[(flags & 0xff) as usize] =
                self.n_to_pl_c[(flags & 0xff) as usize].wrapping_add(1);
            self.flag_buf = flags >> 8;
            flags += 1;
            if flags & 0xff == 0 {
                corr_huff(&mut self.ch_set_c, &mut self.n_to_pl_c);
            } else {
                break;
            }
        }

        self.ch_set_c[flags_place] = self.ch_set_c[new_flags_place];
        self.ch_set_c[new_flags_place] = flags as u16;
        Ok(())
    }

    fn decode_num(
        &mut self,
        num: u32,
        mut start_pos: u32,
        dec_tab: &[u16],
        pos_tab: &[u16],
    ) -> u32 {
        let num = num & 0xfff0;
        let mut i = 0usize;
        while dec_tab[i] as u32 <= num {
            start_pos += 1;
            i += 1;
        }
        self.bits.add_bits(start_pos as usize);
        ((num - if i > 0 { dec_tab[i - 1] as u32 } else { 0 }) >> (16 - start_pos))
            + pos_tab[start_pos as usize] as u32
    }

    fn copy_string(&mut self, distance: u32, length: u32, out: &mut impl Write) -> Result<()> {
        if self.output_written + length as usize > self.target {
            return Err(Error::InvalidData("RAR 1.3 match exceeds output size"));
        }

        if (!self.first_win_done && distance as usize > self.unp_ptr)
            || distance as usize > 0x10000
            || distance == 0
        {
            for _ in 0..length {
                self.put_byte(0, out)?;
            }
        } else {
            for _ in 0..length {
                let byte = self.window[(self.unp_ptr.wrapping_sub(distance as usize)) & 0xffff];
                self.put_byte(byte, out)?;
            }
        }
        Ok(())
    }

    fn put_byte(&mut self, byte: u8, out: &mut impl Write) -> Result<()> {
        if self.output_written >= self.target {
            return Err(Error::InvalidData("RAR 1.3 literal exceeds output size"));
        }
        self.window[self.unp_ptr] = byte;
        self.unp_ptr = (self.unp_ptr + 1) & 0xffff;
        out.write_all(&[byte])
            .map_err(|_| Error::InvalidData("RAR 1.3 output write failed"))?;
        self.output_written += 1;
        Ok(())
    }

    fn remember_match(&mut self, distance: u32, length: u32) {
        self.old_dist[self.old_dist_ptr] = distance;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.last_dist = distance;
    }

    fn short_len1(&self, pos: usize) -> u32 {
        if pos == 1 {
            self.buf60 + 3
        } else {
            SHORT_LEN1[pos] as u32
        }
    }

    fn short_len2(&self, pos: usize) -> u32 {
        if pos == 3 {
            self.buf60 + 3
        } else {
            SHORT_LEN2[pos] as u32
        }
    }

    fn init_huff(&mut self) {
        for i in 0..256 {
            self.ch_set[i] = (i as u16) << 8;
            self.ch_set_b[i] = (i as u16) << 8;
            self.ch_set_a[i] = i as u16;
            self.ch_set_c[i] = (0u8.wrapping_sub(i as u8) as u16) << 8;
        }
        self.n_to_pl = [0; 256];
        self.n_to_pl_b = [0; 256];
        self.n_to_pl_c = [0; 256];
        corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
    }
}

fn corr_huff(char_set: &mut [u16; 256], num_to_place: &mut [u8; 256]) {
    let mut pos = 0usize;
    for rank in (0..=7).rev() {
        for _ in 0..32 {
            char_set[pos] = (char_set[pos] & !0xff) | rank;
            pos += 1;
        }
    }
    *num_to_place = [0; 256];
    for rank in (0..=6).rev() {
        num_to_place[rank] = ((7 - rank) * 32) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::{unpack15_decode, unpack15_encode, Unpack15};

    #[test]
    fn decode_member_from_reader_accepts_incremental_input() {
        struct TinyReader<'a> {
            input: &'a [u8],
        }

        impl std::io::Read for TinyReader<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.input.is_empty() {
                    return Ok(0);
                }
                let len = self.input.len().min(out.len()).min(2);
                out[..len].copy_from_slice(&self.input[..len]);
                self.input = &self.input[len..];
                Ok(len)
            }
        }

        let expected = b"RAR 1.4 incremental input fixture\n".repeat(32);
        let packed = unpack15_encode(&expected).unwrap();
        assert_eq!(unpack15_decode(&packed, expected.len()).unwrap(), expected);

        let mut reader = TinyReader { input: &packed };
        let mut decoder = Unpack15::new();
        let mut output = Vec::new();
        decoder
            .decode_member_from_reader(&mut reader, expected.len(), false, &mut output)
            .unwrap();

        assert_eq!(output, expected);
    }
}

#[derive(Clone)]
struct BitReader {
    input: Vec<u8>,
    bit_pos: usize,
    final_input: bool,
}

impl BitReader {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            bit_pos: 0,
            final_input: false,
        }
    }

    fn new_final(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            bit_pos: 0,
            final_input: true,
        }
    }

    fn append(&mut self, input: &[u8]) {
        self.compact();
        self.input.extend_from_slice(input);
    }

    fn finish(&mut self) {
        self.final_input = true;
    }

    fn compact(&mut self) {
        let bytes = self.bit_pos / 8;
        if bytes == 0 {
            return;
        }
        self.input.drain(..bytes);
        self.bit_pos -= bytes * 8;
    }

    fn get_bits(&self) -> Result<u32> {
        let mut value = 0u32;
        for i in 0..16 {
            value <<= 1;
            let bit_index = self.bit_pos + i;
            let byte = match self.input.get(bit_index / 8).copied() {
                Some(byte) => byte,
                None if self.final_input => 0,
                None => return Err(Error::NeedMoreInput),
            };
            value |= ((byte >> (7 - (bit_index % 8))) & 1) as u32;
        }
        Ok(value)
    }

    fn add_bits(&mut self, count: usize) {
        self.bit_pos += count;
    }
}

#[derive(Default)]
struct BitWriter {
    output: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            bit_pos: 0,
        }
    }

    fn write_bits(&mut self, value: u32, count: usize) {
        for i in (0..count).rev() {
            let bit = ((value >> i) & 1) as u8;
            if self.bit_pos.is_multiple_of(8) {
                self.output.push(0);
            }
            if bit != 0 {
                let idx = self.output.len() - 1;
                self.output[idx] |= 1 << (7 - (self.bit_pos % 8));
            }
            self.bit_pos += 1;
        }
    }

    fn finish(self) -> Vec<u8> {
        self.output
    }
}
