//! Config-record parsing, NAL framing and keyframe detection.
//!
//! Two things this crate exists to stop: each app re-deriving NAL framing with
//! subtly different rules, and each app deciding sync state from a different
//! bit. Both halves are offered for each framing — length-prefixed (what MP4
//! demuxers hand out) and Annex-B (what hardware decoders want) — because a
//! caller cannot choose which one it has; the demuxer decides.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

/// ISO/IEC 14496-15 §5.3.3.1 `AVCDecoderConfigurationRecord` to Annex-B,
/// carrying the SPS and PPS from it.
pub fn parse_avcc(data: &[u8]) -> Vec<u8> {
    if data.len() < 6 || data[0] != 1 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut pos = 6usize;
    let num_sps = (data[5] & 0x1F) as usize;
    for _ in 0..num_sps {
        if pos + 2 > data.len() {
            break;
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len > data.len() {
            break;
        }
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        out.extend_from_slice(&data[pos..pos + len]);
        pos += len;
    }
    if pos >= data.len() {
        return out;
    }
    let num_pps = data[pos] as usize;
    pos += 1;
    for _ in 0..num_pps {
        if pos + 2 > data.len() {
            break;
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len > data.len() {
            break;
        }
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        out.extend_from_slice(&data[pos..pos + len]);
        pos += len;
    }
    out
}

/// ISO/IEC 14496-15 §8.3.3.1.2 `HEVCDecoderConfigurationRecord` to Annex-B,
/// carrying the VPS, SPS and PPS from every array in it.
pub fn parse_hvcc(data: &[u8]) -> Vec<u8> {
    if data.len() < 23 || data[0] != 1 {
        return Vec::new();
    }
    let num_arrays = data[22] as usize;
    let mut out = Vec::new();
    let mut pos = 23usize;
    for _ in 0..num_arrays {
        if pos >= data.len() {
            break;
        }
        pos += 1;
        if pos + 2 > data.len() {
            break;
        }
        let num_nalus = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..num_nalus {
            if pos + 2 > data.len() {
                break;
            }
            let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if pos + len > data.len() {
                break;
            }
            out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
            out.extend_from_slice(&data[pos..pos + len]);
            pos += len;
        }
    }
    out
}

/// `lengthSizeMinusOne` from an `AVCDecoderConfigurationRecord` (byte 4).
///
/// A record too short to carry the field falls back to 4, the width every
/// path here assumes when there is no configured width to read.
pub fn nal_length_size_avcc(extradata: &[u8]) -> u8 {
    if extradata.len() < 5 {
        return 4;
    }
    (extradata[4] & 0x03) + 1
}

/// `lengthSizeMinusOne` from an `HEVCDecoderConfigurationRecord` (byte 21).
pub fn nal_length_size_hvcc(extradata: &[u8]) -> u8 {
    if extradata.len() > 21 {
        (extradata[21] & 0x03) + 1
    } else {
        4
    }
}

/// Whether a buffer already is Annex-B.
///
/// Only the head can carry a start code — Annex-B data opens with one. The
/// whole-buffer version of this test also matches a start code inside a NAL
/// payload, which says nothing about how the buffer is framed.
pub fn has_annexb_start_code(data: &[u8]) -> bool {
    data.starts_with(&[0x00, 0x00, 0x00, 0x01]) || data.starts_with(&[0x00, 0x00, 0x01])
}

/// Length-prefixed NAL units to Annex-B.
///
/// `nal_len_size` is the width of each NAL's length prefix, normally 1..=4. A
/// value outside that range returns the input unchanged: there is nothing to
/// reinterpret, and inventing a width would corrupt the stream.
///
/// A zero length is legal padding, so it is skipped rather than treated as
/// truncation. A length reaching past the end means the packet is truncated
/// and every remaining byte belongs to that one incomplete NAL — resyncing
/// would reinterpret its payload as length fields and emit garbage, so
/// conversion stops there instead. When nothing converts, the input comes back
/// so the caller still has a packet rather than a silent empty one.
pub fn avcc_to_annexb(data: &[u8], nal_len_size: usize) -> Vec<u8> {
    if !(1..=4).contains(&nal_len_size) {
        return data.to_vec();
    }
    let start_code: &[u8] = &[0x00, 0x00, 0x00, 0x01];
    let mut output = Vec::with_capacity(data.len() + 64);
    let mut offset = 0;
    while offset + nal_len_size <= data.len() {
        let mut nalu_len = 0usize;
        for _ in 0..nal_len_size {
            nalu_len = (nalu_len << 8) | data[offset] as usize;
            offset += 1;
        }
        if nalu_len == 0 {
            continue;
        }
        if offset + nalu_len > data.len() {
            break;
        }
        output.extend_from_slice(start_code);
        output.extend_from_slice(&data[offset..offset + nalu_len]);
        offset += nalu_len;
    }
    if output.is_empty() {
        data.to_vec()
    } else {
        output
    }
}

fn skip_start_code(d: &[u8]) -> &[u8] {
    if d.starts_with(&[0x00, 0x00, 0x00, 0x01]) {
        &d[4..]
    } else if d.starts_with(&[0x00, 0x00, 0x01]) {
        &d[3..]
    } else {
        d
    }
}

fn find_start_code(d: &[u8]) -> Option<usize> {
    d.windows(4)
        .position(|w| w == [0x00, 0x00, 0x00, 0x01])
        .or_else(|| d.windows(3).position(|w| w == [0x00, 0x00, 0x01]))
}

/// Scan Annex-B NAL units, returning `true` as soon as `f` matches.
fn scan_annexb(mut data: &[u8], mut f: impl FnMut(&[u8]) -> bool) -> bool {
    loop {
        let nal = skip_start_code(data);
        if nal.len() == data.len() {
            return false;
        }
        data = nal;
        if data.is_empty() {
            return false;
        }
        let end = find_start_code(&data[1..])
            .map(|p| p + 1)
            .unwrap_or(data.len());
        if f(&data[..end]) {
            return true;
        }
        data = &data[end..];
    }
}

/// Scan length-prefixed NAL units, returning `true` as soon as `f` matches.
///
/// A zero length, or one reaching past the end, ends the scan as `false`: what
/// follows cannot be read as framing, so there is nothing left to test.
fn scan_length_prefixed(
    mut data: &[u8],
    nal_len_size: usize,
    mut f: impl FnMut(&[u8]) -> bool,
) -> bool {
    while data.len() >= nal_len_size {
        let mut n = 0usize;
        for &b in &data[..nal_len_size] {
            n = (n << 8) | b as usize;
        }
        data = &data[nal_len_size..];
        if n == 0 || n > data.len() {
            return false;
        }
        if f(&data[..n]) {
            return true;
        }
        data = &data[n..];
    }
    false
}

/// Sync-frame detection for packets framed as they come out of a container.
///
/// Every function is conservative: it reports `true` only when sure, because
/// calling a delta frame a key frame feeds it to a decoder that has no
/// reference to build from.
pub mod sync {
    use super::{scan_annexb, scan_length_prefixed};

    fn h264_nal_is_sync(nal: &[u8]) -> bool {
        // Type 5 is IDR, the only H.264 random access point. Types 20 and 21
        // are slice extensions whose IDR status lives in a header this does
        // not parse, so they are not counted rather than guessed at.
        matches!(nal.first().map(|b| b & 0x1F), Some(5))
    }

    fn hevc_nal_is_sync(nal: &[u8]) -> bool {
        // IRAP covers BLA (16..=18), IDR (19..=20), CRA (21) and the reserved
        // IRAP slots (22..=23). NAL type 32 is VPS, which is not one — an
        // in-band parameter set is not a random access point.
        matches!(nal.first().map(|b| (b >> 1) & 0x3F), Some(16..=23))
    }

    /// H.264 access unit carrying an IDR, in AVCC framing.
    pub fn h264_avcc_has_idr(data: &[u8], nal_len_size: usize) -> bool {
        scan_length_prefixed(data, nal_len_size, h264_nal_is_sync)
    }

    /// H.264 access unit carrying an IDR, in Annex-B framing.
    pub fn h264_annexb_has_idr(data: &[u8]) -> bool {
        scan_annexb(data, h264_nal_is_sync)
    }

    /// HEVC access unit carrying an IRAP picture, in AVCC framing.
    pub fn hevc_hvcc_has_keyframe(data: &[u8], nal_len_size: usize) -> bool {
        scan_length_prefixed(data, nal_len_size, hevc_nal_is_sync)
    }

    /// HEVC access unit carrying an IRAP picture, in Annex-B framing.
    pub fn hevc_annexb_has_keyframe(data: &[u8]) -> bool {
        scan_annexb(data, hevc_nal_is_sync)
    }

    /// Whether an HEVC access unit carries RASL pictures (types 8 and 9).
    ///
    /// In an open-GOP stream these follow the IRAP in decode order but
    /// predict from the *previous* GOP, so a decoder that just resumed
    /// mid-stream never saw what they reference. A caller that resumed
    /// mid-stream drops them. RADL (types 6 and 7) also leads the IRAP but
    /// predicts forward from it, so it is kept.
    pub fn hevc_hvcc_has_rasl(data: &[u8], nal_len_size: usize) -> bool {
        scan_length_prefixed(data, nal_len_size, |nal| {
            matches!(nal.first().map(|b| (b >> 1) & 0x3F), Some(8 | 9))
        })
    }

    /// RFC 6386 §9.1: the frame tag's first bit is the frame type, 0 for key
    /// frames.
    pub fn vp8_is_keyframe(data: &[u8]) -> bool {
        matches!(data.first(), Some(b) if b & 0x01 == 0)
    }

    /// VP9's uncompressed header, first byte, most significant bit first:
    /// `frame_marker(2) | profile_low(1) | profile_high(1) |
    /// show_existing_frame(1) | frame_type(1, 0 = key) | show_frame(1) |
    /// error_resilient(1)`.
    ///
    /// `show_existing_frame` re-displays a frame already in a reference slot,
    /// so it is never a key frame. It matters that it is checked at all: for
    /// that packet the next three bits are `frame_to_show_map_idx`, so a check
    /// reading `frame_type` from its fixed position reports any re-display
    /// with an even slot as a key frame.
    ///
    /// Profile 3 inserts a reserved bit after the profile fields and shifts
    /// everything that follows, so it returns `false` rather than decoding the
    /// wrong bits.
    pub fn vp9_is_keyframe(data: &[u8]) -> bool {
        let Some(&b) = data.first() else {
            return false;
        };
        if (b >> 6) & 0x03 != 0x02 {
            return false;
        }
        let profile = ((b >> 5) & 0x01) | (((b >> 4) & 0x01) << 1);
        if profile == 3 {
            return false;
        }
        if (b >> 3) & 0x01 == 1 {
            return false;
        }
        (b >> 2) & 0x01 == 0
    }

    fn leb128(data: &[u8], pos: &mut usize) -> Option<usize> {
        let mut value = 0usize;
        for i in 0..8 {
            let b = *data.get(*pos)?;
            *pos += 1;
            value |= ((b & 0x7F) as usize) << (i * 7);
            if b & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    /// Whether an AV1 packet starts a fresh decodable sequence.
    ///
    /// True on a `SEQUENCE_HEADER` OBU, or on a frame whose uncompressed
    /// header has `show_existing_frame == 0` and a key (0) or intra-only (2)
    /// frame type. A delta returns `false`, so a software decoder stood up
    /// after a hardware failure waits for a real key frame instead of being
    /// handed a delta it cannot reconstruct — rav1d rejects those as invalid
    /// data.
    pub fn av1_is_keyframe(data: &[u8]) -> bool {
        let mut pos = 0usize;
        let mut saw_seq_header = false;
        while pos < data.len() {
            let hdr = data[pos];
            pos += 1;
            // OBU header: forbidden(1)=0 | type(4) | ext(1) | has_size(1) | reserved(1)
            if hdr & 0x80 != 0 {
                return saw_seq_header;
            }
            let obu_type = (hdr >> 3) & 0x0F;
            let has_ext = (hdr >> 2) & 0x01 != 0;
            let has_size = (hdr >> 1) & 0x01 != 0;
            if has_ext {
                if pos >= data.len() {
                    break;
                }
                pos += 1;
            }
            let payload_len = if has_size {
                match leb128(data, &mut pos) {
                    Some(n) => n,
                    None => break,
                }
            } else {
                data.len().saturating_sub(pos)
            };
            let payload_start = pos;
            let payload_end = payload_start.saturating_add(payload_len).min(data.len());
            match obu_type {
                1 => saw_seq_header = true,
                // FRAME_HEADER | FRAME | REDUNDANT_FRAME_HEADER: the first
                // payload byte holds show_existing_frame(1) | frame_type(2) |
                // show_frame(1) | ... read most significant bit first.
                3 | 6 | 7 if payload_start < payload_end => {
                    let b = data[payload_start];
                    if (b >> 7) & 0x01 == 0 {
                        let frame_type = (b >> 5) & 0x03;
                        if frame_type == 0 || frame_type == 2 {
                            return true;
                        }
                    }
                }
                _ => {}
            }
            if saw_seq_header {
                return true;
            }
            pos = payload_end;
            if !has_size {
                break;
            }
        }
        saw_seq_header
    }
}

#[cfg(test)]
mod tests {
    use super::sync::*;
    use super::*;

    #[test]
    fn annexb_detection_is_head_only() {
        assert!(has_annexb_start_code(&[0, 0, 0, 1, 0x65]));
        assert!(has_annexb_start_code(&[0, 0, 1, 0x65]));
        // A start code inside the payload is not how the buffer is framed.
        assert!(!has_annexb_start_code(&[1, 0, 0, 0, 1, 0x65]));
        assert!(!has_annexb_start_code(&[]));
        assert!(!has_annexb_start_code(&[0, 0, 0]));
    }

    #[test]
    fn zero_length_padding_is_skipped() {
        // A zero-length entry followed by a real 2-byte NAL.
        let data = [0, 0, 0, 0, 0, 0, 0, 2, 0x65, 0x88];
        assert_eq!(avcc_to_annexb(&data, 4), vec![0, 0, 0, 1, 0x65, 0x88]);
    }

    #[test]
    fn an_unconvertible_packet_comes_back_intact() {
        // Every length is zero, so nothing was converted.
        let data = [0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(avcc_to_annexb(&data, 4), data.to_vec());
        // Out-of-range width is not a width to reinterpret.
        let nals = [0, 0, 0, 2, 0x65, 0x88];
        assert_eq!(avcc_to_annexb(&nals, 0), nals.to_vec());
        assert_eq!(avcc_to_annexb(&nals, 5), nals.to_vec());
    }

    #[test]
    fn truncation_stops_instead_of_resyncing() {
        // The length overruns the packet, so the rest is one incomplete NAL.
        // Emitting anything would reinterpret its payload as length fields.
        let data = [0x00, 0xff, 0x00, 0x00, 0x65];
        assert_eq!(avcc_to_annexb(&data, 4), data.to_vec());
        // Complete NALs before the bad one still convert.
        let data = [0, 0, 0, 2, 0x65, 0x88, 0, 0, 0, 9, 0x41];
        assert_eq!(avcc_to_annexb(&data, 4), vec![0, 0, 0, 1, 0x65, 0x88]);
    }

    #[test]
    fn short_records_do_not_panic() {
        for len in 0..30 {
            let d = vec![1u8; len];
            let _ = parse_avcc(&d);
            let _ = parse_hvcc(&d);
            let _ = nal_length_size_avcc(&d);
            let _ = nal_length_size_hvcc(&d);
        }
        let _ = parse_avcc(&[]);
        let _ = parse_hvcc(&[]);
    }

    #[test]
    fn length_sizes_default_to_four() {
        assert_eq!(nal_length_size_avcc(&[]), 4);
        assert_eq!(nal_length_size_hvcc(&[]), 4);
        let mut avcc = vec![0u8; 5];
        avcc[4] = 0x02;
        assert_eq!(nal_length_size_avcc(&avcc), 3);
        let mut hvcc = vec![0u8; 22];
        hvcc[21] = 0x03;
        assert_eq!(nal_length_size_hvcc(&hvcc), 4);
    }

    #[test]
    fn h264_idr_is_found_in_both_framings() {
        let idr = [0x65u8, 0x88, 0x84];
        let p = [0x41u8, 0x9a, 0x20];
        let mut avcc = vec![0, 0, 0, 3];
        avcc.extend_from_slice(&p);
        avcc.extend_from_slice(&[0, 0, 0, 3]);
        avcc.extend_from_slice(&idr);
        assert!(h264_avcc_has_idr(&avcc, 4));
        assert!(!h264_avcc_has_idr(&[0, 0, 0, 3, 0x41, 0x9a, 0x20], 4));
        assert!(!h264_avcc_has_idr(&[0, 0, 0, 40, 0x65], 4));

        let annexb = [0, 0, 0, 1, 0x41, 0x9a, 0x20, 0, 0, 0, 1, 0x65, 0x88, 0x84];
        assert!(h264_annexb_has_idr(&annexb));
        assert!(!h264_annexb_has_idr(&[0, 0, 0, 1, 0x41, 0x9a, 0x20]));
    }

    /// A trailing start code with no NAL after it leaves the scan with nothing
    /// to index into.
    #[test]
    fn annexb_scan_survives_a_trailing_start_code() {
        assert!(h264_annexb_has_idr(&[0, 0, 0, 1, 0x65, 0x88, 0, 0, 0, 1]));
        assert!(!h264_annexb_has_idr(&[0, 0, 0, 1]));
    }

    #[test]
    fn hevc_irap_covers_bl_idr_and_cra_but_not_parameter_sets() {
        // 16 = BLA_W_LP, 19 = IDR_W_RADL, 21 = CRA_NUT.
        for nal_type in [16u8, 19, 21, 23] {
            let packet = [0, 0, 0, 2, nal_type << 1, 0x01];
            assert!(hevc_hvcc_has_keyframe(&packet, 4), "type {nal_type}");
            let annexb = [0, 0, 0, 1, nal_type << 1, 0x01];
            assert!(hevc_annexb_has_keyframe(&annexb), "type {nal_type}");
        }
        // 32 is VPS: an in-band parameter set is not a random access point.
        assert!(!hevc_hvcc_has_keyframe(&[0, 0, 0, 2, 32 << 1, 0x01], 4));
        // Type 7 is RADL, an inter picture.
        assert!(!hevc_hvcc_has_keyframe(&[0, 0, 0, 2, 7 << 1, 0x01], 4));
    }

    #[test]
    fn only_rasl_pictures_count_as_leading() {
        for nal_type in [8u8, 9] {
            let packet = [0, 0, 0, 2, nal_type << 1, 0x01];
            assert!(hevc_hvcc_has_rasl(&packet, 4), "type {nal_type}");
        }
        // RADL predicts forward from the IRAP and stays.
        assert!(!hevc_hvcc_has_rasl(&[0, 0, 0, 2, 7 << 1, 0x01], 4));
    }

    /// The bug this catches: a `show_existing_frame` packet re-displays a
    /// frame from a reference slot and is not a key frame, but the bits a
    /// check reading `frame_type` from the wrong position sees belong to
    /// `frame_to_show_map_idx` — which reads as a key frame whenever the slot
    /// index is even.
    #[test]
    fn vp9_show_existing_frame_is_never_a_keyframe() {
        // frame_marker 0b10, profile 0, show_existing_frame 1, slot index 0.
        assert!(!vp9_is_keyframe(&[0b1000_1000]));
        assert!(!vp9_is_keyframe(&[0b1000_1010]));
        assert!(!vp9_is_keyframe(&[0b1000_1110]));
    }

    #[test]
    fn vp9_keyframe_needs_the_right_marker_and_frame_type() {
        // frame_marker 0b10, profile 0, show_existing 0, frame_type 0 = key.
        assert!(vp9_is_keyframe(&[0b1000_0000]));
        assert!(vp9_is_keyframe(&[0b1000_0011]));
        // frame_type 1 = inter frame, whatever error_resilient says.
        assert!(!vp9_is_keyframe(&[0b1000_0100]));
        assert!(!vp9_is_keyframe(&[0b1000_0101]));
        // Wrong frame marker.
        assert!(!vp9_is_keyframe(&[0b0000_0000]));
        // Profile 3 shifts the layout, so it is refused rather than misread.
        assert!(!vp9_is_keyframe(&[0b1011_0000]));
        assert!(!vp9_is_keyframe(&[]));
    }

    #[test]
    fn vp8_keyframe_is_frame_tag_bit_zero() {
        assert!(vp8_is_keyframe(&[0x00]));
        assert!(vp8_is_keyframe(&[0b1000_0000]));
        assert!(!vp8_is_keyframe(&[0x01]));
        assert!(!vp8_is_keyframe(&[]));
    }

    fn obu(obu_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![(obu_type << 3) | 0b010, payload.len() as u8];
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn av1_fresh_sequences_are_keyframes() {
        assert!(av1_is_keyframe(&obu(1, &[0x00])));
        // show_existing_frame 0 | frame_type 0 = KEY | show_frame 1.
        assert!(av1_is_keyframe(&obu(6, &[0b0001_0000])));
        // frame_type 2 = INTRA_ONLY, which a stream can use to start a
        // sequence after a seek without repeating its sequence header.
        assert!(av1_is_keyframe(&obu(6, &[0b0101_0000])));
    }

    #[test]
    fn av1_deltas_are_not_keyframes() {
        // show_existing_frame 0 | frame_type 1 = INTER.
        assert!(!av1_is_keyframe(&obu(6, &[0b0011_0000])));
        // show_existing_frame 1 — re-display of a frame already decoded.
        assert!(!av1_is_keyframe(&obu(6, &[0b1000_0000])));
        assert!(!av1_is_keyframe(&[]));
    }
}
