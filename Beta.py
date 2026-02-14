#!/usr/bin/env python3
"""
Discord Voice Node Offset Finder v2.0
=======================================
Automatically discovers all 18 patch offsets for any discord_voice.node build
using tiered signature scanning, chained derivation, sliding-window recovery,
and structural heuristics.

Resolution pipeline (each tier is attempted only if the previous one failed):
  Tier 1 — Primary byte-pattern signatures (8 anchors)
  Tier 2 — Relaxed alternate signatures (broader wildcards)
  Tier 3 — Patched-binary fallback patterns
  Tier 4 — Topologically-sorted relative derivation (9 chained offsets)
  Tier 5 — Sliding-window derivation recovery (±128 bytes around expected)
  Tier 6 — Structural heuristic scanning (Opus constants, imul patterns)

Cross-validation verifies consistency between independently-found offsets.

Signature stability verified across:
  - December 2025 build (9219)
  - February 2026 build (Feb 9, 2026)

Usage:
  python discord_voice_node_offset_finder.py <path_to_discord_voice.node>
  python discord_voice_node_offset_finder.py  (auto-detects Discord install)

Requirements: Python 3.6+ (stdlib only)
Optional:     networkx + matplotlib (for dependency graph PNG)
"""

import sys
import os
import struct
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

try:
    import networkx as nx
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    VIZ_AVAILABLE = True
except ImportError:
    VIZ_AVAILABLE = False

VERSION = "2.0"


# region Configuration

# Relative offset derivation map.
# Format: derived_name -> [(anchor_name, delta), ...] (tried in order)
# Multiple paths provide chained fallback: if the first anchor isn't found,
# the next path is attempted.  This is critical for DuplicateEmulateBitrateModified
# which chains through EmulateBitrateModified (itself derived).
DERIVATIONS = {
    "EmulateStereoSuccess2": [
        ("EmulateStereoSuccess1", 0xC),
    ],
    "Emulate48Khz": [
        ("EmulateStereoSuccess1", 0x168),
    ],
    "EmulateBitrateModified": [
        ("EmulateStereoSuccess1", 0x45F),
    ],
    "HighPassFilter": [
        ("EmulateStereoSuccess1", 0xC275),
    ],
    "SetsBitrateBitwiseOr": [
        ("SetsBitrateBitrateValue", 0x8),
    ],
    "AudioEncoderOpusConfigIsOk": [
        ("AudioEncoderOpusConfigSetChannels", 0x29C),
    ],
    "DcReject": [
        ("HighpassCutoffFilter", 0x1E0),
    ],
    "EncoderConfigInit1": [
        ("AudioEncoderOpusConfigSetChannels", 0xA),
    ],
    "DuplicateEmulateBitrateModified": [
        ("EmulateBitrateModified", 0x4EE6),           # primary: chained via derived anchor
        ("EmulateStereoSuccess1", 0x45F + 0x4EE6),    # fallback: direct from root anchor
    ],
}

# Sliding window parameters for derivation recovery.
# When exact delta fails byte verification, scan this many bytes in each
# direction for the expected original bytes.
SLIDING_WINDOW_DEFAULT = 128
SLIDING_WINDOW_OVERRIDES = {
    # Single-byte expected values get a tighter window to reduce false positives
    "EmulateStereoSuccess2": 48,     # expected: 0x75 (jne)
    "EncoderConfigInit1": 48,        # expected: 00 7D 00 00 (distinctive 4-byte)
}

# endregion Configuration


# region Signature Definitions

class Signature:
    """Defines a byte pattern signature with optional relaxed alternates."""

    def __init__(self, name, pattern_hex, target_offset, description,
                 expected_original=None, patch_bytes=None, patch_len=None,
                 disambiguator=None, alt_patterns=None):
        self.name = name
        self.pattern_hex = pattern_hex
        self.pattern = self._parse(pattern_hex)
        self.target_offset = target_offset
        self.description = description
        self.expected_original = expected_original
        self.patch_bytes = patch_bytes
        self.patch_len = patch_len
        self.disambiguator = disambiguator
        self.alt_patterns = []
        if alt_patterns:
            for alt_hex, alt_off in alt_patterns:
                self.alt_patterns.append((self._parse(alt_hex), alt_off))

    @staticmethod
    def _parse(hex_str):
        return [None if b == '??' else int(b, 16) for b in hex_str.split()]

    def __repr__(self):
        return f"Signature({self.name})"


def _mono_downmixer_disambiguator(data, match_offset):
    """Select the correct MonoDownmixer by checking for REX.R movzx (44 0F B6)
    after the jg branch.  Uses a broad 70-byte window so the match survives
    if the compiler inserts extra instructions between the jg and the movzx."""
    jg_pos = match_offset + 19
    if jg_pos + 6 > len(data):
        return False
    # Tight window first (high confidence, fast)
    if b'\x44\x0f\xb6' in data[jg_pos + 6 : jg_pos + 18]:
        return True
    # Broad window (survives extra compiler-inserted instructions)
    if b'\x44\x0f\xb6' in data[jg_pos + 6 : jg_pos + 70]:
        return True
    return False


# 9 independent anchor signatures with relaxed alternates.
# Primary patterns are exact; alt_patterns wildcard bytes the compiler may vary.
SIGNATURES = [
    Signature(
        name="EmulateStereoSuccess1",
        pattern_hex="E8 ?? ?? ?? ?? BD ?? 00 00 00 80 BC 24 80 01 00 00 01",
        target_offset=6,
        description="Stereo channel count: call <rel>; mov ebp, CHANNELS; cmp byte [rsp+0x180], 1",
        expected_original="01",
        patch_bytes="02",
        alt_patterns=[
            # Stack offset 0x180 might change with MSVC version bump
            ("E8 ?? ?? ?? ?? BD ?? 00 00 00 80 BC 24 ?? ?? 00 00 01", 6),
            # Even broader: just the mov ebp + cmp structure
            ("BD ?? 00 00 00 80 BC 24 ?? ?? 00 00 01", 1),
        ],
    ),

    Signature(
        name="AudioEncoderOpusConfigSetChannels",
        pattern_hex="48 B9 14 00 00 00 80 BB 00 00 48 89 08 48 C7 40 08 ?? 00 00 00",
        target_offset=17,
        description="Opus config: mov rcx, {48000<<32|20}; mov [rax],rcx; mov qword [rax+8], CHANNELS",
        expected_original="01",
        patch_bytes="02",
        alt_patterns=[
            # Wildcard the [rax+8] offset in case struct layout shifts
            ("48 B9 14 00 00 00 80 BB 00 00 48 89 08 48 C7 40 ?? ?? 00 00 00", 17),
            # Wildcard the store register too
            ("48 B9 14 00 00 00 80 BB 00 00 48 89 ?? 48 C7 ?? ?? ?? 00 00 00", 17),
        ],
    ),

    Signature(
        name="MonoDownmixer",
        pattern_hex="48 89 F9 E8 ?? ?? ?? ?? 84 C0 74 0D 83 BE ?? ?? 00 00 09 0F 8F",
        target_offset=8,
        description="Mono downmix gate: mov rcx,rdi; call; test al,al; jz +0xD; cmp [rsi+??], 9; jg",
        expected_original="84 C0 74 0D",
        patch_bytes="90 90 90 90 90 90 90 90 90 90 90 90 E9",
        patch_len=13,
        disambiguator=_mono_downmixer_disambiguator,
        alt_patterns=[
            # Compiler might use different register for mov rcx,rdi
            ("48 89 ?? E8 ?? ?? ?? ?? 84 C0 ?? ?? 83 ?? ?? ?? 00 00 09 0F 8F", 8),
        ],
    ),

    Signature(
        name="SetsBitrateBitrateValue",
        pattern_hex="89 F8 48 B9 ?? ?? ?? ?? 01 00 00 00 48 09 C1 48 89 4E 1C",
        target_offset=4,
        description="Bitrate setter: mov eax,edi; mov rcx,imm64; or rcx,rax; mov [rsi+0x1C],rcx",
        expected_original=None,
        alt_patterns=[
            # Struct offset 0x1C might change
            ("89 F8 48 B9 ?? ?? ?? ?? 01 00 00 00 48 09 C1 48 89 ?? ??", 4),
            # Source register might change
            ("89 ?? 48 B9 ?? ?? ?? ?? 01 00 00 00 48 09 C1 48 89 ?? ??", 4),
        ],
    ),

    Signature(
        name="ThrowError",
        pattern_hex="56 56 57 53 48 81 EC C8 00 00 00 0F 29 B4 24 B0 00 00 00 4C 89 CE 4C 89 C7 89 D3",
        target_offset=-1,
        description="Error handler: push rsi;rdi;rbx; sub rsp,0xC8; movaps [rsp+0xB0],xmm6; ...",
        expected_original="41",
        patch_bytes="C3",
        alt_patterns=[
            # Stack frame size and SSE save offset might change together
            ("56 56 57 53 48 81 EC ?? ?? 00 00 0F 29 B4 24 ?? ?? 00 00 4C 89 CE 4C 89 C7 89 D3", -1),
        ],
    ),

    Signature(
        name="DownmixFunc",
        pattern_hex="57 41 56 41 55 41 54 56 57 55 53 48 83 EC 10 48 89 0C 24 45 85 C0",
        target_offset=-1,
        description="Downmix function: push r15..r12,rsi,rdi,rbp,rbx; sub rsp,0x10; ...",
        expected_original="41",
        patch_bytes="C3",
        alt_patterns=[
            # Sub rsp size might change
            ("57 41 56 41 55 41 54 56 57 55 53 48 83 EC ?? 48 89 0C 24 45 85 C0", -1),
            # Even more relaxed: just the 8 push sequence
            ("57 41 56 41 55 41 54 56 57 55 53 48 83 EC ?? 48 89 0C 24", -1),
        ],
    ),

    Signature(
        name="CreateAudioFrameStereo",
        pattern_hex="B8 80 BB 00 00 BD 00 7D 00 00 0F 43 E8",
        target_offset=31,
        description="Audio frame: mov eax,48000; mov ebp,32000; cmovae ebp,eax; ... second cmov",
        expected_original="4C 0F 43 E8",
        patch_bytes="49 89 C5 90",
        alt_patterns=[
            # cmov encoding might vary (0F 43 is cmovae, could be 0F 42 cmovb)
            ("B8 80 BB 00 00 BD 00 7D 00 00 0F ?? E8", 31),
        ],
    ),

    Signature(
        name="HighpassCutoffFilter",
        pattern_hex="56 48 83 EC 30 44 0F 29 44 24 20 0F 29 7C 24 10 0F 29 34 24",
        target_offset=0,
        description="HP cutoff filter: push rsi; sub rsp,0x30; SSE saves (xmm8,xmm7,xmm6)",
        expected_original="56 48 83 EC 30",
        patch_bytes=None,
        patch_len=0x100,
        alt_patterns=[
            # Sub rsp size and SSE save offsets might shift together
            ("56 48 83 EC ?? 44 0F 29 44 24 ?? 0F 29 7C 24 ?? 0F 29 34 24", 0),
        ],
    ),

    Signature(
        name="EncoderConfigInit2",
        pattern_hex="48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 48 10 66 C7 40 18 00 00 C6 40 1A 00",
        target_offset=6,
        description="Encoder config constructor 2: mov rcx,packed_qword; mov [rax+0x10],rcx; ...",
        expected_original="00 7D 00 00",
        patch_bytes="00 D0 07 00",
        patch_len=4,
        alt_patterns=[
            # Struct member offsets might shift
            ("48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 48 ?? 66 C7 40 ?? 00 00 C6 40 ?? 00", 6),
        ],
    ),
]

# endregion Signature Definitions


# region PE Parser

def parse_pe(data):
    """Extract PE info and compute file offset adjustment dynamically from .text section."""
    if len(data) < 0x40 or data[:2] != b'MZ':
        return None

    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if pe_offset + 4 > len(data) or data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        return None

    coff = pe_offset + 4
    num_sections = struct.unpack_from('<H', data, coff + 2)[0]
    timestamp = struct.unpack_from('<I', data, coff + 4)[0]
    opt_header_size = struct.unpack_from('<H', data, coff + 16)[0]

    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]

    if magic == 0x20B:  # PE32+
        image_base = struct.unpack_from('<Q', data, opt + 24)[0]
    else:  # PE32
        image_base = struct.unpack_from('<I', data, opt + 28)[0]

    sections = []
    sec_offset = opt + opt_header_size
    for i in range(num_sections):
        s = sec_offset + i * 40
        name = data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', data, s + 8)[0]
        vaddr = struct.unpack_from('<I', data, s + 12)[0]
        raw_size = struct.unpack_from('<I', data, s + 16)[0]
        raw_offset = struct.unpack_from('<I', data, s + 20)[0]
        sections.append({
            'name': name, 'vsize': vsize, 'vaddr': vaddr,
            'raw_size': raw_size, 'raw_offset': raw_offset
        })

    # Dynamic adjustment: .text VA - .text raw offset
    # Falls back to first executable section, then to hardcoded 0xC00
    file_offset_adjustment = None
    text_section = None
    for sec in sections:
        if sec['name'] == '.text':
            text_section = sec
            file_offset_adjustment = sec['vaddr'] - sec['raw_offset']
            break

    if file_offset_adjustment is None:
        for sec in sections:
            if sec['vaddr'] > 0 and sec['raw_offset'] > 0:
                file_offset_adjustment = sec['vaddr'] - sec['raw_offset']
                text_section = sec
                break

    if file_offset_adjustment is None:
        file_offset_adjustment = 0xC00  # hardcoded fallback
        text_section = sections[0] if sections else None

    build_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)

    return {
        'image_base': image_base,
        'timestamp': timestamp,
        'build_time': build_time,
        'sections': sections,
        'pe_offset': pe_offset,
        'text_section': text_section,
        'file_offset_adjustment': file_offset_adjustment,
    }

# endregion PE Parser


# region Signature Scanner

def scan_pattern(data, pattern, limit=0, start=0, end=None):
    """Fast pattern scanner using bytes.find() for initial candidate skip.

    Instead of checking every byte position (O(n*m) in Python), this finds
    the first non-wildcard byte using C-speed bytes.find(), then verifies
    the full pattern only at candidate positions.  ~100x faster than pure
    Python loop on a 14MB binary.
    """
    matches = []
    pat_len = len(pattern)
    if end is None:
        end = len(data)

    # Find first non-wildcard byte for the fast skip
    first_fixed = None
    for i, b in enumerate(pattern):
        if b is not None:
            first_fixed = (i, b)
            break

    if first_fixed is None:
        return matches  # all wildcards = meaningless

    skip_to, first_byte = first_fixed
    needle = bytes([first_byte])
    pos = start

    while pos <= end - pat_len:
        idx = data.find(needle, pos + skip_to, end)
        if idx < 0:
            break

        candidate = idx - skip_to
        if candidate < start:
            pos = idx + 1
            continue

        if candidate + pat_len > end:
            break

        # Full pattern check at candidate
        match = True
        for j, p in enumerate(pattern):
            if p is not None and data[candidate + j] != p:
                match = False
                break

        if match:
            matches.append(candidate)
            if 0 < limit <= len(matches):
                return matches

        pos = candidate + 1

    return matches


def find_offset(data, sig, text_start=0, text_end=None):
    """Find offset using tiered pattern matching: primary -> relaxed alternates.
    Returns (file_offset, error_or_None, tier_string)."""

    tiers = [(sig.pattern, sig.target_offset, "primary")]
    for i, (p, o) in enumerate(sig.alt_patterns):
        tiers.append((p, o, f"relaxed-{i+1}"))

    for pattern, target_off, tier in tiers:
        matches = scan_pattern(data, pattern, start=text_start, end=text_end)

        if len(matches) == 0:
            continue

        if len(matches) == 1:
            file_offset = matches[0] + target_off
            if 0 <= file_offset < len(data):
                return file_offset, None, tier

        # Multiple matches — resolve via disambiguator then byte validation
        resolved = list(matches)

        if sig.disambiguator and len(resolved) > 1:
            valid = [m for m in resolved if sig.disambiguator(data, m)]
            if len(valid) >= 1:
                resolved = valid

        if len(resolved) > 1 and sig.expected_original:
            expected = bytes.fromhex(sig.expected_original.replace(' ', ''))
            valid = []
            for m in resolved:
                tf = m + target_off
                if 0 <= tf and tf + len(expected) <= len(data):
                    if data[tf:tf+len(expected)] == expected:
                        valid.append(m)
            if len(valid) >= 1:
                resolved = valid

        if len(resolved) > 1 and sig.patch_bytes and not sig.patch_bytes.startswith('<'):
            # Also check if any match shows already-patched bytes (still valid)
            patched = bytes.fromhex(sig.patch_bytes.replace(' ', ''))
            valid = []
            for m in resolved:
                tf = m + target_off
                if 0 <= tf and tf + len(patched) <= len(data):
                    if data[tf:tf+len(patched)] == patched:
                        valid.append(m)
            if len(valid) >= 1:
                resolved = valid

        if len(resolved) == 1:
            file_offset = resolved[0] + target_off
            if 0 <= file_offset < len(data):
                return file_offset, None, tier
        elif len(resolved) > 1:
            # For relaxed tiers, accept first match with a warning flag
            if tier != "primary":
                file_offset = resolved[0] + target_off
                if 0 <= file_offset < len(data):
                    return file_offset, None, f"{tier}(ambig:{len(resolved)})"

    return None, f"no matches across {len(tiers)} tier(s)", "none"

# endregion Signature Scanner


# region Offset Discovery Engine

def _topo_sort_derivations(derivations):
    """Sort derivation keys so parents resolve before children.

    This ensures EmulateBitrateModified resolves before
    DuplicateEmulateBitrateModified which depends on it."""
    all_derived = set(derivations.keys())
    order = []
    visited = set()

    def visit(name):
        if name in visited:
            return
        visited.add(name)
        if name in derivations:
            for anchor, _delta in derivations[name]:
                if anchor in all_derived:
                    visit(anchor)
        order.append(name)

    for name in derivations:
        visit(name)
    return order


def _all_offset_names():
    """Complete ordered list of all 18 offset names."""
    return [
        "EmulateStereoSuccess1", "EmulateStereoSuccess2", "Emulate48Khz",
        "EmulateBitrateModified", "SetsBitrateBitrateValue", "SetsBitrateBitwiseOr",
        "HighPassFilter", "CreateAudioFrameStereo", "AudioEncoderOpusConfigSetChannels",
        "AudioEncoderOpusConfigIsOk", "MonoDownmixer", "ThrowError", "DownmixFunc",
        "HighpassCutoffFilter", "DcReject", "DuplicateEmulateBitrateModified",
        "EncoderConfigInit1", "EncoderConfigInit2",
    ]


def _sliding_window_recover(data, anchor_config, delta, name, adj):
    """When exact derivation delta fails byte verification, scan nearby.

    The compiler sometimes inserts or removes a few bytes between the anchor
    and the target due to instruction scheduling or alignment changes.  This
    scans ±WINDOW bytes around the expected position looking for the known
    original bytes at that offset.

    Returns (config_offset, slide_distance) or (None, 0).
    """
    if name not in EXPECTED_ORIGINALS:
        return None, 0

    exp_hex, exp_len = EXPECTED_ORIGINALS[name]
    if not exp_hex:
        return None, 0

    expected = bytes.fromhex(exp_hex.replace(' ', ''))
    if len(expected) < 2:
        # Single-byte expected values are too common for safe sliding
        # (e.g., 0x01, 0x41) — only allow tiny window
        window = min(SLIDING_WINDOW_OVERRIDES.get(name, 16), 16)
    else:
        window = SLIDING_WINDOW_OVERRIDES.get(name, SLIDING_WINDOW_DEFAULT)

    exact_file = anchor_config + delta - adj

    # Check exact position first
    if 0 <= exact_file and exact_file + len(expected) <= len(data):
        if data[exact_file:exact_file + len(expected)] == expected:
            return anchor_config + delta, 0

    # Scan window, preferring closer matches
    for dist in range(1, window + 1):
        for direction in (+1, -1):
            candidate = exact_file + (dist * direction)
            if 0 <= candidate and candidate + len(expected) <= len(data):
                if data[candidate:candidate + len(expected)] == expected:
                    config_off = candidate + adj
                    return config_off, dist * direction

    return None, 0


def _run_heuristic_scan(data, missing_names, adj, text_start, text_end):
    """Last-resort structural search for missing offsets near known constants.

    Searches for instruction patterns that are functionally tied to each offset,
    even if the surrounding code has changed enough to break the primary signature.
    """
    hints = []

    # --- Bitrate imul patterns: search for `imul reg, reg/rm, 0x7D00` (32000) ---
    if "EmulateBitrateModified" in missing_names or "DuplicateEmulateBitrateModified" in missing_names:
        imul_pat = Signature._parse("69 ?? 00 7D 00 00")
        matches = scan_pattern(data, imul_pat, start=text_start, end=text_end)
        for m in matches:
            candidate_file = m + 2
            reason = f"imul *,32000 @file:0x{m:X}"
            if "EmulateBitrateModified" in missing_names:
                hints.append(("EmulateBitrateModified", candidate_file, reason))
            if "DuplicateEmulateBitrateModified" in missing_names:
                hints.append(("DuplicateEmulateBitrateModified", candidate_file, reason))

    # --- 48000/32000 constant pair for CreateAudioFrameStereo ---
    if "CreateAudioFrameStereo" in missing_names:
        pair_pat = Signature._parse("B8 80 BB 00 00 BD 00 7D 00 00")
        matches = scan_pattern(data, pair_pat, start=text_start, end=text_end, limit=5)
        for m in matches:
            # Scan forward for the second cmovae (4C 0F 43 E8)
            for off in range(20, 60):
                pos = m + off
                if pos + 4 <= len(data) and data[pos:pos+4] == b'\x4C\x0F\x43\xE8':
                    hints.append(("CreateAudioFrameStereo", pos, f"48k/32k pair + cmovae @file:0x{m:X}"))
                    break

    # --- Opus packed config constant {48000<<32 | 20} = 0xBB80_0000_0014 ---
    if "AudioEncoderOpusConfigSetChannels" in missing_names:
        bb80_pat = Signature._parse("48 B9 14 00 00 00 80 BB 00 00")
        matches = scan_pattern(data, bb80_pat, start=text_start, end=text_end, limit=5)
        for m in matches:
            # Scan forward for mov qword [rax+N], imm (48 C7 40 NN)
            for scan in range(12, 40):
                pos = m + scan
                if pos + 5 <= len(data) and data[pos] == 0x48 and data[pos+1] == 0xC7:
                    target = pos + 4
                    if target < len(data):
                        hints.append(("AudioEncoderOpusConfigSetChannels", target,
                                     f"Opus config struct @file:0x{m:X}"))
                    break

    # --- Opus string proximity: search near "Opus" strings in binary ---
    if missing_names:
        opus_positions = []
        search_start = text_start
        while True:
            pos = data.find(b'Opus', search_start, text_end)
            if pos < 0:
                break
            opus_positions.append(pos)
            search_start = pos + 1
            if len(opus_positions) >= 20:
                break

        if opus_positions:
            for name in missing_names:
                # Only use this for Opus-related offsets
                if "Encoder" not in name and "Config" not in name:
                    continue
                for opus_pos in opus_positions[:10]:
                    window_start = max(text_start, opus_pos - 0x400)
                    window_end = min(text_end, opus_pos + 0x400)
                    # Look for the packed Opus constant nearby
                    const_pat = Signature._parse("80 BB 00 00")  # 48000 as dword
                    sub_matches = scan_pattern(data, const_pat, start=window_start, end=window_end)
                    for sm in sub_matches[:3]:
                        hints.append((name, sm, f"near Opus string @file:0x{opus_pos:X}"))

    return hints[:15]


def _cross_validate(results, adj, data):
    """Cross-validate independently found offsets for internal consistency.

    Checks:
      1. Derivation pairs: if both anchor and derived are found independently,
         verify their distance matches the expected delta.
      2. Encoder config pair: EncoderConfigInit1 and EncoderConfigInit2 should
         be in different functions but have the same patched field structure.
      3. Bitrate offsets: all bitrate-related offsets should contain the same
         default bitrate value (32000 = 0x7D00).
    """
    warnings = []

    # Check derivation distances
    for derived_name, paths in DERIVATIONS.items():
        if derived_name not in results:
            continue
        for anchor_name, expected_delta in paths:
            if anchor_name not in results:
                continue
            actual_delta = results[derived_name] - results[anchor_name]
            if actual_delta != expected_delta:
                warnings.append(
                    f"Delta mismatch: {derived_name} - {anchor_name} = "
                    f"0x{actual_delta:X} (expected 0x{expected_delta:X})"
                )
            break  # Only check the first available anchor

    # Check EncoderConfigInit pair consistency
    if "EncoderConfigInit1" in results and "EncoderConfigInit2" in results:
        for name in ["EncoderConfigInit1", "EncoderConfigInit2"]:
            f = results[name] - adj
            if 0 <= f and f + 4 <= len(data):
                val = data[f:f+4]
                if val != b'\x00\x7D\x00\x00' and val != b'\x00\xD0\x07\x00':
                    warnings.append(f"{name}: unexpected config bytes {val.hex(' ')} "
                                    f"(expected 00 7D 00 00 or 00 D0 07 00)")

    # Check bitrate consistency
    bitrate_names = ["EmulateBitrateModified", "DuplicateEmulateBitrateModified"]
    bitrate_vals = {}
    for name in bitrate_names:
        if name in results:
            f = results[name] - adj
            if 0 <= f and f + 3 <= len(data):
                bitrate_vals[name] = data[f:f+3]

    if len(bitrate_vals) == 2:
        vals = list(bitrate_vals.values())
        if vals[0] != vals[1]:
            warnings.append(
                f"Bitrate mismatch: {bitrate_names[0]}={vals[0].hex(' ')} vs "
                f"{bitrate_names[1]}={vals[1].hex(' ')}"
            )

    return warnings


def discover_offsets(data, pe_info):
    """Run full offset discovery pipeline with tiered fallback.
    Returns (results_dict, errors_list, adjustment, tiers_used_dict)."""
    results = {}
    errors = []
    tiers_used = {}

    adj = pe_info['file_offset_adjustment'] if pe_info and pe_info.get('file_offset_adjustment') is not None else 0xC00

    text_start = 0
    text_end = len(data)
    if pe_info and pe_info.get('text_section'):
        ts = pe_info['text_section']
        text_start = ts['raw_offset']
        text_end = text_start + ts['raw_size']

    # ─── Phase 1: Primary + Relaxed Signatures ─────────────────────
    print("\n" + "=" * 65)
    print("  PHASE 1: Signature Scanning (primary + relaxed)")
    print("=" * 65)

    for sig in SIGNATURES:
        file_off, err, tier = find_offset(data, sig, text_start, text_end)
        if err:
            print(f"  [FAIL] {sig.name}: {err}")
            errors.append((sig.name, err))
        else:
            config_off = file_off + adj
            tag = "OK" if tier == "primary" else "ALT"
            print(f"  [{tag:4s}] {sig.name:45s} = 0x{config_off:X}  (file 0x{file_off:X})  [{tier}]")

            if sig.expected_original:
                expected = bytes.fromhex(sig.expected_original.replace(' ', ''))
                actual = data[file_off:file_off+len(expected)]
                if actual != expected:
                    print(f"         WARNING: Expected {expected.hex(' ')} but found {actual.hex(' ')}")

            results[sig.name] = config_off
            tiers_used[sig.name] = tier

    # ─── Phase 1b: Patched Binary Fallbacks ────────────────────────
    patched_fallbacks = []

    if "MonoDownmixer" not in results:
        fb_pat = Signature._parse("48 89 F9 E8 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 E9")
        matches = scan_pattern(data, fb_pat, start=text_start, end=text_end)
        if len(matches) > 1:
            matches = [m for m in matches if _mono_downmixer_disambiguator(data, m)]
        if len(matches) == 1:
            config_off = matches[0] + 8 + adj
            results["MonoDownmixer"] = config_off
            tiers_used["MonoDownmixer"] = "patched-fallback"
            patched_fallbacks.append("MonoDownmixer")
            print(f"  [FALL] MonoDownmixer{' ':30s} = 0x{config_off:X}  [patched NOP sled]")

    if "SetsBitrateBitrateValue" not in results:
        for fb_hex in [
            "89 F8 48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 90 90 90 48 89 4E 1C",
            "89 ?? 48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 90 90 90 48 89 ?? ??",
        ]:
            fb_pat = Signature._parse(fb_hex)
            matches = scan_pattern(data, fb_pat, start=text_start, end=text_end)
            if len(matches) == 1:
                config_off = matches[0] + 4 + adj
                results["SetsBitrateBitrateValue"] = config_off
                tiers_used["SetsBitrateBitrateValue"] = "patched-fallback"
                patched_fallbacks.append("SetsBitrateBitrateValue")
                print(f"  [FALL] SetsBitrateBitrateValue{' ':20s} = 0x{config_off:X}  [patched or->NOP]")
                break

    if "HighpassCutoffFilter" not in results:
        hp_key = "HighPassFilter"
        if hp_key not in results and "EmulateStereoSuccess1" in results:
            results[hp_key] = results["EmulateStereoSuccess1"] + 0xC275
        if hp_key in results:
            hp_file = results[hp_key] - adj
            if (0 <= hp_file and hp_file + 11 <= len(data) and
                data[hp_file] == 0x48 and data[hp_file+1] == 0xB8 and data[hp_file+10] == 0xC3):
                hpc_va = struct.unpack_from('<Q', data, hp_file + 2)[0]
                if pe_info:
                    hpc_config = hpc_va - pe_info['image_base']
                    if 0 < hpc_config < len(data):
                        results["HighpassCutoffFilter"] = hpc_config
                        tiers_used["HighpassCutoffFilter"] = "patched-stub-extract"
                        patched_fallbacks.append("HighpassCutoffFilter")
                        print(f"  [FALL] HighpassCutoffFilter{' ':23s} = 0x{hpc_config:X}  [from HP stub VA=0x{hpc_va:X}]")

    if patched_fallbacks:
        print(f"\n  NOTE: Binary appears already patched. Fallback used for: {', '.join(patched_fallbacks)}")

    # ─── Phase 2: Derivation (topologically sorted, chain-aware) ───
    print("\n" + "=" * 65)
    print("  PHASE 2: Relative Offset Derivation (chain-aware)")
    print("=" * 65)

    for derived_name in _topo_sort_derivations(DERIVATIONS):
        if derived_name in results:
            continue

        paths = DERIVATIONS[derived_name]
        found = False
        for anchor_name, delta in paths:
            if anchor_name not in results:
                continue

            config_off = results[anchor_name] + delta
            file_off = config_off - adj

            if file_off < 0 or file_off >= len(data):
                continue

            # Verify expected bytes at exact delta
            verified_exact = True
            if derived_name in EXPECTED_ORIGINALS:
                exp_hex, _ = EXPECTED_ORIGINALS[derived_name]
                if exp_hex:
                    expected = bytes.fromhex(exp_hex.replace(' ', ''))
                    actual = data[file_off:file_off+len(expected)]
                    if actual != expected:
                        verified_exact = False

            if verified_exact:
                print(f"  [ OK ] {derived_name:45s} = 0x{config_off:X}  (from {anchor_name} + 0x{delta:X})")
                results[derived_name] = config_off
                tiers_used[derived_name] = f"derived({anchor_name}+0x{delta:X})"
                found = True
                break

        # If exact delta didn't verify, try sliding window
        if not found:
            for anchor_name, delta in paths:
                if anchor_name not in results:
                    continue
                slid_off, slide_dist = _sliding_window_recover(
                    data, results[anchor_name], delta, derived_name, adj
                )
                if slid_off is not None and slide_dist != 0:
                    sign = "+" if slide_dist > 0 else ""
                    print(f"  [SLID] {derived_name:45s} = 0x{slid_off:X}  "
                          f"(from {anchor_name} + 0x{delta:X} {sign}{slide_dist})")
                    results[derived_name] = slid_off
                    tiers_used[derived_name] = f"sliding({anchor_name}+0x{delta:X}{sign}{slide_dist})"
                    found = True
                    break

        # If exact worked without verification (no expected bytes), accept it
        if not found:
            for anchor_name, delta in paths:
                if anchor_name not in results:
                    continue
                config_off = results[anchor_name] + delta
                file_off = config_off - adj
                if 0 <= file_off < len(data):
                    print(f"  [ OK ] {derived_name:45s} = 0x{config_off:X}  (from {anchor_name} + 0x{delta:X})  [unverified]")
                    results[derived_name] = config_off
                    tiers_used[derived_name] = f"derived-unverified({anchor_name}+0x{delta:X})"
                    found = True
                    break

        if not found:
            tried = ", ".join(a for a, _ in paths)
            print(f"  [FAIL] {derived_name}: no anchor available (tried: {tried})")
            errors.append((derived_name, f"no anchor available (tried: {tried})"))

    # ─── Phase 2b: Heuristic Recovery ──────────────────────────────
    missing = [n for n in _all_offset_names() if n not in results]
    if missing:
        print("\n" + "=" * 65)
        print("  PHASE 2b: Heuristic Recovery")
        print("=" * 65)

        hints = _run_heuristic_scan(data, missing, adj, text_start, text_end)
        if hints:
            for name, file_off, reason in hints:
                if name in results:
                    continue
                config_off = file_off + adj
                # Verify expected bytes before accepting heuristic result
                if name in EXPECTED_ORIGINALS:
                    exp_hex, exp_len = EXPECTED_ORIGINALS[name]
                    if exp_hex:
                        expected = bytes.fromhex(exp_hex.replace(' ', ''))
                        actual = data[file_off:file_off+len(expected)]
                        if actual != expected:
                            continue  # silently skip non-matching candidates
                print(f"  [HEUR] {name:45s} = 0x{config_off:X}  [{reason}]")
                results[name] = config_off
                tiers_used[name] = f"heuristic({reason})"
        else:
            print(f"  No heuristic candidates for: {', '.join(missing)}")

    errors = [(n, e) for n, e in errors if n not in results]
    return results, errors, adj, tiers_used

# endregion Offset Discovery Engine


# region Validation

# Expected original bytes at each patch site (for verification)
# Format: (hex_string_or_None, byte_length)
EXPECTED_ORIGINALS = {
    "EmulateStereoSuccess1":    ("01", 1),
    "EmulateStereoSuccess2":    ("75", 1),
    "Emulate48Khz":             ("0F 42 C1", 3),
    "EmulateBitrateModified":   (None, 3),      # variable imul immediate
    "SetsBitrateBitrateValue":  (None, 5),      # variable immediate
    "SetsBitrateBitwiseOr":     ("48 09 C1", 3),
    "HighPassFilter":           (None, 11),      # variable prologue
    "CreateAudioFrameStereo":   (None, 4),       # cmov variant
    "AudioEncoderOpusConfigSetChannels": ("01", 1),
    "AudioEncoderOpusConfigIsOk": ("8B 11 31 C0", 4),
    "MonoDownmixer":            ("84 C0 74 0D", 4),
    "ThrowError":               ("41", 1),
    "DownmixFunc":              ("41", 1),
    "HighpassCutoffFilter":     (None, 0x100),   # full function body
    "DcReject":                 (None, 0x1B6),   # full function body
    "DuplicateEmulateBitrateModified": (None, 3), # variable imul immediate
    "EncoderConfigInit1":       ("00 7D 00 00", 4),
    "EncoderConfigInit2":       ("00 7D 00 00", 4),
}

# Patch bytes for each offset (for already-patched detection)
PATCH_INFO = {
    "EmulateStereoSuccess1":    ("02", "Channel count 1->2"),
    "EmulateStereoSuccess2":    ("EB", "jne->jmp (force stereo)"),
    "Emulate48Khz":             ("90 90 90", "cmovb->NOPs (force 48kHz)"),
    "EmulateBitrateModified":   ("00 D0 07", "imul 32000->512000 bps"),
    "SetsBitrateBitrateValue":  ("00 D0 07 00 00", "512000 in imm64"),
    "SetsBitrateBitwiseOr":     ("90 90 90", "or rcx,rax->NOPs"),
    "HighPassFilter":           ("<dynamic: mov rax, IMAGE_BASE+HPC; ret>", "Redirect to HPC"),
    "CreateAudioFrameStereo":   ("49 89 C5 90", "cmovae->mov r13,rax; nop"),
    "AudioEncoderOpusConfigSetChannels": ("02", "Channel count 1->2"),
    "AudioEncoderOpusConfigIsOk": ("48 C7 C0 01 00 00 00 C3", "return 1"),
    "MonoDownmixer":            ("90 90 90 90 90 90 90 90 90 90 90 90 E9", "NOP sled + jmp"),
    "ThrowError":               ("C3", "ret (disable throws)"),
    "DownmixFunc":              ("C3", "ret (disable downmix)"),
    "HighpassCutoffFilter":     ("<injected: hp_cutoff>", "Custom HP cutoff + gain"),
    "DcReject":                 ("<injected: dc_reject>", "Custom DC reject + gain"),
    "DuplicateEmulateBitrateModified": ("00 D0 07", "Dup imul 32000->512000"),
    "EncoderConfigInit1":       ("00 D0 07 00", "Config qword: 32000->512000"),
    "EncoderConfigInit2":       ("00 D0 07 00", "Config qword: 32000->512000"),
}


def validate_offsets(data, results, adj):
    """Validate discovered offsets against expected byte patterns."""
    print("\n" + "=" * 65)
    print("  PHASE 3: Byte Verification")
    print("=" * 65)

    verified = 0
    warnings = 0

    for name, config_off in sorted(results.items(), key=lambda x: x[1]):
        file_off = config_off - adj

        if file_off < 0 or file_off >= len(data):
            print(f"  [FAIL] {name:45s} offset 0x{config_off:X} out of bounds")
            warnings += 1
            continue

        if name in EXPECTED_ORIGINALS:
            expected_hex, length = EXPECTED_ORIGINALS[name]
            actual = data[file_off:file_off+length]

            if expected_hex:
                expected = bytes.fromhex(expected_hex.replace(' ', ''))
                if actual[:len(expected)] == expected:
                    print(f"  [PASS] {name:45s} original bytes: {actual[:len(expected)].hex(' ')}")
                    verified += 1
                else:
                    # Check if already patched
                    patch_hex = PATCH_INFO.get(name, (None,))[0]
                    if patch_hex and not patch_hex.startswith('<'):
                        try:
                            patched = bytes.fromhex(patch_hex.replace(' ', ''))
                            if actual[:len(patched)] == patched:
                                print(f"  [WARN] {name:45s} ALREADY PATCHED: {actual[:len(patched)].hex(' ')}")
                                warnings += 1
                                continue
                        except ValueError:
                            pass
                    print(f"  [WARN] {name:45s} unexpected: {actual[:len(expected)].hex(' ')} (expected {expected_hex})")
                    warnings += 1
            else:
                print(f"  [INFO] {name:45s} bytes: {actual[:min(8,length)].hex(' ')} (no fixed expected)")
                verified += 1

    return verified, warnings


def check_injection_sites(data, results, adj):
    """Verify injection sites have enough room (scan for cc padding)."""
    print("\n" + "=" * 65)
    print("  PHASE 4: Injection Site Capacity")
    print("=" * 65)

    for name, inject_size, desc in [("HighpassCutoffFilter", 0x100, "hp_cutoff"), ("DcReject", 0x1B6, "dc_reject")]:
        if name not in results:
            print(f"  [SKIP] {name}: not found")
            continue

        file_off = results[name] - adj
        func_end = None
        for i in range(file_off, min(file_off + 0x400, len(data) - 3)):
            if data[i:i+4] == b'\xcc\xcc\xcc\xcc':
                func_end = i
                break

        if func_end is None:
            print(f"  [WARN] {name}: no cc padding within 1KB")
            continue

        available = func_end - file_off
        margin = available - inject_size
        status = "OK" if margin >= 0 else "OVER"
        print(f"  [{status:4s}] {name:30s}  available={available} (0x{available:X})  "
              f"needed={inject_size} (0x{inject_size:X})  margin={margin:+d} bytes")

# endregion Validation


# region Output Formatters

def format_powershell_config(results, pe_info=None, file_path=None, file_size=None):
    """Generate PowerShell offset table — copy-paste directly into patcher."""
    lines = []
    if pe_info and file_path and file_size:
        md5 = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
        build_str = pe_info['build_time'].strftime('%b %d %Y')
        lines.append(f"    # Auto-generated by discord_voice_node_offset_finder.py v{VERSION}")
        lines.append(f"    # Build: {build_str} | Size: {file_size} | MD5: {md5}")

    lines.append("    Offsets = @{")
    ordered = _all_offset_names()
    max_len = max(len(n) for n in ordered)
    for name in ordered:
        pad = " " * (max_len - len(name))
        if name in results:
            lines.append(f"        {name}{pad} = 0x{results[name]:X}")
        else:
            lines.append(f"        {name}{pad} = 0x0  # NOT FOUND")
    lines.append("    }")
    return "\n".join(lines)


def format_cpp_namespace(results):
    """Generate C++ namespace block for reference."""
    lines = ["namespace Offsets {"]
    for name in sorted(results.keys()):
        lines.append(f"    constexpr uint32_t {name} = 0x{results[name]:X};")
    lines.append("};")
    return "\n".join(lines)


def format_json(results, pe_info, file_path, file_size, adj, tiers_used):
    """Generate machine-readable JSON output."""
    return json.dumps({
        "tool": "discord_voice_node_offset_finder",
        "version": VERSION,
        "file": str(file_path),
        "file_size": file_size,
        "md5": hashlib.md5(open(file_path, 'rb').read()).hexdigest(),
        "pe_timestamp": pe_info['timestamp'] if pe_info else None,
        "pe_build_time": pe_info['build_time'].isoformat() if pe_info else None,
        "image_base": hex(pe_info['image_base']) if pe_info else None,
        "file_offset_adjustment": hex(adj),
        "offsets": {name: hex(off) for name, off in sorted(results.items())},
        "resolution_tiers": tiers_used,
        "total_found": len(results),
        "total_expected": 18,
    }, indent=2)

# endregion Output Formatters


# region Visualization

def generate_viz_graph(results, out_dir):
    """Generate dependency graph PNG (requires networkx + matplotlib)."""
    if not VIZ_AVAILABLE:
        return None
    try:
        G = nx.DiGraph()
        sig_names = {s.name for s in SIGNATURES}
        for name in results:
            color = '#5865F2' if name in sig_names else '#ED4245'
            G.add_node(name, color=color)
        for derived, paths in DERIVATIONS.items():
            if derived not in results:
                continue
            for anchor, delta in paths:
                if anchor in results:
                    G.add_edge(anchor, derived, label=f"+0x{delta:X}")
                    break
        if len(G.nodes) == 0:
            return None

        plt.figure(figsize=(14, 9))
        pos = nx.spring_layout(G, k=2.5, iterations=60, seed=42)
        colors = [G.nodes[n].get('color', '#99AAB5') for n in G.nodes()]
        nx.draw(G, pos, with_labels=True, node_color=colors, node_size=2800,
                font_size=7, font_weight='bold', arrows=True, edge_color='#72767D',
                arrowsize=15, font_color='white', edgecolors='#2C2F33', linewidths=1.5)
        edge_labels = nx.get_edge_attributes(G, 'label')
        nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=7, font_color='#B9BBBE')
        plt.title("Offset Derivation Graph", fontsize=14, fontweight='bold', color='#FFFFFF')
        plt.gca().set_facecolor('#36393F')
        plt.gcf().set_facecolor('#2C2F33')
        plt.axis('off')

        viz_path = out_dir / 'offsets_graph.png'
        plt.savefig(viz_path, dpi=150, bbox_inches='tight', facecolor='#2C2F33')
        plt.close()
        return viz_path
    except Exception:
        try:
            plt.close()
        except Exception:
            pass
        return None

# endregion Visualization


# region Auto-Detection

def find_discord_node():
    """Try to find discord_voice.node in standard install locations (Windows)."""
    if sys.platform != 'win32':
        return None
    localappdata = os.environ.get('LOCALAPPDATA', '')
    if not localappdata:
        return None
    for client in ['Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment']:
        base = Path(localappdata) / client
        if not base.exists():
            continue
        for app_dir in sorted(base.glob('app-*'), reverse=True):
            modules = app_dir / 'modules'
            if not modules.exists():
                continue
            for vd in modules.glob('discord_voice*'):
                for candidate in [vd / 'discord_voice' / 'discord_voice.node', vd / 'discord_voice.node']:
                    if candidate.exists():
                        return candidate
    return None

# endregion Auto-Detection


# region Main

def main():
    print("=" * 65)
    print(f"  Discord Voice Node Offset Finder v{VERSION}")
    print("  Tiered signature scanning with chain-aware derivation")
    print("=" * 65)

    if len(sys.argv) >= 2:
        file_path = Path(sys.argv[1])
    else:
        print("\nNo file specified, searching for Discord install...")
        file_path = find_discord_node()
        if file_path:
            print(f"  Found: {file_path}")
        else:
            print("  Not found. Usage: python discord_voice_node_offset_finder.py <path>")
            sys.exit(1)

    if not file_path.exists():
        print(f"\nERROR: File not found: {file_path}")
        sys.exit(1)

    data = file_path.read_bytes()
    file_size = len(data)
    print(f"\n  File: {file_path}")
    print(f"  Size: {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)")
    print(f"  MD5:  {hashlib.md5(data).hexdigest()}")

    pe_info = parse_pe(data)
    if pe_info:
        adj = pe_info['file_offset_adjustment']
        ts = pe_info['text_section']
        print(f"\n  PE Image Base:       0x{pe_info['image_base']:X}")
        print(f"  PE Timestamp:        {pe_info['build_time'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if ts:
            print(f"  Offset Adjustment:   0x{adj:X}  (.text VA 0x{ts['vaddr']:X} - raw 0x{ts['raw_offset']:X})")
        else:
            print(f"  Offset Adjustment:   0x{adj:X}  (fallback)")
        print(f"  Sections:            {len(pe_info['sections'])}")
        for s in pe_info['sections']:
            print(f"    {s['name']:8s}  VA=0x{s['vaddr']:08X}  Size=0x{s['raw_size']:08X}  Raw=0x{s['raw_offset']:08X}")
    else:
        print("\n  WARNING: Could not parse PE header")

    # ─── Run pipeline ──────────────────────────────────────────────
    results, errors, adj, tiers_used = discover_offsets(data, pe_info)
    verified, warnings = validate_offsets(data, results, adj)
    check_injection_sites(data, results, adj)

    # ─── Cross-validation ──────────────────────────────────────────
    xval_warnings = _cross_validate(results, adj, data)
    if xval_warnings:
        print("\n" + "=" * 65)
        print("  PHASE 5: Cross-Validation")
        print("=" * 65)
        for w in xval_warnings:
            print(f"  [XVAL] {w}")

    # ─── Visualization ─────────────────────────────────────────────
    if len(results) >= 10:
        viz_path = generate_viz_graph(results, file_path.parent)
        if viz_path:
            print(f"\n  Dependency graph saved: {viz_path}")

    # ─── Summary ───────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  RESULTS SUMMARY")
    print("=" * 65)
    print(f"  Offsets found:    {len(results)} / 18")
    print(f"  Bytes verified:   {verified}")
    print(f"  Warnings:         {warnings}")
    print(f"  Cross-validation: {len(xval_warnings)} issue(s)" if xval_warnings else "  Cross-validation: clean")
    print(f"  Errors:           {len(errors)}")

    # Show resolution tier breakdown
    tier_counts = {}
    for name, tier in tiers_used.items():
        bucket = tier.split('(')[0].split('-')[0]
        tier_counts[bucket] = tier_counts.get(bucket, 0) + 1
    if tier_counts:
        print(f"  Resolution:       {', '.join(f'{k}: {v}' for k, v in sorted(tier_counts.items()))}")

    if errors:
        print(f"\n  Failed offsets:")
        for name, err in errors:
            print(f"    {name}: {err}")

    # ─── Output ────────────────────────────────────────────────────
    if results:
        ps_config = format_powershell_config(results, pe_info, file_path, file_size)
        print("\n" + "=" * 65)
        print("  PATCHER OFFSET TABLE (copy-paste into patcher)")
        print("=" * 65)
        print(ps_config)

        stub_line = ""
        if pe_info and "HighpassCutoffFilter" in results:
            hpc_va = pe_info['image_base'] + results["HighpassCutoffFilter"]
            va_bytes = struct.pack('<Q', hpc_va)
            stub = b'\x48\xB8' + va_bytes + b'\xC3'
            stub_line = f"\n  HighPassFilter stub: {stub.hex(' ')}\n    mov rax, 0x{hpc_va:X}; ret"
            print(stub_line)

        # Save offsets.txt
        script_dir = Path(__file__).resolve().parent
        file_content = ["=" * 65, f"  Discord Voice Node Offset Finder v{VERSION} - Results", "=" * 65]
        if pe_info:
            file_content.append(f"  Build:  {pe_info['build_time'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
        file_content += [f"  File:   {file_path.name}", f"  Size:   {file_size:,} bytes",
                         f"  MD5:    {hashlib.md5(data).hexdigest()}", f"  Adjust: 0x{adj:X}",
                         f"  Found:  {len(results)} / 18", "",
                         "=" * 65, "  COPY-PASTE INTO PATCHER", "=" * 65, ps_config]
        if stub_line:
            file_content += ["", stub_line.strip()]
        file_content += ["", "=" * 65, "  C++ NAMESPACE", "=" * 65, format_cpp_namespace(results), ""]

        for try_dir in [script_dir, file_path.parent, Path.cwd()]:
            try:
                out_path = try_dir / "offsets.txt"
                out_path.write_text("\n".join(file_content))
                print(f"\n  Offset file saved: {out_path}")
                break
            except Exception:
                continue

        try:
            json_path = file_path.with_suffix('.offsets.json')
            json_path.write_text(format_json(results, pe_info, file_path, file_size, adj, tiers_used))
            print(f"  JSON saved: {json_path}")
        except Exception:
            pass

    # ─── Exit code ─────────────────────────────────────────────────
    if len(results) == 18:
        print("\n  *** ALL 18 OFFSETS FOUND SUCCESSFULLY ***")
        return 0
    elif len(results) >= 15:
        print(f"\n  *** PARTIAL SUCCESS: {len(results)}/18 offsets found ***")
        return 1
    else:
        print(f"\n  *** INSUFFICIENT RESULTS: {len(results)}/18 offsets found ***")
        return 2


if __name__ == '__main__':
    code = main()
    input("\n  Press Enter to close...")
    sys.exit(code)

# endregion Main
