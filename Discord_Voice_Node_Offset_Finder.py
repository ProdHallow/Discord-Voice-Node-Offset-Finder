#!/usr/bin/env python3
"""
Discord Voice Node Offset Finder
=================================
Automatically discovers all 18 patch offsets for any discord_voice.node build
using signature scanning and relative offset derivation.

Methodology:
  - 8 unique byte signatures locate independent anchor points
  - 10 additional offsets are derived via stable relative deltas
  - Cross-validation confirms internal consistency
  - PE header analysis extracts image base and section layout

Signature stability verified across:
  - December 2025 build (9219)
  - February 2026 build (Feb 9, 2026)

Usage:
  python discord_voice_node_offset_finder.py <path_to_discord_voice.node>
  python discord_voice_node_offset_finder.py  (auto-detects Discord install)
"""

import sys
import os
import struct
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# region Configuration

FILE_OFFSET_ADJUSTMENT = 0xC00

# Relative offset derivation map (verified stable across builds Jul 2025 - Feb 2026)
# Format: derived_name -> (anchor_name, delta)
DERIVATIONS = {
    "EmulateStereoSuccess2":    ("EmulateStereoSuccess1", 0xC),
    "Emulate48Khz":             ("EmulateStereoSuccess1", 0x168),
    "EmulateBitrateModified":   ("EmulateStereoSuccess1", 0x45F),
    "HighPassFilter":           ("EmulateStereoSuccess1", 0xC275),
    "SetsBitrateBitwiseOr":     ("SetsBitrateBitrateValue", 0x8),
    "AudioEncoderOpusConfigIsOk": ("AudioEncoderOpusConfigSetChannels", 0x29C),
    "DcReject":                 ("HighpassCutoffFilter", 0x1E0),
    # Encoder config init: +0xA from the channels byte in the same constructor
    "EncoderConfigInit1":       ("AudioEncoderOpusConfigSetChannels", 0xA),
    # Duplicate bitrate calc in parallel template function
    "DuplicateEmulateBitrateModified": ("EmulateBitrateModified", 0x4EE6),
}

# endregion Configuration


# region Signature Definitions

class Signature:
    """Defines a byte pattern signature for locating an offset."""
    
    def __init__(self, name, pattern_hex, target_offset, description,
                 expected_original=None, patch_bytes=None, patch_len=None,
                 disambiguator=None):
        """
        Args:
            name: Offset name (matches patcher config key)
            pattern_hex: Space-separated hex bytes, ?? for wildcards
            target_offset: Byte offset from pattern match to target.
                           Positive = forward, negative = backward.
            description: Human-readable explanation
            expected_original: Hex string of expected original bytes at target
            patch_bytes: Hex string of what patcher writes
            patch_len: Length of patch (if different from patch_bytes)
            disambiguator: Optional callable(data, match_offset) -> bool
                           Returns True if this match is the correct one.
        """
        self.name = name
        self.pattern_hex = pattern_hex
        self.pattern = self._parse(pattern_hex)
        self.target_offset = target_offset
        self.description = description
        self.expected_original = expected_original
        self.patch_bytes = patch_bytes
        self.patch_len = patch_len
        self.disambiguator = disambiguator
    
    @staticmethod
    def _parse(hex_str):
        return [None if b == '??' else int(b, 16) for b in hex_str.split()]
    
    def __repr__(self):
        return f"Signature({self.name})"


def _mono_downmixer_disambiguator(data, match_offset):
    """Select the correct MonoDownmixer match by checking for REX.R movzx (44 0F B6)
    within 12 bytes after the jg (0F 8F) branch. The real downmixer loads channel
    flags via movzx r??d; the false positive does test [reg+off] flag checks instead."""
    # Pattern: ... 09 0F 8F <4-byte rel32> <code>
    # jg is at match_offset + 19 (relative to pattern start)
    jg_pos = match_offset + 19
    if jg_pos + 18 > len(data):
        return False
    after_jg = data[jg_pos + 6 : jg_pos + 18]  # skip 0F 8F + 4-byte displacement
    return b'\x44\x0f\xb6' in after_jg


# 8 independent anchor signatures - verified unique across Jul 2025, Dec 2025, Feb 2026
SIGNATURES = [
    Signature(
        name="EmulateStereoSuccess1",
        pattern_hex="E8 ?? ?? ?? ?? BD ?? 00 00 00 80 BC 24 80 01 00 00 01",
        target_offset=6,
        description="Stereo channel count: call <rel>; mov ebp, CHANNELS; cmp byte [rsp+0x180], 1",
        expected_original="01",
        patch_bytes="02",
    ),
    
    Signature(
        name="AudioEncoderOpusConfigSetChannels",
        pattern_hex="48 B9 14 00 00 00 80 BB 00 00 48 89 08 48 C7 40 08 ?? 00 00 00",
        target_offset=17,
        description="Opus config init: mov rcx, {48000<<32|20}; mov [rax],rcx; mov qword [rax+8], CHANNELS",
        expected_original="01",
        patch_bytes="02",
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
    ),
    
    Signature(
        name="SetsBitrateBitrateValue",
        pattern_hex="89 F8 48 B9 ?? ?? ?? ?? 01 00 00 00 48 09 C1 48 89 4E 1C",
        target_offset=4,
        description="Bitrate setter: mov eax,edi; mov rcx,imm64; or rcx,rax; mov [rsi+0x1C],rcx",
        expected_original=None,
    ),
    
    Signature(
        name="ThrowError",
        pattern_hex="56 56 57 53 48 81 EC C8 00 00 00 0F 29 B4 24 B0 00 00 00 4C 89 CE 4C 89 C7 89 D3",
        target_offset=-1,
        description="Error handler body: push rsi;rdi;rbx; sub rsp,0xC8; movaps; mov r14,rcx; mov rdi,r8; mov ebx,edx",
        expected_original="41",
        patch_bytes="C3",
    ),
    
    Signature(
        name="DownmixFunc",
        pattern_hex="57 41 56 41 55 41 54 56 57 55 53 48 83 EC 10 48 89 0C 24 45 85 C0",
        target_offset=-1,
        description="Downmix function body: push r15..r12,rsi,rdi,rbp,rbx; sub rsp,0x10; mov [rsp],rcx; test r8d,r8d",
        expected_original="41",
        patch_bytes="C3",
    ),
    
    Signature(
        name="CreateAudioFrameStereo",
        pattern_hex="B8 80 BB 00 00 BD 00 7D 00 00 0F 43 E8",
        target_offset=31,
        description="Audio frame rate select: mov eax,48000; mov ebp,32000; cmovae ebp,eax; ... target is second cmov",
        expected_original="4C 0F 43 E8",
        patch_bytes="49 89 C5 90",
    ),
    
    Signature(
        name="HighpassCutoffFilter",
        pattern_hex="56 48 83 EC 30 44 0F 29 44 24 20 0F 29 7C 24 10 0F 29 34 24",
        target_offset=0,
        description="HP cutoff filter: push rsi; sub rsp,0x30; SSE register saves (xmm8,xmm7,xmm6)",
        expected_original="56 48 83 EC 30",
        patch_bytes=None,  # Injected code (0x100 bytes)
        patch_len=0x100,
    ),
    
    Signature(
        name="EncoderConfigInit2",
        pattern_hex="48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 48 10 66 C7 40 18 00 00 C6 40 1A 00",
        target_offset=6,
        description="Encoder config init (constructor 2): mov rcx,packed_qword; mov [rax+0x10],rcx; mov word [rax+0x18],0; mov byte [rax+0x1a],0 — patches high dword from 32000 to 512000",
        expected_original="00 7D 00 00",
        patch_bytes="00 D0 07 00",
        patch_len=4,
    ),
]

# endregion Signature Definitions


# region PE Parser

def parse_pe(data):
    """Extract minimal PE info: image base, timestamp, sections."""
    if data[:2] != b'MZ':
        return None
    
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
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
    
    build_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    
    return {
        'image_base': image_base,
        'timestamp': timestamp,
        'build_time': build_time,
        'sections': sections,
        'pe_offset': pe_offset,
    }

# endregion PE Parser


# region Signature Scanner

def scan_pattern(data, pattern):
    """Scan binary for pattern matches. Returns list of file offsets."""
    matches = []
    pat_len = len(pattern)
    
    # Optimize: find first non-wildcard byte for initial skip
    first_fixed = None
    for i, b in enumerate(pattern):
        if b is not None:
            first_fixed = (i, b)
            break
    
    if first_fixed is None:
        return matches  # All wildcards - meaningless
    
    skip_to, first_byte = first_fixed
    pos = 0
    
    while pos <= len(data) - pat_len:
        # Fast scan to first fixed byte
        idx = data.find(bytes([first_byte]), pos + skip_to)
        if idx < 0:
            break
        
        candidate = idx - skip_to
        if candidate < 0:
            pos = idx + 1
            continue
        
        if candidate + pat_len > len(data):
            break
        
        # Full pattern check
        match = True
        for j, p in enumerate(pattern):
            if p is not None and data[candidate + j] != p:
                match = False
                break
        
        if match:
            matches.append(candidate)
        
        pos = candidate + 1
    
    return matches


def find_offset(data, sig):
    """Find a single offset using a signature. Returns (config_offset, file_offset) or None."""
    matches = scan_pattern(data, sig.pattern)
    
    if len(matches) == 0:
        return None, "no matches found"
    
    if len(matches) > 1:
        # Try disambiguator first (most reliable)
        if sig.disambiguator:
            valid = [m for m in matches if sig.disambiguator(data, m)]
            if len(valid) == 1:
                matches = valid
            elif len(valid) > 1:
                pass  # Fall through to byte validation
            # If disambiguator eliminated all, fall through too
        
        # Try expected_original byte validation
        if len(matches) > 1 and sig.expected_original:
            expected = bytes.fromhex(sig.expected_original.replace(' ', ''))
            valid = []
            for m in matches:
                target_file = m + sig.target_offset
                if target_file >= 0 and target_file + len(expected) <= len(data):
                    if data[target_file:target_file+len(expected)] == expected:
                        valid.append(m)
            if len(valid) == 1:
                matches = valid
            elif len(valid) > 1:
                return None, f"{len(valid)} matches after byte validation (expected unique)"
        
        if len(matches) > 1:
            return None, f"{len(matches)} matches found (expected unique)"
    
    file_offset = matches[0] + sig.target_offset
    config_offset = file_offset + FILE_OFFSET_ADJUSTMENT
    
    return config_offset, None

# endregion Signature Scanner


# region Offset Discovery Engine

def discover_offsets(data):
    """Run full offset discovery. Returns dict of results."""
    results = {}
    errors = []
    
    print("\n" + "=" * 65)
    print("  PHASE 1: Independent Signature Scanning")
    print("=" * 65)
    
    # Phase 1: Find all independent anchors
    for sig in SIGNATURES:
        config_off, err = find_offset(data, sig)
        if err:
            print(f"  [FAIL] {sig.name}: {err}")
            errors.append((sig.name, err))
        else:
            file_off = config_off - FILE_OFFSET_ADJUSTMENT
            print(f"  [ OK ] {sig.name:45s} = 0x{config_off:X}  (file 0x{file_off:X})")
            
            # Verify expected original bytes
            if sig.expected_original:
                expected = bytes.fromhex(sig.expected_original.replace(' ', ''))
                actual = data[file_off:file_off+len(expected)]
                if actual != expected:
                    print(f"         WARNING: Expected {expected.hex(' ')} but found {actual.hex(' ')}")
            
            results[sig.name] = config_off
    
    # Phase 1b: Fallback signatures for already-patched binaries
    patched_fallbacks = []
    
    if "MonoDownmixer" not in results:
        patched_fallbacks.append(("MonoDownmixer", "patched NOP sled"))
        # Universal fallback: 48 89 F9 E8 ?? ?? ?? ?? 90×12 E9 (with disambiguator)
        fb_pat = Signature._parse(
            "48 89 F9 E8 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 E9"
        )
        matches = scan_pattern(data, fb_pat)
        # Apply same disambiguator: check for 44 0F B6 after where jg would be
        # In patched binary, the jg is NOPed out, but we can look further into
        # the function body. Just take first match if only one, otherwise skip.
        if len(matches) == 1:
            config_off = matches[0] + 8 + FILE_OFFSET_ADJUSTMENT
            results["MonoDownmixer"] = config_off
            print(f"  [FALL] MonoDownmixer                                 = 0x{config_off:X}  (detected via patched NOP sled)")
    
    if "SetsBitrateBitrateValue" not in results:
        # Patched fallback: or rcx,rax (48 09 C1) was NOPed to 90 90 90
        # AND the imm64 was overwritten with the new bitrate, so wildcard all 8 bytes
        fb_pat = Signature._parse(
            "89 F8 48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 90 90 90 48 89 4E 1C"
        )
        matches = scan_pattern(data, fb_pat)
        if len(matches) == 1:
            config_off = matches[0] + 4 + FILE_OFFSET_ADJUSTMENT
            results["SetsBitrateBitrateValue"] = config_off
            patched_fallbacks.append(("SetsBitrateBitrateValue", "patched NOP in or rcx,rax"))
            print(f"  [FALL] SetsBitrateBitrateValue                       = 0x{config_off:X}  (detected via patched or→NOP)")
    
    if "HighpassCutoffFilter" not in results:
        # First, ensure HighPassFilter is available (derive from ES1 if needed)
        if "HighPassFilter" not in results and "EmulateStereoSuccess1" in results:
            results["HighPassFilter"] = results["EmulateStereoSuccess1"] + 0xC275
        
        if "HighPassFilter" in results:
            # Extract HPC address from the HighPassFilter redirect stub: 48 B8 <imm64> C3
            hp_file = results["HighPassFilter"] - FILE_OFFSET_ADJUSTMENT
            if (hp_file >= 0 and hp_file + 11 <= len(data) and
                data[hp_file] == 0x48 and data[hp_file+1] == 0xB8 and data[hp_file+10] == 0xC3):
                hpc_va = struct.unpack_from('<Q', data, hp_file + 2)[0]
                pe_info = parse_pe(data)
                if pe_info:
                    hpc_config = hpc_va - pe_info['image_base']
                    if 0 < hpc_config < len(data):
                        results["HighpassCutoffFilter"] = hpc_config
                        patched_fallbacks.append(("HighpassCutoffFilter", "extracted from HP redirect stub"))
                        print(f"  [FALL] HighpassCutoffFilter                          = 0x{hpc_config:X}  (extracted from HP stub: VA=0x{hpc_va:X})")
                    else:
                        print(f"  [INFO] HighPassFilter stub has non-standard address (VA=0x{hpc_va:X}) - old hardcoded value?")
    
    if patched_fallbacks:
        names = ", ".join(n for n, _ in patched_fallbacks)
        print(f"\n  NOTE: Binary appears already patched. Fallback detection used for: {names}")
    
    # Phase 2: Derive dependent offsets
    print("\n" + "=" * 65)
    print("  PHASE 2: Relative Offset Derivation")
    print("=" * 65)
    
    for derived_name, (anchor_name, delta) in DERIVATIONS.items():
        if derived_name in results:
            # Already found (via fallback), skip derivation but cross-check
            continue
        
        if anchor_name in results:
            config_off = results[anchor_name] + delta
            file_off = config_off - FILE_OFFSET_ADJUSTMENT
            
            # Bounds check
            if file_off < 0 or file_off >= len(data):
                print(f"  [FAIL] {derived_name}: derived offset 0x{config_off:X} out of bounds")
                errors.append((derived_name, "derived offset out of bounds"))
                continue
            
            print(f"  [ OK ] {derived_name:45s} = 0x{config_off:X}  (from {anchor_name} + 0x{delta:X})")
            results[derived_name] = config_off
        else:
            print(f"  [SKIP] {derived_name}: anchor {anchor_name} not found")
            errors.append((derived_name, f"anchor {anchor_name} not found"))
    
    # Remove errors for offsets that were found via fallback
    errors = [(n, e) for n, e in errors if n not in results]
    
    return results, errors

# endregion Offset Discovery Engine


# region Validation

# Expected original bytes at each patch site (for verification)
EXPECTED_ORIGINALS = {
    "EmulateStereoSuccess1":    ("01", 1),
    "EmulateStereoSuccess2":    ("75", 1),
    "Emulate48Khz":             ("0F 42 C1", 3),
    "EmulateBitrateModified":   (None, 3),      # Variable imul immediate
    "SetsBitrateBitrateValue":  (None, 5),      # Variable immediate
    "SetsBitrateBitwiseOr":     ("48 09 C1", 3),
    "HighPassFilter":           (None, 11),      # Variable prologue
    "CreateAudioFrameStereo":   (None, 4),       # cmov variant may differ
    "AudioEncoderOpusConfigSetChannels": ("01", 1),
    "AudioEncoderOpusConfigIsOk": ("8B 11 31 C0", 4),
    "MonoDownmixer":            ("84 C0 74 0D", 4),
    "ThrowError":               ("41", 1),
    "DownmixFunc":              ("41", 1),
    "HighpassCutoffFilter":     (None, 0x100),   # Full function body
    "DcReject":                 (None, 0x1B6),   # Full function body
    "DuplicateEmulateBitrateModified": (None, 3), # Variable imul immediate (parallel function)
    "EncoderConfigInit1":       ("00 7D 00 00", 4),  # Packed qword high dword = 32000
    "EncoderConfigInit2":       ("00 7D 00 00", 4),  # Packed qword high dword = 32000
}

# Patch bytes for each offset
PATCH_INFO = {
    "EmulateStereoSuccess1":    ("02", "Channel count 1→2"),
    "EmulateStereoSuccess2":    ("EB", "jne→jmp (force stereo path)"),
    "Emulate48Khz":             ("90 90 90", "cmovb→NOPs (force 48kHz)"),
    "EmulateBitrateModified":   ("00 D0 07", "imul immediate 32000→512000 bps"),
    "SetsBitrateBitrateValue":  ("00 D0 07 00 00", "512000 in imm64"),
    "SetsBitrateBitwiseOr":     ("90 90 90", "or rcx,rax→NOPs"),
    "HighPassFilter":           ("<dynamic: mov rax, IMAGE_BASE+HPC; ret>", "Disable HP filter"),
    "CreateAudioFrameStereo":   ("49 89 C5 90", "cmovae→mov r13,rax; nop"),
    "AudioEncoderOpusConfigSetChannels": ("02", "Channel count 1→2"),
    "AudioEncoderOpusConfigIsOk": ("48 C7 C0 01 00 00 00 C3", "return 1 (always valid)"),
    "MonoDownmixer":            ("90 90 90 90 90 90 90 90 90 90 90 90 E9", "NOP sled + jmp (skip downmix)"),
    "ThrowError":               ("C3", "ret (disable error throws)"),
    "DownmixFunc":              ("C3", "ret (disable downmix)"),
    "HighpassCutoffFilter":     ("<injected: hp_cutoff function>", "Custom HP cutoff + gain"),
    "DcReject":                 ("<injected: dc_reject function>", "Custom DC reject + gain"),
    "DuplicateEmulateBitrateModified": ("00 D0 07", "Duplicate imul immediate 32000→512000 bps"),
    "EncoderConfigInit1":       ("00 D0 07 00", "Encoder config packed qword: 32000→512000"),
    "EncoderConfigInit2":       ("00 D0 07 00", "Encoder config packed qword: 32000→512000"),
}


def validate_offsets(data, results):
    """Validate discovered offsets against expected byte patterns."""
    print("\n" + "=" * 65)
    print("  PHASE 3: Byte Verification")
    print("=" * 65)
    
    verified = 0
    warnings = 0
    
    for name, config_off in sorted(results.items(), key=lambda x: x[1]):
        file_off = config_off - FILE_OFFSET_ADJUSTMENT
        
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
                            patched = bytes.fromhex(patch_hex.replace(' ', '').replace('×', '').replace('+', ''))
                            if actual[:len(patched)] == patched:
                                print(f"  [WARN] {name:45s} ALREADY PATCHED: {actual[:len(patched)].hex(' ')}")
                                warnings += 1
                                continue
                        except ValueError:
                            pass  # Non-standard patch description, skip check
                    print(f"  [WARN] {name:45s} unexpected: {actual[:len(expected)].hex(' ')} (expected {expected_hex})")
                    warnings += 1
            else:
                print(f"  [INFO] {name:45s} bytes: {actual[:min(8,length)].hex(' ')} (no fixed expected)")
                verified += 1
    
    return verified, warnings


def check_injection_sites(data, results):
    """Verify injection sites have enough space (cc padding)."""
    print("\n" + "=" * 65)
    print("  PHASE 4: Injection Site Capacity")
    print("=" * 65)
    
    injections = [
        ("HighpassCutoffFilter", 0x100, "hp_cutoff function"),
        ("DcReject", 0x1B6, "dc_reject function"),
    ]
    
    for name, inject_size, desc in injections:
        if name not in results:
            print(f"  [SKIP] {name}: offset not found")
            continue
        
        file_off = results[name] - FILE_OFFSET_ADJUSTMENT
        
        # Find function end (cc padding)
        func_end = None
        for i in range(file_off, min(file_off + 0x400, len(data) - 3)):
            if data[i:i+4] == b'\xcc\xcc\xcc\xcc':
                func_end = i
                break
        
        if func_end is None:
            print(f"  [WARN] {name}: no cc padding found within 1KB")
            continue
        
        available = func_end - file_off
        fits = available >= inject_size
        margin = available - inject_size
        status = "OK" if fits else "OVERFLOW"
        
        print(f"  [{status:4s}] {name:30s}  available={available} (0x{available:X})  "
              f"needed={inject_size} (0x{inject_size:X})  margin={margin:+d} bytes")

# endregion Validation


# region Output Formatters

def format_powershell_config(results, pe_info=None, file_path=None, file_size=None):
    """Generate PowerShell offset table block - copy-paste directly into the patcher."""
    lines = []
    
    # Build info comment
    if pe_info and file_path and file_size:
        md5 = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
        build_str = pe_info['build_time'].strftime('%b %d %Y')
        lines.append(f"    # Auto-generated by discord_voice_node_offset_finder.py")
        lines.append(f"    # Build: {build_str} | Size: {file_size} | MD5: {md5}")
    
    lines.append("    Offsets = @{")
    
    # Fixed order matching the patcher layout
    ordered_names = [
        "EmulateStereoSuccess1",
        "EmulateStereoSuccess2",
        "Emulate48Khz",
        "EmulateBitrateModified",
        "SetsBitrateBitrateValue",
        "SetsBitrateBitwiseOr",
        "HighPassFilter",
        "CreateAudioFrameStereo",
        "AudioEncoderOpusConfigSetChannels",
        "AudioEncoderOpusConfigIsOk",
        "MonoDownmixer",
        "ThrowError",
        "DownmixFunc",
        "HighpassCutoffFilter",
        "DcReject",
        "DuplicateEmulateBitrateModified",
        "EncoderConfigInit1",
        "EncoderConfigInit2",
    ]
    
    max_len = max(len(n) for n in ordered_names)
    
    for name in ordered_names:
        pad = " " * (max_len - len(name))
        if name in results:
            lines.append(f"        {name}{pad} = 0x{results[name]:X}")
        else:
            lines.append(f"        {name}{pad} = 0x0  # NOT FOUND")
    
    lines.append("    }")
    return "\n".join(lines)


def format_cpp_namespace(results):
    """Generate C++ namespace block for the patcher."""
    lines = ["namespace Offsets {"]
    for name in sorted(results.keys()):
        lines.append(f"    constexpr uint32_t {name} = 0x{results[name]:X};")
    lines.append("    constexpr uint32_t FILE_OFFSET_ADJUSTMENT = 0xC00;")
    lines.append("};")
    return "\n".join(lines)


def format_json(results, pe_info, file_path, file_size):
    """Generate machine-readable JSON output."""
    return json.dumps({
        "tool": "discord_voice_node_offset_finder",
        "file": str(file_path),
        "file_size": file_size,
        "md5": hashlib.md5(open(file_path, 'rb').read()).hexdigest(),
        "pe_timestamp": pe_info['timestamp'] if pe_info else None,
        "pe_build_time": pe_info['build_time'].isoformat() if pe_info else None,
        "image_base": hex(pe_info['image_base']) if pe_info else None,
        "file_offset_adjustment": hex(FILE_OFFSET_ADJUSTMENT),
        "offsets": {name: hex(off) for name, off in sorted(results.items())},
        "total_found": len(results),
        "total_expected": 18,
    }, indent=2)

# endregion Output Formatters


# region Auto-Detection

def find_discord_node():
    """Try to find discord_voice.node in standard install locations (Windows)."""
    if sys.platform != 'win32':
        return None
    
    localappdata = os.environ.get('LOCALAPPDATA', '')
    if not localappdata:
        return None
    
    clients = ['Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment']
    
    for client in clients:
        base = Path(localappdata) / client
        if not base.exists():
            continue
        
        # Find latest app-* folder
        app_dirs = sorted(base.glob('app-*'), reverse=True)
        for app_dir in app_dirs:
            modules = app_dir / 'modules'
            if not modules.exists():
                continue
            
            voice_dirs = list(modules.glob('discord_voice*'))
            for vd in voice_dirs:
                # Check both discord_voice/discord_voice.node and discord_voice.node directly
                for candidate in [vd / 'discord_voice' / 'discord_voice.node', vd / 'discord_voice.node']:
                    if candidate.exists():
                        return candidate
    
    return None

# endregion Auto-Detection


# region Main

def main():
    print("=" * 65)
    print("  Discord Voice Node Offset Finder")
    print("  Signature-based automated offset discovery")
    print("=" * 65)
    
    # Determine input file
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
    
    # Read file
    data = file_path.read_bytes()
    file_size = len(data)
    print(f"\n  File: {file_path}")
    print(f"  Size: {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)")
    print(f"  MD5:  {hashlib.md5(data).hexdigest()}")
    
    # Parse PE
    pe_info = parse_pe(data)
    if pe_info:
        print(f"\n  PE Image Base: 0x{pe_info['image_base']:X}")
        print(f"  PE Timestamp:  {pe_info['build_time'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Sections:      {len(pe_info['sections'])}")
        for s in pe_info['sections']:
            print(f"    {s['name']:8s}  VA=0x{s['vaddr']:08X}  Size=0x{s['raw_size']:08X}  Raw=0x{s['raw_offset']:08X}")
    else:
        print("\n  WARNING: Could not parse PE header")
    
    # Run offset discovery
    results, errors = discover_offsets(data)
    
    # Validate
    verified, warnings = validate_offsets(data, results)
    check_injection_sites(data, results)
    
    # Summary
    print("\n" + "=" * 65)
    print("  RESULTS SUMMARY")
    print("=" * 65)
    print(f"  Offsets found:    {len(results)} / 18")
    print(f"  Bytes verified:   {verified}")
    print(f"  Warnings:         {warnings}")
    print(f"  Errors:           {len(errors)}")
    
    if errors:
        print(f"\n  Failed offsets:")
        for name, err in errors:
            print(f"    {name}: {err}")
    
    # Output formats
    if results:
        # Generate the copy-paste-ready offset table
        ps_config = format_powershell_config(results, pe_info, file_path, file_size)
        
        print("\n" + "=" * 65)
        print("  PATCHER OFFSET TABLE (copy-paste into patcher)")
        print("=" * 65)
        print(ps_config)
        
        # Compute HighPassFilter stub bytes
        stub_line = ""
        if pe_info and "HighpassCutoffFilter" in results:
            hpc_va = pe_info['image_base'] + results["HighpassCutoffFilter"]
            va_bytes = struct.pack('<Q', hpc_va)
            stub = b'\x48\xB8' + va_bytes + b'\xC3'
            stub_line = f"\n  HighPassFilter stub: {stub.hex(' ')}\n    mov rax, 0x{hpc_va:X}; ret"
            print(stub_line)
        
        # Save text file next to the script (or CWD if script dir is read-only)
        script_dir = Path(__file__).resolve().parent
        out_name = "offsets.txt"
        save_dir = script_dir
        
        # Build the file content
        file_content = []
        file_content.append("=" * 65)
        file_content.append("  Discord Voice Node Offset Finder - Results")
        file_content.append("=" * 65)
        if pe_info:
            file_content.append(f"  Build:  {pe_info['build_time'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
        file_content.append(f"  File:   {file_path.name}")
        file_content.append(f"  Size:   {file_size:,} bytes")
        file_content.append(f"  MD5:    {hashlib.md5(data).hexdigest()}")
        file_content.append(f"  Found:  {len(results)} / 18")
        file_content.append("")
        file_content.append("")
        file_content.append("=" * 65)
        file_content.append("  COPY-PASTE INTO PATCHER (between === OFFSET TABLE === markers)")
        file_content.append("=" * 65)
        file_content.append(ps_config)
        if stub_line:
            file_content.append("")
            file_content.append(stub_line.strip())
        file_content.append("")
        file_content.append("")
        file_content.append("=" * 65)
        file_content.append("  C++ NAMESPACE (for reference)")
        file_content.append("=" * 65)
        file_content.append(format_cpp_namespace(results))
        file_content.append("")
        
        txt_content = "\n".join(file_content)
        
        # Try save locations in order: script dir, binary dir, CWD
        saved = False
        for try_dir in [save_dir, file_path.parent, Path.cwd()]:
            try:
                out_path = try_dir / out_name
                out_path.write_text(txt_content)
                print(f"\n  Offset file saved: {out_path}")
                saved = True
                break
            except Exception:
                continue
        
        if not saved:
            print(f"\n  WARNING: Could not save offset file to disk")
        
        # Also save JSON
        json_path = file_path.with_suffix('.offsets.json')
        try:
            json_path.write_text(format_json(results, pe_info, file_path, file_size))
            print(f"  JSON saved: {json_path}")
        except Exception:
            pass
    
    # Exit code
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
