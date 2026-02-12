# Discord Voice Node Offset Finder — Developer Reference

**Automated signature-based offset discovery for `discord_voice.node` binary patching**

![Python](https://img.shields.io/badge/Python-3.6+-3776AB?style=flat-square)
![Offsets](https://img.shields.io/badge/Offsets-18-5865F2?style=flat-square)
![Signatures](https://img.shields.io/badge/Signatures-8-00C853?style=flat-square)

> **Full transparency:** I am not a Python developer... in fact i SUCK at python — I'm pretty good at ps1 and familiar with most of c++. The offset research, signature design, and binary analysis are a collection of My,Cypher,Shaun, and Oracle's determination; the actual Python implementation was written almost entirely by Claude (Anthropic). If the code is clean, that's Claude. If the signatures are clever, that's us. If something is broken, it's probably both of our faults lol!

---

## Credits

**ProdHallow** - Reverse engineering, offset research, signature design, binary analysis, patch methodology, and telling Claude what to write

**Cypher** - Reverse engineering, offset research, signature design, binaru analysis, patch methodology

**Shaun** - Reverse engineering, offset research, signature design, binaru analysis, patch methodology

**Oracle** - Reverse engineering, offset research, signature design, binaru analysis, patch methodology

**Claude (Anthropic)** — Python implementation, script architecture, documentation, and translating "patch the second cmov 31 bytes after the 48000/32000 mov pair" into working code

**Cypher | Oracle | Shaun** —  Deserve a MASSIVE shoutout for the oginal offset discovery and research

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
  - [Phase 1: Signature Scanning](#phase-1-signature-scanning)
  - [Phase 1b: Patched Binary Fallbacks](#phase-1b-patched-binary-fallbacks)
  - [Phase 2: Relative Offset Derivation](#phase-2-relative-offset-derivation)
  - [Phase 3: Byte Verification](#phase-3-byte-verification)
  - [Phase 4: Injection Site Capacity](#phase-4-injection-site-capacity)
- [The 18 Offsets](#the-18-offsets)
  - [Offset Map](#offset-map)
  - [Dependency Graph](#dependency-graph)
- [Signature Reference](#signature-reference)
  - [Signature Format](#signature-format)
  - [Signature Catalogue](#signature-catalogue)
  - [Disambiguators](#disambiguators)
- [Derivation Reference](#derivation-reference)
- [PE Layout & File Offset Adjustment](#pe-layout--file-offset-adjustment)
- [Output Formats](#output-formats)
  - [Console Output](#console-output)
  - [offsets.txt](#offsetstxt)
  - [JSON](#json)
  - [PowerShell Config Block](#powershell-config-block)
  - [C++ Namespace Block](#c-namespace-block)
- [Auto-Detection](#auto-detection)
- [Exit Codes](#exit-codes)
- [Adding a New Offset](#adding-a-new-offset)
- [Porting to a New Build](#porting-to-a-new-build)
- [Known Limitations](#known-limitations)

---

## Overview

The offset finder locates 18 specific code locations inside Discord's native voice module (`discord_voice.node`) that the companion PowerShell patcher needs to modify. Rather than hardcoding raw addresses that break every time Discord ships a new build, the finder uses **byte-pattern signatures** that survive recompilation, combined with **relative offset derivation** to reach nearby patch sites from a single anchor.

The tool is designed so that when Discord ships a new `discord_voice.node`, a developer can run it against the new binary. If all 18 offsets resolve, the existing patcher works as-is — just swap the offset table. If signatures break, the console output tells you exactly which ones failed and why, so you know where to focus your reverse engineering.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    discord_voice.node                     │
│                  (PE64 / x86-64 binary)                  │
└──────────────┬───────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│   PE Header Parser       │  → image_base, sections, timestamp
└──────────┬───────────────┘
           ▼
┌──────────────────────────┐     ┌──────────────────────┐
│  Phase 1: Sig Scanner    │────▶│  8 anchor offsets    │
│  (8 unique patterns)     │     └──────────┬───────────┘
└──────────────────────────┘                │
                                            ▼
┌──────────────────────────┐     ┌──────────────────────┐
│  Phase 2: Derivation     │────▶│ +10 derived offsets  │
│  (anchor + delta)        │     └──────────┬───────────┘
└──────────────────────────┘                │
                                            ▼
┌──────────────────────────┐     ┌──────────────────────┐
│  Phase 3: Verification   │────▶│ 18 verified offsets  │
│  (expected original bytes)│     └──────────┬───────────┘
└──────────────────────────┘                │
                                            ▼
┌──────────────────────────┐     ┌──────────────────────┐
│  Phase 4: Injection Check│────▶│ Capacity validation  │
│  (cc padding analysis)   │     └──────────┬───────────┘
└──────────────────────────┘                │
                                            ▼
                                   offsets.txt / .json
                                   PowerShell config
                                   C++ namespace
```

---

## Quick Start

```bash
# Explicit path
python discord_voice_node_offset_finder.py "C:\path\to\discord_voice.node"

# Auto-detect from Discord install (Windows only)
python discord_voice_node_offset_finder.py
```

The script requires only the Python standard library (no pip dependencies). Python 3.6+ is required.

When run, it prints a full diagnostic log to the console and writes two files alongside the binary:

- `offsets.txt` — human-readable results with copy-paste-ready patcher config
- `discord_voice.offsets.json` — machine-readable results

The console stays open after completion (press Enter to close) so you can read the output when double-clicking the script.

---

## How It Works

### Phase 1: Signature Scanning

The core of the tool. Eight hand-crafted byte patterns are scanned across the entire binary using a fast first-byte-skip algorithm:

1. For each signature, find the first non-wildcard byte
2. Use Python's `bytes.find()` to jump to candidates (this is C-speed, not Python-loop-speed)
3. Verify the full pattern at each candidate position
4. Apply disambiguation if multiple matches are found

Each signature targets a **functionally unique** instruction sequence. Wildcards (`??`) mask bytes that change between builds (relative call displacements, register encodings that the compiler may vary, etc.) while fixed bytes anchor on instruction opcodes and immediate values that are semantically tied to the feature being patched.

**Match resolution priority:**

1. If exactly 1 match → use it
2. If multiple matches → try `disambiguator` callback → try `expected_original` byte filter → fail if still ambiguous
3. If 0 matches → record error, attempt patched-binary fallback in Phase 1b

### Phase 1b: Patched Binary Fallbacks

If a signature fails (e.g., the binary is already patched), the tool attempts alternate detection:

| Offset | Fallback Strategy |
|--------|-------------------|
| `MonoDownmixer` | Scan for the patched NOP sled pattern: `48 89 F9 E8 ?? ?? ?? ?? 90×12 E9` |
| `SetsBitrateBitrateValue` | Scan for the NOPed `or rcx,rax`: `89 F8 48 B9 ??×8 90 90 90 48 89 4E 1C` |
| `HighpassCutoffFilter` | Extract the target VA from the `HighPassFilter` redirect stub (`48 B8 <imm64> C3`) and subtract `image_base` |

This means the tool works on both unpatched **and** already-patched binaries — useful for verifying a patch was applied correctly or for re-running after a gain change.

### Phase 2: Relative Offset Derivation

Nine of the 18 offsets are derived by adding a **fixed delta** to an anchor found in Phase 1. These deltas have been verified stable across multiple builds (Jul 2025 through Feb 2026) because the derived offsets live in the same function or the same compilation unit as their anchor — the compiler preserves their relative positions even when absolute addresses shift.

```
Derived Offset = Anchor Offset + Delta
```

Example: `EmulateStereoSuccess2` is always exactly `+0xC` bytes after `EmulateStereoSuccess1` because they're two instructions apart in the same basic block.

If an anchor wasn't found in Phase 1, all its dependents are skipped (not silently — the console reports `[SKIP] ... anchor not found`).

### Phase 3: Byte Verification

Every discovered offset is checked against `EXPECTED_ORIGINALS` — a table of what bytes should exist at each patch site in an unpatched binary. This catches:

- **Wrong build:** Signature matched but the surrounding code is different (rare but possible with wildcards)
- **Already patched:** The bytes match the patcher's output instead of the original — reported as `[WARN] ALREADY PATCHED`
- **Corruption:** Neither original nor patched bytes match

Offsets with variable originals (like `EmulateBitrateModified` whose imul immediate depends on the build's default bitrate) are tagged `(no fixed expected)` and verified by structure rather than exact bytes.

### Phase 4: Injection Site Capacity

Two offsets (`HighpassCutoffFilter` and `DcReject`) are **code injection sites** — the patcher overwrites the original function body with custom compiled C code. Phase 4 verifies there's enough room by scanning for `CC CC CC CC` (int3 padding) after the function start:

```
Available = (first CC padding address) - (function start)
Needed    = injection code size (0x100 for hp_cutoff, 0x1B6 for dc_reject)
Margin    = Available - Needed
```

If `Margin < 0`, the injection would overwrite the next function. This has never happened (margins are typically 200+ bytes), but the check exists as a safety net for future builds where the compiler might optimize these functions to be smaller.

---

## The 18 Offsets

### Offset Map

| # | Name | Source | Patch Effect |
|---|------|--------|--------------|
| 1 | `EmulateStereoSuccess1` | Signature | Channel count `1` → `2` |
| 2 | `EmulateStereoSuccess2` | Derived (1 + 0xC) | `jne` → `jmp` (force stereo path) |
| 3 | `Emulate48Khz` | Derived (1 + 0x168) | `cmovb` → `NOP×3` (force 48kHz) |
| 4 | `EmulateBitrateModified` | Derived (1 + 0x45F) | `imul` immediate → 512000 bps |
| 5 | `SetsBitrateBitrateValue` | Signature | imm64 low bytes → 512000 |
| 6 | `SetsBitrateBitwiseOr` | Derived (5 + 0x8) | `or rcx,rax` → `NOP×3` |
| 7 | `HighPassFilter` | Derived (1 + 0xC275) | Redirect to `HighpassCutoffFilter` VA |
| 8 | `CreateAudioFrameStereo` | Signature | `cmovae r13,rax` → `mov r13,rax; nop` |
| 9 | `AudioEncoderOpusConfigSetChannels` | Signature | Channel count `1` → `2` in config struct |
| 10 | `AudioEncoderOpusConfigIsOk` | Derived (9 + 0x29C) | Force `return 1` (always valid) |
| 11 | `MonoDownmixer` | Signature | `NOP×12 + jmp` (skip mono downmix gate) |
| 12 | `ThrowError` | Signature | `ret` at entry (disable error throws) |
| 13 | `DownmixFunc` | Signature | `ret` at entry (disable downmix function) |
| 14 | `HighpassCutoffFilter` | Signature | Injection site for custom `hp_cutoff()` |
| 15 | `DcReject` | Derived (14 + 0x1E0) | Injection site for custom `dc_reject()` |
| 16 | `DuplicateEmulateBitrateModified` | Derived (4 + 0x4EE6) | Parallel `imul` immediate → 512000 bps |
| 17 | `EncoderConfigInit1` | Derived (9 + 0xA) | Config struct packed qword: 32000 → 512000 |
| 18 | `EncoderConfigInit2` | Signature | Config struct packed qword: 32000 → 512000 |

### Dependency Graph

```
EmulateStereoSuccess1 (sig)
 ├─→ EmulateStereoSuccess2     (+0x00C)
 ├─→ Emulate48Khz              (+0x168)
 ├─→ EmulateBitrateModified    (+0x45F)
 │    └─→ DuplicateEmulateBitrateModified  (+0x4EE6)
 └─→ HighPassFilter            (+0xC275)

AudioEncoderOpusConfigSetChannels (sig)
 ├─→ EncoderConfigInit1        (+0x00A)
 └─→ AudioEncoderOpusConfigIsOk (+0x29C)

SetsBitrateBitrateValue (sig)
 └─→ SetsBitrateBitwiseOr      (+0x008)

HighpassCutoffFilter (sig)
 └─→ DcReject                  (+0x1E0)

MonoDownmixer (sig)             [standalone]
CreateAudioFrameStereo (sig)    [standalone]
ThrowError (sig)                [standalone]
DownmixFunc (sig)               [standalone]
EncoderConfigInit2 (sig)        [standalone]
```

If `EmulateStereoSuccess1` fails, you lose 5 offsets. If `AudioEncoderOpusConfigSetChannels` fails, you lose 3. The other anchors are standalone or have only one dependent each.

---

## Signature Reference

### Signature Format

Each `Signature` object defines:

| Field | Type | Description |
|-------|------|-------------|
| `name` | str | Offset name matching the patcher's config key |
| `pattern_hex` | str | Space-separated hex bytes. `??` = wildcard (matches any byte) |
| `target_offset` | int | Byte delta from pattern match start to the actual patch site. Can be negative (target is before the pattern). |
| `description` | str | Human-readable disassembly of what the pattern encodes |
| `expected_original` | str \| None | Hex bytes expected at the target in an unpatched binary |
| `patch_bytes` | str \| None | Hex bytes the patcher writes (for already-patched detection) |
| `patch_len` | int \| None | Total patch length if different from `patch_bytes` length |
| `disambiguator` | callable \| None | `fn(data, match_offset) → bool` for multi-match resolution |

**How `target_offset` works:**

```
Pattern match at file position M
Target file offset = M + target_offset
Config offset (RVA) = Target file offset + FILE_OFFSET_ADJUSTMENT (0xC00)
```

A `target_offset` of 0 means the patch site is the first byte of the pattern itself. A value of 17 means the patch site is 17 bytes into the matched pattern. A value of -1 means the patch site is 1 byte before the pattern starts (used for `ThrowError` and `DownmixFunc` where the pattern matches the function body but the patch targets the byte before).

### Signature Catalogue

#### 1. EmulateStereoSuccess1

```
Pattern:  E8 ?? ?? ?? ?? BD ?? 00 00 00 80 BC 24 80 01 00 00 01
Offset:   +6 (the ?? byte in BD ?? 00 00 00)
Encodes:  call <rel32>; mov ebp, CHANNELS; cmp byte [rsp+0x180], 1
```

The `BD` is `mov ebp, imm32`. The second byte of that immediate is the channel count (`01` for mono). The pattern anchors on the distinctive `cmp byte [rsp+0x180], 1` which is a stack-frame-specific comparison unique to the stereo emulation function.

This is the **most important anchor** — 5 other offsets derive from it.

#### 2. AudioEncoderOpusConfigSetChannels

```
Pattern:  48 B9 14 00 00 00 80 BB 00 00 48 89 08 48 C7 40 08 ?? 00 00 00
Offset:   +17 (the ?? byte)
Encodes:  mov rcx, 0xBB80_0000_0014; mov [rax],rcx; mov qword [rax+8], CHANNELS
```

The magic constant `0xBB80_0000_0014` packs two Opus config fields: `48000` (0xBB80, sample rate) in the high dword and `20` (0x14, frame size in ms) in the low dword. This is globally unique in the binary.

#### 3. MonoDownmixer

```
Pattern:  48 89 F9 E8 ?? ?? ?? ?? 84 C0 74 0D 83 BE ?? ?? 00 00 09 0F 8F
Offset:   +8 (the 84 byte — start of test al,al)
Encodes:  mov rcx,rdi; call <fn>; test al,al; jz +0xD; cmp [rsi+offs], 9; jg <rel32>
```

This pattern has **two matches** in the binary because the compiler emits similar code in two different functions. The `_mono_downmixer_disambiguator` callback (see below) selects the correct one.

#### 4. SetsBitrateBitrateValue

```
Pattern:  89 F8 48 B9 ?? ?? ?? ?? 01 00 00 00 48 09 C1 48 89 4E 1C
Offset:   +4 (start of the imm64)
Encodes:  mov eax,edi; mov rcx, <bitrate_imm64>; or rcx,rax; mov [rsi+0x1C], rcx
```

The `48 09 C1` (`or rcx, rax`) and `48 89 4E 1C` (`mov [rsi+0x1C], rcx`) form a unique two-instruction suffix. The patcher overwrites both the immediate value and NOPs out the `or` to store a clean 512000 value.

#### 5. ThrowError

```
Pattern:  56 56 57 53 48 81 EC C8 00 00 00 0F 29 B4 24 B0 00 00 00 4C 89 CE 4C 89 C7 89 D3
Offset:   -1 (one byte before pattern = the push r14 that precedes push rsi)
Encodes:  push r14; push rsi; push rdi; push rbx; sub rsp,0xC8; movaps [rsp+0xB0],xmm6; ...
```

The combination of `sub rsp, 0xC8` + SSE save to `[rsp+0xB0]` + the three `mov` register saves is unique. The `41` byte before the pattern is the REX prefix of `push r14` — the patcher replaces it with `C3` (ret) to disable the entire function.

#### 6. DownmixFunc

```
Pattern:  57 41 56 41 55 41 54 56 57 55 53 48 83 EC 10 48 89 0C 24 45 85 C0
Offset:   -1 (push r15 before the matched push r14)
Encodes:  push r15; push r14; push r13; push r12; push rsi; push rdi; push rbp; push rbx; sub rsp,0x10; ...
```

Eight callee-saved register pushes followed by `sub rsp,0x10` and `mov [rsp],rcx; test r8d,r8d` — this specific sequence of 8 pushes is unique in the binary. Note: this function has **zero direct `CALL` references** — it's invoked via function pointer / vtable, which is why we can't find callers via simple xref scanning.

#### 7. CreateAudioFrameStereo

```
Pattern:  B8 80 BB 00 00 BD 00 7D 00 00 0F 43 E8
Offset:   +31 (second cmovae, 31 bytes past the pattern start)
Encodes:  mov eax, 48000; mov ebp, 32000; cmovae ebp, eax; ... [31 bytes later] ... cmovae r13, rax
```

The magic pair `48000` (0xBB80) and `32000` (0x7D00) as adjacent `mov` immediates is globally unique. The target is a second `cmovae` 31 bytes later that conditionally selects a buffer size — the patcher forces it unconditional.

#### 8. HighpassCutoffFilter

```
Pattern:  56 48 83 EC 30 44 0F 29 44 24 20 0F 29 7C 24 10 0F 29 34 24
Offset:   +0 (pattern start = function entry)
Encodes:  push rsi; sub rsp,0x30; movaps [rsp+0x20],xmm8; movaps [rsp+0x10],xmm7; movaps [rsp],xmm6
```

Three SSE register saves to specific stack slots after `sub rsp,0x30`. This is unique because the exact combination of `xmm8`/`xmm7`/`xmm6` saves to these offsets only appears in the high-pass cutoff filter function.

#### 9. EncoderConfigInit2

```
Pattern:  48 B9 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 48 10 66 C7 40 18 00 00 C6 40 1A 00
Offset:   +6 (byte 6 of the 8-byte immediate in mov rcx)
Encodes:  mov rcx, <packed_qword>; mov [rax+0x10], rcx; mov word [rax+0x18], 0; mov byte [rax+0x1a], 0
```

The post-`mov` instruction sequence (`mov [rax+0x10]`, `mov word [rax+0x18], 0`, `mov byte [rax+0x1a], 0`) is a config struct initializer pattern unique to the second Opus encoder constructor. The target is bytes 6-9 of the immediate (the high dword of the packed qword), which encodes the default bitrate.

### Disambiguators

#### `_mono_downmixer_disambiguator`

**Problem:** The MonoDownmixer pattern matches twice — once in the actual audio frame processing function and once in a different function with similar control flow.

**Solution:** After the `jg` (0F 8F) branch in the pattern, the real downmixer loads channel flags via `movzx r??d, byte [rsp+??]` (encoded as `44 0F B6`). The false positive uses `test [reg+offset]` instead.

```python
def _mono_downmixer_disambiguator(data, match_offset):
    jg_pos = match_offset + 19         # 0F 8F is at pattern byte 19
    after_jg = data[jg_pos+6 : jg_pos+18]  # skip the 6-byte jg instruction
    return b'\x44\x0f\xb6' in after_jg     # REX.R movzx present?
```

---

## Derivation Reference

All relative deltas in one table:

| Derived Offset | Anchor | Delta | Hex | Rationale |
|----------------|--------|-------|-----|-----------|
| `EmulateStereoSuccess2` | `EmulateStereoSuccess1` | +12 | +0xC | Next conditional branch in same basic block |
| `Emulate48Khz` | `EmulateStereoSuccess1` | +360 | +0x168 | Sample rate `cmovb` in same function |
| `EmulateBitrateModified` | `EmulateStereoSuccess1` | +1119 | +0x45F | Bitrate `imul` in same function |
| `HighPassFilter` | `EmulateStereoSuccess1` | +49781 | +0xC275 | HP filter call in same compilation unit |
| `SetsBitrateBitwiseOr` | `SetsBitrateBitrateValue` | +8 | +0x8 | `or` instruction immediately after `mov rcx, imm64` |
| `AudioEncoderOpusConfigIsOk` | `AudioEncoderOpusConfigSetChannels` | +668 | +0x29C | Validation function in same translation unit |
| `EncoderConfigInit1` | `AudioEncoderOpusConfigSetChannels` | +10 | +0xA | Same constructor, 10 bytes after channels byte |
| `DcReject` | `HighpassCutoffFilter` | +480 | +0x1E0 | Next function in .text section (adjacent) |
| `DuplicateEmulateBitrateModified` | `EmulateBitrateModified` | +20198 | +0x4EE6 | Parallel template instantiation in same TU |

**Stability basis:** These deltas survive recompilation because:

- Same basic block (ES2 from ES1): Instruction sequence is deterministic
- Same function (48Khz, Bitrate from ES1): No code between them that varies in size
- Same compilation unit (HighPassFilter from ES1, ConfigIsOk from Channels): Linker preserves intra-TU ordering
- Adjacent functions (DcReject from HPC): Linker preserves function order within a section

The deltas were verified identical between the December 2025 (build 9219) and February 2026 (Feb 9) builds.

---

## PE Layout & File Offset Adjustment

`discord_voice.node` is a PE64 DLL (actually a Node.js native addon). The constant `FILE_OFFSET_ADJUSTMENT = 0xC00` converts between **file offsets** (raw position in the .node file) and **config offsets** (RVAs used by the patcher):

```
Config Offset (RVA) = File Offset + 0xC00
File Offset         = Config Offset - 0xC00
```

This adjustment exists because the `.text` section's raw file offset and virtual address differ by exactly `0xC00` in all observed builds. The PE parser extracts this from the section headers at runtime, but it's also hardcoded as a constant since it hasn't changed.

**Why not just use the PE section table?** The patcher's offset table historically uses config offsets (effectively RVAs), and changing the convention would break compatibility. The `0xC00` constant is verified against the actual PE headers at parse time.

**Typical PE section layout (Feb 2026 build):**

```
Section   VirtualAddr  RawSize     RawOffset
.text     0x00001000   0x00B96000  0x00000400
.rdata    0x00B97000   0x002A0000  0x00B96400
.data     0x00E37000   0x00038000  0x00E36400
.pdata    0x00E73000   0x0006D000  0x00E6E400
.reloc    0x00EE1000   0x00048000  0x00EDC400
```

---

## Output Formats

### Console Output

Full diagnostic log with color-coded status markers:

```
[ OK ] — Offset found and verified
[FAIL] — Signature matched nothing or was ambiguous
[FALL] — Found via patched-binary fallback
[PASS] — Original bytes match expected
[WARN] — Bytes don't match (possibly already patched)
[INFO] — No fixed expected bytes; showing what's there
[SKIP] — Anchor missing, derivation skipped
```

### offsets.txt

Saved next to the script (fallback: next to the binary, then CWD). Contains:

1. File metadata (build date, size, MD5)
2. Copy-paste PowerShell config block
3. HighPassFilter stub bytes
4. C++ namespace block

### JSON

Saved as `<input_file>.offsets.json`. Machine-readable format:

```json
{
  "tool": "discord_voice_node_offset_finder",
  "file": "C:\\path\\to\\discord_voice.node",
  "file_size": 14296504,
  "md5": "abcdef1234567890...",
  "pe_timestamp": 1739012345,
  "pe_build_time": "2026-02-09T...",
  "image_base": "0x180000000",
  "file_offset_adjustment": "0xc00",
  "offsets": {
    "AudioEncoderOpusConfigIsOk": "0x3A7610",
    "AudioEncoderOpusConfigSetChannels": "0x3A7374",
    ...
  },
  "total_found": 18,
  "total_expected": 18
}
```

### PowerShell Config Block

Drop-in replacement for the patcher's `Offsets = @{ ... }` hashtable:

```powershell
    Offsets = @{
        EmulateStereoSuccess1             = 0x53840B
        EmulateStereoSuccess2             = 0x538417
        Emulate48Khz                      = 0x538573
        ...
    }
```

### C++ Namespace Block

For reference or for embedding in a standalone C++ patcher:

```cpp
namespace Offsets {
    constexpr uint32_t AudioEncoderOpusConfigIsOk = 0x3A7610;
    constexpr uint32_t AudioEncoderOpusConfigSetChannels = 0x3A7374;
    ...
    constexpr uint32_t FILE_OFFSET_ADJUSTMENT = 0xC00;
};
```

---

## Auto-Detection

On Windows, if no file path is provided, the script searches standard Discord install locations:

```
%LOCALAPPDATA%\Discord\app-*\modules\discord_voice*\discord_voice\discord_voice.node
%LOCALAPPDATA%\DiscordCanary\app-*\modules\discord_voice*\discord_voice\discord_voice.node
%LOCALAPPDATA%\DiscordPTB\app-*\modules\discord_voice*\discord_voice\discord_voice.node
%LOCALAPPDATA%\DiscordDevelopment\app-*\modules\discord_voice*\discord_voice\discord_voice.node
```

It picks the latest `app-*` directory (sorted descending) and the first matching voice module. This works for stock Discord; mod clients (BetterDiscord, Vencord, etc.) share the same install path.

On non-Windows platforms, auto-detection is not supported — pass the path explicitly.

---

## Exit Codes

| Code | Meaning | Threshold |
|------|---------|-----------|
| `0` | All 18 offsets found | 18/18 |
| `1` | Partial success — enough for basic patching | 15-17/18 |
| `2` | Insufficient — too many missing for safe patching | < 15/18 |

The thresholds are intentionally conservative. 15/18 means the three v5.0 offsets (`DuplicateEmulateBitrateModified`, `EncoderConfigInit1`, `EncoderConfigInit2`) might be missing — the patcher can still function at reduced effectiveness (bitrate defaults may leak through on some code paths).

---

## Adding a New Offset

When reverse engineering reveals a new patch site:

### Step 1: Determine if it needs a signature or can be derived

If the new offset is **within ~64KB of an existing anchor** and the relative distance is stable across builds, add a derivation. If it's in a completely different function/region, add a new signature.

### Step 2a: Adding a derivation

Edit the `DERIVATIONS` dict:

```python
DERIVATIONS = {
    ...
    "NewOffsetName": ("AnchorName", 0x1234),  # delta verified across 2+ builds
}
```

### Step 2b: Adding a signature

1. **Find a unique byte sequence** around your target in the disassembly. Include instruction opcodes and distinctive immediates. Avoid bytes that are likely to change (relative call displacements, register choices the optimizer might vary).

2. **Wildcard volatile bytes** with `??`. Common wildcards: `E8 ?? ?? ?? ??` (relative call), register operands the compiler might swap.

3. **Verify uniqueness** by searching the binary for your pattern — it must match exactly once (or use a disambiguator).

4. Add to the `SIGNATURES` list:

```python
Signature(
    name="NewOffsetName",
    pattern_hex="AA BB ?? CC DD EE",
    target_offset=3,           # patch site is 3 bytes into the pattern
    description="What this code does in x86 terms",
    expected_original="CC",    # byte(s) at the target in unpatched binary
    patch_bytes="FF",          # what the patcher writes (for already-patched detection)
),
```

### Step 3: Add validation entries

```python
EXPECTED_ORIGINALS["NewOffsetName"] = ("CC", 1)        # expected hex, length
PATCH_INFO["NewOffsetName"] = ("FF", "Description")    # patch hex, description
```

### Step 4: Add to output ordering

In `format_powershell_config`, add the name to `ordered_names` in the desired position.

### Step 5: Update counts

- Docstring: update offset/signature/derived counts
- Exit code thresholds: update `18` to `19`, partial threshold if needed
- README (this file): add to the offset table and dependency graph

---

## Porting to a New Build

When Discord ships a new `discord_voice.node`:

1. **Run the finder against it.** If 18/18 → done, copy the offset table into the patcher.

2. **If signatures break**, the console tells you which ones. Open the new binary in a disassembler (Ghidra, IDA, Binary Ninja) and:

   - Search for the **functional pattern** (not the exact bytes) near the old RVA
   - Check if the instruction encoding changed (e.g., compiler chose a different register)
   - Update the pattern, adding wildcards for the changed bytes
   - Re-verify uniqueness

3. **If derivations break** (anchor found but derived offset's bytes don't match), the compiler reordered code within the function. You'll need to either:

   - Update the delta
   - Promote the derived offset to a full signature

4. **If `FILE_OFFSET_ADJUSTMENT` changes**, update the constant. Check the PE section headers: `config_offset = file_offset + (.text virtual_address - .text raw_offset)`.

5. **Test the patcher** with the new offsets on the new binary before distributing.

---

## Known Limitations

- **Single-build validation only.** The tool confirms offsets are correct for the provided binary, but can't guarantee the patcher's patches are semantically correct on a new build (the code around the patch sites might have changed meaning).

- **No cross-reference analysis.** The tool doesn't trace callers or data flow. If Discord restructures how functions are called (e.g., inlining the downmixer), the offsets might resolve but the patches might not have the desired effect.

- **Windows auto-detection only.** macOS and Linux Discord installs use different paths and potentially different binary formats (though the voice module is typically the same PE64 binary on all platforms via Electron).

- **No ASLR handling.** The tool works with file offsets / RVAs, not runtime virtual addresses. The patcher handles ASLR via `GetModuleHandle` at runtime.

- **Disambiguator fragility.** The MonoDownmixer disambiguator relies on a specific instruction (`44 0F B6`, REX.R movzx) appearing within 12 bytes of the branch. If the compiler restructures that code, the disambiguator might fail even though the signature matches. In that case, a new disambiguator or a more specific signature pattern would be needed.
