# 🔍 Discord Voice Node Offset Finder — Developer Reference

**Automated signature-based offset discovery for `discord_voice.node` binary patching**

![Python](https://img.shields.io/badge/Python-3.6+-3776AB?style=flat-square)
![Offsets](https://img.shields.io/badge/Offsets-19%20%28Win%29-5865F2?style=flat-square)
![Signatures](https://img.shields.io/badge/Signatures-9-00C853?style=flat-square)

> **Full transparency:** I am not a Python developer... in fact i SUCK at python — I'm pretty good at ps1 and familiar with most of c++. The offset research, signature design, and binary analysis are a collection of My, Cypher, Shaun, and Oracle's determination; the actual Python implementation was written almost entirely by Claude (Anthropic). If the code is clean, that's Claude. If the signatures are clever, that's us. If something is broken, it's probably both of our faults lol!

---

## 👥 Credits

**ProdHallow** - Reverse engineering, offset research, signature design, binary analysis, patch methodology, and telling Claude what to write

**Cypher** - Reverse engineering, offset research, signature design, binary analysis, patch methodology

**Shaun** - Reverse engineering, offset research, signature design, binary analysis, patch methodology

**Oracle** - Reverse engineering, offset research, signature design, binary analysis, patch methodology

**Crue** - Reverse engineering, offset research, signature design, binary analysis, patch methodology

**Geeko** - Reverse engineering, offset research, signature design, binary analysis, patch methodology

**Claude (Anthropic)** — Python implementation, script architecture, documentation, and translating "patch the second cmov 31 bytes after the 48000/32000 mov pair" into working code

**Cypher | Oracle | Shaun** —  Deserve a MASSIVE shoutout for the original offset discovery and research

---

## 📑 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [GUI](#gui)
- [How It Works](#how-it-works)
  - [Phase 1: Signature Scanning](#phase-1-signature-scanning)
  - [Phase 1b: Patched Binary Fallbacks](#phase-1b-patched-binary-fallbacks)
  - [Phase 2: Relative Offset Derivation](#phase-2-relative-offset-derivation)
  - [Phase 3: Byte Verification](#phase-3-byte-verification)
  - [Phase 4: Injection Site Capacity](#phase-4-injection-site-capacity)
- [Offsets (source of truth)](#offsets-source-of-truth)
- [Signature Reference](#signature-reference)
  - [Signature Format](#signature-format)
- [PE Layout & File Offset Adjustment](#pe-layout--file-offset-adjustment)
- [Output Formats](#output-formats)
  - [Console Output](#console-output)
  - [offsets.txt](#offsetstxt)
  - [JSON](#json)
  - [Windows Patcher Paste Block](#windows-patcher-paste-block)
  - [C++ Namespace Block](#c-namespace-block)
- [Auto-Detection](#auto-detection)
- [Exit Codes](#exit-codes)
- [Adding a New Offset](#adding-a-new-offset)
- [Porting to a New Build](#porting-to-a-new-build)
- [Known Limitations](#known-limitations)

---

## 📌 Overview

The offset finder locates the code locations inside Discord's native voice module (`discord_voice.node`) that the companion PowerShell patcher needs to modify. **On Windows, the patcher expects 19 offsets** (including EncoderConfigInit1/2 and BWE_Thr2/Thr3). Rather than hardcoding raw addresses that break every time Discord ships a new build, the finder uses **byte-pattern signatures** that survive recompilation, combined with **relative offset derivation** and **BWE discovery** (518400/921600 imm32) to reach all patch sites.

The tool is designed so that when Discord ships a new `discord_voice.node`, a developer can run it against the new binary. If all 19 Windows patcher offsets resolve, the existing patcher works as-is — just paste the generated block into the patcher's offset region. If signatures break, the console output tells you exactly which ones failed and why.

The **v5** finder uses a tiered resolution pipeline and supports Windows (PE), Linux (ELF), and macOS (Mach-O). It uses **9** anchor signatures to derive offsets; on Windows it also discovers BWE_Thr2 and BWE_Thr3 by scanning for the 518400/921600 immediates. **On current Discord builds, the finder resolves all 19 Windows patcher offsets.** Linux/macOS patcher lists may use a different count (e.g. 18).

---

## 🏗️ Architecture

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
│  Phase 1: Sig Scanner    │────▶│  9 anchor offsets    │
│  (9 unique patterns)     │     └──────────┬───────────┘
└──────────────────────────┘                │
                                            ▼
┌──────────────────────────┐     ┌──────────────────────┐
│  Phase 2: Derivation      │────▶│ + derived offsets    │
│  (anchor + delta)         │     │ + BWE (Win)          │
└──────────────────────────┘     └──────────┬───────────┘
                                            ▼
┌──────────────────────────┐     ┌──────────────────────┐
│  Phase 3: Verification   │────▶│ 19 (Win) verified     │
│  (expected original bytes)│     └──────────┬───────────┘
└──────────────────────────┘                │
                                            ▼
┌──────────────────────────┐     ┌──────────────────────┐
│  Phase 4: Injection Check │────▶│ Capacity validation  │
│  (cc padding analysis)   │     └──────────┬───────────┘
└──────────────────────────┘                │
                                            ▼
                                   offsets.txt / .json
                                   Windows patcher block
                                   C++ namespace
```

---

## 🚀 Quick Start

```bash
# Explicit path
python discord_voice_node_offset_finder_v5.py "C:\path\to\discord_voice.node"

# Auto-detect from Discord install (Windows only)
python discord_voice_node_offset_finder_v5.py
```

**GUI (optional):** Run `offset_finder_gui.py` from the same folder for a graphical interface (see [GUI](#gui)).

The script requires only the Python standard library (no pip dependencies). Python 3.6+ is required.

When run, it prints a full diagnostic log to the console and writes two files alongside the binary:

- `offsets.txt` — human-readable results with copy-paste-ready patcher config
- `discord_voice.offsets.json` — machine-readable results

The console stays open after completion (press Enter to close) so you can read the output when double-clicking the script.

---

## 🖥️ GUI

A graphical interface is provided by **`offset_finder_gui.py`** in the same directory. Run it (e.g. `python offset_finder_gui.py`) to select a `discord_voice.node` file, run the finder, and view colorized output. The GUI auto-loads the offset finder script from the same folder (e.g. `discord_voice_node_offset_finder_v5.py`) and uses a dark theme to match the Stereo Installer. **Copy Block** copies the Windows patcher paste block (region + OffsetsMeta + Offsets + endregion) for pasting into the patcher. The debug section shows **patch names only** (one per line per group), matching the patcher's Debug mode labels. Credits for the GUI: Oracle | Shaun | Hallow | Ascend | Sentry | Sikimzo | Cypher.

---

## ⚙️ How It Works

### Phase 1: Signature Scanning

The core of the tool. Nine hand-crafted byte patterns are scanned across the entire binary using a fast first-byte-skip algorithm:

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

If a signature fails (e.g., the binary is already patched), the tool may attempt alternate detection for some anchors (e.g. patched-byte patterns or redirect stubs). See the script for the current fallbacks. This allows the tool to work on both unpatched **and** already-patched binaries — useful for verifying a patch was applied correctly or for re-running after a gain change.

### Phase 2: Relative Offset Derivation

Many of the 19 Windows offsets are derived by adding a **fixed delta** to an anchor found in Phase 1. These deltas have been verified stable across multiple builds (Jul 2025 through Feb 2026) because the derived offsets live in the same function or the same compilation unit as their anchor — the compiler preserves their relative positions even when absolute addresses shift. On Windows, **BWE_Thr2** and **BWE_Thr3** are discovered by scanning for 518400 and 921600 (little-endian imm32) in the BuildBitrateTable region, not by derivation.

```
Derived Offset = Anchor Offset + Delta
```

If an anchor wasn't found in Phase 1, all its dependents are skipped (not silently — the console reports `[SKIP] ... anchor not found`).

### Phase 3: Byte Verification

Every discovered offset is checked against `EXPECTED_ORIGINALS` — a table of what bytes should exist at each patch site in an unpatched binary. This catches:

- **Wrong build:** Signature matched but the surrounding code is different (rare but possible with wildcards)
- **Already patched:** The bytes match the patcher's output instead of the original — reported as `[WARN] ALREADY PATCHED`
- **Corruption:** Neither original nor patched bytes match

Offsets with variable expected bytes (e.g. bitrate-dependent immediates) are tagged `(no fixed expected)` and verified by structure rather than exact bytes.

### Phase 4: Injection Site Capacity

Some offsets are **code injection sites** — the patcher overwrites the original function body with custom compiled C code. Phase 4 verifies there's enough room by scanning for `CC CC CC CC` (int3 padding) after the function start:

```
Available = (first CC padding address) - (function start)
Needed    = injection code size (defined in the script)
Margin    = Available - Needed
```

If `Margin < 0`, the injection would overwrite the next function. The check exists as a safety net for builds where the compiler might shrink these functions.

---

## 📍 Offsets (source of truth)

The finder discovers a fixed set of patch offsets: some are found directly by signatures (anchors), others are derived from anchors by adding deltas, and on Windows **BWE_Thr2** and **BWE_Thr3** are found by scanning for 518400/921600 immediates. The exact names, count, and derivation chain are defined in the script. The **Windows patcher list** (`WINDOWS_PATCHER_OFFSET_NAMES`) has **19** names and matches the order and keys expected by `Discord_voice_node_patcher.ps1`. Run the finder or inspect `discord_voice_node_offset_finder_v5.py` (e.g. `SIGNATURES`, `DERIVATIONS`, BWE discovery, `EXPECTED_ORIGINALS`) for the current list. When an anchor fails, its dependents are skipped and reported in the console.

---

## 📝 Signature Reference

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

A `target_offset` of 0 means the patch site is the first byte of the pattern itself. Positive values mean the patch site is that many bytes into the matched pattern; negative values mean the patch site is before the pattern start (e.g. for entry-point patches where the pattern matches the function body but the patch targets the prologue byte).

---

## 📐 PE Layout & File Offset Adjustment

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

## 📤 Output Formats

### Console Output

Full diagnostic log with color-coded status markers:

```
[ OK ] ✅ — Offset found and verified
[FAIL] ❌ — Signature matched nothing or was ambiguous
[FALL] 🔄 — Found via patched-binary fallback
[BWE ] 📊 — BWE_Thr2/Thr3 found via imm32 scan (Windows)
[PASS] ✅ — Original bytes match expected
[WARN] ⚠️ — Bytes don't match (possibly already patched)
[INFO] ℹ️ — No fixed expected bytes; showing what's there
[SKIP] ⏭️ — Anchor missing, derivation skipped
```

Success line for Windows: **✅ ALL 19 WINDOWS PATCHER OFFSETS FOUND**.

### offsets.txt

Saved next to the script (fallback: next to the binary, then CWD). Contains:

1. File metadata (build date, size, MD5)
2. Windows patcher paste block (region + OffsetsMeta + Offsets + endregion)
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
    "AudioEncoderOpusConfigIsOk": "0x3A7540",
    "AudioEncoderOpusConfigSetChannels": "0x3A72A4",
    "BWE_Thr2": "0x44005B",
    "BWE_Thr3": "0x44006A",
    ...
  },
  "total_found": 19,
  "total_expected": 19
}
```

### Windows Patcher Paste Block

The finder outputs a block that **replaces the entire** `# region Offsets (PASTE HERE)` … `# endregion Offsets` section in `Discord_voice_node_patcher.ps1`:

- `$Script:OffsetsMeta = @{ FinderVersion = "…"; Build = "…"; Size = …; MD5 = "…" }`
- `$Script:Offsets = @{ CreateAudioFrameStereo = 0x…; … }` (all 19 keys in patcher order)

Copy the block between `--- BEGIN COPY (Windows) ---` and `--- END COPY ---` and paste into the patcher. No manual editing of key order is needed. The GUI **Copy Block** button copies this same block (without the BEGIN/END markers) to the clipboard.

### C++ Namespace Block

For reference or for embedding in a standalone C++ patcher:

```cpp
namespace Offsets {
    constexpr uint32_t AudioEncoderOpusConfigIsOk = 0x3A7540;
    constexpr uint32_t AudioEncoderOpusConfigSetChannels = 0x3A72A4;
    constexpr uint32_t BWE_Thr2 = 0x44005B;
    constexpr uint32_t BWE_Thr3 = 0x44006A;
    ...
    constexpr uint32_t FILE_OFFSET_ADJUSTMENT = 0xC00;
};
```

---

## 🔎 Auto-Detection

On Windows, if no file path is provided, the script searches standard Discord install locations:

```
%LOCALAPPDATA%\Discord\app-*\modules\discord_voice*\discord_voice\discord_voice.node
%LOCALAPPDATA%\DiscordCanary\app-*\modules\discord_voice*\discord_voice\discord_voice.node
%LOCALAPPDATA%\DiscordPTB\app-*\modules\discord_voice*\discord_voice\discord_voice.node
%LOCALAPPDATA%\DiscordDevelopment\app-*\modules\discord_voice*\discord_voice\discord_voice.node
```

It picks the latest `app-*` directory (sorted descending) and the first matching voice module. This works for stock Discord; mod clients (BetterDiscord, Vencord, etc.) share the same install path.

**Auto-detection of the install path is Windows-only.** On Linux and macOS, pass the path to `discord_voice.node` explicitly. **Offset discovery itself is cross-platform:** the finder resolves all 19 Windows patcher offsets on current builds when given the Windows binary.

---

## 🚦 Exit Codes

| Code | Meaning | Threshold |
|------|---------|------------|
| `0` | ✅ All required offsets found (Windows: 19/19 patcher offsets) | 19/19 (Win) |
| `1` | ⚠️ Partial success — enough for basic patching | 16–18/19 (Win) |
| `2` | ❌ Insufficient — too many missing for safe patching | < 16/19 (Win) |

The thresholds are intentionally conservative. Partial success allows the patcher to still function at reduced effectiveness when a few offsets are missing. See the script for the exact counts and thresholds per platform.

---

## ➕ Adding a New Offset

When reverse engineering reveals a new patch site:

### Step 1: Determine if it needs a signature or can be derived

If the new offset is **within ~64KB of an existing anchor** and the relative distance is stable across builds, add a derivation. If it's in a completely different function/region (or is a distinct constant like BWE), add a new signature or a dedicated discovery step (e.g. BWE imm32 scan).

### Step 2a: Adding a derivation

Edit the `DERIVATIONS` dict:

```python
DERIVATIONS = {
    ...
    "NewOffsetName": [("AnchorName", 0x1234)],  # delta verified across 2+ builds
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

### Step 4: Add to Windows patcher ordering

In `WINDOWS_PATCHER_OFFSET_NAMES`, add the name in the desired position (must match patcher's `offsetOrder`). Update `format_windows_patcher_block` / output ordering if needed.

### Step 5: Update counts

- Docstring: update offset/signature counts (e.g. "Windows: 19 offsets")
- Exit code thresholds: update total offset count and partial threshold if needed

---

## 🔄 Porting to a New Build

When Discord ships a new `discord_voice.node`:

1. **Run the finder against it.** If 19/19 Windows patcher offsets → done, copy the Windows patcher block into the patcher's offset region.

2. **If signatures break**, the console tells you which ones. Open the new binary in a disassembler (Ghidra, IDA, Binary Ninja) and:

   - Search for the **functional pattern** (not the exact bytes) near the old RVA
   - Check if the instruction encoding changed (e.g., compiler chose a different register)
   - Update the pattern, adding wildcards for the changed bytes
   - Re-verify uniqueness

3. **If derivations break** (anchor found but derived offset's bytes don't match), the compiler reordered code within the function. You'll need to either:

   - Update the delta
   - Promote the derived offset to a full signature

4. **If BWE discovery fails**, check that the 518400/921600 immediates still exist in the BuildBitrateTable region and adjust the scan range or logic if the binary layout changed.

5. **If `FILE_OFFSET_ADJUSTMENT` changes**, update the constant. Check the PE section headers: `config_offset = file_offset + (.text virtual_address - .text raw_offset)`.

6. **Test the patcher** with the new offsets on the new binary before distributing.

---

## ⚠️ Known Limitations

- **Single-build validation only.** The tool confirms offsets are correct for the provided binary, but can't guarantee the patcher's patches are semantically correct on a new build (the code around the patch sites might have changed meaning).

- **No cross-reference analysis.** The tool doesn't trace callers or data flow. If Discord restructures how functions are called (e.g., inlining the downmixer), the offsets might resolve but the patches might not have the desired effect.

- **No ASLR handling.** The tool works with file offsets / RVAs, not runtime virtual addresses. The patcher handles ASLR via `GetModuleHandle` at runtime.

- **Auto-detection is Windows-only.** Only the automatic search for the binary path is limited to Windows. Given the path to `discord_voice.node`, the finder can resolve all 19 Windows patcher offsets on the Windows PE binary.

- **Disambiguator fragility.** Some signatures use disambiguator callbacks to choose among multiple pattern matches. Those callbacks rely on nearby instruction patterns; if the compiler restructures the code, a disambiguator can fail even when the signature still matches. Updating the disambiguator or tightening the signature in the script fixes it.
