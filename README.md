# 🔍 Discord Voice Node Offset Finder — Developer Reference

**Automated signature-based offset discovery for `discord_voice.node` binary patching**

![Python](https://img.shields.io/badge/Python-3.6+-3776AB?style=flat-square)
![Offsets](https://img.shields.io/badge/Offsets-17%20%28all%20platforms%29-5865F2?style=flat-square)
![Formats](https://img.shields.io/badge/Formats-PE%20%7C%20ELF%20%7C%20Mach--O-00C853?style=flat-square)

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

**Cypher | Oracle | Shaun** — Deserve a MASSIVE shoutout for the original offset discovery and research

---

## 📑 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [GUI](#gui)
- [How It Works](#how-it-works)
  - [Phase 0: Symbol Table Resolution](#phase-0-symbol-table-resolution)
  - [Phase 1: Signature Scanning](#phase-1-signature-scanning)
  - [Phase 2: Relative Offset Derivation](#phase-2-relative-offset-derivation)
  - [Phase 3: Byte Verification](#phase-3-byte-verification)
  - [Phase 4: Injection Site Capacity](#phase-4-injection-site-capacity)
  - [ARM64 Discovery (macOS fat binary)](#arm64-discovery-macos-fat-binary)
- [Offsets (source of truth)](#offsets-source-of-truth)
- [Signature Reference](#signature-reference)
- [PE / ELF / Mach-O Layout](#pe--elf--macho-layout)
- [Output Formats](#output-formats)
  - [Console Output](#console-output)
  - [offsets.txt & JSON](#offsetstxt--json)
  - [Patcher paste blocks](#patcher-paste-blocks)
- [Auto-Detection](#auto-detection)
- [Exit Codes](#exit-codes)
- [Adding a New Offset](#adding-a-new-offset)
- [Porting to a New Build](#porting-to-a-new-build)
- [Known Limitations](#known-limitations)

---

## 📌 Overview

The offset finder locates the code locations inside Discord's native voice module (`discord_voice.node`) that the companion patchers (Windows PowerShell, Linux shell, macOS) need to modify. **All platforms use the same 17 offsets.** Rather than hardcoding raw addresses that break every time Discord ships a new build, the finder uses **byte-pattern signatures**, **symbol-table resolution** (ELF/Mach-O), and **relative offset derivation** to reach all patch sites.

When Discord ships a new `discord_voice.node`, run the finder against it. If all 17 offsets resolve (and on macOS fat binaries, both x86_64 and arm64), paste the generated block into the appropriate patcher. If signatures break, the console output shows which ones failed and why.

The **v5** finder uses a tiered pipeline and supports **Windows (PE)**, **Linux (ELF)**, and **macOS (Mach-O**, including universal fat binaries with x86_64 + arm64). On Windows it uses anchor signatures plus derivation; on Linux/macOS it uses symbol tables plus pattern scans and, for arm64, a literal-32000 fallback for `EmulateBitrateModified`.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    discord_voice.node                     │
│              (PE64 / ELF / Mach-O x86_64 / arm64)         │
└──────────────┬───────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│  Format detection        │  → PE / ELF / Mach-O (fat)
│  Section & symbol parse  │  → .text, image_base, symbols
└──────────┬───────────────┘
           ▼
┌──────────────────────────┐     ┌──────────────────────┐
│  Phase 0: Symbol table   │────▶│  Anchors (ELF/Mach-O) │
│  (ELF/Mach-O only)       │     └──────────┬───────────┘
└──────────────────────────┘                │
┌──────────────────────────┐                │
│  Phase 1: Sig / scan     │────────────────┤
│  (anchors + alternates)  │                │
└──────────┬───────────────┘                ▼
           │                    ┌──────────────────────┐
           │                    │  Phase 2: Derivation │
           │                    │  anchor + delta      │
           │                    │  + heuristic (32000) │
           │                    └──────────┬───────────┘
           │                               ▼
           │                    ┌──────────────────────┐
           │                    │  Phase 3: Verification│
           │                    │  Phase 4: Capacity     │
           │                    └──────────┬───────────┘
           │                               ▼
           │                    ┌──────────────────────┐
           │                    │  17 offsets verified │
           │                    │  (+ arm64 if fat)     │
           │                    └──────────┬───────────┘
           │                               ▼
           │                    offsets.txt / .json
           │                    (temp files cleaned on exit)
           │                    Windows / Linux / macOS blocks
           └───────────────────────────────────────────────
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

The script requires only the Python standard library for core functionality. Optional: `networkx` and `matplotlib` for the dependency graph (saved as `offsets_graph.png` when available; all created files are removed on exit).

**Python 3.6+** is required.

When run, it prints a full diagnostic log and writes **offsets.txt** and **&lt;binary&gt;.offsets.json** (and optionally the graph). **All of these output files are deleted when the script exits** so they don’t clutter the filesystem; copy the patcher block from the console or from the GUI before closing.

On Windows, the console stays open after completion (press Enter to close) when double-clicking the script.

---

## 🖥️ GUI

A graphical interface is provided by **`offset_finder_gui.py`** in the same directory. Run it (e.g. `python offset_finder_gui.py`) to select a `discord_voice.node` file, run the finder, and view colorized output. The GUI loads the offset finder script from the same folder and uses a dark theme. **Copy Block** copies the Windows patcher paste block for pasting into the patcher. Credits: Oracle | Shaun | Hallow | Ascend | Sentry | Sikimzo | Cypher.

---

## ⚙️ How It Works

### Phase 0: Symbol Table Resolution

On **ELF** (Linux) and **Mach-O** (macOS), the finder uses the binary’s symbol table to resolve many offsets directly (e.g. `ThrowError`, `DownmixFunc`, `HighpassCutoffFilter`) or to narrow scans to specific functions. This avoids fragile byte patterns where symbols are available. x86_64 and arm64 slices in a fat Mach-O are processed separately; arm64 uses its own symbol map and scans.

### Phase 1: Signature Scanning

Hand-crafted byte patterns are scanned across the binary (or within symbol-resolved functions). Wildcards (`??`) mask bytes that change between builds. The pipeline uses multiple tiers (primary signatures, relaxed patterns, clang/platform-specific alternates) so that all 17 offsets resolve on current Discord builds. Match resolution: single match → use it; multiple → disambiguator or expected-original filter; zero → derivation or heuristic fallback.

### Phase 2: Relative Offset Derivation

Many offsets are derived by adding a **fixed delta** to an anchor found in Phase 0/1. These deltas are stable across builds because the derived sites live in the same function or compilation unit. Example: `SetsBitrateBitwiseOr = SetsBitrateBitrateValue + 0x8`. If an anchor is missing, dependents are skipped and reported. On **Windows**, `EmulateBitrateModified` can also be found by a heuristic scan for the 32000 literal; on **arm64**, a literal-32000 fallback is used when derivation isn’t available (e.g. different function layout than Windows).

### Phase 3: Byte Verification

Every discovered offset is checked against expected original bytes at each patch site. This catches wrong build, already-patched binaries, or corruption. Offsets with variable expected bytes are tagged and verified by structure where needed.

### Phase 4: Injection Site Capacity

For injection sites (e.g. HighpassCutoffFilter, DcReject), the finder checks that there is enough space (e.g. int3 padding) after the function start for the patcher’s injected code. If the margin is negative, the build is reported as risky.

### ARM64 Discovery (macOS fat binary)

For Mach-O **fat** binaries (x86_64 + arm64), the finder runs a separate arm64 pipeline on the arm64 slice: symbol table resolution, function-based scans, and derivations where applicable. **EmulateBitrateModified** on arm64 is resolved via a scan for the 32-bit literal 32000 (0x00007D00) when derivation from EmulateStereoSuccess1 isn’t possible (e.g. different code layout). Success requires **17/17** for both x86_64 and arm64 when the arm64 slice is present.

---

## 📍 Offsets (source of truth)

The finder discovers a **fixed set of 17 patch offsets**, same for Windows, Linux, and macOS:

- **Anchors:** found by signatures or symbol table (e.g. CreateAudioFrameStereo, AudioEncoderOpusConfigSetChannels, MonoDownmixer, EmulateStereoSuccess1, SetsBitrateBitrateValue, …).
- **Derived:** anchor + delta (e.g. EmulateStereoSuccess2, Emulate48Khz, SetsBitrateBitwiseOr, AudioEncoderOpusConfigIsOk, EncoderConfigInit1/2, …).
- **Heuristic:** EmulateBitrateModified (imul/32000 on x86; literal 32000 on arm64 when derivation fails).

The exact names and derivation chain are in `discord_voice_node_offset_finder_v5.py` (`ALL_OFFSET_NAMES`, `DERIVATIONS`, `SIGNATURES`, `ARM64_SYMBOL_MAP`, etc.). The order matches **$Script:RequiredOffsetNames** in the Windows patcher and the **REQUIRED_OFFSET_NAMES** in the Linux patcher.

---

## 📝 Signature Reference

Each signature defines: **name** (patcher key), **pattern_hex** (space-separated hex, `??` = wildcard), **target_offset** (byte delta from match start to patch site), **description**, **expected_original** / **patch_bytes** (for verification and already-patched detection), and optional **disambiguator**. Config offset (RVA) = file offset + `file_offset_adjustment` (from section headers at runtime).

---

## 📐 PE / ELF / Mach-O Layout

- **Windows (PE):** Config offsets are effectively RVAs. `file_offset_adjustment` (e.g. 0xC00) is derived from .text (VA − raw_offset) and converts between file offset and the values stored in the patcher block.
- **Linux (ELF):** File offsets are used for patching; the finder outputs `OFFSET_*` and `FILE_OFFSET_ADJUSTMENT` for the shell patcher.
- **macOS (Mach-O):** For fat binaries, x86_64 and arm64 each have their own slice; the finder outputs file/fat offsets and optional `declare -A OFFSETS`-style blocks for the macOS patcher.

---

## 📤 Output Formats

### Console Output

Full diagnostic log with status markers: `[SYM]`, `[SCAN]`, `[OK]`, `[FAIL]`, `[HEUR]`, `[PASS]`, `[INFO]`, `[XVAL]`, etc. Success examples:

- Windows: **ALL 17 WINDOWS PATCHER OFFSETS FOUND**
- macOS: **ALL 17 x86_64 OFFSETS FOUND SUCCESSFULLY | arm64: 17/17**

### offsets.txt & JSON

- **offsets.txt** — Written to script dir, then binary dir, then CWD (first that succeeds). Contains patcher-ready blocks (Windows region block, or PowerShell-style table for non-PE) and file-offset comments. **Removed on script exit.**
- **&lt;input&gt;.offsets.json** — Machine-readable (tool version, file, size, MD5, format, offsets, resolution_tiers, arm64_offsets when applicable). **Removed on script exit.**

Copy any block you need from the console (or GUI) before the process exits.

### Patcher paste blocks

- **Windows:** Replace the entire `# region Offsets (PASTE HERE)` … `# endregion Offsets` section in `Discord_voice_node_patcher.ps1`. Block includes `$Script:OffsetsMeta` and `$Script:Offsets` (17 keys in patcher order). Copy between `--- BEGIN COPY (Windows) ---` and `--- END COPY ---`.
- **Linux:** Block for `discord_voice_patcher_linux.sh`: `EXPECTED_MD5`, `EXPECTED_SIZE`, `OFFSET_*=0xHEX`, `FILE_OFFSET_ADJUSTMENT=0`.
- **macOS:** Block for macOS patcher: `declare -A OFFSETS=( [Name]=0xHEX ... ); FILE_OFFSET_ADJUSTMENT=0` (fat file offsets for the x86_64 slice; arm64 table is printed separately when applicable).

---

## 🔎 Auto-Detection

**Windows:** If no file path is given, the script searches:

```
%LOCALAPPDATA%\Discord\app-*\modules\discord_voice*\discord_voice\discord_voice.node
```

and equivalent paths for DiscordCanary, DiscordPTB, DiscordDevelopment. It uses the latest `app-*` and first matching voice module.

**Linux / macOS:** Pass the path to `discord_voice.node` explicitly.

---

## 🚦 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All required offsets found (Windows: 17/17; macOS: 17/17 x86_64 and 17/17 arm64 when present) |
| `1` | Partial success (e.g. 15–16/17 or arm64 missing one) |
| `2` | Insufficient (too many missing for safe patching) |

Thresholds are in the script (e.g. partial when `total_x86 >= n_required - 2`).

---

## ➕ Adding a New Offset

1. **Decide** whether the new site can be **derived** (stable delta from an existing anchor) or needs a **new signature** or **scan** (e.g. literal scan).
2. **Derivation:** Add to `DERIVATIONS` with anchor name and delta (hex). **Signature:** Add a `Signature` with pattern, `target_offset`, expected bytes, and optional disambiguator. **ARM64:** Add to `ARM64_SYMBOL_MAP` / scan logic if needed.
3. **Validation:** Add expected original bytes (and patch bytes if used) to the expected-originals map used by Phase 3.
4. **Ordering:** Add the name to `ALL_OFFSET_NAMES` (and thus `WINDOWS_PATCHER_OFFSET_NAMES`) in the position that matches the patcher’s required order.
5. **Docs:** Update this README and script docstring if counts or behavior change.

---

## 🔄 Porting to a New Build

1. Run the finder on the new `discord_voice.node`. If 17/17 (and arm64 17/17 when applicable) → paste the new block(s) into the patcher(s).
2. **If a signature fails:** Inspect the new binary in a disassembler; adjust the pattern (wildcards, disambiguator) or add an alternate.
3. **If a derivation fails:** Re-measure the delta or promote the offset to a signature.
4. **If heuristic/literal scan fails:** Check that the constant (e.g. 32000) still appears and adjust the scan or fallback logic.
5. **If section layout changes:** The script reads adjustment from section headers; only change constants if the parser is wrong for the new build.
6. Test the patcher with the new offsets before distributing.

---

## ⚠️ Known Limitations

- **Single-build validation.** The tool verifies offsets for the given binary; it does not guarantee that the patcher’s patches remain semantically correct on a different build (code around the site may have changed).
- **No cross-reference analysis.** It doesn’t trace callers or data flow; offsets may resolve but patches might not have the intended effect if Discord restructures code.
- **No ASLR handling.** Work is in file offsets / RVAs; the patcher resolves base address at runtime.
- **Auto-detection is Windows-only.** Path search is Windows-only; given a path, the finder supports PE, ELF, and Mach-O.
- **Cross-validation warning.** On macOS, a delta mismatch between EmulateBitrateModified and EmulateStereoSuccess1 is expected when EmulateBitrateModified is found via the literal-32000 fallback (different function); it is harmless.
