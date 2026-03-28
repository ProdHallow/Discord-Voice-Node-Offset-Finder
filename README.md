# 🔍 Discord Voice Node Offset Finder

Automated discovery of patch sites inside Discord’s native voice module (`discord_voice.node`) for Windows (PE), Linux (ELF), and macOS (Mach-O, including universal fat binaries with x86_64 and arm64).

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square)
![Offsets](https://img.shields.io/badge/Patcher%20offsets-17-5865F2?style=flat-square)
![Formats](https://img.shields.io/badge/Binary%20formats-PE%20%7C%20ELF%20%7C%20Mach--O-00C853?style=flat-square)

**Finder script:** `discord_voice_node_offset_finder_v5.py` (v5.1)  
**Optional GUI:** `offset_finder_gui.py` (v1.1.1)

---

# ⚠️ ATTENTION!!! I WILL BE MERGING EVERY DISCORD AUDIO RELATED REPO TO [Discord Audio Collective](https://github.com/ProdHallow/Discord-Stereo-Windows-MacOS-Linux)
---

## 👥 Credits

**Research, signatures, and patch methodology:** ProdHallow, Cypher, Shaun, Oracle, Crue, Geeko  

**Python tooling and architecture:** substantial assistance from Claude (Anthropic) in earlier iterations; this tree continues to evolve with the maintainers.

**GUI:** Oracle, Shaun, Hallow, Ascend, Sentry, Sikimzo, Cypher, Crue, Geeko  

**Original offset discovery:** Cypher, Oracle, Shaun (among others above).

---

## 📑 Table of contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [GUI](#gui)
- [Discord Stereo Hub](#discord-stereo-hub)
- [How it works](#how-it-works)
- [Offsets (source of truth)](#offsets-source-of-truth)
- [Outputs](#outputs)
- [Auto-detection (Windows)](#auto-detection-windows)
- [Exit codes](#exit-codes)
- [Adding or porting offsets](#adding-or-porting-offsets)
- [Known limitations](#known-limitations)

---

## 📌 Overview

Discord ships `discord_voice.node` as a native module. Stereo patchers need **17 named locations** (same logical set on all platforms). Hard-coded file addresses break every build; this finder uses **byte signatures**, **symbol tables** (ELF / Mach-O), **fixed deltas from anchors**, and **targeted heuristics** (e.g. 32000 literals) to recover those locations for a given binary.

When Discord updates, run the finder on the new `discord_voice.node`. If resolution succeeds (17/17 for PE; 17/17 x86_64 and 17/17 arm64 when an arm64 slice exists), paste the generated block into the matching patcher.

---

## 📦 Requirements

- **Python 3.8+** (standard library only for core CLI; optional `networkx` + `matplotlib` for dependency graphs).
- **GUI:** `tkinter` (often `python3-tk` / full python.org installer on macOS).

---

## 🚀 Quick start

```bash
# Explicit path (all platforms)
python discord_voice_node_offset_finder_v5.py "C:\path\to\discord_voice.node"

# Windows: auto-pick latest discord_voice.node from local Discord installs (see below)
python discord_voice_node_offset_finder_v5.py
```

The CLI prints a full diagnostic log. It also writes **`offsets.txt`** and **`<binary>.offsets.json`** (and optionally **`offsets_graph.png`**) to disk during the run; those paths are registered and **removed on process exit** via `atexit`, so copy anything you need from the terminal (or use the GUI) before the process ends.

On Windows, when the script is run interactively (e.g. double-click), the console may wait for **Enter** before closing.

---

## 🖥️ GUI

Run from this directory:

```bash
python offset_finder_gui.py
```

- Loads **`discord_voice_node_offset_finder_v5.py`** from the same folder, or from **Discord Stereo Hub’s script cache** if the hub has synced the finder there (`%LOCALAPPDATA%\DiscordStereoHub\scripts` on Windows, `~/.cache/DiscordStereoHub/scripts` elsewhere).
- Dark-themed log; **Copy Output** / **Copy Block** for patcher paste regions.
- Toggles include **Verbose output** and **Save JSON offsets file** (writes `<file>.offsets.json` next to the scanned binary when enabled).
- Debug: set **`OFFSET_FINDER_DEBUG=1`** or pass **`--debug`** for a more verbose log on Windows.

---

## 🔗 Discord Stereo Hub

The **Stereo Hub** can download/sync the finder into its cache and launch **Offset Finder (experts)** from Advanced options. Keeping **`OFFSET FINDER/LATEST`** as the canonical copy and letting the hub refresh from your manifest/GitHub is the usual workflow.

---

## ⚙️ How it works

| Stage | Role |
|--------|------|
| **Format detection** | PE / ELF / Mach-O (fat); `.text`, `image_base`, adjustments. |
| **Phase 0 (ELF / Mach-O)** | Symbol resolution or narrowed scan hints where symbols exist. |
| **Phase 1** | Signature scan (primary → relaxed → clang/platform alternates); validation at match sites. |
| **Phase 1b / fallbacks** | Patched-binary fallbacks and stub-derived sites when patterns match. |
| **Phase 2** | Derivation: `DERIVATIONS` (anchor + delta), with sliding recovery when exact bytes differ. |
| **Phase 2b** | Heuristics (e.g. `EmulateBitrateModified` near anchors or full-text scan with distance caps). |
| **Validation** | Expected bytes, bounds, **duplicate RVA** detection (two names must not share the same config offset). |
| **Cross-validation** | Consistency checks on derived distances and encoder config literals (`_cross_validate`). |
| **ARM64 (fat Mach-O)** | Separate `discover_offsets_arm64` pipeline; literal-32000 fallback for `EmulateBitrateModified` when layout differs from x86_64. |
| **PE extras** | Optional bitrate audit in verbose mode (`run_bitrate_audit_pe`). |

Implementation details live in `discord_voice_node_offset_finder_v5.py` (`SIGNATURES`, `DERIVATIONS`, `ALL_OFFSET_NAMES`, `ARM64_SYMBOL_MAP`, etc.).

**Counting:** Patcher progress uses a **deduplicated** name list (`count_patcher_offsets_found`) so duplicate names in a list could never inflate “hits”; missing-offset errors are **deduplicated** per name after phases complete.

---

## 📍 Offsets (source of truth)

Seventeen names, same set as **`$Script:RequiredOffsetNames`** (Windows patcher) and Linux **`REQUIRED_OFFSET_NAMES`**. Order is defined by **`ALL_OFFSET_NAMES`** in the finder script.

---

## 📤 Outputs

| Artifact | Description |
|----------|-------------|
| **Console** | Marked lines: `[SYM]`, `[SCAN]`, `[OK]`, `[FAIL]`, `[HEUR]`, `[XVAL]`, etc. |
| **Windows block** | Between `--- BEGIN COPY (Windows) ---` and `--- END COPY ---`: replace `# region Offsets` … `# endregion Offsets` in `Discord_voice_node_patcher.ps1`. |
| **Linux block** | For `discord_voice_patcher_linux.sh`: fingerprints + `OFFSET_*` + `FILE_OFFSET_ADJUSTMENT`. |
| **macOS block** | `OFFSETS` / `ARM64_OFFSETS` associative arrays and `FILE_OFFSET_ADJUSTMENT` as emitted. |
| **JSON** | `<input>.offsets.json`: version, MD5, format, hex offsets, `resolution_tiers`, arm64 fields when present. |

CLI-generated `offsets.txt` / `.offsets.json` / graph files are deleted on exit unless you copy them first; the GUI can persist **JSON** (and related options) according to its checkboxes.

---

## 🔎 Auto-detection (Windows)

If no path is passed, the CLI searches under:

`%LOCALAPPDATA%\Discord\app-*\…` (and Canary / PTB / Development trees) for `discord_voice.node`, preferring the newest `app-*` build.

**Linux / macOS:** always pass the path to `discord_voice.node`.

---

## 🚦 Exit codes

| Code | Meaning (typical) |
|------|-------------------|
| **0** | PE: 17/17 patcher offsets. Non-PE: 17/17 x86_64 and arm64 complete when an arm64 slice is present. |
| **1** | Partial (e.g. most offsets found). |
| **2** | Too few offsets for safe patching. |

Exact thresholds are implemented in the script’s `main()` summary logic.

---

## 🔄 Adding or porting offsets

1. **New build fails:** Run the finder; note which names fail in Phase 1 / 2 / arm64.
2. **Adjust or add** a `Signature`, a `DERIVATIONS` edge, an ELF/Mach-O map entry, or an arm64 scan rule.
3. **Extend** expected-byte maps used for validation.
4. **Insert** the name into **`ALL_OFFSET_NAMES`** in the same order the patchers expect (keep Windows / Linux / macOS lists aligned).
5. **Re-run** on clean and patched binaries if you rely on fallbacks.

---

## ⚠️ Known limitations

- Validates **this** binary only; semantic safety on other builds is not guaranteed.
- No full program analysis (callers, CFG); wrong-but-matching patterns are still possible in theory.
- **ASLR** is handled by patchers at runtime; the finder works in file/RVA space.
- **Auto-discovery of install path** is Windows-only; other OSes need an explicit file path.
- **Cross-validation** may warn on macOS when `EmulateBitrateModified` comes from the arm64 literal-32000 path (different layout than Windows delta expectations); treat as context, not always a hard failure.

---

*Last README polish aligned with finder v5.1 and GUI v1.1.1 in this folder.*
