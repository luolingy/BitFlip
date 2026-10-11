# Rust crates for parsing binary file formats — license & capability survey

**Purpose:** input for BitFlip's decision on adding Mach-O (incl. fat/universal) and later APK/DEX.
**Hard constraints assumed:** single self-contained executable, zero runtime dependencies,
no GPL/LGPL/AGPL/SSPL. Acceptable: Apache-2.0, MIT, BSD, MPL-2.0, Zlib.

**Data sources:** crates.io API (`https://crates.io/api/v1/crates/<NAME>`), docs.rs API pages,
GitHub REST API + `raw.githubusercontent.com`. Every license/download/date below is a registry or
repository fact, not an inference.

**Verification rule:** anything I could not confirm is marked **[unverified]**. I did not build or
run any crate; capability claims come from each crate's documented public API surface.

---

## 0. Executive summary

| Decision | Crate | Why |
|---|---|---|
| **ADOPT for Mach-O (incl. fat) — WITH MITIGATION** | `object` 0.40.0 | Only crate that does thin + fat + code signature + dyld cache. Pure Rust, Apache-2.0 OR MIT. **BUT its README disclaims malware-analysis use — see §1.1.** |
| **OK for fat Mach-O, NOT signatures** | `goblin` 0.10.7 | MIT, pure Rust, `Mach::Fat(MultiArch)`. No code-signature or dyld-cache parsing. |
| **REJECT** | `lief` / `lief-rs` | License is fine (Apache-2.0), but it is C++ FFI and **downloads prebuilt binaries at build time**. |
| **REJECT (license)** | `exe`, `dotnetdll`, `smali` | **GPL-3.0** — infectious, forbidden. |
| **USE for APK** | `zip` 9.0.1 | MIT, pure Rust, repo is `zip-rs/zip2`. |
| **USE for Java .class** | `cafebabe` 0.9.0 | **0BSD** (no attribution burden), pure Rust. |
| **DEX = weak spot** | `dex` (MIT, frozen 2021) | No maintained permissive full DEX parser exists. |
| **.NET is NOT a dead end** | `dotscope` (Apache-2.0) | 259k LOC pure-Rust .NET RE framework — corrects my initial conclusion. |

**Three GPL landmines found.** `exe`, `dotnetdll`, and `smali` are all GPL-3.0 on *every* published
version. All three look like reasonable, well-targeted crates — the license is the only thing
wrong with them. They must be excluded.

**Two premises in the task brief were outdated and are corrected in this report:**
- **`xz2`/liblzma is NOT LGPL** — liblzma is **0BSD**; the LGPL lives only in GNU `getopt_long`,
  which is not compiled. Objection to `xz2` is staleness, not licensing. (§5.2)
- **`symbolic-debuginfo` never moved or forked** — still `getsentry`, still MIT, still shipping in 2026. (§5.4)

---

## 1. General multi-format parsers

### 1.1 `object` (gimli-rs/object) — RECOMMENDED

| Field | Value |
|---|---|
| License | **Apache-2.0 OR MIT** (dual) |
| Pure Rust | **Yes** — no FFI |
| Downloads | 650,319,172 total / 120,660,931 recent |
| Latest | **0.40.0** (published 2026-08-01; docs.rs build dated 2026-10-08) |
| Repo | https://github.com/gimli-rs/object |
| Code size | 47,779 Rust LOC, 96 files |
| MSRV | 1.85, edition 2024 |

**Verdict: ACCEPTABLE — USE IT, with a documented adversarial-input mitigation.**

> ⚠️ **SECURITY CAVEAT — read before adopting.** `object`'s own README
> (https://raw.githubusercontent.com/gimli-rs/object/master/README.md) states verbatim:
>
> > "This crate is intended to be used with trusted inputs. For example, it is suitable for use as
> > part of a compiler toolchain, **but not for malware analysis or a service exposed to arbitrary
> > inputs.**"
> >
> > "There is little effort to mitigate denial of service attacks (such as algorithmic complexity
> > attacks due to overlapping structures)."
> >
> > "The crate does not aim to replicate the behaviour of platform loaders such as the Windows
> > loader or dynamic linkers. Data returned by the parser may not match the data used by a loader."
>
> **BitFlip parses arbitrary untrusted binaries, which is exactly the stated non-use-case.** The
> license is fine; the *threat model* is not. This is the most important finding in this report.
>
> Two mitigations, both consistent with CLAUDE.md §7 ("拿不到就说拿不到"):
> 1. **Adopt `object` but wrap every parse in explicit resource limits** — wall-clock timeout,
>    allocation cap, and a bounded section/relocation/predecessor count. Treat a limit hit as an
>    explicit degraded result surfaced to the user, never as a silent empty success.
> 2. **Keep `goblin` on the adversarial path** — it is the crate already battle-tested against
>    hostile input by the broader RE ecosystem, and route to `object` only where goblin is blind
>    (fat Mach-O, code signatures, dyld cache).
>
> Note also the loader-fidelity disclaimer: `object` explicitly does NOT promise that parsed data
> matches what a real loader would do. For a tool whose stated principle is "说的就是真的", any
> on-disk-vs-loaded divergence must be a labelled finding, not an implicit assumption.

Features relevant to BitFlip (from https://docs.rs/object/latest/object/read/macho/index.html):
- `MachOFile` / `MachOFile32` / `MachOFile64`, implementing the unified `Object` trait.
- **`MachOFatFile`** (32/64 aliases), `FatHeader`, `FatArch32`/`FatArch64` + the `FatArch` trait.
- **`CodeSignature`**, `CodeDirectory`, `CodeSignatureBlob`, `CodeSignatureBlobIterator`.
- Entitlements constants exist: `CSMAGIC_EMBEDDED_ENTITLEMENTS`, `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS`,
  `CSSLOT_ENTITLEMENTS`, `CSSLOT_DER_ENTITLEMENTS`, `CsBlobIndex` — so entitlement *location* is
  modelled. Whether a high-level entitlement-decoding helper exists is **[unverified]**.
- **`DyldCache`** + `DyldCacheImage`, `DyldCacheMapping`, `DyldCacheSlideInfo`,
  `DyldCacheRelocationIterator`, `DyldChainedFixups`.

Version history (from the repo CHANGELOG, reported by a subagent):
- dyld cache added **0.25.0**; split cache **0.28.0**; dyld API reworked **0.37.0**.
- **`MachOFatFile` introduced in 0.32.0** — it replaced `FatHeader::parse_arch32/64`, which were *removed*.
  I independently confirmed `MachOFatFile` is **absent** from 0.28.4 (2022) docs and **present** in 0.40.0.

**Feature-gating note:** `default = ["read","compression"]`, so `flate2` + `ruzstd` come in by default.
A read-only consumer can use `default-features = false, features = ["read","std","macho"]`.
`wasmparser` is only pulled in by the `wasm` feature; `crc32fast`/`indexmap`/`hashbrown` are write-side.

### 1.2 `goblin` (m4b/goblin) — already in use via adi

| Field | Value |
|---|---|
| License | **MIT** |
| Pure Rust | Yes (depends on `scroll`, `plain`) |
| Downloads | 77,880,458 total / 18,786,313 recent |
| Latest | **0.10.7** (2026-05-28, edition 2024, MSRV 1.85) |
| Repo | https://github.com/m4b/goblin |
| Code size | 23,003 Rust LOC |

**Verdict: ACCEPTABLE — USE IT (for thin + fat Mach-O; do not rely on it for code signatures).**

Confirmed from docs.rs (https://docs.rs/goblin/latest/goblin/mach/enum.Mach.html):
```
pub enum Mach<'a> {
    Fat(MultiArch<'a>),   // "A 'fat' multi-architecture binary container"
    Binary(MachO<'a>),
}
```
plus `goblin::mach::fat` exposing `FatHeader`, `FatArch`, and `FAT_MAGIC` / `FAT_CIGAM`,
`SIZEOF_FAT_HEADER`, `SIZEOF_FAT_ARCH`.

**Limits (verified by a subagent reading `src/mach/load_command.rs`):** `LC_CODE_SIGNATURE` exists
only as a load-command variant carrying the blob's offset/size. A grep for `entitle`, `superblob`,
`CodeDirectory`, `CSMAGIC` returned **zero matches**. No dyld-cache module. So goblin tells you
*where* a signature is, not *what is in it*.

⚠️ **Pin 0.10.7, not 0.10.6** — 0.10.6 was yanked on 2026-05-28 and replaced by 0.10.7.

### 1.3 `lief` / `lief-rs` — REJECT (engineering, not license)

**The license question resolves favourably.** I verified three independent ways:
- GitHub license API: `https://api.github.com/repos/lief-project/LIEF/license` → `spdx_id: "Apache-2.0"`.
- `raw.githubusercontent.com/lief-project/LIEF/main/LICENSE` → full Apache-2.0 text, "Copyright 2017-2026
  R. Thomas / Quarkslab".
- crates.io: `lief` 1.0.0 and `lief-ffi` 1.0.0 both `"license":"Apache-2.0"`.

Its vendored third-party set is also all permissive: mbedtls (Apache-2.0), nlohmann/json (MIT),
spdlog (MIT), Catch2 (BSL-1.0), expected (CC0), frozen (Apache-2.0), utfcpp (BSL-1.0).
`src/third-party/` contains exactly one file. **No GPL anywhere. License verdict: ACCEPTABLE.**

**It fails anyway, on two hard engineering grounds:**

1. **Not pure Rust — C++ behind a `cxx` FFI bridge.**
   `lief` 1.0.0 dependencies: `bitflags`, **`cxx =1.0.197`**, **`lief-ffi`**, `num-bigint`,
   `num-derive`, `num-traits`.
   `lief-ffi` 1.0.0 dependencies: **`cxx`**, **`lief-build`** (build-dep), `miette`.
   `lief-ffi` itself is a thin shim — crates.io line counts are 5–26 Rust LOC across 2 files.
   The "162,033 Rust LOC" on the `lief` crate page is generated binding code.

2. **Build-time network download of prebuilt binaries** — the real blocker.
   Per the official docs (https://lief.re/doc/latest/api/rust/index.html):
   > "`lief-build`: build-script helper used by `lief-ffi` to fetch the pre-compiled artifacts and
   > emit the `cargo` link directives."
   > "LIEF provides pre-compiled versions of these artifacts, which are downloaded from GitHub
   > (for releases) or an S3 bucket (for nightly builds)."
   Artifacts are `libLIEF.a` + `lief-sys.a`. The escape hatch is `LIEF_RUST_PRECOMPILED`, which
   requires building LIEF yourself (`cmake -DLIEF_RUST_API=ON`) *and* generating the C++ cxx bridge
   with `lief-ffigen`. The docs say "Both steps can take several minutes."

   **Corroborating evidence:** docs.rs shows **"docs.rs failed to build lief-1.0.0"**, and the same
   for 0.17.6, 0.17.5, … back to 0.15.0 — *every version*. LIEF's own docs confirm the cause is
   network restrictions (https://github.com/rust-lang/docs.rs/issues/2563).

**Verdict: DON'T USE.** For a reproducible, self-contained, single-executable build, a dependency
that fetches opaque prebuilt C++ binaries at compile time is disqualifying regardless of license.
Downloads are tiny anyway: 37,549 (`lief`), 34,638 (`lief-ffi`).

### 1.4 PE / ELF single-format crates

| Crate | License | Verdict | Notes |
|---|---|---|---|
| `exe` | **GPL-3.0** | **DON'T — GPL BLOCKER** | GPL-3.0 on every version incl. 0.5.7 (2026-04-19). 6,068 LOC. Exclude. |
| `pelite` | MIT | Optional | 911,481 dl, but **frozen 2022-11-04** (0.10.0). "zero-allocation, memory-safe PE". |
| `pe-parser` | MIT | DON'T | Only 969 LOC, `clap` is a *default* feature; a pretty-printer CLI, not a library. 30,669 dl. |
| `elf` (cole14/rust-elf) | **MIT/Apache-2.0** | Optional | 12,782,896 dl, 0.8.0 (2025-05-14), 8,579 LOC, MSRV 1.81. Pure Rust, `no_std`-capable. |
| `xmas-elf` | **Apache-2.0 OR MIT** | Optional | 3,128,428 dl, 0.10.0 (2025-03-26), 1,883 LOC. Zero-allocation, `no_std`. |
| `rabinkarp` | — | **DOES NOT EXIST** | crates.io 404. |

**Strategic note:** BitFlip already has hand-written PE/COFF/ELF parsers. Adopting `object` for
Mach-O does **not** oblige you to replace those — `object` can be introduced for the Mach-O path
alone. If you later want one unified backend, `object` covers PE (incl. COFF), ELF, Mach-O, XCOFF,
and WASM behind one trait.

---

## 2. Mach-O specifics

### 2.1 Fat / universal Mach-O

| Crate | Fat support | API |
|---|---|---|
| **`object` 0.40.0** | **YES** | `MachOFatFile` / `MachOFatFile32` / `MachOFatFile64` (`parse`, `header`, `arches`); `macho::FatHeader`; `FatArch` trait. **Introduced 0.32.0**; the old `FatHeader::parse_arch32/64` were removed. |
| **`goblin` 0.10.7** | **YES** | `mach::Mach::Fat(MultiArch)`; `mach::fat::{FatHeader, FatArch, FAT_MAGIC, FAT_CIGAM}`. Exact version that added it: **[unverified]**. |
| `mach_object` | [unverified] | 0.1.17, Apache-2.0, **frozen 2022-06-18**, 336,409 dl. |
| `macho` (richo/macho-rs) | [unverified] | 0.4.1, MIT, **last release 2016-08-19** — dead. |
| `macho2` / `schnauzer` | [unverified] | 2025-04-13 / 2023-09-13; tiny adoption. Names found by subagent. |

**Direct answer to "Can `object` handle Mach-O fat binaries? Which version?"** — **Yes, since 0.32.0**
via `MachOFatFile`, which replaced an older `FatHeader::parse_arch32/64` API. Use ≥ 0.32.0; 0.40.0 is current.

### 2.2 Code signatures, entitlements, dyld shared cache

| Capability | `object` | `goblin` | `apple-codesign` |
|---|---|---|---|
| `LC_CODE_SIGNATURE` superblob | **yes** (`CodeSignature`) | location only | yes |
| CodeDirectory | **yes** (`CodeDirectory`) | no | yes |
| Entitlements | constants present; decode helper **[unverified]** | no | yes |
| dyld shared cache | **yes** (`DyldCache`) | no | no |

**`apple-codesign` (indygreg/apple-platform-rs)**

| Field | Value |
|---|---|
| License | **MPL-2.0** (confirmed in crates.io *and* repo LICENSE) |
| Pure Rust | **Yes** — "Pure Rust interface to code signing on Apple platforms" |
| Downloads | 1,092,507 total / 252,675 recent |
| Latest | 0.29.0, **2024-11-29** (≈2 years stale) |
| Ships | `rcodesign` binary; 21,025 Rust LOC |

**Verdict: ACCEPTABLE (MPL-2.0 is on your allowed list) — but NEEDS INVESTIGATION before use.**
MPL-2.0 is *file-level* copyleft: linking into a larger work is permitted, but modifications to
apple-codesign's own files must be published. As an unmodified dependency this is fine. Flag it
for a conscious licensing decision; the staleness (2024-11-29) is the other concern.

**Name traps (important):**
- **`codesign`** is a **Microsoft/Authenticode** crate, *not* Apple. Do not be misled by the name.
- **`mach-o` does not exist.** `mach_o` (underscore) exists but is a macOS-only FFI binding to
  Apple's system library — useless cross-platform. `mach_o_sys` is likewise FFI.
- **`security-framework`** is FFI to Apple's Security.framework, macOS/iOS-only. Not applicable.
- These do **not** exist: `dyld-cache`, `dyld-shared-cache`, `dyld_shared_cache`, `machofile`,
  `macholibre`, `mach-o-parser`, `mach_object_dwarf`, `dsc_extractor`.

**Other dyld-cache parsers:** `dylex` (MIT, 2026-10-04, but only 443 downloads — immature),
`macho-dyld-cache` (MIT, created 2026-07-25, ~247 downloads — unproven), `dyld-trie` (MIT/Apache,
only parses export tries). **`ipsw` (blacktop) is Go and has no Rust port** — confirmed from its
`go.mod` (`module github.com/blacktop/ipsw`).

---

## 3. DEX / Android

### 3.1 DEX — the weak spot

**Answer to "Is there a maintained pure-Rust DEX parser?" — No, not a fully satisfying one.**

| Crate | License | Pure Rust | Downloads | Last release | Verdict |
|---|---|---|---|---|---|
| `dex` | **MIT** | yes | 35,605 | **2021-05-31** (0.5.0) | **Best available** — 3,051 LOC, real parser, repo `letmutx/dex-parser`. Frozen ~5 yrs. |
| `dalvik` | **MIT OR Apache-2.0** | yes | 7,146 | **2024-05-29** (0.2.0) | **USE** — but it is a *disassembler*, not a container parser. 2,285 LOC. |
| `dexparser` | MIT | yes | 4,779 | 2021-03-24 (0.6.2) | Stale. NEEDS INVESTIGATION. |
| `smali` | **GPL-3.0-only** | yes | 4,983 | 2026-08-05 (0.6.2) | **DON'T — GPL BLOCKER.** |
| `android-dex` | MIT | — | 530 | 2025-07-09 (0.0.0) | **DON'T** — `code_lines: 0`, no repo. Placeholder squat. |
| `dvm` | MIT | — | 48,400 | 2026-10-07 | **DON'T** — **name trap**: "Deno Version Manager". |

**Not existing (404):** `dex-parser`, `dex-parser-rs`, `dex_parser`, `dexlib`.
**Unverified:** 2026 newcomers `dex-parser-rust`, `dexvm`, `droidsaw`, `droidsaw-dex` (tiny download
counts, licenses not confirmed). `r8` Rust bindings: not found (absence ≠ proof).
**Note:** crates.io `q=dex` returns 1,732 hits, overwhelmingly crypto/DEX-*exchange* crates — irrelevant.

**Recommendation: DON'T start DEX yet.** If DEX is needed, budget for either adopting the frozen
`dex` (MIT) and maintaining it yourself, or hand-writing a DEX reader — DEX's header/string/type/
proto/field/method/class tables are well-specified and no harder than what you already do for PE.

### 3.2 APK / ZIP — good shape

| Crate | License | Downloads | Last release | Verdict |
|---|---|---|---|---|
| **`zip` 9.0.1** | **MIT** | 295,981,864 | 2026-10-10 | **USE IT.** |
| `rc-zip` 5.4.1 | Apache-2.0 OR MIT | 2.11M | 2025-11-19 | USE |
| `rc-zip-sync` 4.4.2 | Apache-2.0 OR MIT | 1.86M | 2025-11-27 | USE |
| `rawzip` 0.5.2 | MIT | 566k | 2026-10-04 | Strong candidate; `no_std`-capable |
| `async_zip` 0.0.19 | MIT | 7.19M | 2026-08-22 | Only if async |
| `zip_next` | — | — | 2024 | **DON'T** — dead 2-line wrapper; its own text says use `zip`. |

**Your premise is CONFIRMED:** `zip` 9.0.1 reports `"license":"MIT"` and its `repository` field points
at **`github.com/zip-rs/zip2`**, corroborated by `trustpub_data: {provider:"github", repository:"zip-rs/zip2"}`.
**`zip2` does not exist as a crate** (404) — `zip2` is only the *repo* name; the crate is `zip`.
`zip`'s default DEFLATE backend is **zlib-rs (pure Rust)**, not C zlib.

---

## 4. Java class files (JAR/JVM)

| Crate | License | Downloads | Last release | Verdict |
|---|---|---|---|---|
| **`cafebabe` 0.9.0** | **0BSD** | 61,451 | 2025-06-03 | **BEST PICK** — 4,566 LOC; 0BSD imposes no attribution. |
| `classfile-parser` 0.3.8 | MIT | 31,447 | 2024-10-10 | USE — solid alternative. |
| `classfile` | MIT | 3,664 | 2026-09-24 | NEEDS INVESTIGATION — very new. |
| `jclass` | Apache-2.0 | 3,752 | 2025-05-28 | NEEDS INVESTIGATION — 0.1.x, parse+edit. |
| `jvm-class` | MIT | 94 | — | **DON'T** — explicitly limited to class major versions 45–52 (Java 1.1–8); fails modern files. |
| `bytecode` | MIT | 5,481 | 2022 | DON'T — only 297 LOC, too thin. |

**Not existing (404):** `java-class`, `jasmin`.
**Caveat (applies to all rows):** "parses .class files" reflects each crate's own description; no
crate was built or executed in this research. `cafebabe` being 0BSD is verified from crates.io metadata.

---

## 5. Other formats a RE tool would want

### 5.1 Compiled / bytecode formats

| Format | Crate | License | Downloads | Last release | Verdict |
|---|---|---|---|---|---|
| WASM | `wasmparser` | **Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT** | 258,396,111 | 0.261.0 (2026-10-02) | **USE** — the reference implementation; exception is permissive-compatible. |
| DWARF | **`gimli` 0.34.0** | **MIT OR Apache-2.0** | 592,733,555 | 2026-06-25 | **USE** — 42,307 LOC, MSRV 1.88, edition 2024. |
| .NET/CIL | `dotnetdll` | **GPL-3.0+** | 12,416 | 2026-06-24 (0.3.0) | **DON'T — GPL BLOCKER.** |
| PDB | `pdb` (willglynn) | MIT OR Apache-2.0 | 6,941,620 | 0.8.0 (**2022-06-08**) | Optional — 8,993 LOC, pure Rust, but stale. |
| UEFI | `uefi` (rust-osdev) | MIT OR Apache-2.0 | 2,598,789 | 0.41.0 (2026-09-21) | Optional — 23,347 LOC; firmware/PE-COFF UEFI images. |

**.NET — my earlier "dead end" conclusion was WRONG; there is a permissive stack.** `dotnetdll` is
GPL-3.0+ and must be avoided, but it is **not** the only option. A subagent found four permissive
alternatives, and I verified the strongest myself:

| Crate | License | Downloads | Latest | Notes |
|---|---|---|---|---|
| **`dotscope`** | **Apache-2.0** (verified; also `trustpub_data` → github `ATRAPSLLC/dotscope`) | 17,905 | 0.9.1 (2026-09-05) | **259,352 Rust LOC**, 902 files, MSRV 1.95. "high-performance, cross-platform framework for analyzing and reverse engineering .NET PE executables". Features include deobfuscation, x86 emulation, legacy crypto (DES/MD5/SHA1 for .NET obfuscator strings). |
| `clrmeta` | MIT | — | — | [unverified] |
| `cildec` | MIT | — | — | "zero-dependency, panic-free" [unverified] |
| `dnfile` (Rust port) | Apache-2.0 | — | — | repo `marirs/dnfile-rs`. [unverified] |

Note `dotscope` default features pull in `iced-x86` + emulation; a read-only metadata consumer should
disable defaults. Also `smart-rename` pulls `mistralrs`/`tokio` — keep that OFF. **API stability and
format coverage for all four are [unverified]** — metadata only, source not reviewed.

**Correction to the task brief's premise:** `dnfile` **does** exist as a Rust crate (Apache-2.0).
Python `dnfile` is MIT; Python `dncil` is Apache-2.0 (Mandiant) with no Rust counterpart.

**WASM note:** `wasmparser`'s `Apache-2.0 WITH LLVM-exception` is a *permissive* exception (it exists
to remove the Apache patent-retaliation concern for LLVM-style projects); it is compatible with a
proprietary binary. `walrus` (WASM transformation) and the rest of `wasm-tools` share this license family.

### 5.2 Compression (for compressed sections/embedded archives)

| Crate | License | FFI? | Downloads | Last release | Verdict |
|---|---|---|---|---|---|
| `flate2` | MIT/Apache-2.0 | **No** (default `rust_backend` = `miniz_oxide`) | ~740M | active | USE |
| **`ruzstd`** | **MIT** | **No — pure Rust** | 70,893,096 | 0.9.0 (2026-07-26) | **USE** — pure-Rust zstd *decoder*; replaces FFI `zstd` for reading. |
| **`bzip2` 0.6.1** | MIT OR Apache-2.0 | **No as of 0.6.x** | 176,054,361 | 2025-10-16 | **USE** — default feature is now `dep:libbz2-rs-sys` (**pure Rust**); C `bzip2-sys` is opt-in. |
| `zstd` | BSD-3-Clause | **Yes** (C libzstd) | 419M | 2026-10-10 | Permissive but FFI; prefer `ruzstd` for decode. |
| `xz2` | MIT/Apache-2.0 | **Yes** (C liblzma) | 70,327,219 | 0.1.7 (**2022-06-06**) | DON'T — but for *staleness*, **not** licensing. See note. |

**CORRECTION — `xz2`/liblzma is NOT an LGPL risk.** This is a widely repeated but outdated concern.
I fetched the official XZ Utils `COPYING` (https://raw.githubusercontent.com/tukaani-project/xz/master/COPYING),
which states verbatim:
> "- liblzma is under the BSD Zero Clause License (0BSD)."
> "The command line tools xz, xzdec, lzmadec, and lzmainfo are under 0BSD except that, on systems
> that don't have a usable getopt_long, GNU getopt_long is compiled and linked in from the 'lib'
> directory. The getopt_long code is under GNU LGPLv2.1+."

The LGPL exists **only in GNU `getopt_long`**, which is not part of liblzma and is not compiled by
`lzma-sys` (it builds the library, not the CLI tools). The `xz2`/`lzma-sys` crates' own license is
`MIT/Apache-2.0`. Older pins (e.g. xz-5.2) said "liblzma is in the public domain" — same conclusion.
**So the only objection to `xz2` is that it wraps C and has been frozen since 2022.** For
decompression, prefer pure-Rust `lzma-rs` (MIT).

**Verified correction worth noting:** `bzip2` is **no longer FFI-only**. crates.io shows
`"features":{"bzip2-sys":["dep:bzip2-sys"],"default":["dep:libbz2-rs-sys"],...}` — the *default* is
the pure-Rust implementation. This was a common assumption that is now outdated.

**On "FFI vs. zero runtime dependencies":** FFI to a C library is not automatically disqualifying —
`zstd-sys`/`lzma-sys` with `static`/`vendored` compile the C *into* your artifact, so you still ship
one static executable with no runtime `.dll`. The real costs are a C compiler at **build** time,
longer builds, a larger binary, and a weaker pure-Rust audit story. With `ruzstd` + `bzip2` 0.6 +
`flate2` defaults, a **100% pure-Rust** stack is now achievable, which is the better answer.

### 5.3 Archives / misc

`ar` (MIT, pure Rust, 9.99M dl), `msi` (MIT, 5.96M dl, 2026-02-23), `cab` (MIT, 7.03M dl) — all
pure Rust, all USE. `decompression` is **404** (it is a keyword, not a crate).
Note: `ar` **is** the `rust-ar` project (repo `mdsteele/rust-ar`), but the crate name `rust-ar`
does not exist — the crate is `ar`.

### 5.4 Additional corrections to premises in the task brief

| Claim to check | Verified result |
|---|---|
| `symbolic-debuginfo` code moved / was forked | **False.** Still `getsentry/symbolic`, still **MIT**, still actively released — **13.9.0 on 2026-07-09**, and 14.0.0-alpha.3 on 2026-07-23 (2,252,830 dl, 12,556 LOC). No fork. |
| `pdb` is `microsoft/pdb` and MIT | **Both wrong.** The crate `pdb` is **`willglynn/pdb`**, license **MIT OR Apache-2.0**, frozen at 0.8.0 (2022-06-08). Microsoft's repo publishes a *different* crate, `ms-pdb` (MIT), whose README self-describes as "NOT AUTHORITATIVE... NOT A REFERENCE IMPLEMENTATION". |
| `bzip2` is BSD-4-Clause-like | **Avoidable.** libbz2's Julian Seward licence is four-clause but its condition 2 is *not* an advertising clause. Moot anyway: `bzip2` 0.6.x defaults to the pure-Rust `libbz2-rs-sys`. |
| `wasmtime` Apache-2.0 WITH LLVM-exception | **Confirmed and compatible** — the exception only *relaxes* Apache-2.0 §3/§9 obligations. But it is a JIT, not a parser; it depends on `wasmparser`. Use `wasmparser` directly. |
| `zstd` license | crates.io says **BSD-3-Clause**; the C library's own LICENSE is MIT. Both permissive — they disagree, but it doesn't matter. |
| `fdt` license | **[unverified]** reported as MPL-2.0 rather than MIT/Apache. MPL-2.0 is on your allowed list as an unmodified dependency. MIT alternatives: `device_tree_parser`, `deforest`. |
| `unicode-ident` license | Reported as `(MIT OR Apache-2.0) AND Unicode-3.0` — note the **AND**: both must be satisfied. Permissive, but list it explicitly in any license inventory. |
| `zerocopy` version | Reported `max_version` = **0.9.0-alpha.0** — pin explicitly so a resolver cannot select an alpha. |
| `cxxbridge` | Reported **yanked** (2019). Use `cxx` / `cxxbridge-cmd`. |
| `nes`, `sm4`, `nso`, `nca`, `assets`, `fit`, `dvm` | **All name traps.** Respectively: an error-handling library, Chinese SM4 crypto, Nintendo Switch **Online** API, pharmacokinetics, a generic asset manager, sports-device FIT (not U-Boot FIT), Deno Version Manager. |

**Crates confirmed NOT to exist (404):** `rabinkarp`, `pe-parser` exists but `ecma335`, `rust-ar`,
`java-class`, `jasmin`, `dex-parser`, `dexlib`, `dex_parser`, `dex-parser-rs`, `zip2`, `mach-o`,
`dyld-cache`, `dyld-shared-cache`, `dyld_shared_cache`, `machofile`, `macholibre`, `mach-o-parser`,
`mach_object_dwarf`, `dsc_extractor`, `decompression`, `android-dex`(exists, empty), `uboot`,
`uefi-firmware`, `gcn`, `nintendo`, `nintendo-rom`, `rp2a03`, `unity-asset-parser`, `debuginfo`.
For U-Boot's uImage header (`IH_MAGIC 0x27051956`) **no crate exists — it must be hand-written.**

> ⚠️ A subagent reported these 404s and other details from `raw.githubusercontent.com` fetches I did
> not individually re-verify; they are marked as reported rather than confirmed where I did not
> personally re-fetch them. The three items I *did* re-verify myself (the `object` README warning,
> the XZ `COPYING` text, and `dotscope`/`symbolic-debuginfo` crates.io metadata) are quoted verbatim above.

---

## 6. Consolidated verdict table

| Crate | License | Verdict | FFI? | Downloads | Last release |
|---|---|---|---|---|---|
| `object` | Apache-2.0 OR MIT | **ACCEPTABLE — USE** | pure Rust | 650,319,172 | 0.40.0 / 2026-08-01 |
| `goblin` | MIT | **ACCEPTABLE — USE** | pure Rust | 77,880,458 | 0.10.7 / 2026-05-28 |
| `lief` / `lief-ffi` | Apache-2.0 | **ACCEPTABLE LICENSE, DON'T USE** | **C++ FFI + build-time download** | 37,549 | 1.0.0 / 2026-07-12 |
| `exe` | **GPL-3.0** | **UNACCEPTABLE** | pure Rust | ~40k | 0.5.7 / 2026-04-19 |
| `dotnetdll` | **GPL-3.0+** | **UNACCEPTABLE** | pure Rust | 12,416 | 0.3.0 / 2026-06-24 |
| `smali` | **GPL-3.0-only** | **UNACCEPTABLE** | pure Rust | 4,983 | 0.6.2 / 2026-08-05 |
| `pelite` | MIT | ACCEPTABLE | pure Rust | 911,481 | 0.10.0 / 2022-11-04 |
| `elf` | MIT/Apache-2.0 | ACCEPTABLE | pure Rust | 12,782,896 | 0.8.0 / 2025-05-14 |
| `xmas-elf` | Apache-2.0 OR MIT | ACCEPTABLE | pure Rust | 3,128,428 | 0.10.0 / 2025-03-26 |
| `pe-parser` | MIT | ACCEPTABLE, low value | pure Rust | 30,669 | 0.7.0 / 2025-03-12 |
| `apple-codesign` | **MPL-2.0** | ACCEPTABLE — NEEDS INVESTIGATION | pure Rust | 1,092,507 | 0.29.0 / 2024-11-29 |
| `dex` | MIT | ACCEPTABLE — frozen | pure Rust | 35,605 | 0.5.0 / 2021-05-31 |
| `dalvik` | MIT OR Apache-2.0 | ACCEPTABLE | pure Rust | 7,146 | 0.2.0 / 2024-05-29 |
| `zip` | MIT | **ACCEPTABLE — USE** | pure Rust | 295,981,864 | 9.0.1 / 2026-10-10 |
| `rc-zip` | Apache-2.0 OR MIT | ACCEPTABLE | pure Rust | 2.11M | 5.4.1 / 2025-11-19 |
| `rawzip` | MIT | ACCEPTABLE | pure Rust | 566,543 | 0.5.2 / 2026-10-04 |
| `cafebabe` | **0BSD** | **ACCEPTABLE — USE** | pure Rust | 61,451 | 0.9.0 / 2025-06-03 |
| `classfile-parser` | MIT | ACCEPTABLE | pure Rust | 31,447 | 0.3.8 / 2024-10-10 |
| `gimli` | MIT OR Apache-2.0 | ACCEPTABLE — USE | pure Rust | 592,733,555 | 0.34.0 / 2026-06-25 |
| `wasmparser` | Apache-2.0 WITH LLVM-exception OR … | ACCEPTABLE — USE | pure Rust | 258,396,111 | 0.261.0 / 2026-10-02 |
| `pdb` | MIT OR Apache-2.0 | ACCEPTABLE — stale | pure Rust | 6,941,620 | 0.8.0 / 2022-06-08 |
| `uefi` | MIT OR Apache-2.0 | ACCEPTABLE | pure Rust | 2,598,789 | 0.41.0 / 2026-09-21 |
| `ruzstd` | MIT | ACCEPTABLE — USE | **pure Rust** | 70,893,096 | 0.9.0 / 2026-07-26 |
| `bzip2` | MIT OR Apache-2.0 | ACCEPTABLE — USE | pure Rust (0.6+) | 176,054,361 | 0.6.1 / 2025-10-16 |
| `flate2` | MIT/Apache-2.0 | ACCEPTABLE — USE | pure Rust (default) | ~740M | active |
| `zstd` | BSD-3-Clause | ACCEPTABLE but FFI | C via FFI | 419M | 2026-10-10 |
| `xz2` | MIT/Apache-2.0 | DON'T | C via FFI | 70,327,219 | 0.1.7 / 2022-06-06 |
| `mach_object` | Apache-2.0 | ACCEPTABLE — stale | pure Rust | 336,409 | 0.1.17 / 2022-06-18 |

**No crate in this survey had a missing or ambiguous license field** — every existing crate reported
an explicit SPDX identifier, so there is no "unknown license → NEEDS_REVIEW" item.

---

## 7. Explicitly unverified

1. Whether `object` provides a high-level *entitlements decoder* — only the constants
   (`CSMAGIC_EMBEDDED_ENTITLEMENTS`, `CSSLOT_*`, `CsBlobIndex`) were confirmed.
2. The exact `goblin` release that introduced `MultiArch` / `Mach::Fat`.
3. Fat-Mach-O support in `mach_object`, `macho`, `macho2`, `schnauzer` — source not read.
4. Fine-grained parse coverage of `apple-codesign` — inferred from its description and metadata.
5. Licenses of 2026 DEX newcomers (`dex-parser-rust`, `dexvm`, `droidsaw`, `droidsaw-dex`).
6. Whether `object` 0.40.0's `DyldCache` handles every dyld generation (the CHANGELOG notes
   updates to `DyldCacheHeader` for dyld-1340 in 0.40.0, implying version-tracking churn).
7. Last-commit dates / issue counts for every crate — only *release* recency was measured.
   "Maintenance" statements in this report are inferred from release recency, which is a proxy.
8. API stability and format coverage of the .NET alternatives (`clrmeta`, `cildec`, `dnfile-rs`) —
   metadata only, source not reviewed. `dotscope`'s license and size are confirmed; its *behaviour*
   is not.
9. The 404 status of the ~30 non-existent crates listed in §5.4, and the name-trap explanations —
   reported from a subagent's fetches, not individually re-verified by me (except where noted).
10. `fdt`'s MPL-2.0 license — reported, not personally re-fetched.
11. **No crate was built, executed, fuzz-tested, or benchmarked.** All capability claims are
    documentation-based. In particular, no claim here should be read as evidence that a crate
    *correctly* parses hostile input.
12. The `object` adversarial-input caveat is quoted verbatim from its README, but the *practical
    severity* for BitFlip's specific input mix is unmeasured — the mitigation design in §8 is the
    responsible default, not a quantified requirement.

---

## 8. Recommended action for BitFlip

1. **Add `object` 0.40.0 for Mach-O** (`default-features = false, features = ["read","std","macho"]`).
   It covers thin + fat + code signature + dyld cache in one pure-Rust, MIT/Apache dependency.
   This directly satisfies the "ADD Mach-O including fat/universal" requirement.
   **→ Gate this on a decision about adversarial input** (see item 2). Do not adopt `object` as the
   *only* parser on the untrusted path without resource limits.
2. **Decide the untrusted-input policy before shipping `object`.** Its README explicitly excludes
   malware analysis and disclaims DoS mitigation — which is BitFlip's exact use case. Either
   (a) wrap all `object` calls in a timeout + allocation cap + bounded-iteration guard and surface
   limit hits as explicit degraded results, or (b) keep `goblin` primary on the adversarial path and
   use `object` only for fat Mach-O / code signatures / dyld cache. **(a) and (b) combine well.**
3. **Keep `goblin`** where it already works; note it cannot do code signatures, so route any
   signature/entitlement/dyld work to `object` (or `apple-codesign` if deep CMS is needed).
4. **Do not add `lief`** — document the build-time-binary-download reason, since the license alone
   would have passed.
5. **Add the three GPL crates to a deny-list** in CI: `exe`, `dotnetdll`, `smali`. A `cargo-deny`
   `licenses` check would catch these automatically and is worth wiring into preflight.
6. **Defer DEX.** Preview the APK path with `zip` 9.0.1 (MIT) now; treat DEX as a hand-written
   parser or an adopt-and-maintain of `dex` (MIT).
7. **Java class**, if/when needed, starts with `cafebabe` (0BSD).
8. **.NET, if/when needed, starts with `dotscope`** (Apache-2.0) — but review its source and API
   stability first, and disable its default `iced-x86`/emulation features.
9. **Compression: stay pure Rust** — `flate2` (default `miniz_oxide`), `ruzstd`, `lzma-rs`,
   `bzip2` 0.6 (pure-Rust default). Reserve FFI `zstd` for *compression* only if ever needed.
10. **Two items needing a conscious decision:** `apple-codesign` (MPL-2.0, stale since 2024-11-29)
    and `fdt` (reported MPL-2.0).
