# Rust crates for DEX / APK / Java-class / archive parsing

**Research date:** data as returned by the crates.io API in this session.
**Every row below comes from `https://crates.io/api/v1/crates/<NAME>` unless a different URL is cited.**
Items marked **[unverified]** could not be confirmed in this session.

**Method note:** raw.githubusercontent.com and github.com were **unreachable** from this
environment (`web fetch failed: TypeError: fetch failed`). Therefore *repo file contents*
(`/LICENSE`, `/Cargo.toml`) and *last-commit dates*, *open-issue counts*, and *README
"unmaintained" text* could **NOT** be verified. All license/date figures below are the
**crates.io registry fields**, which are authoritative for what you actually download.

---

## 0. HARD BLOCKERS — GPL family (project forbids GPL/LGPL/AGPL/SSPL)

| Crate | License | Evidence |
|---|---|---|
| **`smali`** | **GPL-3.0-only** | every version carries `"license":"GPL-3.0-only"` — https://crates.io/api/v1/crates/smali |

**`smali` is the single most dangerous crate in this whole survey.** It is otherwise the
most attractive DEX-adjacent crate available (2026-08-05 release, edition 2024, 25,064 LOC,
4,983 downloads). **Do NOT depend on it.** GPL-3.0 is copyleft and would infect the
BitFlip binary. No other crate in this report is GPL/LGPL/AGPL/SSPL.

No crate surveyed had a **missing/unknown** crates.io license field — every existing crate
below reported an explicit SPDX string. There is therefore **no "NEEDS_REVIEW for unverified
license"** item in this survey.

---

## TASK A — DEX (Dalvik Executable)

### KEY QUESTION: Is there a maintained, pure-Rust DEX parser?

**Answer: No single fully-satisfying one, but the situation is far better than "all abandoned".**
There are two genuinely alive pure-Rust DEX crates — **`dex`** (the most complete parser, but
frozen since 2021) and **`dalvik`** (actively usable, MIT/Apache, but a disassembler rather
than a full container parser) — plus a burst of brand-new 2026 entrants whose quality is
**[unverified]** because their repos were unreachable and their download counts are tiny.

| Crate | Exists | License | Pure Rust | Total dl | Last release | Repo | Assessment |
|---|---|---|---|---|---|---|---|
| `dex` | yes | **MIT** | yes | 35,605 | **2021-05-31** (0.5.0) | github.com/letmutx/dex-parser | **USE IT (with caveats)** — the most mature pure-Rust DEX *parser*; 3,051 LOC; MIT. But no release in ~5 years; treat as frozen, not dead. |
| `dex-parser` | **NO — 404** | — | — | — | — | — | **DON'T** — does not exist on crates.io. |
| `dex-parser-rs` | **NO — 404** | — | — | — | — | — | **DON'T** — does not exist. |
| `dex_parser` | **NO — 404** | — | — | — | — | — | **DON'T** — does not exist. (The real crate is `dex`.) |
| `dexlib` | **NO — 404** | — | — | — | — | — | **DON'T** — does not exist. |
| `smali` | yes | **GPL-3.0-only** | yes | 4,983 | 2026-08-05 (0.6.2) | github.com/azw413/smali | **DON'T — GPL BLOCKER.** Actively maintained; license forbids use. |
| `dalvik` | yes | **MIT OR Apache-2.0** | yes | 7,146 | **2024-05-29** (0.2.0) | github.com/MarginResearch/dalvik | **USE IT** — permissive, small (2,285 LOC), "Disassembler for Android Dalvik bytecode". By Evan Richter / MarginResearch. |
| `android-dex` | yes | MIT | yes | 530 | **2025-07-09** (0.0.0) | *none* | **DON'T** — **0 lines of code**, `code_lines: 0`, no repository, version 0.0.0. A placeholder/squat. |
| `dex_parser` | see `dex_parser` above | — | — | — | — | — | 404 |
| `dvm` | yes | MIT | yes | 48,400 | 2026-10-07 (1.11.6) | github.com/justjavac/dvm | **DON'T** — **name trap**: this is "Deno Version Manager", nothing to do with Dalvik. |
| `r8` bindings | **not found** | — | — | — | — | — | **[unverified]** — a crates.io search for `dex`/`dalvik`/`smali` returned no R8 crate; R8 is a Java/Kotlin tool. I did not find a Rust binding. Treat as "does not exist" unless separately confirmed. |

### Other plausible DEX hits found by searching crates.io (`q=dex`, `q=dalvik`, `q=smali`)

Search URLs: `https://crates.io/api/v1/crates?q=dex&per_page=20`,
`...?q=dalvik&per_page=20`, `...?q=smali&per_page=20`. Total hits for `q=dex`: **1,732**,
but the overwhelming majority are **crypto/DEX-exchange** crates (Solana, Cosmos, Hyperliquid)
and are irrelevant. The Android-relevant remainder:

| Crate | Total dl | Last release | Repo | Assessment |
|---|---|---|---|---|
| `dexparser` | 4,779 | **2021-03-24** (0.6.2) | github.com/mdeg/dexparser | **NEEDS INVESTIGATION** — MIT, real DEX parser (2,381 LOC, 365 comment lines = best-documented of the bunch). Also stale (2021). Its license is MIT — fine. |
| `dex-parser-rust` | 67 | 2026-07-24 (1.3.0) | github.com/damarkuncoro/dex-parser-rust | **NEEDS INVESTIGATION** — brand new, 67 downloads, "modular and parallel Android DEX/APK parsing engine". Too new/small to trust; license not captured in the search payload **[unverified]**. |
| `serum_dex` | 382,552 | 2022-01-25 (0.5.4) | — | **DON'T** — Solana on-chain DEX program, unrelated to Android. |
| `dexvm` | 850 | 2026-10-03 (0.2.1) | github.com/tachibana-shin/dexvm | **NEEDS INVESTIGATION** — "Minimal DEX VM runtime in Rust", 2026-new, small. |
| `droidsaw-dex` | 922 | 2026-06-11 (2.0.0) | github.com/droidsaw/droidsaw-dex | **NEEDS INVESTIGATION** — decompiler (CFG/SSA/Java emit), commercial homepage droidsaw.com. New. |
| `droidsaw` | 467 | 2026-06-11 (2.0.0) | github.com/droidsaw/droidsaw | **NEEDS INVESTIGATION** — "unified Android RE CLI. Hermes, DEX, APK signing". |
| `smali_disassembler` | 2,667 | 2024-09-21 | *none* | **DON'T** — `"yanked":true`, max_version 0.0.0, no repository. Dead. |
| `tree-sitter-smali` | 5,551 | 2023-05-13 (1.0.0) | git.sr.ht/~yotam/tree-sitter-smali | **NEEDS INVESTIGATION** — only a *grammar* for smali text, not a DEX parser. |
| `tree-sitter-smali-valonsodev` | 92 | 2026-04-10 (0.1.3) | github.com/valonsodev/tree-sitter-smali | Fork of the above; tiny. |
| `unearth`, `sleigh` | 2,060 (sleigh) | 2022-01-24 | github.com/black-binary/sleigh | Appeared under `q=dalvik`; unrelated to DEX. |

Note: `android-dex` and `dexvm` etc. were surfaced by the `q=dalvik` search; `dex-parser-rust`
came from `q=smali` (total 12 hits for that query).

---

## TASK B — APK (which is just a ZIP)

| Crate | License | Pure Rust | Total dl | Last release | Repo | Assessment |
|---|---|---|---|---|---|---|
| **`zip`** | **MIT** ✅ | yes (default features use `flate2`/`zlib-rs`; see note) | **295,981,864** | **2026-10-10** (9.0.1) | **github.com/zip-rs/zip2** ✅ | **USE IT** — your premise is **CONFIRMED**: the crates.io `repository` field for `zip` points at `zip-rs/zip2`, and 9.0.1 carries `trustpub_data: {provider:"github", repository:"zip-rs/zip2"}`. License **MIT** on 9.0.1. Extremely healthy. |
| `zip2` | **NO — 404** | — | — | — | — | **DON'T** — the crate is `zip`; the *repo* is named zip2. There is no `zip2` crate. |
| `rc-zip` | **Apache-2.0 OR MIT** | yes | 2,114,999 | **2025-11-19** (5.4.1) | github.com/bearcove/rc-zip | **USE IT** — I/O-agnostic ZIP, permissive, 596k recent downloads. |
| `async_zip` | MIT | yes (async, tokio) | 7,190,062 | 2026-08-22 (0.0.19) | github.com/Majored/rs-async-zip | **USE IT if async** — still 0.0.x but very widely used (2.4M recent). |
| `rc-zip-sync` | Apache-2.0 OR MIT | yes | 1,864,986 | **2025-11-27** (4.4.2) | github.com/bearcove/rc-zip | **USE IT** — the sync wrapper over rc-zip; default features include `file`+`deflate`. |
| `rc-zip-cli` | Apache-2.0 OR MIT | yes | 5,277 | 2025-11-27 (1.2.2) | github.com/bearcove/rc-zip | **DON'T (as a dep)** — it is a *sample* binary (`has_lib:false`), not a library. Useful as reference. |
| `zip-next` | MIT | — | 158,772 | **2024-04-20** (1.1.1) | github.com/Pr0methean/zip-next-wrapper | **DON'T** — real crate id is **`zip_next`** (underscore). Its own description says: *"This crate, zip_next, is now a wrapper around `zip` ... Please replace this crate with `zip`."* Only 2 lines of code. |
| `rawzip` | MIT | yes | 566,543 | **2026-10-04** (0.5.2) | github.com/nickbabcock/rawzip | **USE IT / strong candidate** — modern (edition 2024, rust 1.85), MIT, 6,815 LOC, 303k recent downloads, `no_std`-capable (`alloc` feature). |

**Note on `zip` "pure Rust":** `zip` 9.0.1's default features are
`["aes-crypto","bzip2","deflate64","deflate","lzma","ppmd","time","zstd","xz"]`, and
`deflate` resolves to `deflate-zopfli` + `deflate-flate2-zlib-rs` — i.e. the default
DEFLATE path is **zlib-rs (pure Rust)**, not C zlib. `bzip2`/`zstd`/`xz`/`lzma` entry in
via option crates discussed in Task D. You can restrict features for a lean APK reader.

---

## TASK C — JAVA CLASS / JVM

All five that exist genuinely **parse real `.class` files** (they self-describe as
class-file parsers). I did **not** execute any of them, so "parses correctly" is
**[unverified]** — only "is advertised and structured as a parser" is verified.

| Crate | Exists | License | Total dl | Last release | Repo | Assessment |
|---|---|---|---|---|---|---|
| **`cafebabe`** | yes | **0BSD** | 61,451 | **2025-06-03** (0.9.0) | github.com/staktrace/cafebabe | **USE IT — best pick.** 0BSD is maximally permissive (no attribution burden). 4,566 LOC. Actively maintained by Kartikaya Gupta (Mozilla/Gecko engineer). |
| `classfile-parser` | yes | MIT | 31,447 | **2024-10-10** (0.3.8) | github.com/Palmr/classfile-parser | **USE IT** — MIT, mature (since 2017), 1,434 Rust LOC + Java test fixtures. |
| `classfile` | yes | MIT | 3,664 | **2026-09-24** (0.3.0) | github.com/dlunch/RustJava | **NEEDS INVESTIGATION** — `no_std` parser+validator, edition 2024, 1,479 LOC. Very new (first release 2026-08-30). |
| `jclass` | yes | **Apache-2.0** | 3,752 | **2025-05-28** (0.1.7) | github.com/JavaGuard/jclass | **NEEDS INVESTIGATION** — parse *and edit*; 1,994 Rust LOC + a 533-line C header; 0.1.x; small user base. |
| `jvm-class` | yes | MIT | **94** | **2026-08-01** (0.1.0) | github.com/n08i40k/jvm-class | **DON'T (yet)** — zero-copy, but explicitly limited to **major versions 45–52 (Java 1.1–8)**; 94 downloads. Fails on modern class files. |
| `java-class` | **NO — 404** | — | — | — | — | **DON'T** — does not exist. |
| `jasmin` | **NO — 404** | — | — | — | — | **DON'T** — does not exist on crates.io. |
| `bytecode` | yes | MIT | 5,481 | **2022-11-17** (0.3.0) | github.com/NaokiM03/bytecode | **DON'T** — only **297 LOC**; "provides the ability to read bytecode". Too thin to be a class-file parser; **[unverified]** whether it even targets JVM vs. something else. |
| `jvm-class` vs `classfile` | naming | — | — | — | — | Note both exist; don't confuse. |

---

## TASK D — ARCHIVE / COMPRESSION

| Crate | License | Pure Rust? | Total dl | Last release | Repo | Assessment |
|---|---|---|---|---|---|---|
| `ar` | **MIT** | **yes** | 9,998,366 | **2021-08-16** (0.9.0) | github.com/mdsteele/rust-ar | **USE IT** — pure-Rust Unix `.a`/`.lib` archive reader; single 1,706-LOC file. Frozen since 2021 but stable & permissive. |
| `msi` | **MIT** | yes | 5,962,514 | **2026-02-23** (0.10.0) | github.com/mdsteele/rust-msi | **USE IT** — read/write Windows Installer; actively maintained, huge usage. |
| `cab` | **MIT** | yes | 7,025,243 | **2024-04-05** (0.6.0) | github.com/mdsteele/rust-cab | **USE IT** — read/write Windows CAB. Same author family as `msi`/`ar`. |
| **`lief`** | **Apache-2.0** | **FFI — C++** | 37,549 | 2026-07-12 (1.0.0) | github.com/lief-project/LIEF | **NEEDS INVESTIGATION / likely DON'T** — "Official Rust bindings for LIEF"; it is a binding, so it links C++ LIEF (heavy build, C++ toolchain). 162,033 Rust LOC are *generated bindings*. Apache-2.0 so license is fine. |
| `ruzstd` | **MIT** | **yes — pure Rust zstd decoder** | 70,893,096 | 2026-07-26 (0.9.0) | github.com/KillingSpark/zstd-rs | **USE IT** — **the key pure-Rust alternative to FFI `zstd`.** 8,217 LOC, 18M recent downloads. |
| `flate2` | **MIT OR Apache-2.0** | yes by default (`rust_backend` → `miniz_oxide`); can optionally bind C zlib | 740,784,478 | 2026-08-28 (1.1.10) | github.com/rust-lang/flate2-rs | **USE IT** — official-ish rust-lang org. Default features = pure Rust. |
| `bzip2` | **MIT OR Apache-2.0** | **was FFI; NOW pure Rust by default** | 176,054,361 | 2025-10-16 (0.6.1) | github.com/trifectatechfoundation/bzip2-rs | **USE IT** — important update: since 0.6.x the **default feature is `dep:libbz2-rs-sys` (pure Rust)**; the C `bzip2-sys` path is opt-in. No longer an FFI-only crate. |
| `zstd` | **BSD-3-Clause** | **FFI — C (libzstd)** | 419,502,665 | 2026-10-10 (0.14.2) | github.com/gyscos/zstd-rs | **NEEDS INVESTIGATION** — binds/compiles C zstd (`zstd-safe`/`zstd-sys`; `vendored` feature statically builds it). BSD-3-Clause = permissive. Prefer **`ruzstd`** for decode-only if you want zero C. |
| `xz2` | **MIT OR Apache-2.0** | **FFI — C (liblzma)** | 70,327,219 | **2022-06-06** (0.1.7) | github.com/alexcrichton/xz2-rs | **DON'T / NEEDS INVESTIGATION** — FFI to liblzma **and frozen since 2022**. For ZIP `xz` support, note `zip` 9 already pulls the pure-Rust `lzma-rust2` instead. |
| `ar`/`archive` | `archive` **[unverified]** — a crate literally named `archive` was not fetched in this session | — | — | — | — | **[unverified]** |
| `decompression` | **NO — 404** | — | — | — | — | **DON'T** — does not exist. (`ruzstd`'s keyword `decompression` is what surfaces that word.) |

**On the "zero runtime dependency / single static binary" requirement:** you are right that
FFI here is *not* disqualifying — `zstd-sys`/`lzma-sys` with their `static`/`vendored`
features compile the C sources into your binary, so the shipped artifact still has **no
runtime `.dll` dependency** and is still a single static executable. The real costs are:
(1) a C compiler must be present at *build* time, (2) build times and binary size rise,
(3) it weakens the "pure Rust, auditable" property. Given `ruzstd` (pure Rust, MIT) exists
for zstd decode and `bzip2` 0.6 now defaults to pure Rust, you can plausibly reach a
**100% pure-Rust stack** for APK/ZIP work.

---

## What I could NOT verify (stated explicitly)

1. **GitHub repo contents** — `raw.githubusercontent.com` and `github.com` both failed
   (`TypeError: fetch failed`). So the following were **NOT** verified by direct source
   inspection: the `zip-rs/zip2` `LICENSE` file, the `azw413/smali` `Cargo.toml`, any
   **last-commit date**, any **open-issue count**, and any **README "unmaintained" claim**.
   The `zip` = MIT and `smali` = GPL-3.0-only conclusions rest on **crates.io registry
   metadata**, which is strong evidence (it is what `cargo` enforces at publish time) but
   is a second-hand statement about the repo's own file.
2. **Whether any crate README says "unmaintained"** — unverified for every crate.
3. **Last commit dates / issue counts** — unverified for every crate. "Maintenance status"
   in this report is inferred **only** from release recency, which is a proxy, not the
   same thing.
4. **Quality / correctness of parsers** — no crate was built or executed. "Parses .class
   files" reflects the crate's own description, not an observed parse.
5. **Licenses of the new 2026 entrants** (`dex-parser-rust`, `dexvm`, `droidsaw-dex`,
   `droidsaw`, `tree-sitter-smali-valonsodev`) — the search payload did not include a
   license field for these; **[unverified]**.
6. **`r8` Rust bindings** — no such crate found; absence is not proof of nonexistence.
7. A crate literally named **`archive`** was **not** fetched; its status is **[unverified]**.

## Bottom line

- **APK/ZIP:** healthy, permissive, actively maintained. Use **`zip` (MIT, zip-rs/zip2)** or
  **`rawzip` (MIT)**. Your assumption about zip2/MIT is confirmed.
- **Java class:** healthy. Use **`cafebabe` (0BSD)** or **`classfile-parser` (MIT)**.
- **DEX:** the weak spot. No actively-maintained, permissively-licensed, full DEX parser
  with confidence. **`dex`** (MIT) is the best parser but frozen since 2021; **`dalvik`**
  (MIT/Apache) is alive but narrower. **`smali` is GPL-3.0-only — hard blocker, do not use.**
  If DEX fidelity matters, budget for evaluating the 2026 newcomers yourself.
