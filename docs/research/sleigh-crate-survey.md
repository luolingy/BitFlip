# SLEIGH / Ghidra-decompiler Rust crate survey

Research date: data pulled live from crates.io API v1, GitHub REST API v3, and raw.githubusercontent.com.
All numbers are as returned by those APIs at fetch time. Anything not directly verified is marked **unverified**.

Consumer context: BitFlip — single self-contained Rust executable, zero runtime deps, capstone (BSD-3)
for 9 architectures. Hard rule: GPL / LGPL / AGPL / SSPL unacceptable. Apache-2.0, MIT, BSD, MPL-2.0,
Zlib acceptable.

---

## 0. Executive summary

| Crate | License (SPDX) | Pure Rust? | Latest | Downloads | Verdict |
|---|---|---|---|---|---|
| **ghidra-decompiler** (koute) | Apache-2.0 | **YES — pure Rust** | 2.1.0 (2026-09-25) | 92 | **ACCEPTABLE** (license) / immature |
| wazabin-sleigh | MIT | YES | 0.1.14 (2026-09-29) | 638 | ACCEPTABLE |
| wazabin-pcode | MIT | YES | 0.1.4 (2026-09-17) | 774 | ACCEPTABLE |
| wazabin-sleigh-precompile | **MIT AND Apache-2.0** | YES (embeds slaspec data) | 0.1.14 (2026-09-29) | 480 | ACCEPTABLE (data = Apache-2.0) |
| wazabin-qcode-sleigh | MIT | YES | 0.5.0 (2026-09-28) | 123 | ACCEPTABLE |
| rsleigh (ShaneBreazeale) | Apache-2.0 | YES | 0.5.0 (2026-09-07) | 226 | ACCEPTABLE |
| pcode-ir (ShaneBreazeale) | Apache-2.0 | YES | 0.5.0 (2026-09-07) | 1,162 | ACCEPTABLE |
| jingle | MIT | YES (lib part) | 0.6.38 (2026-08-03) | 12,679 | ACCEPTABLE |
| **jingle_sleigh** | MIT | **NO — FFI, C/C++** | 0.5.13 (2026-08-10) | 11,368 | ACCEPTABLE (MIT) but breaks static build |
| libsla | Apache-2.0 | **NO — FFI (-sys)** | 1.2.0 (2025-11-16) | 8,934 | ACCEPTABLE (license) / FFI |
| sleigh-compiler | Apache-2.0 | **NO — FFI, vendored C++** | 2.0.2 (2025-07-28) | 6,579 | ACCEPTABLE (license) / FFI |
| sleigh-config | Apache-2.0 | data crate (.sla files) | 1.0.1 (2025-10-17) | 5,157 | ACCEPTABLE |
| sleigh-rs (rbran) | MIT | YES (parser only) | 0.1.5 (2023-07-18) | 8,785 | ACCEPTABLE but **abandoned** |
| fugue-sleigh | MIT | YES (tiny) | 0.2.0 (2025-01-20) | 10,207 | ACCEPTABLE / 1 version, stale |
| mogi_sleigh | MIT OR Apache-2.0 | YES | 0.1.0 (2026-04-11) | 353 | **ACCEPTABLE license, but see repo note** |
| mogi_sleigh_parser | MIT OR Apache-2.0 | YES | 0.1.0 (2026-04-11) | 424 | same |
| reoxide | Apache-2.0 | FFI bindings to external decompiler | 0.7.0 (2025-09-16) | 1,106 | ACCEPTABLE license / **not a SLEIGH crate** |
| fission-systems/Fission | Apache-2.0 | YES | not published (repo) | n/a | ACCEPTABLE / not a dependency |
| sefcom/oxidizer | BSD-2-Clause | **NO — Python + angr** | repo, last push 2026-09-08 | n/a | ACCEPTABLE license / **unusable for Rust** |

**Headline conclusions**
1. **No crate in this list is GPL/LGPL/AGPL/SSPL.** Every one is MIT, Apache-2.0, BSD-2-Clause, or MIT OR Apache-2.0. The infectious-license fear does not materialize for the *code*.
2. **The real risk is not license, it is FFI.** `jingle_sleigh`, `libsla`, `sleigh-compiler` all compile vendored Ghidra C++ decompiler sources. That directly violates BitFlip's "single self-contained executable" goal — though notably **Ghidra's C++ decompiler is itself Apache-2.0**, not GPL.
3. **`ghidra-decompiler` by koute is the only pure-Rust full decompiler** and is Apache-2.0. Its README explicitly says "It has no C, C++ or Java dependencies" and "Apache-2.0, as Ghidra."
4. **The Ghidra processor specification files (.slaspec/.sinc) carry NO per-file license notice.** Verified by fetching raw files — see §17.

---

## 1. ghidra-decompiler (koute)

- **License:** `Apache-2.0` (crates.io), GitHub API license field `apache-2.0`. LICENSE + NOTICE files present.
- **Latest version:** 2.1.0, published **2026-09-25T11:39:49Z** (3 versions total: 2.0.0, 2.1.0, plus initial).
- **Downloads:** **92 total** (65 for 2.1.0). Essentially brand new / barely adopted.
- **Pure Rust vs FFI:** **PURE RUST.** README: "A pure Rust port of the Ghidra decompiler (Ghidra 12.2, `Ghidra/Features/Decompiler/src/decompile/cpp`). **It has no C, C++ or Java dependencies.** The output is textually identical to the C++ decompiler on the test corpora in `tests/data`." crates.io linecounts: 152,204 Rust LOC across 126 files, zero C/C++, zero comment lines (machine-ported).
- **Architectures:** feature-gated. Default features = `["demangle", "x86", "arm", "aarch64", "mips", "powerpc", "riscv"]`. `all-processors` adds: 6502, 68000, 8048, 8051, 8085, aarch64, arm, atmel, bpf, cp1600, cr16, dalvik, data, ebpf, hcs08, hcs12, hexagon, jvm, loongarch, m16c, m8c, mc6800, mcs96, mips, nds32, pa-risc, pic, powerpc, riscv, sparc, superh, superh4, ti_msp430, toy, tricore, v850, x86, xtensa, z80. **This is a superset of BitFlip's 9 capstone architectures.**
- **Maintenance:** Repo `koute/ghidra-decompiler` created 2026-09-25, pushed 2026-09-25. 6 stars, 2 forks, 0 open issues. Only ~2 days of commit history at fetch time — **too new to judge trajectory.**
- **Crate size:** 7.4 MB (large; affects build time and binary size).
- **MSRV:** Rust 1.88, edition 2024. GitHub `updated_at` 2026-10-10 suggests repo activity after last push.
- **Assessment:** **License is clean and it is the only candidate that fully preserves the single-binary zero-dependency goal while replacing decompiler functionality.** But with 92 downloads and a 2-day-old history, plus a self-declared "automatically ported by an agent" provenance, treat it as experimental — usable for evaluation, **not production-proven.**

## 2. wazabin-sleigh

- **License:** `MIT` (crates.io). GitHub repo license field: `mit`.
- **Latest version:** 0.1.14, published **2026-09-29T13:18:38Z** (15 versions).
- **Downloads:** **638 total**, 635 recent. Very low.
- **Pure Rust vs FFI:** **PURE RUST.** Repo: `wazabin/sleigh`, a Cargo workspace. Linecounts: 15,229 Rust LOC + one Pest grammar (422 lines). No `-sys` crate, no bindgen, no C++ in the code crate.
- **Architectures:** Not enumerated per-arch in the crate itself; architecture coverage comes from the companion `wazabin-sleigh-precompile` crate's build config. README says "Compatibility against the vendored Ghidra corpus is measured, not asserted."
- **Maintenance:** Repo created 2026-08-24, pushed 2026-09-29. **0 stars, 0 forks, 0 watchers**, 4 open issues. Published via crates.io **trusted publishing** (GitHub Actions OIDC), which is a positive supply-chain signal. Developed by "Thalium" (linked author blog).
- **Assessment:** Clean MIT pure-Rust SLEIGH compiler + decoder, actively released (15 versions in ~5 weeks), but **zero community adoption — unverified in production.**

## 3. wazabin-pcode

- **License:** `MIT`.
- **Latest version:** 0.1.4, published **2026-09-17T09:21:51Z** (4 versions).
- **Downloads:** **774 total**, 771 recent.
- **Pure Rust vs FFI:** **PURE RUST** (4,416 Rust LOC). Repo `wazabin/pcode`. Trusted publishing enabled.
- **Architectures:** n/a — it is a p-code vocabulary/AST/diagnostics crate, architecture-agnostic.
- **Maintenance:** Repo part of the wazabin org; actively released Sept 2026.
- **Assessment:** Supporting IR types crate, MIT, pure Rust. Fine as a dependency; too small/no adoption to have a production track record.

## 4. wazabin-sleigh-precompile

- **License:** **`MIT AND Apache-2.0`** (crates.io — note: AND, not OR). This is deliberate dual-scope, not dual-choice.
- **Latest version:** 0.1.14, published **2026-09-29T13:23:25Z** (15 versions).
- **Downloads:** **480 total**.
- **Pure Rust vs FFI:** **PURE RUST**, but it **embeds Ghidra processor specifications**. README (decoded verbatim): *"The Rust code is licensed under the MIT License. The vendored `open_sleigh` processor specifications remain licensed under Apache-2.0; see that directory's LICENSE and NOTICE files."*
- **The data source is a git submodule:** `precompile/open_sleigh` resolves to `Garfield1002/open_sleigh` — **"Community-maintained SLEIGH processor specifications for Ghidra"**, GitHub license field `apache-2.0`. `precompile/LICENSE` is a **10-byte pointer file** (i.e. just a filename reference), with the actual Apache-2.0 + NOTICE living in the `open_sleigh/` directory.
- **Serialization note:** README states the embedded form is **`bincode`** over the `sleigh` crate, regenerated by `build.rs` at build time rather than checked in. This matters for BitFlip: it means a **`build.rs` that compiles SLaspec at build time** (slow — README says "Compiling a real specification takes hundreds of milliseconds"), but the *runtime* has zero external deps.
- **Architectures:** Configured via `precompile/build_config.toml`; modules expose named `RegisterId` constants. Exact arch list not enumerated in the readme — **unverified** which processors are in the default build config.
- **Assessment:** **ACCEPTABLE.** MIT code + Apache-2.0 data is exactly the combination BitFlip's rules allow. It is the cleanest "embed processor specs, stay pure Rust" path. Caveat: it pulls an Apache-2.0 data corpus from a **different third party** (`Garfield1002/open_sleigh`, 10 stars) than the code author — supply-chain and attribution diligence needed.

## 5. wazabin-qcode-sleigh

- **License:** `MIT`.
- **Latest version:** 0.5.0, published **2026-09-28T11:10:07Z** (7 versions).
- **Downloads:** **123 total**. Lowest in the survey.
- **Pure Rust vs FFI:** **PURE RUST** (6,120 Rust LOC, 5 files). Repo `wazabin/qcode`.
- **Description:** "High-performance lifting of wazabin-sleigh flat p-code into QCode."
- **Architectures:** architecture-agnostic (p-code lifting layer).
- **MSRV:** Rust 1.88.
- **Assessment:** Small, MIT, pure Rust, but 123 downloads and rapid breaking version churn (0.4.x → 0.5.0 in 2 weeks). **Not production-usable as a stable dependency yet.**

## 6. rsleigh (ShaneBreazeale)

- **License:** `Apache-2.0`.
- **Latest version:** 0.5.0, published **2026-09-07T02:48:22Z** (6 versions).
- **Downloads:** **226 total**, 129 recent.
- **Pure Rust vs FFI:** **PURE RUST.** Description: "SLEIGH (.slaspec) parser and Rust decoder/P-code emitter codegen — Ghidra-compatible disassembly in pure Rust". 19,424 Rust LOC / 87 files. Also contains Python (1,648 LOC) and Java (213 LOC) helper scripts in the repo, but the crate is Rust.
- **Distinctive design:** This is a **codegen** approach — it parses `.slaspec` and **emits Rust code** for decoders, rather than interpreting specs at runtime. Features: `cli`, `default`, `no_overflow_inline`, `strict_solve`, `thread`. Has a binary name `rsleigh`.
- **Architectures:** Not enumerated. Repo description says "multi-arch decompilation."
- **Maintenance:** Repo created 2026-04-08, **pushed 2026-10-11T09:41:00Z** — active within days of this research. 10 stars, 3 forks, 0 open issues, discussions enabled.
- **Assessment:** Apache-2.0, pure Rust, actively maintained, and the codegen model is attractive for BitFlip (no runtime spec compilation). But 226 downloads / 10 stars = **no production track record.** Promising experimental option.

## 7. pcode-ir (ShaneBreazeale)

- **License:** `Apache-2.0`.
- **Latest version:** 0.5.0, published **2026-09-07T02:03:52Z** (8 versions).
- **Downloads:** **1,162 total**, 720 recent.
- **Pure Rust vs FFI:** **PURE RUST.** Single file, 1,393 LOC. Categories include **`no-std`** — a genuinely useful property. Optional `serde` feature.
- **Architectures:** n/a (IR type definitions).
- **Maintenance:** Same repo as rsleigh (`ShaneBreazeale/rsleigh`), actively pushed 2026-10-11.
- **Assessment:** Clean, small, Apache-2.0, `no-std`-capable p-code IR types. **Reasonable to depend on**; low risk but low adoption.

## 8. jingle (toolCHAINZ)

- **License:** `MIT`. README/LICENSE verified: standard MIT text, "Copyright (c) 2024 toolCHAINZ". GitHub license field `mit`.
- **Latest version:** 0.6.38, published **2026-08-03T15:13:57Z** (**73 versions**).
- **Downloads:** **12,679 total** — the most-downloaded crate in this survey by a wide margin (next is jingle_sleigh at 11,368).
- **Pure Rust vs FFI:** The **`jingle` crate itself** is pure Rust (15,460 Rust LOC, 80 files). But its functionality is SMT modeling of p-code; the actual SLEIGH decoding is delegated to `jingle_sleigh`, which **is FFI**. Optional features: `bin`, `gimli`, **`pyo3`** (which pulls `z3-sys`).
- **Architectures:** Not enumerated; architecture support inherits from `jingle_sleigh`.
- **Maintenance:** Repo created 2024-05-21, pushed 2026-08-10. 38 stars, 4 forks, 7 open issues. Sustained ~2-year release cadence with 73 versions. Trusted publishing (GitHub Actions).
- **Assessment:** The most mature and widely used project here. MIT is acceptable. **BUT** its decoding backbone is FFI, and its purpose is SMT/symbolic solving (Z3), not general disassembly — it is a different tool than "replace capstone." Usable if you want p-code SMT; wrong shape if you want a decoder.

## 9. jingle_sleigh (toolCHAINZ)

- **License:** `MIT` (crates.io + repo).
- **Latest version:** 0.5.13, published **2026-08-10T20:47:08Z** (36 versions).
- **Downloads:** **11,368 total**.
- **Pure Rust vs FFI:** **FFI — C and C++.** crates.io linecounts for 0.5.13: **C++ 13,034 LOC / 29 files, C++ Headers 4,408 LOC / 24 files, C 3,942 LOC, C Headers 1,789 LOC**, plus Rust 6,162 LOC and a Pest grammar. crates.io category: `api-bindings`, description: "An FFI layer for Ghidra's SLEIGH". This **compiles vendored Ghidra decompiler C++**.
- **Architectures:** Inherits whatever the vendored Ghidra SLEIGH build supports; the crate itself does not enumerate. **unverified** exact list.
- **Maintenance:** Same repo as jingle, active through 2026-08-10, trusted publishing.
- **Assessment:** **License-wise ACCEPTABLE (MIT).** But it is exactly the FFI case BitFlip warns about: it pulls Ghidra's C++ into the build, requires a C++ toolchain, complicates static linking, and inflates the binary. **Not compatible with the single-self-contained-executable requirement.**

## 10. libsla (mnemonikr)

- **License:** `Apache-2.0`.
- **Latest version:** 1.2.0, published **2025-11-16T00:39:34Z** (13 versions).
- **Downloads:** **8,934 total**, 1,491 recent.
- **Pure Rust vs FFI:** **FFI.** Description: "Rust bindings to Ghidra Sleigh library libsla". The **1.0.x versions were published from `github.com/mnemonikr/symbolic-pcode`** and the crate manifest for that lineage shows **C++ 100,100 LOC / 106 files + C++ Headers 19,538 LOC** plus Lex/Happy grammar files — i.e. a vendored Ghidra decompiler C++ tree. The 1.2.0 crate itself is only 893 Rust LOC (26 KB) wrapping `libsla-sys`. Features include `fuzzing` → `libsla-sys/fuzzing`, confirming a `-sys` split.
- **Architectures:** Not enumerated; derived from the vendored C++ SLEIGH. Repo itself exposes p-code disassembly, so any Ghidra SLEIGH language works. **unverified** exact list.
- **Maintenance:** Repo created 2025-09-23, **last push 2025-11-16** — no commits in ~11 months as of this research. 13 stars, 2 forks, 2 open issues. **Effectively dormant.**
- **Assessment:** Apache-2.0 keeps the license clean, but it is a `-sys` FFI binding to vendored C++ → **violates the zero-runtime-dependency/single-binary goal**, and the repo has been quiet since 2025-11-16.

## 11. sleigh-compiler (mnemonikr)

- **License:** `Apache-2.0`.
- **Latest version:** 2.0.2, published **2025-07-28T06:31:30Z** (5 versions).
- **Downloads:** **6,579 total**, 1,828 recent (4,867 on 2.0.2 alone).
- **Pure Rust vs FFI:** **FFI — heavy.** "Rust bindings for the Ghidra SLEIGH compiler. Used to compile processor .slaspec files into .sla files". The 2.0.2 crate is 1.7 MB and its linecounts are **C 3,942 + C Headers 1,606 + C++ 111,232 + C++ Headers 21,614** vs only **149 Rust LOC**. It is a vendored Ghidra C++ compiler with a thin Rust wrapper.
- **Architectures:** Compiles SLEIGH specs; can target any processor Ghidra has specs for. This is a build-time tool, not a decoder.
- **Maintenance:** Repo `mnemonikr/sleigh-compiler`; last crates.io release 2025-07-28 (~14 months stale). Same author as libsla. **unverified** whether repo has newer commits.
- **Assessment:** Apache-2.0, but a 143,000-LOC vendored C++ build dependency. **Usable only as a build-time spec compiler, never as part of a single static binary,** and it is stale.

## 12. sleigh-config (mnemonikr)

- **License:** `Apache-2.0`.
- **Latest version:** 1.0.1, published **2025-10-17T04:40:10Z** (4 versions).
- **Downloads:** **5,157 total**, 1,695 recent.
- **Pure Rust vs FFI:** **Not code — data.** "Precompiled .sla files and other processor configuration files needed to interface with Ghidra SLEIGH." Only 80 Rust LOC / 2 files; the crate is 1.59 MB of compiled `.sla` artifacts. crates.io linecounts are all HTML/Rust (build tooling).
- **Architectures:** Feature-gated, exactly matching BitFlip's need and more: `6502, 68000, 8048, 8051, 8085, AARCH64, ARM, Atmel, BPF, CP1600, CR16, DATA, Dalvik, HCS08, HCS12, JVM, Loongarch, M16C, M8C, MC6800, MCS96, MIPS, PA-RISC, PIC, PowerPC, RISCV, Sparc, SuperH, SuperH4, TI_MSP430, Toy, V850, Xtensa, Z80, eBPF, tricore, x86`. **Covers all 9 BitFlip architectures.**
- **Maintenance:** Repo `mnemonikr/sleigh-config`, last release 2025-10-17 (~1 year stale).
- **Assessment:** **ACCEPTABLE license (Apache-2.0) and the most useful piece of the mnemonikr stack** — it is a data-only crate that ships compiled `.sla` blobs, with no FFI. It is intended to pair with `libsla`. Note the stale maintenance (~1 year) and that the `.sla` files are derived from Apache-2.0 Ghidra specs, so **Apache-2.0 attribution/NOTICE obligations apply to the data**.

## 13. sleigh-rs (rbran)

- **License:** `MIT`.
- **Latest version:** 0.1.5, published **2023-07-18T13:07:44Z** (**6 versions; no release in >3 years**).
- **Downloads:** **8,785 total**, but only **99 recent** — the classic signature of a dead dependency still being pulled transitively.
- **Pure Rust vs FFI:** **PURE RUST**, 13,320 Rust LOC / 63 files. Description: "Ghidra Sleigh parser". It is a **parser only** — it parses `.slaspec` into a tree; it does **not** decode instructions.
- **Architectures:** n/a — spec parser, architecture-agnostic.
- **Maintenance:** **ABANDONED.** Repo `rbran/sleigh-rs`: created 2022-03-30, **last push 2024-12-29**, 45 stars, 7 forks, 8 open issues. `updated_at` 2026-08-12 is only metadata (stars/watch), not commits.
- **Assessment:** MIT and pure Rust, but stale since 2024 and functionally incomplete (parser only, no decoder). **Not production-usable** — it solves only one small part of the problem.

## 14. fugue-sleigh

- **License:** `MIT`.
- **Latest version:** **0.2.0 — the only version ever published**, on **2025-01-20T13:58:58Z**.
- **Downloads:** **10,207 total**, 891 recent.
- **Pure Rust vs FFI:** **PURE RUST** — 2,500 Rust LOC / 5 files + a Pest grammar. **Total crate size 22,795 bytes (22 KB)** — trivially small.
- **Repository:** `repository` field is **`null`** on crates.io. Homepage `https://fugue.re`. Publisher is **`xorpse` = Sam L. Thomas** (well-known RE/security researcher, author of `fugue`). Description is generic: "A binary analysis framework written in Rust" — it is a component of the commercial-ish `fugue.re` project, not a standalone SLEIGH library.
- **Architectures:** **unverified** — no README/repo found via the crate metadata to enumerate.
- **Maintenance:** Single release, no repo link, no commits visible. **No maintained public repository.**
- **Assessment:** MIT and pure Rust, but with **no public source repository and no releases in ~21 months**, you cannot audit, patch, or track it. **Not production-usable** — treat as a vendored blob of unknown provenance despite the permissive license.

## 15/16. mogi_sleigh and mogi_sleigh_parser

- **License (both):** **`MIT or Apache-2.0`** (crates.io, OR form — you may choose either). Repo GitHub license field is `null`.
- **Latest versions:** **0.1.0 for both — the only versions ever published.** mogi_sleigh on **2026-04-11T09:48:54Z**, mogi_sleigh_parser on **2026-04-11T00:10:38Z**.
- **Downloads:** mogi_sleigh **353**, mogi_sleigh_parser **424**.
- **Pure Rust vs FFI:** **PURE RUST.** mogi_sleigh: 18,308 Rust LOC / 78 files (718 KB crate). mogi_sleigh_parser: 5,546 Rust LOC / 66 files. Publishing user is **`mlgiraud` = Mark Giraud** (a known Rust reverse-engineering author). Repo `mogikai/mogi`.
- **Architectures:** Not enumerated. `mogi_sleigh` is "Sleigh compiler for MOGI" — a compiler, not a decoder. MOGI targets decompiler-generation from binaries (it is a research tool). **unverified** processor list.
- **Maintenance:** Repo `mogikai/mogi` created 2024-07-26, **last push 2026-08-03**. **0 stars, 0 forks, 0 watchers, 0 open issues**, and the GitHub API reports **`license: null`** — no LICENSE file detected at repo root even though the published crates declare MIT OR Apache-2.0.
- **Assessment:** License is acceptable (MIT OR Apache-2.0, your choice) and the code is pure Rust. But: a **single 0.1.0 release**, **zero adoption**, **no repo-level LICENSE file**, and it is a **research compiler**, not a production decoder. **NEEDS_REVIEW on provenance, and not production-usable today.**

## 17. Ghidra processor specification files (.slaspec / .sinc) — THE CRITICAL QUESTION

This determines whether BitFlip can ship processor specs. Findings:

**Ghidra repo license (verified):** `NationalSecurityAgency/ghidra` GitHub API reports license SPDX **`apache-2.0`**, default branch `master`, 83,070 stars. Root `LICENSE` fetched from raw.githubusercontent.com is the **verbatim Apache License 2.0 text**.

**Per-file license headers (verified by fetching raw files):**
- `Ghidra/Processors/x86/data/languages/x86.slaspec` — **contains only `@include` directives. No license header at all.**
- `Ghidra/Processors/x86/data/languages/ia.sinc` — fetched in full (50 KB); **a grep for `apache|license|copyright|GHIDRA` (case-insensitive) across the fetched content returned zero license-header matches.** Only unrelated prose ("NOTE: ST registers moved with Ghidra 10.0.3...").
- `Ghidra/Processors/MIPS/data/languages/mips.sinc` — fetched; **comment header is purely technical** (e_flags notes, register naming, FPU notes). No license/copyright line.
- `Ghidra/Processors/MIPS/data/languages/mips32le.slaspec` — **only `@define` and `@include` lines, no header.**
- `Ghidra/Processors/AARCH64/data/languages/AARCH64.slaspec` — **only two `@define` blocks and one `@include`, no header.**

**Contrast — the C++ decompiler source DOES carry a per-file header.** `Ghidra/Features/Decompiler/src/decompile/cpp/slgh_compile.hh` begins with:
```
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * ...
```
So Ghidra is inconsistent: C++ source files are individually stamped Apache-2.0; **the `.slaspec`/`.sinc` processor specification files are not individually stamped.**

**Interpretation (this is a legal-reading judgement, not a verified fact — flagging as reasoned, not proven):**
- The Apache-2.0 grant in `LICENSE` covers "the Work ... as indicated by a copyright notice that is included in or attached to the work". The absence of per-file headers in `.sinc`/`.slaspec` is **not** a relicense or a public-domain dedication; the repo-level LICENSE is the governing grant for repo contents.
- Therefore the **safest and correct reading is that Ghidra `.slaspec`/`.sinc` files are Apache-2.0**, same as the rest of the repo. **This is ACCEPTABLE for BitFlip.**
- **Obligation:** Apache-2.0 §4 requires you to (a) give recipients a copy of the License, (b) retain NOTICE file attributions, and (c) state significant changes. Shipping the specs means shipping Apache-2.0 attribution for them. **I could not fetch the Ghidra root `NOTICE` file** (the fetch failed), so **the exact NOTICE content is unverified** — verify it before shipping.
- **No copyleft risk:** Apache-2.0 is not infectious for BitFlip's purposes. Shipping `.slaspec` files as **data** alongside a proprietary binary is permitted.
- **Caveat:** some `.sla`/spec artifacts in the wild are derived from **third-party** Ghidra processor modules contributed under varying terms. The `wazabin` stack sidesteps this by vendoring `Garfield1002/open_sleigh` (declared Apache-2.0), but **individual spec files there should be spot-checked for third-party provenance** — I did not audit them.

**Bottom line for shipping specs:** ship them under Apache-2.0 with LICENSE + NOTICE attribution. This is **LICENSE VERDICT = ACCEPTABLE**. The blocker is not license — it is **build/embedding mechanics** (compiling specs at build time is slow; precompiled `.sla` blobs must be produced by a C++ toolchain unless you use a pure-Rust compiler).

## 18. reoxide

- **License:** `Apache-2.0`.
- **Latest version:** 0.7.0, published **2025-09-16T06:31:39Z** (3 versions; 0.6.1 and 0.6.2 were **yanked**).
- **Downloads:** **1,106 total**, only **30 recent** — heavy decay after the initial publish.
- **Pure Rust vs FFI:** **FFI bindings to an external decompiler.** crates.io categories explicitly include **`external-ffi-bindings`**. Description: "Rust-bindings for the ReOxide decompiler extension framework", `lib_links: "reoxide"`. Repository is on **Codeberg** (`codeberg.org/ReOxide/reoxide`), not GitHub. Homepage `reoxide.eu`.
- **Not a SLEIGH crate:** ReOxide is a **decompiler extension framework** with its own SDK; it is unrelated to Ghidra SLEIGH and unrelated to capstone-style decoding. It is a plugin API for the ReOxide decompiler.
- **Architectures:** Framework-dependent; **unverified**.
- **Maintenance:** Last release 2025-09-16 (~13 months stale). Two of three versions yanked, which usually signals a broken publish. 30 recent downloads = effectively unused.
- **Assessment:** Apache-2.0 is fine, but this is **a plugin SDK for a third-party decompiler framework**, needing that host runtime. It cannot serve as an in-process decoder for a single self-contained executable. **NEEDS_REVIEW / not applicable to BitFlip's requirement.**

## 19. fission-systems/Fission (GitHub)

- **License:** `Apache-2.0` (GitHub API license field; README states "Apache-2.0. See LICENSE for the terms and NOTICE for third-party attributions").
- **Latest version:** **Not published on crates.io** — this is a GitHub monorepo, not a consumable crate. `crates.io` has no `fission` crate from this org (not checked exhaustively; the monorepo crates are all `fission-*` and unpublished).
- **Downloads:** n/a (not on crates.io).
- **Pure Rust vs FFI:** **PURE RUST.** Repo language: Rust. README: "A Rust-native reverse-engineering workspace. It loads binaries, lifts instruction semantics through Ghidra-style Sleigh specifications."
- **Structure:** ~24 workspace crates: `fission-analysis-db`, `-analysis-protocol`, `-cli`, `-core`, `-decompiler`, `-dir`, `-dynamic`, `-emulator`, `-loader`, `-midend-core`, `-midend-normalize`, `-midend-prehir`, `-midend-structuring`, `-pcode`, `-plugin`, `-project`, `-script`, `-signatures`, `**-sleigh**`, `-solver`, `-static`, `-ttd`. **`fission-sleigh` is the relevant crate.**
- **Architectures:** README says "lifts instruction semantics through Ghidra-style Sleigh specifications... Sleight specifications and signature data live in `utils/`, which is committed". **No enumerated architecture list found — unverified.**
- **Maintenance:** Repo created **2026-07-23**, **pushed 2026-10-11T12:18:21Z** (same day as this research). **17 stars, 2 forks, 7 open issues.** Repo size 747 MB. Very active but very young.
- **Honest self-assessment (quoted):** *"The long term target is restoration rather than readability... That target is **not reached**. Decompiling one binary's 68 functions and compiling them as a single unit currently stops on 20 errors."*
- **Assessment:** Apache-2.0, pure Rust, genuinely active, and architecturally the closest analogue to what BitFlip wants. **But it is not a library you depend on** — it is a whole workspace with its own opinions, 747 MB, created 3 months ago, and its own README declares the core goal unreached. **Not production-usable as a dependency;** valuable as a **reference implementation** to study (especially `fission-sleigh` and `fission-pcode`).

## 20. sefcom/oxidizer (GitHub)

- **License:** **`BSD-2-Clause`** (GitHub API license field).
- **Latest version:** Not on crates.io. Repo `sefcom/oxidizer`, "A Rust decompiler built on top of angr".
- **Downloads:** n/a.
- **Pure Rust vs FFI:** **NOT RUST — it is Python.** GitHub reports `language: "Python"`. It is a decompiler built on **angr** (a Python binary-analysis framework). It is included in this survey presumably because the name suggests Rust, but the repo is Python.
- **Architectures:** Inherits angr/VEX architecture support; **unverified** exact list.
- **Maintenance:** Created 2023-10-13, **last push 2026-09-08**, 540 stars, 18 forks, 12 open issues. Genuinely maintained.
- **Assessment:** BSD-2-Clause is acceptable as a license, but **it is a Python program depending on angr** — it cannot be linked, embedded, or shipped inside a single Rust executable with zero runtime dependencies. **Not applicable to BitFlip.** Only useful as an algorithmic reference.

---

## 21. Cross-cutting notes for BitFlip

**On "FFI pulls in Ghidra's C++, which may have different licensing":** The premise is partly incorrect and worth correcting. **Ghidra's C++ decompiler source is Apache-2.0**, not GPL — verified via the per-file header in `slgh_compile.hh` ("IP: GHIDRA ... Licensed under the Apache License, Version 2.0"). So `jingle_sleigh`, `libsla`, and `sleigh-compiler` are **license-clean**. The reason to avoid them is **not licensing — it is that they compile ~120k LOC of vendored C++**, which breaks the single-static-binary / zero-dependency goal, adds a C++ toolchain requirement, inflates binary size, and (for `sleigh-compiler`) makes every build slow.

**On the "infectious license" fear:** **It does not apply to any crate in this survey.** Measured license distribution: MIT (5), Apache-2.0 (8), BSD-2-Clause (1), MIT-OR-Apache-2.0 (2), MIT-AND-Apache-2.0 (1). **Zero GPL, LGPL, AGPL, or SSPL.** However — note that this survey only covers the named crates. **Transitive** dependencies were not audited (e.g. `jingle`'s `z3-sys`, `rsleigh`'s CLI deps, `wazabin`'s bincode/pest deps). Run `cargo deny` / `cargo-about` over the actual tree before shipping.

**Ranked shortlist for replacing/paralleling capstone within the single-binary constraint:**
1. **`ghidra-decompiler` (koute)** — only pure-Rust full decompiler, Apache-2.0, zero C/C++. Highest payoff, lowest maturity.
2. **`wazabin-sleigh` + `wazabin-sleigh-precompile`** — pure-Rust SLEIGH compiler/decoder with embedded Apache-2.0 specs. MIT + Apache-2.0. Note: compiles specs in `build.rs` (slow builds).
3. **`rsleigh`** — Apache-2.0 pure-Rust **codegen** (emits Rust decoders from specs). Attractive build model, low adoption.
4. **`sleigh-config`** — Apache-2.0 data-only `.sla` blobs covering all 9 target architectures; needs a decoder to pair with (`libsla`, which is FFI).
5. **Reference-only, do not depend on:** `fission-systems/Fission` (study `fission-sleigh`/`fission-pcode`), `sefcom/oxidizer` (algorithms).

**Explicitly not usable for BitFlip's stated goal:** `jingle_sleigh`, `libsla`, `sleigh-compiler` (all FFI/vendored C++), `reoxide` (needs external host), `sefcom/oxidizer` (Python/angr), `fugue-sleigh` (no public repo), `sleigh-rs` (abandoned, parser-only).

**Items marked unverified (do not treat as fact):** exact architecture lists for `jingle_sleigh`, `libsla`, `sleigh-compiler`, `fugue-sleigh`, `mogi_sleigh`, `fission-sleigh`; the content of Ghidra's root `NOTICE` file; whether `mnemonikr/sleigh-compiler` and `mnemonikr/sleigh-config` repos have commits newer than their last crates.io publish; third-party provenance of individual files inside `Garfield1002/open_sleigh`; and the legal interpretation in §17 (reasoned from the Apache-2.0 text, not legal advice).
