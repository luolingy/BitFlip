#!/usr/bin/env python3
"""生成数据/代码判定的黄金 fixture。

# 为什么需要它

M6 验收标准 2 要求"数据/代码误判率有量化指标与回归门禁"。量化需要
**黄金标准** —— 一组"这些地址确实是代码、那些确实是数据"的标注。

标注不能来自我们自己的分析器（那是自己跟自己比），必须来自编译器。

# 做法

写一个 C 文件，让编译器明确产出两类东西：

* **代码**：一组真实函数。它们的地址能从符号表读出来，而且符号表里
  带大小 —— 这就是编译器盖章的代码范围。
* **数据**：一组全局数组，内容刻意做成**看起来像指令**的字节
  （例如 0x55 0x48 0x89 0xe5 是 `push rbp; mov rbp,rsp` 的序言）。
  这样才测得出"只看能不能解码"的误判 —— 如果数据是随机的零，
  任何判定器都能轻易说"这不是代码"，测不出真问题。

然后用 `llvm-nm` / `llvm-objdump` 把编译器的结论读出来，生成标注文件。

# 输出

* `<out>` —— 编译产物（.o 或 .exe）
* `<out>.truth.txt` —— 标注：每行 `<addr> <code|data> <name>`

用法：
    python scripts/gen-codemap-fixture.py --out tests/fixtures/generated/codemap-x86_64.exe
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# 刻意做成"像指令"的数据。前几字节是 x86_64 的常见函数序言，
# 后面是看起来像指令的填充 —— 目的就是让"能不能解码"失效。
DATA_PREAMBLE = "55 48 89 e5 48 83 ec 20 48 8d 3d 00 00 00 00"

SOURCE_TEMPLATE = r"""
/* 数据/代码判定 fixture。
 *
 * 编译成 x86_64 PE，带符号表（不 strip），这样函数名与边界都还在。
 */

/* 一组"像代码"的数据数组。内容刻意选成 x86_64 函数序言的字节，
 * 用来检验判定器**不会**因为"能解码"就把它当代码。 */
__attribute__((used, section(".rdata")))
const unsigned char cm_looks_like_code_0[64] = {{
{data0}
}};

__attribute__((used, section(".rdata")))
const unsigned char cm_looks_like_code_1[64] = {{
{data1}
}};

/* 一组普通字符串数据，作为对照。 */
__attribute__((used, section(".rdata")))
const char cm_strings[] = "bitflip codemap fixture / 数据代码判定";

/* 真实函数。每个都做点无法被优化掉的计算，保证生成代码。 */
volatile int cm_sink;

static int cm_mix(int v, int k) {{
    return (v * 2654435761u) ^ (v >> (k & 7));
}}

int cm_alpha(int x) {{
    int a = cm_mix(x, 3);
    int b = cm_mix(a, 5);
    return a ^ b;
}}

int cm_beta(int x) {{
    int r = 0;
    for (int i = 0; i < (x & 31); i++) {{
        r = cm_mix(r + i, i);
    }}
    return r;
}}

int cm_gamma(int x, int y) {{
    switch (x & 15) {{
    case 0: return cm_mix(y, 1);
    case 1: return cm_mix(y, 2);
    case 2: return cm_mix(y, 3);
    case 3: return cm_mix(y, 4);
    case 4: return cm_mix(y, 5);
    case 5: return cm_mix(y, 6);
    case 6: return cm_mix(y, 7);
    case 7: return cm_mix(y, 8);
    case 8: return cm_mix(y, 9);
    case 9: return cm_mix(y, 10);
    case 10: return cm_mix(y, 11);
    case 11: return cm_mix(y, 12);
    case 12: return cm_mix(y, 13);
    case 13: return cm_mix(y, 14);
    case 14: return cm_mix(y, 15);
    default: return cm_mix(y, 16);
    }}
}}

/* 入口。不叫 main，避免 mingw 的 CRT 依赖。 */
void cm_entry(int argc, char **argv) {{
    cm_sink = cm_alpha(argc) + cm_beta(argc) + cm_gamma(argc, argc);
    cm_sink += (int)cm_looks_like_code_0[0];
    cm_sink += (int)cm_looks_like_code_1[0];
    cm_sink += (int)cm_strings[0];
}}
"""


def find_tool(name: str) -> str | None:
    """在常见的 LLVM 安装位置找工具。"""
    candidates = [
        os.environ.get("LLVM_BIN"),
        r"E:\LLVM\bin",
    ]
    for base in candidates:
        if not base:
            continue
        p = Path(base) / f"{name}.exe"
        if p.exists():
            return str(p)
        p = Path(base) / name
        if p.exists():
            return str(p)
    # 退回到 PATH
    from shutil import which

    return which(name) or which(f"{name}.exe")


def hex_bytes(spec: str, count: int) -> list[str]:
    """把十六进制串展开成 count 字节，循环使用。"""
    raw = [int(b, 16) for b in spec.split()]
    out = []
    for i in range(count):
        out.append(f"0x{raw[i % len(raw)]:02x}")
    return out


def build_source() -> str:
    data = hex_bytes(DATA_PREAMBLE, 64)
    # 每行 12 个，读起来不至于太长
    lines = []
    for i in range(0, len(data), 12):
        lines.append(", ".join(data[i : i + 12]) + ",")
    body = "\n".join(lines)
    return SOURCE_TEMPLATE.format(data0=body, data1=body)


def compile_fixture(clang: str, src: Path, out: Path) -> None:
    """编译成带符号表的 x86_64 PE。"""
    cmd = [
        clang,
        "-O2",
        "-g0",
        "--target=x86_64-pc-windows-gnu",
        "-fuse-ld=lld",
        "-nostdlib",
        "-Wl,-e,cm_entry",
        "-Wl,--no-insert-timestamp",
        "-o",
        str(out),
        str(src),
    ]
    print("编译：", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, file=sys.stderr)
        print(r.stderr, file=sys.stderr)
        raise SystemExit(f"编译失败（exit {r.returncode}）")


def read_symbols(nm: str, target: Path) -> list[tuple[int, int, str]]:
    """读符号表：返回 (地址, 大小, 名字)。"""
    r = subprocess.run([nm, "--print-size", "--defined-only", str(target)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        raise SystemExit("llvm-nm 失败")
    out = []
    for line in r.stdout.splitlines():
        # 形如 `0000000140001000 0000000000000040 T cm_alpha`
        m = re.match(r"^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S)\s+(.+)$", line.strip())
        if not m:
            # 无大小的形式
            m2 = re.match(r"^([0-9a-fA-F]+)\s+(\S)\s+(.+)$", line.strip())
            if m2:
                out.append((int(m2.group(1), 16), 0, m2.group(3).strip()))
            continue
        out.append((int(m.group(1), 16), int(m.group(2), 16), m.group(4).strip()))
    return out


def load_vaddr(objdump: str, target: Path) -> int:
    """读 PE 的镜像基址，把 COFF 符号的节内偏移换算成虚拟地址。"""
    r = subprocess.run([objdump, "-p", str(target)], capture_output=True, text=True)
    m = re.search(r"ImageBase:\s*(0x[0-9a-fA-F]+)", r.stdout)
    if not m:
        return 0
    return int(m.group(1), 16)


def read_unwind(objdump: str, target: Path) -> list[tuple[int, int, str]]:
    """读 `.pdata` 展开表：返回 (起始, 结束, 名字)。

    这是**编译器写死的**函数范围，比符号表可靠 —— lld 生成的 COFF
    符号表里 size 是 0（实测），拿不到边界，而 `.pdata` 一定带
    StartAddress 与 EndAddress。
    """
    r = subprocess.run([objdump, "--unwind", str(target)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return []
    out: list[tuple[int, int, str]] = []
    start = end = None
    name = ""
    for line in r.stdout.splitlines():
        line = line.strip()
        m = re.match(r"StartAddress:\s*(?:(\S+)\s*\()?(0x[0-9a-fA-F]+)\)?", line)
        if m:
            name = m.group(1) or ""
            start = int(m.group(2), 16)
            continue
        m = re.match(r"EndAddress:\s*\(?(0x[0-9a-fA-F]+)\)?", line)
        if m and start is not None:
            end = int(m.group(1), 16)
            out.append((start, end, name))
            start = end = None
            name = ""
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="生成数据/代码判定黄金 fixture")
    ap.add_argument("--out", required=True, help="输出文件路径")
    ap.add_argument("--keep-source", action="store_true", help="保留生成的 .c 文件")
    args = ap.parse_args()

    clang = find_tool("clang")
    nm = find_tool("llvm-nm")
    objdump = find_tool("llvm-objdump")
    if not clang or not nm:
        print("找不到 clang / llvm-nm，请设置 LLVM_BIN", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    src = out.with_suffix(".c")
    src.write_text(build_source(), encoding="utf-8")

    compile_fixture(clang, src, out)

    base = load_vaddr(objdump, out) if objdump else 0
    syms = read_symbols(nm, out)
    unwind = read_unwind(objdump, out) if objdump else []

    # 符号表里带 `cm_` 前缀的名字 → 地址。用来判 data，以及在
    # unwind 缺失时兜底给代码范围。
    sym_by_name = {
        name: addr
        for addr, _size, name in syms
        if name.startswith("cm_")
    }

    CODE_NAMES = {"cm_alpha", "cm_beta", "cm_gamma", "cm_entry", "cm_mix"}

    truth: list[str] = []
    covered: set[int] = set()

    # ── 代码：优先用 `.pdata` 的精确范围 ──
    for start, end, name in unwind:
        if not (name.startswith("cm_") or name in CODE_NAMES):
            continue
        # 每个函数只标注入口与**中间**几个地址：我们要测的是"判定器
        # 对代码的识别率"，标全部字节会让打分被长函数主导。
        for a in (start, start + 1, (start + end) // 2, end - 1):
            truth.append(f"{a:016x} code {name or 'cm_func'}")
            covered.add(a)

    # ── 代码兜底：符号表里是 T 的，且 .pdata 没覆盖到 ──
    for addr, _size, name in syms:
        if name in CODE_NAMES and addr not in covered:
            truth.append(f"{addr:016x} code {name}")
            covered.add(addr)

    # ── 数据：`.rdata`/`.data` 里的 cm_ 符号 ──
    for addr, _size, name in syms:
        if not name.startswith("cm_"):
            continue
        if name in CODE_NAMES:
            continue
        # 同样只取几个代表地址
        for off in (0, 1, 8, 32):
            a = addr + off
            if a not in covered:
                truth.append(f"{a:016x} data {name}")
                covered.add(a)

    # 结果按地址排序，便于人核对
    truth.sort()
    truth_path = Path(str(out) + ".truth.txt")
    header = [
        "# 数据/代码判定黄金标准（由编译器产出，非本分析器）",
        "# 格式：<16位十六进制地址> <code|data> <符号名>",
        "# 生成：python scripts/gen-codemap-fixture.py --out <out>",
        f"# 目标：{out.name}  镜像基址：{base:#x}",
        f"# 代码范围来自 .pdata 展开表：{len(unwind)} 条",
    ]
    truth_path.write_text("\n".join(header + truth) + "\n", encoding="utf-8")

    print(f"已生成 {out}（{out.stat().st_size} 字节）")
    print(f"已生成 {truth_path}（{len(truth)} 条标注）")
    print(f"  code: {sum(1 for t in truth if ' code ' in t)}")
    print(f"  data: {sum(1 for t in truth if ' data ' in t)}")
    for line in truth:
        print("  " + line)

    if not args.keep_source:
        src.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
