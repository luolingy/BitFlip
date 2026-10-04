#!/usr/bin/env python3
"""生成跳转表（switch）测试 fixture。

# 为什么必须自己生成

跳转表的验收标准是"目标集合与编译器实际生成的**完全一致**"（PLAN M6
验收标准 1）。这要求两件事：

1. 我们**知道**正确答案是什么；
2. 这个答案来自编译器，不是来自我们自己的分析器。

做法：写一个 `switch` 语句覆盖一段**连续、密集**的 case 值
（0..N），编译器必然生成跳转表而不是比较链。然后用 llvm-objdump
把编译器生成的真实指令读出来，从中提取出表的地址与表项，作为黄金
数据。分析器的结论必须与它逐项相等。

密集 case 很关键：稀疏 case（0, 100, 1000）编译器会退回"比较链"，
根本不会生成表，那时测试会变成"在不存在的东西上验证正确性"。

# 为什么用 -O2

-O0 下 clang 往往也生成比较链；-O2 才会把它优化成表。但 -O2 也可能
把整个函数**常量折叠**掉（如果调用者可推导），所以用 `volatile` 和
外部可见的入口阻止它。

用法：
    python scripts/gen-jump-table-fixture.py --out tests/fixtures/generated/switch-x86_64.exe
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# case 的个数。取 16 是个折中：足够让编译器选择跳转表，又小到
# 黄金数据可以逐项写进测试里核对。
CASE_COUNT = 16

C_SOURCE = """\
// 自动生成，请勿手工修改。生成器：scripts/gen-jump-table-fixture.py
//
// 跳转表相关的 fixture。
//
// 密集的 0..{n} 连续 case：这种形态编译器会生成跳转表。
// 稀疏 case 会退化成比较链，那样就测不到跳转表了。
//
// case 体用 `jt_frob(i)` 而不是线性表达式：线性表达式（如 `i*3+7`）
// 会被 clang 在 -O2 下折叠成**闭式计算**（`leal 0x7(%rcx,%rcx,2)`），
// 根本不生成跳转表 —— 实测第一个版本就是这样，测试于是在"不存在
// 跳转表的函数"上验证跳转表识别。

volatile int jt_sink;

static int jt_frob(int v);

int jt_switch(int x) {{
    switch (x) {{
{cases}
        default:
            return -1;
    }}
}}

// 第二个 switch：case 顺序打乱，确认我们读的是**表序**而不是源码序。
int jt_switch_shuffled(int x) {{
    switch (x) {{
{cases_shuffled}
        default:
            return -1;
    }}
}}

// 非线性、且对各 case 取值互不相同 —— 编译器无法把它约简成公式，
// 因此只能生成跳转表。
static int jt_frob(int v) {{
    unsigned u = (unsigned)v * 2654435761u;
    u ^= u >> 13;
    return (int)(u & 0x3ff);
}}

// 真正的入口（-nostdlib，没有 CRT）。
//
// **不叫 `main`**：mingw 目标下名字为 `main` 的函数会让编译器引用
// `__main`（CRT 的一部分），而我们是 -nostdlib，链接会失败。
// 用 argc 驱动参数，避免两个 switch 被常量折叠掉。
void jt_entry(int argc, char **argv) {{
    (void)argv;
    jt_sink = jt_switch(argc);
    jt_sink += jt_switch_shuffled(argc + 1);
}}
"""


def find_clang() -> str:
    """找一个可用的 clang。"""
    for candidate in ("clang", "clang.exe"):
        found = shutil.which(candidate)
        if found:
            return found
    # 本机已知位置的兜底
    fallback = Path(r"E:\LLVM\bin\clang.exe")
    if fallback.exists():
        return str(fallback)
    print("找不到 clang", file=sys.stderr)
    sys.exit(1)


def find_objdump() -> str:
    """找 llvm-objdump（用来提取黄金数据）。"""
    for candidate in ("llvm-objdump", "llvm-objdump.exe"):
        found = shutil.which(candidate)
        if found:
            return found
    fallback = Path(r"E:\LLVM\bin\llvm-objdump.exe")
    if fallback.exists():
        return str(fallback)
    print("找不到 llvm-objdump", file=sys.stderr)
    sys.exit(1)


def build_source() -> str:
    """构造 C 源码。"""
    cases = "\n".join(
        f"        case {i}:\n            return jt_frob({i});" for i in range(CASE_COUNT)
    )
    # 打乱顺序：确认分析器读的是表里的顺序（由编译器定）而不是源码顺序。
    order = list(range(CASE_COUNT))
    order = order[1::2] + order[0::2]
    cases_shuffled = "\n".join(
        f"        case {i}:\n            return jt_frob({i}) + 1;" for i in order
    )
    return C_SOURCE.format(n=CASE_COUNT, cases=cases, cases_shuffled=cases_shuffled)


def dump_disassembly(objdump: str, target: Path) -> str:
    """反汇编，返回文本。"""
    result = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(target)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("反汇编失败：", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description="生成跳转表 fixture")
    parser.add_argument("--out", required=True, help="输出的 PE 路径")
    parser.add_argument("--keep-source", action="store_true", help="保留中间 C 文件")
    parser.add_argument(
        "--arch",
        default="x86_64",
        help="目标架构（默认 x86_64）",
    )
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    src = out.with_suffix(".c")
    src.write_text(build_source(), encoding="utf-8")

    clang = find_clang()
    target = f"{args.arch}-pc-windows-gnu"
    cmd = [
        clang,
        # -O2 是生成跳转表的必要条件（-O0 多为比较链）。
        "-O2",
        "-fno-omit-frame-pointer",
        f"--target={target}",
        # 用 lld 而不是 mingw ld：后者会去找 mainCRTStartup 与 __main，
        # 而我们是 -nostdlib（没有 CRT）。lld 配合显式入口可以直接链出
        # 一个干净的可执行文件。
        "-fuse-ld=lld",
        "-nostdlib",
        "-Wl,-e,jt_entry",
        "-o",
        str(out),
        str(src),
    ]
    print(f"编译：{' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("编译失败：", file=sys.stderr)
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return 1

    if not args.keep_source:
        src.unlink(missing_ok=True)

    print(f"已生成 {out}（{out.stat().st_size} 字节）")

    # 把编译器生成的真实跳转表打出来，供人工核对与黄金数据提取。
    objdump = find_objdump()
    disasm = dump_disassembly(objdump, out)
    jmp_lines = [
        line
        for line in disasm.splitlines()
        if re.search(r"\bjmp\s+(r|e)ax\b|\bjmpq?\s+\*", line)
    ]
    if jmp_lines:
        print(f"\n发现 {len(jmp_lines)} 处间接跳转：")
        for line in jmp_lines:
            print(f"  {line.strip()}")
    else:
        # 这不是错误，但必须说出来：没有间接跳转意味着 fixture 没测到
        # 我们想测的东西，测试会在"不存在的东西上验证正确性"。
        print(
            "\n警告：没有发现间接跳转 —— 编译器没有生成跳转表。\n"
            "      这条 fixture 无法验证跳转表识别，请检查优化等级与 case 分布。",
            file=sys.stderr,
        )
        return 0

    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    sys.exit(main())
