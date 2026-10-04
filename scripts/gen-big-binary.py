#!/usr/bin/env python3
"""生成 100MB 级的大文件逆向测试 fixture。

为什么不直接把系统上的大文件（MRT.exe 之类）拿来测：那种文件只能证明
"没崩"。大文件上真正危险的失败模式是"没崩但结果全错"——分块扫描的地址
错位、跨块丢数据、覆盖率统计漏算，这些都需要**已知的正确答案**。

本脚本的做法是把一份结构完全确定的 C 源展开 N 次，再把结果链接成可执行
文件；每一份 unit 产出固定数量的函数与字符串，因此所有期望值都能用 N 的
公式算出来。测试里直接断言具体数字。

实际抓到的 bug（保留在注释里当回归说明）：
    `StringScanner::feed` 早先用块内下标当偏移，导致大于一个分块的段
    会产出成批地址相同的字符串，排序去重后只剩第一块。在 100MB 的
    `.rdata` 上表现为"只扫出 122/300 个 unit"。修复后 1200/1200。

用法：
    python scripts/gen-big-fixture.py --out tests/fixtures/generated/big-x86_64.exe

脚本会依次生成源码、调用 clang 链接。生成物全部落在 gitignored 的
tests/fixtures/generated/ 下（见 CLAUDE.md §0.2：样本不入库）。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

# 与 gen-big-fixture.py（C 源生成器）保持一致的常量。
# 每份 unit 产出 4 个字符串字面量与 3 个函数
# （str_xxx 是数据不是函数：它返回一个指针，但 clang 会把它内联成
#  数据引用，所以不计入函数期望值 —— 这里只算 work/hash/chain 三个）。
STRINGS_PER_UNIT = 4
FUNCS_PER_UNIT = 3

# 默认规模：320 份 unit，每份 320 KiB 填充 ≈ 100 MB 可执行文件。
#
# 填充是**摊进每份 unit** 的（见 gen-big-fixture.py 的 emit_unit），
# 不是堆在文件末尾 —— 堆在末尾会让所有待断言的字符串挤在第一个 4 MiB
# 分块里，"跨分块扫描"这条覆盖就形同虚设。第一版正是那样，带 bug 的
# 代码在 100MB 文件上依然全绿。
#
# 100MB 这个量级是刻意的：稳稳越过 8 MiB 嗅探窗口与 4 MiB 扫描分块
# 两个边界，各跨一个数量级。
DEFAULT_UNITS = 320
# 每份 unit 的填充大小（MiB）。320 份 × 320 KiB ≈ 100 MiB。
PAD_KB_PER_UNIT = 320


def find_clang() -> str:
    """找一个能用的 clang。优先 LLVM 目录（本机已验证）。"""
    for candidate in (
        r"E:\LLVM\bin\clang.exe",
        r"C:\Program Files\LLVM\bin\clang.exe",
    ):
        if Path(candidate).exists():
            return candidate
    found = shutil.which("clang")
    if found:
        return found
    print("找不到 clang：请安装 LLVM 或把 clang 放进 PATH", file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    parser = argparse.ArgumentParser(description="生成大文件逆向测试 fixture")
    parser.add_argument(
        "--out",
        required=True,
        help="输出的可执行文件路径（建议放 tests/fixtures/generated/ 下）",
    )
    parser.add_argument(
        "--units", type=int, default=DEFAULT_UNITS, help=f"unit 份数（默认 {DEFAULT_UNITS}）"
    )
    parser.add_argument(
        "--pad-kb",
        type=int,
        default=PAD_KB_PER_UNIT,
        help=f"**每份 unit** 的填充大小 KiB（默认 {PAD_KB_PER_UNIT}；0 = 不填充）",
    )
    parser.add_argument(
        "--keep-source", action="store_true", help="保留下载的 C 源（便于人工检查）"
    )
    args = parser.parse_args()

    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    script_dir = Path(__file__).resolve().parent
    gen_src = script_dir / "gen-big-fixture.py"
    src = out.with_suffix(".c")

    # 生成器按 MiB 收参数；--pad-kb 不足 1 MiB 时向上取整到 1 MiB
    # （填充块的最小粒度就是 1 MiB，见 PAD_UNIT）。
    pad_mib = max(1, round(args.pad_kb / 1024)) if args.pad_kb > 0 else 0

    est = args.units * pad_mib
    print(
        f"[1/3] 生成 C 源：{src.name}"
        f"（{args.units} 份 unit，每份填充 {pad_mib} MiB，合计约 {est} MiB）"
    )
    subprocess.run(
        [sys.executable, str(gen_src), str(src), str(args.units), str(pad_mib)],
        check=True,
    )

    clang = find_clang()
    print(f"[2/3] 编译并链接（clang: {clang}）")
    # -O0 -fno-inline：函数不能被内联或去重，否则"函数数可预测"这个前提就没了。
    # 每份 unit 的填充块都在 main 里被真的读一遍（见 gen-big-fixture.py），
    # 否则会被当成未使用数据删掉。
    cmd = [
        clang,
        "-O0",
        "-fno-inline",
        "--target=x86_64-pc-windows-gnu",
        "-o",
        str(out),
        str(src),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("编译失败：", file=sys.stderr)
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return 1

    size_mib = out.stat().st_size / (1024 * 1024)
    print(f"[3/3] 完成：{out}  {size_mib:.1f} MiB")

    # 自检：输出的文件必须真的够大。生成器静默退化成小文件会让
    # 那些"跨分块"的测试在**没有跨块**的情况下通过，覆盖悄悄消失。
    if size_mib < 16:
        print(
            f"警告：产出只有 {size_mib:.1f} MiB，不足以跨过 4 MiB 扫描分块 —— "
            f"大文件测试会失去意义。请调大 --units 或 --pad-kb。",
            file=sys.stderr,
        )

    if not args.keep_source:
        src.unlink(missing_ok=True)

    print()
    print("期望值（测试可直接引用）：")
    print(f"  函数（符号表内，不含 CRT）：{args.units * FUNCS_PER_UNIT}")
    print(f"  字符串字面量：              {args.units * STRINGS_PER_UNIT}")
    print(f"  可达调用（main 里）：        {len(range(0, args.units, 16))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
