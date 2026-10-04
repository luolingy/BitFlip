#!/usr/bin/env python3
"""生成共享库 fixture（.so / .dll），供 M5 的共享库语义测试使用。

为什么要自造而不是只用系统上的大 .so：系统样本只覆盖"没崩"，而且
97 MB 的样本分析一次要几分钟，不能进常规测试。这里造一个**小而结构完整**
的共享库，导出/导入/重定位都确定已知，测试直接断言精确结果。

用法：
    python scripts/gen-shared-lib.py --out tests/fixtures/generated/libsample.so
    python scripts/gen-shared-lib.py --out tests/fixtures/generated/sample.dll --kind dll
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

# fixture 的内容契约：测试按这些数字断言。
# 改动这里必须同步改 crates/bitflip-core/tests/shared_library.rs。
EXPORTED_FUNCS = [
    "sample_add",
    "sample_mul",
    "sample_chain",
]
# sample_chain 在内部调用 sample_add / sample_mul，
# 因此这两个同时是"导出"与"被调用目标"，用来验证两类来源能正确合并。
EXPORTED_DATA = ["sample_table", "sample_magic"]

C_SOURCE = """\
// 自动生成，请勿手工修改。生成器：scripts/gen-shared-lib.py
//
// 结构刻意做得确定：
//   * 3 个导出函数 + 2 个导出数据符号（用来验证导出表解析与 is_code 判定）
//   * sample_chain 调用另外两个导出函数（验证导出与调用目标两类来源合并）
//   * 一个 static 内部函数（不可导出，验证不会把内部符号当导出）
//   * 一个**只通过函数指针表可达**的函数（验证重定位驱动的指针表识别）
//   * 一个函数指针表（重定位驱动的指针表）

#include <stddef.h>

const int sample_magic = 0x5f3759df;

int sample_add(int a, int b);
int sample_mul(int a, int b);

int sample_add(int a, int b) {
    return a + b;
}

int sample_mul(int a, int b) {
    return a * b;
}

// 内部函数：没有导出，验证导出表只收对外的符号。
static int sample_internal(int x) {
    return x ^ 0x2a;
}

// **只被指针表引用、从不被直接调用**的内部函数。
//
// 这是重定位驱动的指针表识别唯一能覆盖的情形：没有任何 `call` 指向它，
// 没有符号表条目，因此前五个来源一个都碰不到它 —— 只有"重定位表往这个
// 槽位写地址"这条证据能把它找出来。
static int sample_via_pointer(int x, int y) {
    return x * 7 + y;
}

int sample_chain(int seed) {
    int acc = sample_add(seed, 7);
    acc = sample_mul(acc, 3);
    return sample_internal(acc);
}

// 指向自己函数的指针表：重定位驱动的指针表识别会用到它。
typedef int (*sample_fn)(int, int);
sample_fn sample_table[3] = { sample_add, sample_mul, sample_via_pointer };
"""

DEF_SOURCE = """\
; 自动生成，请勿手工修改。生成器：scripts/gen-shared-lib.py
LIBRARY sample
EXPORTS
    sample_add
    sample_mul
    sample_chain
"""


def find_clang() -> str:
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
    parser = argparse.ArgumentParser(description="生成共享库 fixture")
    parser.add_argument("--out", required=True, help="输出的 .so / .dll 路径")
    parser.add_argument(
        "--kind",
        choices=("so", "dll"),
        default="so",
        help="目标类型（默认 so；dll 只做不做链接的最小验证）",
    )
    parser.add_argument("--keep-source", action="store_true", help="保留 C 源")
    args = parser.parse_args()

    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    src = out.with_suffix(".c")
    src.write_text(C_SOURCE, encoding="utf-8", newline="\n")

    clang = find_clang()
    # 用 Linux 目标交叉生成 ELF 共享库：本机是 Windows，clang 可以直接
    # 产出并链接 ELF .so（自带 lld，不需要 WSL）。
    cmd = [
        clang,
        "-shared",
        "-fPIC",
        "-nostdlib",
        "--target=x86_64-linux-gnu",
        "-fuse-ld=lld",
        "-o",
        str(out),
        str(src),
    ]
    print(f"链接：{' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("链接失败：", file=sys.stderr)
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return 1

    # 剥掉 .symtab，只留 .dynsym。
    #
    # 这一步是**为了测试有效**而不是为了好看：完整的 .symtab 里含有
    # `sample_via_pointer`，于是它会以 symbol-table 来源被认出来，
    # 重定位指针表那条路径就永远走不到 —— 测试会在路径没被执行的情况下通过。
    # 剥掉之后，只有"重定位表往该槽位写了地址"这一条证据，才真正验证了实现。
    #
    # 真实世界里的发布版 .so 也基本都是剥过的，这更接近实际输入。
    strip_tool = shutil.which("llvm-strip") or str(
        Path(clang).with_name("llvm-strip.exe")
    )
    strip_result = subprocess.run(
        [strip_tool, "--strip-all", str(out)], capture_output=True, text=True
    )
    if strip_result.returncode != 0:
        print(f"警告：剥离符号失败（{strip_tool}）：{strip_result.stderr}", file=sys.stderr)
    else:
        print(f"已剥离符号表（{Path(strip_tool).name} --strip-all）")

    if not args.keep_source:
        src.unlink(missing_ok=True)

    print(f"完成：{out}（{out.stat().st_size} 字节）")
    print()
    print("期望值（测试按此断言）：")
    print(f"  导出函数：{len(EXPORTED_FUNCS)} 个 —— {', '.join(EXPORTED_FUNCS)}")
    print(f"  导出数据：{len(EXPORTED_DATA)} 个 —— {', '.join(EXPORTED_DATA)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
