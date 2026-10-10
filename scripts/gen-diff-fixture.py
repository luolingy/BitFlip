#!/usr/bin/env python3
"""生成"同族两版本"二进制的差分 fixture 对（v1 / v2）。

# 为什么需要它

差分视图的验收标准必须是**可量化**的，否则"看着挺像"就成了标准。量化需要
黄金真值：一组"这些函数确实新增了、那些确实删了、另外那些确实没动"的标注。

真值不能来自我们自己的差分实现（自己跟自己比），必须来自编译器与链接器：
本脚本编译两个源文件版本，再用 `llvm-nm --print-size` 把两个版本的符号表读出来，
两侧做集合运算得到真值。也就是说，**差异是编译器实际产出的**，不是我们以为的。

# 受控差异（v1 -> v2，刻意包含四类）

1. **新增**：`df_added`（v2 才有）—— 检验"新增"能被报出来。
2. **删除**：`df_removed`（v1 才有）—— 检验"删除"能被报出来。
3. **改动**：`df_changed` 的函数体换成不同的实现 —— 检验"同地址但内容变了"。
   刻意让 v2 的版本体更大，这样它后面的函数地址会**整体后移** —— 这是检验
   地址归一化是否必要的那根钉子（裸比 VA 会把它们全判成"变了"）。
4. **不变**：`df_stable`、`df_helper`、`df_entry` —— 检验**不产生假阳性**。
   "什么都没报错"和"该报的没报"是两件事，所以不变项是必须有的对照组。

# 基址差异（第二个钉子）

`--image-base` 给 v2 换一个基址。这样两个文件的**虚拟地址**整体不同，
而 RVA（相对镜像基址）相同。差分必须按 RVA 比，并且把用的是哪种归一化
**写进输出** —— 否则用户拿到的是一份"全都变了"的假报告。

# 输出

  <out>-v1.exe / <out>-v2.exe     两版样本（PE，x86_64，带符号）
  <out>.truth.txt                 真值清单（由两个符号表相减得到）

用法：
    python scripts/gen-diff-fixture.py --out tests/fixtures/generated/diff-pe-x86_64
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# Windows 控制台默认按本地代码页（本机是 cp936）编码输出，而这个脚本的日志是
# 中文 —— 结果是满屏乱码（实测如此），日志也就白打了。强制 UTF-8 让字节正确。
# `reconfigure` 在 Python 3.7+ 的文本流上可用；不可用就算了，不该因此失败。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass

# v2 的镜像基址：刻意与 v1 不同，用来证明归一化是必需的而不是装饰。
V1_IMAGE_BASE = 0x140000000
V2_IMAGE_BASE = 0x180000000

# 两个版本共有的部分。编译成 x86_64 PE、无 CRT、带符号（不 strip）。
COMMON_PRELUDE = r"""
/* 差分的稳定部分：两个版本里内容与名字都不变。
 * 这些函数是"不产生假阳性"的对照组 —— 差分若把它们报成变化，
 * 那就是在造噪音，比漏报更容易让人失去信任。 */

volatile int df_sink;

__attribute__((noinline))
static int df_helper(int v) {
    return (v * 2654435761u) >> 3;
}

/* v1 与 v2 里逐字节相同。 */
__attribute__((noinline))
int df_stable(int x) {
    int a = df_helper(x);
    return a ^ (a >> 7);
}
"""

# v1 独有的一段。
#
# 关于"独有"有多独有，第一版搞错了：把 df_removed 写成只被 df_entry 调用，
# 于是 -O1 把它**内联**进 df_entry —— 符号标签还在文件里（`llvm-nm` 看得到），
# 但**分析器看到的函数清单里没有它**，测试因此拿到 "df_removed 实际 None"。
# 原因不是差分实现错，是 fixture 没造出"一个真实存在、真被删掉的函数"。
#
# 所以这里要求它以独立函数体存在，而且必须是**可达**代码：死代码会被
# 编译器或链接器（--gc-sections）直接扔掉，那样两个版本里都没有它，
# "删除"就无从谈起。
V1_MIDDLE = r"""
/* v1 独有：v2 里删掉了这个函数。 */
__attribute__((noinline))
int df_removed(int x) {
    int r = df_helper(x) + 0x5eed;
    if (r == 0x7f3a1111) {
        df_sink = r;
    }
    return r + (r >> 11);
}

/* v1 的函数体较小；v2 会换成更大的实现，从而把它后面的函数地址推后。
 *
 * 这里刻意放一个 `volatile` 局部变量：它逼编译器开出栈帧，于是链接器会在
 * `.pdata` 里留下这条函数的起止地址。没有 `.pdata` 的叶子函数**分析器拿不到
 * 结束地址**（看不到区间 → 比不了内容），那样这条 fixture 只能覆盖到
 * "大小不同"，覆盖不到真正的"指令序列不同"。 */
__attribute__((noinline))
int df_changed(int x) {
    volatile int keep = x;
    return df_helper(keep) + 1;
}
"""

# v2 独有的一段：新增函数 + df_changed 的更大实现。
V2_MIDDLE = r"""
/* v2 独有：新增函数。 */
__attribute__((noinline))
int df_added(int x) {
    int r = df_helper(x) * 3;
    if (r == 0x7f3a2222) {
        df_sink = r;
    }
    return r ^ (r >> 9);
}

/* v2 的函数体刻意做得更大：后面的函数地址因此整体后移，
 * 这就是"必须按归一化地址比"的证据。 */
__attribute__((noinline))
int df_changed(int x) {
    int r = 0;
    for (int i = 0; i < (x & 63); i++) {
        r = df_helper(r + i) ^ (r << 1);
        r += df_stable(i);
    }
    r ^= 0x1234;
    r = df_helper(r);
    return r + (r >> 5) + 0xabc;
}
"""

# 两个版本共有的入口。
#
# `df_entry` 与 `df_variant` 在两个版本里**逐字节相同**：入口只调用 df_variant，
# 差异全在 df_variant 里。这样盯住"谁被删谁被加"的钉子只有一处，
# df_entry 的形态也就在两版里一致（便于观察"移动"）。
ENTRY = r"""
int df_variant(int x) {
#ifdef V2
    return df_added(x);
#else
    return df_removed(x);
#endif
}

void df_entry(int argc, char **argv) {
    df_sink = df_stable(argc) + df_changed(argc) + df_variant(argc);
}
"""

# 真值里要跟踪的函数名（其余是链接器/编译器自带的，不属于本次差异）。
TRACKED = [
    "df_stable",
    "df_removed",
    "df_changed",
    "df_added",
    "df_entry",
    "df_helper",
    "df_variant",
]


def find_tool(name: str) -> str | None:
    """在常见的 LLVM 安装位置找工具，退回到 PATH。"""
    from shutil import which

    for base in (os.environ.get("LLVM_BIN"), r"E:\LLVM\bin"):
        if not base:
            continue
        for candidate in (Path(base) / f"{name}.exe", Path(base) / name):
            if candidate.exists():
                return str(candidate)
    return which(name) or which(f"{name}.exe")


def build_source(which: str) -> str:
    """拼出某个版本的完整源文件。"""
    middle = V1_MIDDLE if which == "v1" else V2_MIDDLE
    define = "" if which == "v1" else "\n#define V2 1\n"
    return define + COMMON_PRELUDE + middle + ENTRY


def compile_fixture(clang: str, src: Path, out: Path, image_base: int) -> None:
    """编译成带符号的 x86_64 PE。"""
    cmd = [
        clang,
        "-O1",
        "-g0",
        "--target=x86_64-pc-windows-gnu",
        "-fuse-ld=lld",
        "-nostdlib",
        "-Wl,-e,df_entry",
        "-Wl,--no-insert-timestamp",
        f"-Wl,--image-base={image_base:#x}",
        "-o",
        str(out),
        str(src),
    ]
    print("编译：", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"编译失败（exit {result.returncode}）")


def read_symbols(nm: str, target: Path) -> dict[str, tuple[int, int]]:
    """读符号表：名字 -> (地址, 大小)。

    只保留被跟踪的 `df_*` 名字：链接器会带出 `__image_base__` 之类的
    内部符号，把它们算进差异会让真值变成噪音。
    """
    result = subprocess.run(
        [nm, "--print-size", "--defined-only", str(target)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        raise SystemExit("llvm-nm 失败")

    out: dict[str, tuple[int, int]] = {}
    for line in result.stdout.splitlines():
        match = re.match(
            r"^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S)\s+(.+)$", line.strip()
        )
        if not match:
            continue
        address = int(match.group(1), 16)
        size = int(match.group(2), 16)
        name = match.group(4).strip()
        if name in TRACKED:
            out[name] = (address, size)
    return out


def read_disassembled_function_labels(objdump: str, target: Path) -> set[str]:
    """读 `llvm-objdump -d` 里**真正作为函数被反汇编出来**的标签。

    # 为什么需要这一步（踩过的坑）

    符号在文件里，不等于**分析器能看见一个函数**。第一版 fixture 把
    `df_removed` 写成只被入口调用，`-O1` 把它内联进调用方：`llvm-nm` 照样
    列出 `df_removed`（那是别名标签），但真实代码里没有这个函数体 ——
    分析器看不到它，差分自然也报不出"删除"。

    真值由符号表产出、而实现只看得见函数清单，两者错位时测试会红在
    **实现**上，指向完全错误的方向。所以生成器自己先把这件事查出来：
    符号表里有的、反汇编标签里没有的，就是"不存在独立函数体"的，
    直接报错而不是产出一个会误导人的 fixture。
    """
    result = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(target)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return set()
    labels: set[str] = set()
    for line in result.stdout.splitlines():
        # 形如 `0000000140001030 <df_removed>:`
        match = re.match(r"^[0-9a-fA-F]{8,}\s+<(\S+)>:", line.strip())
        if match:
            labels.add(match.group(1))
    return labels


def check_functions_are_real(
    objdump: str | None, target: Path, symbols: dict[str, tuple[int, int]], wanted: list[str]
) -> None:
    """确认期望的函数**真的以独立函数体的形式存在**。

    这是本脚本最重要的一道自检：它挡的不是"脚本写错"，而是
    "fixture 看起来对、其实测不出该测的东西"。缺一个就直接失败，
    因为缺了的那一条会让端到端测试红在实现上。
    """
    if not objdump:
        print(
            f"  警告：找不到 llvm-objdump，跳过 {target.name} 的函数体自检",
            file=sys.stderr,
        )
        return
    labels = read_disassembled_function_labels(objdump, target)
    if not labels:
        print(
            f"  警告：{target.name} 反汇编里没读到任何函数标签，跳过自检",
            file=sys.stderr,
        )
        return

    missing = [
        name
        for name in wanted
        if name in symbols and not any(label.startswith(name) for label in labels)
    ]
    if missing:
        print("", file=sys.stderr)
        print(
            f"错误：{target.name} 的符号表里有 {missing}，但它们没有被反汇编成"
            "独立函数 —— 大概率被内联了。",
            file=sys.stderr,
        )
        print(
            "  这样的 fixture 测不出对应差异，而且测试会红在差分实现上（方向错误）。",
            file=sys.stderr,
        )
        print("  修法：给这些函数加 noinline，并确保它们真的可达。", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="生成差分 fixture 对")
    parser.add_argument("--out", required=True, help="输出前缀（不含扩展名）")
    parser.add_argument("--keep-source", action="store_true", help="保留 .c 源文件")
    args = parser.parse_args()

    clang = find_tool("clang")
    nm = find_tool("llvm-nm")
    objdump = find_tool("llvm-objdump")
    if not clang or not nm:
        print("找不到 clang / llvm-nm，请设置 LLVM_BIN", file=sys.stderr)
        return 2

    prefix = Path(args.out)
    prefix.parent.mkdir(parents=True, exist_ok=True)

    v1_out = Path(str(prefix) + "-v1.exe")
    v2_out = Path(str(prefix) + "-v2.exe")

    sources: list[Path] = []
    for which, out, base in (
        ("v1", v1_out, V1_IMAGE_BASE),
        ("v2", v2_out, V2_IMAGE_BASE),
    ):
        src = Path(str(prefix) + f"-{which}.c")
        src.write_text(build_source(which), encoding="utf-8")
        sources.append(src)
        compile_fixture(clang, src, out, base)

    v1_syms = read_symbols(nm, v1_out)
    v2_syms = read_symbols(nm, v2_out)

    # 先自检：期望的函数必须真的作为独立函数体存在，否则这个 fixture
    # 测不出它该测的东西（而且会红在实现上，方向错误）。
    check_functions_are_real(
        objdump,
        v1_out,
        v1_syms,
        ["df_stable", "df_removed", "df_changed", "df_entry", "df_variant"],
    )
    check_functions_are_real(
        objdump,
        v2_out,
        v2_syms,
        ["df_stable", "df_added", "df_changed", "df_entry", "df_variant"],
    )

    only_v1 = sorted(set(v1_syms) - set(v2_syms))
    only_v2 = sorted(set(v2_syms) - set(v1_syms))
    both = sorted(set(v1_syms) & set(v2_syms))

    # "同地址不同字节"要按 RVA 比才准 —— 两个文件的基址本来就不同。
    # 这里同时输出 VA 与 RVA，让真值本身就带着"哪种才是对的"这个信息。
    #
    # 注意：真值只按**地址**分类，不判断内容差异。
    # `same-rva` = 两个版本里都在这个 RVA 上（**不代表内容没变**：本 fixture 里
    # `df_changed` 就是"同 RVA 但内容不同"）；`moved-rva` = 两版都在、但 RVA 不同。
    # 内容那一维要靠反汇编比，脚本不越俎代庖。
    moved_rva: list[str] = []
    same_rva: list[str] = []
    for name in both:
        a1, s1 = v1_syms[name]
        a2, s2 = v2_syms[name]
        r1 = a1 - V1_IMAGE_BASE
        r2 = a2 - V2_IMAGE_BASE
        if r1 == r2:
            same_rva.append(name)
        else:
            moved_rva.append(name)

    truth_lines = [
        "# 差分黄金标准（由 clang/lld + llvm-nm 产出，非本项目的差分实现）",
        "# 格式：<added|removed|same-rva|moved-rva> <函数名> [v1_va] [v2_va] [rva]",
        "# 生成：python scripts/gen-diff-fixture.py --out <prefix>",
        f"# v1: {v1_out.name}  镜像基址 {V1_IMAGE_BASE:#x}",
        f"# v2: {v2_out.name}  镜像基址 {V2_IMAGE_BASE:#x}",
        "#",
        "# 注意：两个文件的镜像基址刻意不同。所以裸比虚拟地址会得出"
        "「几乎每个函数都变了」，",
        "# 而按 RVA 比才是真相。差分实现必须按归一化地址比，并把方式写进输出。",
        "#",
        "# same-rva 只说明「两版都出现在这个 RVA 上」，**不说明内容相同**：",
        "# df_changed 就在这一组里，它的内容两版是不同的。",
        "#",
        f"# only-in-v1: {len(only_v1)}  only-in-v2: {len(only_v2)}  "
        f"same-rva: {len(same_rva)}  moved-rva: {len(moved_rva)}",
    ]
    for name in only_v1:
        va, _size = v1_syms[name]
        truth_lines.append(f"removed {name} {va:#x} - -")
    for name in only_v2:
        va, _size = v2_syms[name]
        truth_lines.append(f"added {name} - {va:#x} -")
    for name in same_rva:
        a1, _s1 = v1_syms[name]
        a2, _s2 = v2_syms[name]
        truth_lines.append(f"same-rva {name} {a1:#x} {a2:#x} {a1 - V1_IMAGE_BASE:#x}")
    for name in moved_rva:
        a1, _s1 = v1_syms[name]
        a2, _s2 = v2_syms[name]
        truth_lines.append(f"moved-rva {name} {a1:#x} {a2:#x} -")

    truth_path = Path(str(prefix) + ".truth.txt")
    truth_path.write_text("\n".join(truth_lines) + "\n", encoding="utf-8")

    print("")
    print(f"已生成 {v1_out}（{v1_out.stat().st_size} 字节）")
    print(f"已生成 {v2_out}（{v2_out.stat().st_size} 字节）")
    print(f"已生成 {truth_path}")
    print(f"  removed:   {len(only_v1)}  {only_v1}")
    print(f"  added:     {len(only_v2)}  {only_v2}")
    print(f"  same-rva:  {len(same_rva)}  {same_rva}")
    print(f"  moved-rva: {len(moved_rva)}  {moved_rva}")

    # 两个钉子必须成立，否则这个 fixture 测不出它该测的东西。
    if "df_added" not in only_v2:
        print("警告：df_added 没有落在 only-in-v2，受控差异没生效", file=sys.stderr)
    if "df_removed" not in only_v1:
        print("警告：df_removed 没有落在 only-in-v1，受控差异没生效", file=sys.stderr)
    if not moved_rva:
        print(
            "警告：没有任何函数发生 RVA 移动，地址归一化这条覆盖不到",
            file=sys.stderr,
        )

    if not args.keep_source:
        for src in sources:
            src.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
