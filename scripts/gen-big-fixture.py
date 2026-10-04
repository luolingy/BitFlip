#!/usr/bin/env python3
"""生成用于大文件逆向测试的 C 源。

为什么不直接找系统上的大文件测试：那种文件只能证明"没崩"。
大文件上真正危险的失败模式是"没崩但结果全错"——采样截断、跨块边界丢数据、
覆盖率统计漏算，这些都需要**已知的正确答案**才能发现。

所以这里生成一份结构完全已知的源：每份 unit 产出固定数量的函数、
字符串和一条调用链。生成 N 份，所有期望值都能用 N 的公式算出来，
测试里直接断言具体数字。

源文件是可重复生成的（同样的 N 得到同样的字节），因此不入库；
只有这个生成器和它的输出规模参数进仓库。
"""

from __future__ import annotations

import sys

HEADER = """\
// 自动生成，请勿手工修改。生成器：scripts/gen-big-fixture.py
//
// 每份 unit 产出：
//   * 1 个字符串构造函数（含 4 个不同的字符串字面量）
//   * 1 个哈希函数
//   * 1 个 unit 函数（调用哈希函数）
//   * 1 个 chain 函数（调用 unit 函数，形成调用链）
//   * 1 块 PAD_UNIT 字节的填充数据（把后面的字符串推到更远的分块里）
//
// 这些函数名与字符串都能被静态确定，测试据此断言精确计数。

#include <stdio.h>

#define PAD_UNIT (1024 * 1024)

"""


def emit_unit(idx: int) -> str:
    """产出一份 unit。编号 idx 从 0 起。

    **每份 unit 自带一块填充数据**，这是刻意的：如果填充全部堆在文件末尾，
    所有待断言的字符串都会挤在第一个 4 MiB 分块里，"跨分块扫描"这条
    覆盖就形同虚设 —— 第一版就是这样，带 bug 的代码在 100MB 文件上
    依然全绿。把填充摊进每个 unit，字符串才会均匀铺满整个段。
    """
    tag = f"u{idx:05d}"
    # 可识别字符串的字节写进 pad 数组**内部**（不是单独的 const 数组）。
    #
    # 这是本 fixture 最关键的一处：单独的字符串字面量会被编译器归拢到
    # 只读数据的同一片区域，几百个串全挤在第一个 4 MiB 分块里 ——
    # 那样"跨分块扫描"这条覆盖是空的（实测：带 bug 的代码在 100MB
    # 文件上依然全绿）。写进 pad 内部，它们就必然随 pad 铺满整个段。
    # 把 4 个可识别字符串**拼成一个连续的字节串**，直接写进 pad 数组开头。
    #
    # 两个关键点：
    #  * 写进 pad 内部而不是用独立的字符串字面量 —— 独立的字面量会被编译器
    #    归拢到只读数据的同一片区域，几百个串全挤在第一个 4 MiB 分块里，
    #    跨块路径根本走不到（第一版就是这样，带 bug 依然全绿）。
    #  * 只写**一份**。早先同时在 `pad_marker_[]` 和 `pad_[]` 里各放一份，
    #    同一个字符串在二进制里出现两次，去重后计数自然对不上。
    blob = b"".join(
        f"bitflip-unit-{idx:05d}-{suffix}\0".encode("ascii")
        for suffix in ("alpha", "beta", "gamma", "delta")
    )
    marker_bytes = "".join(f"0x{b:02x}," for b in blob)
    return f"""\
static const unsigned char pad_{tag}[PAD_UNIT] = {{
    // 开头就是 4 个可识别字符串（见生成器注释）：它们随填充块铺满整个段，
    // 因此每一块都落在不同的 4 MiB 扫描分块里。
    {marker_bytes}
    [PAD_UNIT - 8] = 0x62, 0x66, 0x6c, 0x69, 0x70, 0x00, 0x01, 0x02,
}};

const char *str_{tag}(int i) {{
    // 每个串 24 字节（23 字符 + NUL），不含未终止的尾串
    return (const char *)(pad_{tag} + (i & 3) * 24);
}}

/// 触摸本 unit 内嵌的可识别字符串，防止被优化掉。
int marker_{tag}(int i) {{
    return pad_{tag}[(i & 3) * 24];
}}

int {tag}_hash(const char *s) {{
    unsigned int h = 2166136261u;
    while (*s) {{
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }}
    return (int)(h & 0x7fffffff);
}}

int {tag}_work(int depth) {{
    return {tag}_hash(str_{tag}(0)) + depth;
}}

int {tag}_chain(int depth) {{
    if (depth <= 0) {{
        return {idx} * 31;
    }}
    return {tag}_work(depth - 1);
}}

"""


def emit_main(count: int, pad_units: int) -> str:
    """入口：调用每隔一段取一个 unit，保证一部分可达、一部分不可达。

    同时把每份 unit 的填充块都读一遍 —— 不读的话优化器会把它们
    整个删掉，"文件变大"这件事就没发生。
    """
    calls = []
    # 每 16 个里调一个：可达函数数是确定的，用来验证
    # "符号表里有"与"真的可达"这两类函数确实被区分开。
    for i in range(0, count, 16):
        calls.append(f"    total ^= u{i:05d}_chain(argc + {i & 7});")

    # 所有 pad 与 marker 都要被引用，否则会被当成未使用数据删除。
    pads = []
    if pad_units > 0:
        for i in range(count):
            pads.append(f"    total ^= pad_u{i:05d}[argc & (PAD_UNIT - 1)];")
            # 触摸 marker：保证那串可识别字符串真的进二进制。
            # 没有这一句，编译器发现没人用就会把整串丢掉。
            pads.append(f"    total ^= marker_u{i:05d}(argc);")
    body = "\n".join(calls) if calls else "    total = 0;"
    pad_body = "\n".join(pads)
    return f"""\
int main(int argc, char **argv) {{
    int total = 0;
{body}
{pad_body}
    printf("bitflip big fixture: %d (argv=%p)\\n", total, (void *)argv);
    return total & 0x7f;
}}
"""


def main() -> int:
    if len(sys.argv) not in (3, 4):
        print(
            "用法: gen-big-fixture.py <输出路径> <unit 份数> [填充 MiB 数]",
            file=sys.stderr,
        )
        return 2
    out_path = sys.argv[1]
    try:
        count = int(sys.argv[2])
    except ValueError:
        print(f"份数必须是整数：{sys.argv[2]!r}", file=sys.stderr)
        return 2
    if count <= 0:
        print("份数必须为正", file=sys.stderr)
        return 2
    pad_units = 0
    if len(sys.argv) == 4:
        try:
            pad_units = int(sys.argv[3])
        except ValueError:
            print(f"填充大小必须是整数：{sys.argv[3]!r}", file=sys.stderr)
            return 2
        if pad_units < 0:
            print("填充大小不能为负", file=sys.stderr)
            return 2

    parts = [HEADER.format()]
    for i in range(count):
        parts.append(emit_unit(i))
    parts.append(emit_main(count, pad_units))

    # 源里带中文注释（面向用户），所以按 UTF-8 写。
    # 行尾统一 LF：生成结果要可重复，不能跟着平台漂移。
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(parts))
    print(f"已生成 {out_path}：{count} 份 unit，填充 {pad_units} MiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
