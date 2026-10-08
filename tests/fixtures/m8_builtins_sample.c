/*
 * M8 交付物 3（编译器内置模式库）的样本。
 *
 * 目的很具体：让编译器**真的**生成一个需要逐页探测的栈帧，从而把 libgcc 里那个真正的
 * `___chkstk_ms` 连进来。
 *
 * 为什么不用现成的 `m3_coverage_sample.c` 当黄金值：那边没有任何超过 4 KiB 的栈帧，
 * 那个符号未必是真正的逐页探测循环。拿一个"未必是探测循环"的东西当真值，等于什么都没验。
 *
 * 不 include 任何头文件：mingw 的 gcc 在不需要 CRT 类型时也能编；`volatile` 用来阻止
 * 优化把栈访问删掉（栈帧没了，探测也就没了）。
 */

volatile int bf_builtins_sink;

/* 8 KiB 的栈帧：x86_64 上一页是 4 KiB，编译器必须逐页探测，否则可能跳过栈守卫页。 */
int bf_builtins_big(int n)
{
    volatile char page[8192];
    int i;
    int sum = 0;

    for (i = 0; i < 8192; i += 64) {
        page[i] = (char)(n + i);
    }
    for (i = 0; i < 8192; i += 511) {
        sum += page[i];
    }
    bf_builtins_sink = sum;
    return sum;
}

/* 小栈帧：不需要探测。用来确认"不是所有函数都被认成探测助手"（误报要能被看见）。 */
int bf_builtins_small(int a, int b)
{
    int t = a * 3 + b;

    bf_builtins_sink = t;
    return t;
}

int main(void)
{
    return bf_builtins_big(1) + bf_builtins_small(2, 3);
}
