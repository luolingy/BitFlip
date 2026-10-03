// BitFlip M3 覆盖率验收用的样本：刻意做"有分量"的静态链接 mingw exe。
//
// 为什么不用现成的 sample.c：它只有 3 个函数、7KB，覆盖率 95% 这种指标在
// 那么小的样本上毫无意义 —— 3 个函数里错 1 个就是 67%。
//
// 这里刻意包含几类对函数识别有压力的形态，让 95% 这个数字真正有说服力：
//   * 多个真实函数 + 互相调用（考验调用目标推断）
//   * 尾调用与 switch 跳转表（考验间接跳转 —— M3 明确不猜，M6 才做）
//   * 函数指针数组（间接调用，M3 不产出 xref）
//   * 递归函数
//   * static 函数（局部符号，考验符号表与启发式的边界）
//   * 内联候选（--gc-sections 会删掉没人用的函数）
//
// 编译命令见 scripts/gen-m3-coverage-sample.ps1。必须**不带 -g**，
// 且链接后 strip，才能得到"无符号"的真实场景。

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ── 基础算术层：互相调用 ───────────────────────────────────── */

int bf_add(int a, int b) { return a + b; }
int bf_sub(int a, int b) { return a - b; }
int bf_mul(int a, int b) { return a * b; }

int bf_div_safe(int a, int b) {
    if (b == 0) return 0;
    return a / b;
}

int bf_mod_safe(int a, int b) {
    if (b == 0) return 0;
    return a % b;
}

/* ── 递归：自引用，考验"调用目标即函数起点"的推断 ────────── */

int bf_fib(int n) {
    if (n < 2) return n;
    return bf_fib(n - 1) + bf_fib(n - 2);
}

unsigned long bf_fact(unsigned long n) {
    if (n <= 1) return 1;
    return n * bf_fact(n - 1);
}

int bf_ackermann(int m, int n) {
    if (m == 0) return n + 1;
    if (n == 0) return bf_ackermann(m - 1, 1);
    return bf_ackermann(m - 1, bf_ackermann(m, n - 1));
}

/* ── 循环与数组：制造真实的代码体积 ────────────────────────── */

int bf_sum_array(const int *arr, int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) acc += arr[i];
    return acc;
}

int bf_max_array(const int *arr, int n) {
    if (n <= 0) return 0;
    int m = arr[0];
    for (int i = 1; i < n; i++) if (arr[i] > m) m = arr[i];
    return m;
}

int bf_min_array(const int *arr, int n) {
    if (n <= 0) return 0;
    int m = arr[0];
    for (int i = 1; i < n; i++) if (arr[i] < m) m = arr[i];
    return m;
}

long bf_dot_product(const int *a, const int *b, int n) {
    long acc = 0;
    for (int i = 0; i < n; i++) acc += (long)a[i] * (long)b[i];
    return acc;
}

/* ── switch：编译器可能生成跳转表（间接跳转，M3 不猜） ────── */

int bf_switchy(int op, int a, int b) {
    switch (op) {
        case 0: return bf_add(a, b);
        case 1: return bf_sub(a, b);
        case 2: return bf_mul(a, b);
        case 3: return bf_div_safe(a, b);
        case 4: return bf_mod_safe(a, b);
        case 5: return a & b;
        case 6: return a | b;
        case 7: return a ^ b;
        case 8: return a << (b & 31);
        case 9: return a >> (b & 31);
        case 10: return -(a + b);
        case 11: return a > b ? a : b;
        case 12: return a < b ? a : b;
        default: return 0;
    }
}

/* ── 函数指针：间接调用，M3 应当"不解析"而不是猜 ──────────── */

typedef int (*bf_binop)(int, int);

static int op_xor_wrap(int a, int b) { return (a ^ b) + 1; }
static int op_and_wrap(int a, int b) { return (a & b) + 2; }
static int op_or_wrap(int a, int b)  { return (a | b) + 3; }

static bf_binop bf_ops[3] = { op_xor_wrap, op_and_wrap, op_or_wrap };

int bf_dispatch(int idx, int a, int b) {
    if (idx < 0 || idx > 2) return -1;
    return bf_ops[idx](a, b);
}

/* ── static 函数：局部符号，考验符号表边界 ─────────────────── */

static int bf_internal_checksum(const char *s) {
    int h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)*s++;
    return h;
}

static int bf_internal_len(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

int bf_hash_string(const char *s) {
    return bf_internal_checksum(s) ^ bf_internal_len(s);
}

/* ── 字符串处理：产生 .rdata 与 rip 相对引用 ───────────────── */

int bf_count_char(const char *s, char c) {
    int n = 0;
    for (; *s; s++) if (*s == c) n++;
    return n;
}

void bf_reverse(char *s) {
    size_t n = strlen(s);
    for (size_t i = 0; i < n / 2; i++) {
        char t = s[i];
        s[i] = s[n - 1 - i];
        s[n - 1 - i] = t;
    }
}

int bf_is_palindrome(const char *s) {
    size_t n = strlen(s);
    for (size_t i = 0; i < n / 2; i++) {
        if (s[i] != s[n - 1 - i]) return 0;
    }
    return 1;
}

/* ── 数学：引入 libm，撑起静态链接体积 ─────────────────────── */

double bf_hypot3(double x, double y, double z) {
    return sqrt(x * x + y * y + z * z);
}

double bf_clamp(double v, double lo, double hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

double bf_lerp(double a, double b, double t) {
    return a + (b - a) * bf_clamp(t, 0.0, 1.0);
}

/* ── 排序：制造真实的分支密集代码 ─────────────────────────── */

void bf_bubble_sort(int *arr, int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - 1 - i; j++) {
            if (arr[j] > arr[j + 1]) {
                int t = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = t;
            }
        }
    }
}

int bf_partition(int *arr, int lo, int hi) {
    int pivot = arr[hi];
    int i = lo - 1;
    for (int j = lo; j < hi; j++) {
        if (arr[j] <= pivot) {
            i++;
            int t = arr[i];
            arr[i] = arr[j];
            arr[j] = t;
        }
    }
    int t = arr[i + 1];
    arr[i + 1] = arr[hi];
    arr[hi] = t;
    return i + 1;
}

void bf_quick_sort(int *arr, int lo, int hi) {
    if (lo < hi) {
        int p = bf_partition(arr, lo, hi);
        bf_quick_sort(arr, lo, p - 1);
        bf_quick_sort(arr, p + 1, hi);
    }
}

/* ── 位操作：短函数，容易被误判为"内联/尾部" ───────────────── */

unsigned bf_popcount(unsigned x) {
    unsigned n = 0;
    while (x) { n += x & 1u; x >>= 1; }
    return n;
}

unsigned bf_rotl(unsigned x, int r) {
    r &= 31;
    return (x << r) | (x >> ((32 - r) & 31));
}

unsigned bf_mix(unsigned a, unsigned b) {
    a ^= b; b = bf_rotl(b, 7);
    a += b; b ^= a; a = bf_rotl(a, 11);
    return a + b * 2654435761u;
}

int main(void) {
    int arr[128];
    for (int i = 0; i < 128; i++) arr[i] = (i * 37) % 101;

    int total = 0;
    total += bf_sum_array(arr, 128);
    total += bf_max_array(arr, 128);
    total += bf_min_array(arr, 128);
    total += bf_switchy(3, 84, 2);
    total += bf_switchy(9, 1024, 3);
    total += bf_dispatch(1, 12, 5);
    total += bf_hash_string("BitFlip coverage sample");
    total += bf_count_char("BitFlip coverage sample", 'i');
    total += bf_is_palindrome("racecar");
    total += (int)bf_fib(12);
    total += (int)bf_fact(8);
    total += bf_ackermann(2, 3);
    total += (int)bf_hypot3(3.0, 4.0, 12.0);
    total += (int)(bf_lerp(0.0, 100.0, 0.25) * 4);
    total += (int)bf_popcount(0xDEADBEEFu);
    total += (int)bf_mix(0x12345678u, 0x9ABCDEF0u);

    bf_bubble_sort(arr, 64);
    bf_quick_sort(arr, 0, 63);
    total += arr[0] + arr[63];

    char buf[32];
    strcpy(buf, "bitflip");
    bf_reverse(buf);
    total += bf_count_char(buf, 'p');

    printf("total=%d\n", total);
    return total == 0x7fffffff ? 1 : 0;
}
