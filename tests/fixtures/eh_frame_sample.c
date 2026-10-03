/* BitFlip: real ELF fixture for .eh_frame verification.
 *
 * Why this exists: unit tests for the FDE parser use hand-built .eh_frame
 * bytes, which only prove the parser matches MY understanding of DWARF. To
 * prove it matches what a real compiler emits, we need a real binary.
 *
 * Compiled twice by the fixture script:
 *   1. with symbols   -> the unstripped reference (ground truth from .symtab)
 *   2. stripped       -> the case that matters. .eh_frame is then the ONLY
 *                        remaining source of function boundaries.
 *
 * NO libc includes: this is cross-compiled to a Linux ELF target from Windows
 * (see CLAUDE.md section 3 -- ELF targets use clang --target=... because no
 * Linux sysroot/headers exist here). The binary is linked -nostdlib, so it
 * must not reference printf/strlen/etc.
 *
 * `_start` is provided because -nostdlib means no CRT; without an entry point
 * the linker would complain. It calls the functions so none of them get
 * garbage-collected or optimized away.
 *
 * Deliberately uses functions that are NOT tail-call optimizable into each
 * other, so the FDE list stays 1:1 with the source functions.
 */

/* Volatile sink stops the optimizer from folding everything into _start. */
static volatile int sink;

__attribute__((noinline)) int ef_alpha(int x) {
    int acc = 0;
    for (int i = 0; i < x; i++) acc += i * 3 + 1;
    return acc;
}

__attribute__((noinline)) int ef_beta(int x) {
    int acc = 1;
    for (int i = 1; i <= x; i++) acc = acc * 2 + i;
    return acc;
}

__attribute__((noinline)) int ef_gamma(int x, int y) {
    if (x > y) return x - y;
    return y - x;
}

__attribute__((noinline)) int ef_delta(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

__attribute__((noinline)) int ef_epsilon(int x) {
    switch (x & 7) {
        case 0: return x + 1;
        case 1: return x - 1;
        case 2: return x * 2;
        case 3: return x / 2;
        case 4: return x ^ 0x55;
        case 5: return x | 0x0f;
        case 6: return x & 0xf0;
        default: return ~x;
    }
}

__attribute__((noinline)) int ef_zeta(int x) {
    if (x <= 0) return 0;
    return ef_zeta(x - 1) + ef_alpha(x); /* recursion keeps a real frame */
}

__attribute__((noinline)) double ef_eta(double a, double b) {
    double r = a;
    for (int i = 0; i < 8; i++) r = r * 0.5 + b;
    return r;
}

/* Entry point for -nostdlib. Uses `_exit` via inline asm to avoid needing
 * libc at all. */
__attribute__((noreturn)) void bf_exit(int code);

__attribute__((noreturn, noinline)) void bf_exit(int code) {
    /* Linux x86-64: syscall 60 = exit */
    __asm__ volatile("syscall" : : "a"(60), "D"((long)code) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

void _start(void) {
    int total = 0;
    total += ef_alpha(10);
    total += ef_beta(6);
    total += ef_gamma(9, 4);
    total += ef_delta("bitflip");
    total += ef_epsilon(5);
    total += ef_zeta(5);
    total += (int)ef_eta(1.0, 2.0);
    sink = total;
    bf_exit(total & 0x7f);
}
