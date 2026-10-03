/* BitFlip: real AArch64 fixture for CFG verification (PLAN M5 criterion 2).
 *
 * Why this shape: the CFG claims under test are the *boring* ones that are
 * easy to get subtly wrong, so each function here pins exactly one of them.
 * "Spot check" in the acceptance criteria means picking functions whose
 * correct CFG can be written down by hand and compared, not just eyeballing
 * output -- so every function below has a comment stating its expected
 * successor structure.
 *
 * NO libc: cross-compiled from Windows with `clang --target=aarch64-linux-gnu`
 * (no Linux sysroot here, see CLAUDE.md section 3) and linked -nostdlib.
 *
 * `_start` is provided for the -nostdlib link, and calls every function so
 * the linker cannot drop them.
 *
 * Deliberately NOT position-dependent and NOT using any runtime helper: the
 * fixture must be stable across clang versions for the golden values in
 * tests/fixtures generated alongside it to stay meaningful.
 */

static volatile int sink;

/* CFG: one entry, one conditional forward branch, two returns on the two
 * arms -> 3 basic blocks (entry / then / else), entry has 2 successors. */
__attribute__((noinline)) int cfg_absdiff(int x, int y) {
    if (x > y) {
        return x - y;
    }
    return y - x;
}

/* CFG: a back edge. entry -> loop_head; loop_head is conditional (2 succ:
 * body + exit); body -> loop_head. So a cycle of length 1 on the head and
 * exactly one back edge. A CFG builder that only does linear fallthrough
 * produces 1 block here instead of 4. */
__attribute__((noinline)) int cfg_sum(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) {
        acc += i * 3 + 1;
    }
    return acc;
}

/* CFG: no branches at all -> exactly 1 basic block, 1 successor (fallthrough
 * to the return). Pins the "straight-line function" case. */
__attribute__((noinline)) int cfg_mix(int a, int b) {
    int t = a * 3 + b;
    return t ^ 0x5a;
}

/* CFG: a call in the middle. The callee does NOT end the block (control
 * returns), so this is still 2 blocks (the call splits nothing) -- a CFG
 * builder that treats call like a terminator produces 3. */
__attribute__((noinline)) int cfg_call_mid(int n) {
    int a = cfg_mix(n, 7);
    return a + cfg_absdiff(n, 3);
}

/* CFG: nested conditionals -> 5 basic blocks, with the two inner conditions
 * each having 2 successors. Pins that the builder does not collapse nested
 * branches into one. */
__attribute__((noinline)) int cfg_ladder(int x) {
    if (x > 100) {
        if (x > 1000) {
            return 3;
        }
        return 2;
    }
    return x > 0 ? 1 : 0;
}

/* CFG: a switch. clang may lower a small switch to a jump table or to a
 * chain of compares depending on the pattern; either is correct, so the test
 * asserts "every case value is reachable" rather than a block count. */
__attribute__((noinline)) int cfg_dispatch(int x) {
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

/* Recursion: keeps a real stack frame and a self edge. */
__attribute__((noinline)) int cfg_recurse(int x) {
    if (x <= 0) {
        return 0;
    }
    return cfg_recurse(x - 1) + cfg_sum(x);
}

/* AArch64 Linux syscall for exit is 93; x0 = status.
 * Using inline asm avoids needing a Linux sysroot to link against. */
__attribute__((noreturn, noinline)) void cfg_exit(int code) {
    __asm__ volatile("mov x8, #93\n\t"
                     "svc #0\n\t"
                     :
                     : "r"((long)code)
                     : "x8", "memory");
    __builtin_unreachable();
}

void _start(void) {
    int total = 0;
    total += cfg_absdiff(9, 4);
    total += cfg_sum(10);
    total += cfg_mix(3, 5);
    total += cfg_call_mid(6);
    total += cfg_ladder(500);
    total += cfg_dispatch(5);
    total += cfg_recurse(4);
    sink = total;
    cfg_exit(total & 0x7f);
}
