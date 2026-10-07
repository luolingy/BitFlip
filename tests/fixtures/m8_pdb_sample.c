// BitFlip M8 的 PDB 样本：给 MSVC 系工具链编译用。
//
// 为什么单独一份、且**一个头文件都不 include**：clang-cl 编这个文件时不想去拉
// Windows SDK / UCRT 的头文件（那要 vcvars 那一整套环境变量）。这份样本只做纯算术，
// 链接时用 /NODEFAULTLIB /ENTRY:... 直接指到自己的入口，完全不碰 CRT。
//
// 形态要求（与 DWARF 那份同样刻意）：
//   * 几个各自独立、行号互不相同的小函数（PDB 的符号记录与行记录要能对上）；
//   * 一个带循环的函数（一个函数里有多条行记录，行表不能只有一条）；
//   * 互相调用（考验 PDB 里的符号地址与我们的函数识别是否对得上）。

int bf_pdb_add(int a, int b) {
  return a + b;
}

int bf_pdb_sub(int a, int b) {
  return a - b;
}

int bf_pdb_dot(const int *a, const int *b, int n) {
  int sum = 0;
  for (int i = 0; i < n; i++) {
    sum += a[i] * b[i];
  }
  return sum;
}

int bf_pdb_tail(int n) {
  if (n <= 0) {
    return bf_pdb_add(n, 1);
  }
  return bf_pdb_tail(n - 1);
}

int bf_pdb_main(void) {
  int x[4];
  for (int i = 0; i < 4; i++) {
    x[i] = i * 3;
  }
  return bf_pdb_dot(x, x, 4) + bf_pdb_sub(bf_pdb_tail(3), 1);
}

void bf_pdb_entry(void) {
  bf_pdb_main();
}
