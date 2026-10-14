# capstone 的 AArch64 detail 不给预取操作数（`prfm`）

> 结论：capstone 14.0 的 AArch64 detail **从不为 `ARM64_OP_PREFETCH` 赋值**。
> `prfm` / `prfum` 的第一个操作数（预取类型，如 `pldl1keep`）在 detail 里
> 根本不存在，只出现在它自己拼的文本里。
>
> BitFlip 的处理：**如实标出"位置在、值拿不到"**（渲染成 `<prefetch:?>`），
> 不自己从指令位里挖（挖法见文末"可选方案"，留着以后要就捡）。

## 现象

同一份 `.o`，两条输出：

```text
llvm-objdump -d --no-show-raw-insn          我们（bitflip-cli export --format asm-intel）
0x5c  prfm  pldl1keep, [x1]                 000000010000005c  200080f9  prfm [x1]
0x64  prfum pldl3keep, [x3, #0x8]           0000000100000064  648080f8  prfum [x3+0x8]
```

外部反汇编器给 2 个操作数，我们只给 1 个 —— 少的那一个是**预取类型**。
`prfm [x1]` 读起来像一条完整指令，但它不是：没有类型就没有语义。

真实目标里不是罕见情况：195 KB 的 `libBugly_Native.so`（`e_machine=183`）
里有 **21 条** `prfm`。

## 证据：不是我们丢的，是 capstone 没给

C 源码来自 `capstone-sys` 捆绑并实际编译的那份（`AArch64InstPrinter.c` 等）。

1. **枚举存在，但没人赋值。**
   `ARM64_OP_PREFETCH` 只出现在三个地方：`arch/arm64.h`（枚举定义）、
   `bindings/ocaml/arm64_ocaml.c`、`cstool/cstool_arm64.c`。
   反汇编器的 C 代码里**一次赋值也没有**。

2. **打印器给别的操作数都建了 detail，唯独没有预取。**
   `AArch64InstPrinter.c` 里 `detail->arm64.operands[op_count].type = ARM64_OP_*`
   覆盖了 11 种：`BARRIER`、`CIMM`、`FP`、`IMM`、`MEM`、`PSTATE`、`REG`、
   `REG_MRS`、`SME_INDEX`、`SVCR`、`SYS`。没有 `PREFETCH`。

3. **解码器确实算出了这个值，只是没往 detail 里放。**
   `AArch64Disassembler.c` 的 `AArch64_PRFMui` / `AArch64_PRFUMi` 里有
   `MCOperand_CreateImm0(Inst, Rt)` —— 值有了，但那条路径不会写进
   `cs_arm64.operands[]`。

4. **映射表只认三种。**
   `AArch64Mapping.c` 只把 `REG` / `FP` / `IMM` 映射到 detail，
   其余靠打印器的副作用。

也就是说：capstone 自己拼的 `op_str` 是对的（它的打印器直接查表打印），
**结构化 detail 缺这一项**。我们不能拿它的文本当数据源（那等于放弃两套语法
共用一份结构化指令的设计，见 `render.rs` 顶部注释），也不该假造一个值。

### 顺带记一笔：认不出的屏障选项反而**不会**丢

`printBarrierOption`（`AArch64InstPrinter.c` 2038-2086）有两个分支，
`Name == NULL` 时走的是 else：打印成数字**并且**写一个 `ARM64_OP_IMM` 进 detail。
所以"屏障选项认不出来"这件事不会变成静默丢失 —— 它会渲染成一个数字。
这一点影响我们的建模选择：`Barrier` 的 `INVALID` 可以放心当"没有值"处理。

## 我们的处理

`Operand::Prefetch(Option<PrefetchOp>)`：

- capstone 会给值时（将来修好了）→ `Some(op)` → 渲染成 `pldl1keep`；
- 现在 → 我们在助记符是 `prfm`/`prfum` 且 detail 里没有该操作数时，
  在**第一个位置**补一个 `None`（预取类型在两个形式里都是第一操作数），
  渲染成 `<prefetch:?>`。

补位置而不是什么都不做，是因为 `prfm [x1]` 会让人以为指令完整；
`prfm <prefetch:?>, [x1]` 一眼能看出缺东西（CLAUDE.md §7：拿不到就说拿不到）。

`prfm`/`prfum` 的**内存操作数**是有的，正常渲染。

## 可选方案（未实现）

如果要补回这个值，不必重新解码指令，只要读编码里的 `prfop` 字段：

- `prfop = 指令字 & 0x1f`（ARM ARM：PRFM/PRFUM 的 `Rt` 字段即预取操作）；
- capstone 的 `arm64_prefetch_op` 枚举值 = `prfop + 1`，恰好 18 个具名值；
- 名字可按下式拼出：`[4:3]` 类型（`PLD`/`PLI`/`PST`，`0b11` 未分配）、
  `[2:1]` 目标（`L1`/`L2`/`L3`，`0b11` 保留）、`[0]` 策略（`KEEP`/`STRM`）。

**这段是设计草案，没有实现、也没有逐值对拍过。** 真要做，必须先拿
`clang` 汇编出全部 18 个具名形式、用 `llvm-objdump` 逐个确认名字，
再写测试 —— 否则就是把"看着对"的推断当成事实（CLAUDE.md §6.11）。

## 怎么复核

```powershell
# 1) 现象：真值 2 个操作数，我们 1 个
E:\LLVM\bin\llvm-objdump.exe -d --no-show-raw-insn .smoke-logs\probe_ops.o
& .cargo-target\debug\bitflip-cli.exe export .smoke-logs\probe_ops.o --format asm-intel

# 2) 证据：枚举有没有被赋值
Select-String -Path <capstone-sys>\capstone\arch\AArch64\*.c -Pattern 'ARM64_OP_PREFETCH'
```

回归测试在 `crates/bitflip-arch/tests/arm64_operand_kinds.rs`
（`unavailable_operands_are_marked_rather_than_dropped`）：断言 `prfm` 的
第一个操作数是 `Prefetch(None)`，且渲染文本含 `<prefetch:?>`。
