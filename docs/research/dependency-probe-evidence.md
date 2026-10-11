# 依赖实测原始输出（不可编造，这是证据）

命令：`cargo run --manifest-path .smoke-logs/dep-probe/Cargo.toml --example run`

## 1) wazabin SLEIGH 解码 —— 可用

输入：x86_64 `mov eax, 1`（B8 01 00 00 00）
输出：`MOV EAX,1`

## 2) object 判格式 —— 需要足够长的输入（首次被测样本太短）

`FileKind::parse` 对 8-16 字节的合成头报 "Could not read file magic"。
注意这是**我们的测试样本太短**，不是 object 的问题。

## 3) object 解 Mach-O fat —— 可用（关键能力，goblin 没有的）

按规格合成 FAT_MAGIC 头（0xCAFEBABE 大端 + nfat_arch=2 + 2 条 arch 记录）：
输出：`OK, 2 slice(s): cputype=U32(01000007) offset=0x1000 size=0x400 | cputype=U32(0100000c) offset=0x2000 size=0x400`

cputype 0x01000007 = x86_64，0x0100000c = arm64 —— 解析正确。

## 4) ghidra-decompiler 真反编译 —— **能跑，但输出违反 §7**

### 用例 A：`mov eax,1; add eax,2; ret`
输出：
```
xunknown8 func_0x00000000(void)
{
  return 3;
}
```
- 常量折叠是对的（1+2=3）—— 这是真本事，不是假的。
- 但函数名是 `func_0x00000000` —— **正是 CLAUDE.md §7 明文禁止的占位名**。
- 类型是 `xunknown8` —— 一个我们无法核对的类型名。

### 用例 B：带条件分支的完整函数
输入：`test edi,edi; je +5; mov eax,1; ret; xor eax,eax; ret`
输出：
```
void func_0x00000000(void)
{
  return;
}
```
- **整段逻辑消失了**：没有体现 `test edi,edi` 的判断，
  没有体现两个 `ret` 返回不同的值（1 / 0）。
- 这是一个"看起来像成功"的输出（函数名、类型、`return` 都在），
  但它把函数体几乎全部丢掉了，而且**没有任何提示说明它丢掉了**。

这正是 §7 最担心的失败模式：**静默的错误输出**。