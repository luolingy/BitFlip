# 性能：`info` 为什么慢，改了什么，还剩什么

> 触发问题：`owo-terminal.exe`（201 MiB / 425,448 个函数）上 `info` 实测
> **10.8 秒**，而文档写的是 1–2 秒，且嗅探窗口只有 8 MiB —— 数字对不上。
>
> 结论：**慢的不是嗅探，是"打开"里两处与文件大小成正比的浪费。**
> 已修，release 实测 **10.8s → 1.48s**。

## 1. 定位方法：不要猜，插桩

先复现（同一目标连测 3 次，差距很大，说明有 I/O 成分）：

```
run 1: 10.02s
run 2:  6.18s
run 3:  5.52s
```

再按文件大小做对照，看**是否真的随大小增长**：

| 目标 | 大小 | `info` 耗时 |
| --- | --- | --- |
| `codemap-x86_64.exe` | 4 KB | 0.22s |
| `big-x86_64.exe` | 96 MB | 0.60s |
| `owo-terminal.exe` | 201 MB | 3.41s |

4 KB→96 MB（24,000 倍大小）只慢 2.7 倍，但 96 MB→201 MB（2.1 倍）
慢了 5.7 倍 —— **超线性**，说明存在与文件大小成正比的大块内存操作。

于是写了一个**临时**插桩测试（`crates/bitflip-core/tests/profile_open.rs`，
定位完即删），直接给 `Session::open` 的各阶段计时：

```
1. sniff_file             12.112ms  sniffed=8388608B truncated=true
2. parse_object            1.247s   ok=true
   节=14 符号=0 段=14
3. Session::open 总计      1.837s
4. 纯 fs::read（对照）    114.058ms  201 MiB
```

**关键读法**：只有 14 个节、**0 个符号**，配置如此简单却要 1.2 秒 ——
所以时间不来自"数据量"，来自某个按条数循环的操作。

## 2. 根因一：`.pdata` 每条都解码（1.2 秒）

`.pdata`（`RUNTIME_FUNCTION`）在 64 位 PE 里**每个函数一条**：

```
.pdata file_size = 5,011,968 字节 ÷ 12 字节/条 = 417,629 条
```

`parse_pdata` 原本对**每一条**都调用 `parse_unwind_info` 把
`UNWIND_INFO` 解开。41 万次解码 = 1.2 秒。

而这 1.2 秒换来的东西，`info` **一个字段都用不到** ——
`info` 甚至不反汇编。`ObjectInfo::from_object` 完全不读 `unwind`。

### 修法：推迟解码

- `UnwindEntry` 新增 `deferred: bool`。
- 加载器建表时**只读三个 RVA**（`begin`/`end`/`unwind_info`，函数边界要用的），
  `decoded` 留 `None` 且 `deferred = true`。
- 新增 `Object::resolve_unwind(bytes, base)`，由**真正需要**的路径调用
  （`Session::analysis_cached`，即栈帧视图；那条路径本来就要跑几百秒）。

### 为什么必须是两个字段，而不是一个 `None`

`deferred: true, decoded: None` = **还没问**；
`deferred: false, decoded: None` = **问了，但这一条解不出来**。

合成一个 `None` 就是用"未知"冒充"没有"（CLAUDE.md §7），界面会把
"尚未解码"显示成"这个函数没有展开信息"。所以 `is_deferred()` 是公开访问器。

### 为什么 ELF 那边填 `false` 而不是 `true`

ELF 的 `.eh_frame` 只解出函数边界、**没有 CFI 指令解码**。
那是"M3 还没做"（待实现的特性），不是"推迟到需要时做"（性能手段）。
填 `true` 会让 `resolve_unwind` 白跑一遍，还掩盖了 CFI 尚未实现这个事实。

**效果**：`parse_object` **1.247s → 155ms（8 倍）**。

## 3. 根因二：同一个文件读两遍（约 1 秒）

`Session::open` 里读了两遍同一个文件：

1. `parse_target` 内部 `std::fs::read` 一遍用于解析；
2. 之后判断"要留字节"时再 `std::fs::read` 一遍存进 `session.bytes`。

对 201 MiB 的目标就是 **402 MiB 的 I/O + 两次 201 MiB 分配**，
而两次拿到的是同一份数据。

### 修法：读一次，共用

把读盘提到 `open` 里做一次，`parse_target` 改为接收 `Option<&[u8]>`。
读**之前**先检查 `MAX_FULL_PARSE_BYTES`，避免"读 600 MiB 再拒绝"。
不需要保留时（解析失败且非归档）立刻 `drop`，不占着内存。

顺带把 `parse_target` 里的"没有字节"分成两种说法：
超上限是一种结论，读盘失败是另一种。合成一句会让用户分不清该改什么。

## 4. 实测结果

| 目标 | 改前（release） | 改后（release） |
| --- | --- | --- |
| 201 MB `owo-terminal.exe` | 10.8s → | **1.48s** |
| 96 MB fixture | — | 0.43s |
| 4 KB fixture | — | 0.24s |

release 构建，取多次运行的最小值。**回到文档写的 1–2 秒区间内。**

阶段拆解（release，插桩）：

```
1. sniff_file             20.248ms
2. parse_object          200.731ms   ← 改前 1.247s
3. Session::open 总计      1.465s
4. 纯 fs::read（对照）    241.957ms
5. .pdata 条目              417,629 条
6. bitflip_debug::read_target  488.700µs
```

## 5. 还没做的（据实记录，不假装已经解决）

`Session::open` 仍有约 1 秒花在**读整个文件**上，而 `info` 其实只需要文件头。

实测这个目标的解析器**最多只需要读到偏移 `0x3b0`（944 字节）**：

```
e_lfanew              = 0x78
NumberOfSections      = 14
节表                  = 0x180 .. 0x3b0
PointerToSymbolTable  = 0x0   NumberOfSymbols = 0
→ 最大需要读到: 0x3b0
```

也就是说，为了那 944 字节读了 201 MB。

**为什么这次没改**：`Session::bytes` 是 `Arc<[u8]>`，反汇编与成员分析
需要按虚拟地址**随机访问整个文件**。把它改成"按需读全量"或改用
内存映射（mmap）要动 `self.bytes` 的所有读点，并新增一个依赖 ——
那是一次架构改动，应该单独决策（参照 `docs/DECISIONS.md` 的 ADR 流程），
不该塞进一次性能修复里。

预期收益：`info` 再快约 1 秒（到 0.3–0.5 秒级），并且**峰值内存**从
"文件大小"降到"文件头大小" —— 对 200 MB 级目标和硬盘紧张的本机都有意义。

## 6. 防回归

- `crates/bitflip-loader/tests/unwind_golden.rs` 新增
  `parse_defers_unwind_decoding_until_asked`：断言解析阶段**不解码**任何一条，
  且 `resolve_unwind` 幂等（第二次返回 0）。

  这条是必要的：把解码挪回 `parse` 会让性能悄悄退化，而**所有功能测试
  仍然是绿的**（结果一样，只是慢）。性能特性同样需要有人守着。

- 原有的三条黄金测试（`decodes_the_big_function_frame_exactly` 等）改为
  显式 `resolve_unwind` 后再断言 —— 它们测的是**解码器本身**，
  改成推迟解码后必须先把数据解出来，否则测的就不是解码器了。
