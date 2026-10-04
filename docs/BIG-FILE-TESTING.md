# 大文件逆向测试

> 面向在 BitFlip 仓库工作的协作者。这一页说明大文件怎么测、为什么要自造文件，
> 以及本机可用的真实样本。

## 为什么要自造 fixture

拿系统上的大文件测，只能证明**没崩**。大文件上真正危险的失败模式是
"没崩但结果全错"，而这类 bug 只有对着**已知答案**才看得出来。

最典型的例子就是本页记录的那个：`StringScanner::feed` 用分块内的下标当偏移，
每个分块都从段基址重新开始。在 100MB 的 `.rdata` 上表现为字符串地址全部错位、
后面的分块互相覆盖 —— 一个只断言"扫出了字符串"的测试永远抓不到它。

因此 `scripts/gen-big-binary.py` 生成的文件是**结构完全已知**的：

| 量 | 公式 | 默认值（96 份 unit） |
| --- | --- | --- |
| 文件大小 | `units × pad_kb` | 约 96 MiB |
| 函数（符号表内） | `units × 3` | 288 |
| 可识别字符串 | `units × 4` | 384 |
| 跨 4 MiB 扫描分块 | `units × pad_kb / 4096` | 约 24 块 |

测试直接断言这些数字，不做"大于零"这种软弱断言。

### fixture 的两个关键构造

这两条都是踩过坑之后加的，改动生成器时务必保住：

1. **可识别字符串写进填充块数组内部**，而不是当作独立的字符串字面量。
   独立的字面量会被编译器归拢到只读数据的同一片区域 —— 几百个串全挤在
   第一个 4 MiB 分块里，跨块路径根本没被走到，测试就是空转。
   （第一版正是如此：带 bug 的代码在 100MB 文件上依然全绿。）

2. **每个字符串只出现一次**。曾经同时在 `pad_marker_[]` 和 `pad_[]` 里
   各放一份，同一串在二进制里出现两次，去重后计数对不上，
   测试报"找到 480 条，期望 384 条"。

## 生成

```powershell
# 约 80 秒
python scripts/gen-big-binary.py --out tests/fixtures/generated/big-x86_64.exe
```

生成物落在 gitignored 的 `tests/fixtures/generated/`（CLAUDE.md §0.2：样本不入库）。

脚本会在产出小于 16 MiB 时**警告** —— 太小的文件跨不过 4 MiB 分块，
大文件测试会失去意义。

## 测试

```powershell
cargo test -p bitflip-core --test big_file    # 约 30 秒
```

缺少 fixture 时测试会**带着重建命令硬失败**，而不是静默跳过 ——
静默跳过等于这条覆盖不存在，但看起来是绿的。

改动 `StringScanner` 之后，建议手工验证一次测试确实有效：
把 `self.base + self.consumed + i` 改回 `self.base + i`，
`big_file` 应当立刻变红（地址重复 368/384）。改完记得改回来。

## 本机可用的真实样本

自造文件覆盖"分块扫描 + 已知答案"，真实样本覆盖"野生的畸形 PE/ELF"。
两者互补，都要跑。

| 文件 | 大小 | 实测 |
| --- | --- | --- |
| `C:\Windows\System32\MRT.exe` | 220 MB | `info` 1.9 s / `functions` 17.1 s |
| `C:\Windows\System32\lxss\lib\libnvwgf2umx.so` | 97 MB | **大尺寸 ELF**，`info` 0.9 s |
| `C:\Windows\System32\DriverStore\FileRepository\nvami.inf_amd64_*\nvrtum64.dll` | 111 MB | NVIDIA 运行时，段表复杂 |
| `C:\Windows\System32\DriverStore\FileRepository\nvami.inf_amd64_*\nvoptix.dll` | 101 MB | 同上 |

优先用 `C:\Windows\System32\lxss\lib\` 下的 `.so` —— 路径短、权限宽松，
而且补上了 PE 之外的 ELF 路径。

### 实测数据（开发机）

**一定要用 release 构建测。** debug 下慢一个数量级，测出来的数字没有意义
（本页第一版就是这么写错的）。

| 目标 | 大小 | `info`（嗅探前 8 MiB） | `functions`（完整分析） |
| --- | --- | --- | --- |
| `big-x86_64.exe` | 96 MiB | 1.1 s | 2.1 s |
| `MRT.exe` | 220 MB | 1.9 s | 17.1 s |
| `libnvwgf2umx.so` | 97 MB | 0.9 s | — |

对照 M2 的验收标准（`docs/PLAN.md` §M2：100MB 级 PE 首扫 < 15 s）：
96 MiB 的 fixture 完整分析 2.1 s，220 MB 的 `MRT.exe` 17.1 s ——
按文件大小线性外推，100MB 级落在 8 s 上下，**达标**。

`info` 只做嗅探，所以与大文件尺寸基本无关（1–2 s）；
`functions` 要建地址空间、线性 + 递归下降解码、扫全量字符串，随文件大小线性增长。

## 已知的性能问题

220MB 上 17 秒虽已达标，但仍有明显余量可挖（M6/M7）：

- 字符串扫描是单线程线性走全段。按段并行（`rayon`）是最直接的改进 ——
  段之间本来就独立，且 `.rdata` 常常占文件 80% 以上。
- 反汇编的线性扫描与递归下降是两遍。大文件上值得合并成一遍。

这两条属于优化，不是正确性问题；在落地之前不要用大文件做交互式场景的性能基准。
