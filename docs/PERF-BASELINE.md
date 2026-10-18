# 分析性能基线

> **用途**：任何"这次改快了多少"的说法，都要跟这里的数字比，而不是跟记忆比。
> 方法、陷阱与如何复现都写在同一页，免得下一次又重新发明一遍。

## 怎么测

```powershell
# 1) 先确保被测可执行文件就是当前 HEAD 构建出来的那个（见下面第 1 个坑）
& .\scripts\cargo.ps1 test --offline -p bitflip-core --test macho_real_analysis --no-run
#    输出里的 "Executable ... <hash>.exe" 就是**唯一**可信的路径

# 2) 连跑 5 次，取中位数
$env:BITFLIP_TIMING = "1"
.\scripts\timing.ps1 -Exe .cargo-target\debug\deps\macho_real_analysis-<hash>.exe -Runs 5

# 3) 与旧版本比：两版交替跑，而不是先后跑
.\scripts\timing.ps1 -Exe <new>.exe -CompareExe <old>.exe -Runs 5
```

样本：`temp/LiveContainer.ipa` 的主二进制（151 648 字节、15 694 条指令、
aarch64、debug 构建、capstone 按 `-O3` 编）。

## 基线（commit `5dc33e0`，2026-10-17，5 次取中位数）

| 阶段 | 中位数 (µs) | min | max |
|---|---:|---:|---:|
| `Disasm::build` · 线性扫描（建立共享解码账本） | 530 909 | 472 889 | 686 000 |
| `Disasm::build` · 递归下降（从账本里选） | 107 979 | 86 855 | 173 356 |
| `TargetAnalysis::build` · 解码指令索引（唯一一遍） | 392 812 | 298 065 | 622 496 |
| `TargetAnalysis::build` · 数据/代码判定 | 136 700 | 120 403 | 394 129 |
| `TargetAnalysis::build` · 逐函数 CFG | 93 075 | 84 964 | 152 411 |
| `TargetAnalysis::build` · 常量/结构体 | 61 444 | 42 998 | 63 174 |
| `TargetAnalysis::build` · xref 提取 | 54 054 | 45 849 | 61 261 |
| `TargetAnalysis::build` · 跳转表识别 | 39 474 | 33 752 | 48 210 |
| `TargetAnalysis::build` · 参数推断 | 37 368 | 33 339 | 41 279 |
| `TargetAnalysis::build` · 调用图 | 31 036 | 28 267 | 56 057 |
| `TargetAnalysis::build` · 字符串提取 | 30 987 | 27 288 | 53 785 |
| `TargetAnalysis::build` · 来源 4 调用目标 | 9 441 | 7 632 | 21 355 |
| `TargetAnalysis::build` · 来源 5–9 桩/重定位/调试/签名 | 10 940 | 3 675 | 12 435 |
| `TargetAnalysis::build` · 合并候选→函数 | 8 822 | 7 321 | 19 207 |
| `TargetAnalysis::build` · 栈帧扫描 | 11 823 | 10 846 | 17 572 |
| `TargetAnalysis::build` · 来源 1–3.5 符号/导出/展开/起点/入口 | 1 938 | 1 710 | 4 336 |
| `TargetAnalysis::build` · 种子收集 | 555 | 407 | 968 |
| `TargetAnalysis::build` · 重叠检查 | 371 | 206 | 1 042 |
| `TargetAnalysis::build` · 地址空间与解码器 | 118 | 116 | 128 |
| **端到端（`build 全程`，含上面两趟一起）** | **1 645 299** | 1 397 525 | 2 342 519 |

## 读这张表前必须知道的两件事

1. **别用 `LastWriteTime` 挑可执行文件。** 实测踩到：`cargo test --no-run` 打印的是
   `...-93911f485754b330.exe`，而目录里还躺着上一次 profile 实验的
   `...-ebafd2f161a6cdc7.exe`，按时间排序取"最新"正好取到了那个**过期配置**的产物，
   于是量出来的是别人家的二进制。只认 cargo 打印出来的那个路径。
2. **跨会话不可比，只有同一会话内的交替对比才算数。** 同一个二进制
   （`93911f4…`）、同一份样本，5 次中位数在两次会话里分别是 **1 402 494 µs** 与
   **1 645 299 µs**，相差约 17%；单次样本的 `max` 更是到过中位数的 1.6 倍。
   所以：绝对数字只当量级，**判断要看中位数区间是否重叠**。

## 已知的、还没解决的成本

* 单条 `nop` 在 `-O3` 的 capstone 里仍要约 8.5 µs（正常量级 ~1 µs）—— 方向是本地
  打过补丁的 `third-party/capstone`（构建方式或补丁本身），不是本项目的调用结构：
  成块解码实测只快 1.0 倍。
* `TargetAnalysis` 的「解码指令索引」与 `Disasm::build` 的线性扫描解的是同一批指令。
  想复用有两条路（保留 `DecodedInsn`＝128 B/条、或改 10 个消费者的契约），
  两条都已用数字否掉，见 `docs/PLAN.md` 的 M12 性能底账。
