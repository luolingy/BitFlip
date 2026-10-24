# Mach-O 重签（re-sign）设计方案 · 待决策

> 状态：**设计稿，未实现**。本文件只描述"要重签得做什么、风险在哪、范围多大"，
> 供你拍板后单独立项实现。下面的"事实"都来自本仓已落地的代码与真实样本（M12 代码签名片）。
> 读它之前先看边界：**我们目前只做有界完整性校验 + 只读事实，不做信任链、不做封印。**

## 0. 一句话

重签 = 让"我们改造过的 Mach-O 副本"重新拥有一份**与内容自洽**的代码签名，
使 `codesign -v` / 系统的逐页哈希校验重新通过。它**不**恢复 Apple 的信任链——
本项目的定位是本地静态分析与打补丁，重签的目标是"改完还能装上跑/还能过本地校验"，
不是"伪装成 Apple 签名"。

## 1. 为什么这件事是"重大决策"（不是随手加的功能）

1. **它改变产物的法律/许可属性。** 给别人的 app 重签，可能触碰该 app 的许可与 Apple
   的开发者协议。"能不能做"和"该不该默认做"是两回事——本方案默认**不给**这个能力，
   只在用户显式请求、且对自己拥有的产物上使用时才给。
2. **它需要写文件、且写进被签名区。** 与我们"拷贝后只读、patch 只产出 `xxx.patched`"
   的既有安全姿态冲突：重签必然要改写 Mach-O 的 `__LINKEDIT` 尾部与头里的
   `LC_CODE_SIGNATURE`。必须沿用"只写副本、绝不原地"的红线。
3. **签名有密钥/证书依赖。** ad-hoc（`-`）重签不需要证书，只需要哈希；正式重签要
   开发者身份（`.p12`/钥匙串）与 CMS。后者涉及**私钥**——按分类器规则这属于高风险，
   本方案对它**只做设计、默认不实现**（见 §6）。

## 2. 现状盘点（已有事实，直接复用）

本仓现在**已经能正确解析**重签所需的一切结构（`crates/bitflip-loader/src/format/macho/codesign.rs`）：

- SuperBlob：magic `0xfade0cc0`，头 `magic(4)+length(4)+count(4)`，随后 `count×{type(4),offset(4)}`。
- CodeDirectory（type 0）：magic `0xfade0c02`；字段 version/flags/hashOffset/identOffset/
  nSpecialSlots/nCodeSlots/codeLimit/hashSize/hashType/platform/pageSizeLog。
  现能逐页重算 SHA-1/SHA-256 并与 code slot 比对（`Intact`/`Mismatch` 判定已经在用）。
- entitlements（type 5，XML plist）/ requirements（type 2，仅存在性）/ CMS 槽（type 0x1000）。
- CDHash：整段 CodeDirectory 的再哈希（签名结构指纹）。
- 真实样本核对：LiveContainer（ad-hoc，SHA-256，33 页）、SideStore（含 CMS，SHA-1，4728 页）。

也就是说：**"读懂签名"已经完成，"重写签名"是在此基础上把哈希算回去、把 blob 拼回去。**

## 3. 重签要做的事（ad-hoc 路径，最小可行）

给定的输入：一个我们已改过的 Mach-O 副本（`.patched`）。输出：一份**重算过 code slot 哈希**
并**重写 SuperBlob** 的副本。

ad-hoc 重签（`codesign -s -` 的等价物）**不需要证书**，步骤是：

1. **确定签名边界与页大小。** 从 `LC_CODE_SIGNATURE` 读 `dataoff/datasize`；从旧
   CodeDirectory 读 `pageSizeLog`、`hashType`、`codeLimit`、`identifier`、`nCodeSlots`。
   沿用旧值是最稳的（除非用户明确要升级算法）。
2. **重算每页哈希。** 对 `[i*pageSize, min((i+1)*pageSize, codeLimit))` 逐页按 `hashType`
   再哈希，写进新的 code slot。`codeLimit` 一般 = `__LINKEDIT` 之前的内容末（即签名区起点）。
3. **special slots。** ad-hoc 情况下 special slot 通常放空哈希（或 entitlements 的哈希）。
   若保留原 entitlements，需把 entitlements blob 的哈希写进 `CSSLOT_ENTITLEMENTS` 对应槽。
4. **重建 SuperBlob。** 用新的 CodeDirectory（以及可选的 entitlements/requirements blob）
   重新拼一个 SuperBlob：`magic+length+count` + 各 blob 按 4 字节对齐顺序排列 + 末尾不再带
   CMS（ad-hoc 无 CMS 槽）。
5. **回写并调整 `LC_CODE_SIGNATURE`。** 新的 `datasize` 很可能变（尤其换算法时）。要么
   原地覆盖（若新签名 ≤ 旧签名空间，尾部补零），要么移动签名区并改 load command 的
   `dataoff/datasize` 与 `__LINKEDIT` 的 `vmsize/filesize`。**移动是最容易出错的一步**
   （后续所有 load command 的偏移都要一致，fat 切片还要改 slice 大小与对齐）。
6. **重算 `Uuid`？不。** `LC_UUID` 是构建标识，重签不改它（改了反而更可疑，也破坏符号匹配）。

## 4. 正确性与验收（怎么证明"我们对"，而不是"看起来像对"）

这是本方案最该先写死的部分——**没有独立工具的交叉核对，就不算做完**：

- **交叉核对工具**：重签后在装有 Apple 工具的环境用 `codesign -v -v` / `codesign -d --verbose`
  验证"签名与内容自洽"（ad-hoc 只要求内部一致性，不要求信任链）。没装工具的机器如实 SKIP。
  另外用 `otool -l` / 自研只读解析确认 `LC_CODE_SIGNATURE` 的 `dataoff/datasize` 落点正确。
- **自校验闭环**：重签产物喂回**我们自己的** `codesign::parse`，必须报 `Intact`
  （逐页哈希全过），与改前一致（改前是 `Mismatch` 或 ad-hoc）。
- **fat/`.app`/`.ipa` 各形态**各来一份真实样本核对；无法覆盖的形态如实标注"未验证"。
- **账目闭合**：任何"没能重签"的原因（页大小未知、签名区放不下、算法不支持、fat 对齐
  失败）都要有计数与说明，绝不静默降级（§7）。

## 5. 明确的范围与红线

**做（若批准）：**
- 只对**用户显式给出的副本**重签，产物仍是**新文件**（`xxx.resigned`），绝不原地。
- 只做 **ad-hoc 重签**（无 CMS、无证书、无网络）。
- 保留或丢弃 entitlements 由用户选（默认保留原样字节 + 更新其 special slot 哈希）。
- 每一步"没做/没验证"都落进 notes。

**不做（本方案范围内）：**
- **不**接私钥 / 不读钥匙串 / 不产 CMS 签名（正式重签需要开发者身份，属高风险，另议）。
- **不**伪造信任链、不伪造 Apple 证书、不绕过 Gatekeeper/公证——这不是"重签"要做的事。
- **不**改 `LC_UUID`、**不**顺手"优化"其它 load command（少动少错）。
- **不**自动对 `.ipa` 里所有 framework 递归重签（那是产品级流程，先把单二进制做对）。

## 6. 版本与 API 影响（若实现）

- 这是**新功能命令**（预计 `bitflip-cli` 增一个 `resign` 子命令），不改现有 wire 结构，
  因此**大概率不 bump** `CORE/SERVER/ANALYSIS` 版本号；若新增签名摘要字段（如"这个产物
  是重签过的"）才需要，届时再评估。
- 依赖：ad-hoc 只需 `sha1`/`sha2`（已经在用）；**不引入** `apple-codesign`（MPL，见
  `DEPENDENCY-DECISIONS.md`）。

## 7. 风险清单（拍板时请逐条看）

| 风险 | 后果 | 缓解 |
| --- | --- | --- |
| 签名区移动后 load command / fat 偏移不一致 | 产物起不来 | 先只做"原地或尾部追加"路径；移动路径单独做 + 交叉核对 |
| 页大小 / codeLimit 判错 | 逐页哈希全错 | 全部沿用旧 CodeDirectory 的值，不自造 |
| entitlements special slot 漏更新 | `codesign -v` 报 entitlements 不一致 | 保留原字节时同步重算该槽；或显式丢弃并说明 |
| 被当成"绕过版权/许可"的工具 | 法律 / 合规风险 | 默认不给、需显式请求；文档与 UI 注明"仅限自有产物" |
| 正式（带证书）重签涉及私钥 | 高风险，泄密 | **本方案不做**；如要做，单独立项、隔离密钥处理 |

## 8. 落地顺序与进度

1. ✅ 纯函数：给定内容 + 旧 CodeDirectory 参数，产出**新的 CodeDirectory 字节**（含逐页哈希 +
   special slot），只读、可单测（用现有 `codesign::parse` 反向校验 `Intact`）。（A 阶段，`25740a1`）
2. ✅ 纯函数：给定各 blob，**拼回 SuperBlob**，单测对照结构。（A 阶段）
3. ✅ 写盘层（最稳子集）：签名区能原地容纳就原地、尾部补零、`datasize` 不变；放不下/需移动
   明确报错。`codesign::resign_in_place`。（B 阶段，`bc1a91d`）
4. ✅ CLI 落盘 + 交叉核对：`bitflip-cli resign [--apply]` 产出 `xxx.resigned`；
   `scripts/resign-acceptance.ps1`（`codesign -v`，缺工具 SKIP）+ 真实样本
   （PojavLauncher 内 5 个 ad-hoc 二进制全过，CAltKit 14/14）。（C 阶段）
5. ✅ 追加/变大写盘（D 阶段）：新签名比旧 `datasize` 大或签名区不紧贴时，追加到文件末尾并更新
   `LC_CODE_SIGNATURE` 与 `__LINKEDIT` 的 `filesize/vmsize`；第 0 页（含 load command）先定稿再
   算哈希。真实样本强制 SHA-256 触发追加，CAltKit 14/14、Alderis 469/469、MetalANGLE 2840/2840 全过。
6. ✅ fat 多切片 / 通用二进制（E 阶段）：`resign_macho_file` 按头分派，`resign_fat` 逐 slice 重签
   并重排 offset、重建 fat 头；合成 2-slice 全过。`.app` 内多二进制可逐个调用（本命令按文件）。
7. ⬜ 正式重签（带 CMS / 开发者身份 / 私钥）——按 §5/§7 **不做**，需单独立项与密钥隔离。

—— 以上为设计。**是否批准、以及批准到哪一步（只到 1-2 的纯函数？还是含 3-4 的写盘？），
请你定。** 未获批准前不写任何重签实现代码。
