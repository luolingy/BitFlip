# DEX / APK 格式参考（手写解析器用）

> 本文是 BitFlip 自研 APK/DEX 逆向核心的**字节级实现参考**。
> 设计决策见 [`docs/APK-DEX-DESIGN.md`](./APK-DEX-DESIGN.md)。
>
> **凡未取得原文的结论一律标 `UNVERIFIED`，不猜。** 本文末尾有完整清单。
> 带 ✅ 的条目是**在本机真实 APK 上实测**得到的，不是查文档得到的 ——
> 实测与文档冲突时以实测为准，并在原处指出。

## 0. 本机真实样本的实测结论（优先于任何文档）

样本：`C:\Users\Administrator\Downloads\ah-app-release.apk`（1867 条目、37 个 `.so`）
与 `base.apk`（1624 条目、20 个 `.so`）。

| 结论 | 实测数据 | 影响 |
| --- | --- | --- |
| ✅ **DEX 版本是 035，不是 041** | 6 个 dex 全是 `dex\n035\0`，`header_size = 112 (0x70)` | **v041 容器 DEX 可以不做** —— 这是最大的一处范围缩减 |
| ✅ **native 库全部是 DEFLATE 压缩** | `{8: 37}` / `{8: 20}`，STORED 数量 **0** | 必须解压才能拿到 ELF 字节；**不能**直接从 APK 里 mmap |
| ✅ **因此 zipalign 对齐与 16 KB 页要求不重要** | 压缩条目的 `header_offset % 4096` 无意义（如 154、2161、3996） | 不必实现"从 APK 直接映射 `.so`"这条路径 |
| ✅ **`armeabi` 这个 ABI 仍然存在** | `ah-app-release.apk` 有 `arm64-v8a / armeabi / armeabi-v7a / x86 / x86_64` | 文档里 Soong 的 ABI 列表**不完整**，要补 legacy `armeabi` |
| ✅ **`AndroidManifest.xml` 是二进制 XML** | 头 8 字节 `03 00 08 00` = type 0x0003 (`RES_XML_TYPE`) | 需要 AXML 解析，不能按文本读 |
| ✅ **`resources.arsc` 头与文档完全一致** | `02 00 0c 00` = type 0x0002、headerSize 12、`packageCount @ +8 = 1` | 文档的 arsc 布局是对的 |
| ✅ **`.so` 就是普通 ELF64** | `7f454c46`、class=2、machine=**183 (EM_AARCH64)** | **可直接复用现有 ELF 解析路径** |

两个 APK 都是 multidex（`classes.dex` + `classes2.dex` + `classes3.dex`）。

---

## 1. DEX 全局常量

```text
magic               8B   "dex\n035\0" = 64 65 78 0A 30 33 35 00
endian_tag          4B   ENDIAN_CONSTANT         = 0x12345678  (小端布局)
                         REVERSE_ENDIAN_CONSTANT = 0x78563412  (整文件按大端解读)
NO_INDEX (32 位域)  0xFFFFFFFF
16 位域无值         0xFFFF
SHA-1 摘要长度      20
```

- 版本取 `magic[4..7]` 三个 ASCII 数字。**036 被官方跳过**（旧 dalvik 会错误接受并运行），
  ART 的 `kDexMagicVersions` 里没有它。解析器应只接受 `035/037/038/039/040/041`。
- **`header_size` 只可能是 0x70（035–040）或 0x78（041）**。ART 严格校验
  `header_size == GetExpectedHeaderSize()`；`GetExpectedHeaderSize() = version < 41 ? 112 : 120`。
- `REVERSE_ENDIAN_CONSTANT` 出现时**所有** u16/u32 按大端读，但 (a) magic 不交换，
  (b) `insns` 的交换粒度是**单个 u16**（不是 code unit 对），(c) 字符串字节流不受影响。
  实现里检测到 reverse-endian 必须**在结论里显式标注** —— 这种文件极罕见，很可能是构造样本。

### `header_item` 字节表（035–040，112 = 0x70，align 4）

| off | size | 字段 | 说明 |
| --- | --- | --- | --- |
| 0x00 | 8 | `magic` | `dex\n0NN\0` |
| 0x08 | 4 | `checksum` | Adler-32，覆盖 **[12, file_size)** |
| 0x0C | 20 | `signature` | SHA-1，覆盖 **[32, file_size)** |
| 0x20 | 4 | `file_size` | **该 DEX 自身**字节数 |
| 0x24 | 4 | `header_size` | 0x70 / 0x78 |
| 0x28 | 4 | `endian_tag` | 0x12345678 / 0x78563412 |
| 0x2C | 4 | `link_size` | 现实恒 0 |
| 0x30 | 4 | `link_off` | `link_size==0 ⇒ 0` |
| 0x34 | 4 | `map_off` | → `map_list`；可为 0 |
| 0x38 | 4 | `string_ids_size` | |
| 0x3C | 4 | `string_ids_off` | |
| 0x40 | 4 | `type_ids_size` | **≤ 0xFFFF**（ART 强校验 `kDexNoIndex16`） |
| 0x44 | 4 | `type_ids_off` | |
| 0x48 | 4 | `proto_ids_size` | **≤ 0xFFFF** |
| 0x4C | 4 | `proto_ids_off` | |
| 0x50 | 4 | `field_ids_size` | |
| 0x54 | 4 | `field_ids_off` | |
| 0x58 | 4 | `method_ids_size` | |
| 0x5C | 4 | `method_ids_off` | |
| 0x60 | 4 | `class_defs_size` | |
| 0x64 | 4 | `class_defs_off` | |
| 0x68 | 4 | `data_size` | 必须是 4 的倍数 |
| 0x6C | 4 | `data_off` | data 段起点 |

> **更正**：`data_size`/`data_off` **自 035 起就在** header 里，不是 v038+ 新增。

v041 追加（共 120 = 0x78）：`0x70 container_size`、`0x74 header_offset`。

**对齐要求**：`header_item`/`map_list`/`string_id`/`type_id`/`proto_id`/`field_id`/`method_id`/
`class_def`/`type_list`/`code_item`/`annotations_directory_item`/`annotation_set_ref_list`/
`annotation_set_item` 均 **4 字节对齐**；`string_data_item`/`class_data_item`/`debug_info_item`/
`annotation_item`/`encoded_array_item` **无对齐要求**。

### checksum / signature 的覆盖范围

```text
checksum  = adler32(file[12 .. file_size))
signature = sha1  (file[32 .. file_size))
```

**BitFlip 取舍：不一致 ⇒ 写在 `notes` 里，不要拒绝文件。** ART 自己在"未要求校验"时
也只是 `LOG(WARNING) "Ignoring bad checksum"`。拒绝会把"被重新打包过的 APK"
（逆向里最常见的输入）整类挡在门外。

---

## 2. id 段

| 段 | 结构 | 尺寸 | 说明 |
| --- | --- | --- | --- |
| `string_ids` | `{ u32 string_data_off }` | 4 | → `string_data_item` |
| `type_ids` | `{ u32 descriptor_idx }` | 4 | → `string_ids`，内容是类型描述符 |
| `proto_ids` | `{ u32 shorty_idx; u32 return_type_idx; u16 pad; u32 parameters_off }` | 12 | `parameters_off` → `type_list`（0 = 无参） |
| `field_ids` | `{ u16 class_idx; u16 type_idx; u32 name_idx }` | 8 | |
| `method_ids` | `{ u16 class_idx; u16 proto_idx; u32 name_idx }` | 8 | |
| `call_site_ids`（038+） | `{ u32 call_site_off }` | 4 | → `encoded_array_item` |
| `method_handles`（038+） | `{ u16 type; u16 unused; u16 field_or_method_id; u16 unused }` | 8 | |

**最易错点**：`class_idx`/`type_idx`/`proto_idx` 是 **u16**，`name_idx`/`descriptor_idx` 是 **u32**。
所以 `type_ids_size > 0xFFFF` 直接是非法文件。

排序要求（解析器不必强制，但可做自检）：各 id 表按"对应字符串的 UTF-16 顺序"升序、无重复。

> **实测修正**：规范写"必须升序"，但**真实上架 APK 就是不满足的**。
> 本次在一个真实样本（`classes.dex`，8 800 484 字节）上实测到
> `OutOfOrder { pool: StringIds }` —— `string_ids` 乱序。
> 因此排序性检查的结论**只能写进 `notes`**：
> **既不能据此拒绝文件，也不能静默丢掉这条信息。**
> 别把"规范要求"直接当成"现网事实"，也不要反过来以为 ART 会拦下它。

**`call_site_ids` / `method_handles` 只能通过 `map_list` 发现** —— ART 的
`InitializeSectionsFromMapList()` 专门去 map 里找 `0x0007`/`0x0008`。
忽略 map 的解析器会静默漏掉它们。

---

## 3. class_def / class_data

`class_def_item`（32 = 0x20，align 4）：

| off | size | 字段 | 说明 |
| --- | --- | --- | --- |
| 0x00 | 4 | `class_idx` | → `type_ids`，必须是 class |
| 0x04 | 4 | `access_flags` | |
| 0x08 | 4 | `superclass_idx` | 无父类 = **0xFFFFFFFF** |
| 0x0C | 4 | `interfaces_off` | 0 = 无；→ `type_list` |
| 0x10 | 4 | `source_file_idx` | 0xFFFFFFFF = 无此信息 |
| 0x14 | 4 | `annotations_off` | 0 = 无 |
| 0x18 | 4 | `class_data_off` | 0 = 无（如 marker interface） |
| 0x1C | 4 | `static_values_off` | 0 = 无 |

- **version ≥ 037：`class_defs` 必须按 `class_idx` 升序且不重复**
  （`kClassDefinitionOrderEnforcedVersion = 37`）；<037 不要强加。

`class_data_item`（无对齐）：

```text
uleb128 static_fields_size, instance_fields_size, direct_methods_size, virtual_methods_size
encoded_field  : uleb128 field_idx_diff,  uleb128 access_flags
encoded_method : uleb128 method_idx_diff, uleb128 access_flags, uleb128 code_off
```

**diff 语义**：`*_idx_diff` 是与**同一列表**前一个元素的索引之差；
**每个列表的第一个元素直接就是索引本身**（相当于每个列表从 0 重启）。列表内必须递增。
`code_off == 0` ⇒ abstract / native（无 `code_item`）。

`access_flags`：`ACC_PUBLIC 0x1, PRIVATE 0x2, PROTECTED 0x4, STATIC 0x8, FINAL 0x10,
SYNCHRONIZED 0x20, VOLATILE 0x40, TRANSIENT 0x80, NATIVE 0x100, INTERFACE 0x200,
ABSTRACT 0x400, STRICT 0x800, SYNTHETIC 0x1000, ANNOTATION 0x2000, ENUM 0x4000,
CONSTRUCTOR 0x10000, DECLARED_SYNCHRONIZED 0x20000`（0x8000 未用）。

---

## 4. code_item / try / catch

`code_item`（align 4）：

| off | size | 字段 | 说明 |
| --- | --- | --- | --- |
| 0x00 | 2 | `registers_size` | 寄存器数（**不是**字节数） |
| 0x02 | 2 | `ins_size` | 入参字数（word） |
| 0x04 | 2 | `outs_size` | |
| 0x06 | 2 | `tries_size` | |
| 0x08 | 4 | `debug_info_off` | 0 = 无 |
| 0x0C | 4 | `insns_size` | **code unit** 数（不是字节数） |
| 0x10 | 2×n | `insns[]` | u16 数组 |
| — | 2 | `padding`（可选 =0） | **仅当 `tries_size != 0` 且 `insns_size` 为奇数** |
| — | 8×tries | `tries[]` | |
| — | 变长 | `handlers` | `encoded_catch_handler_list` |

**`tries_size != 0 ⇒ 4 字节对齐**（padding 的存在性由 `insns_size` 奇偶决定）。
这条写错就是"后面整体错位 2 字节"。

`try_item = { u32 start_addr; u16 insn_count; u16 handler_off }`
- `start_addr`/`insn_count` 以 **code unit** 计，数组内不重叠且按地址升序。
- `handler_off` 是从 `encoded_catch_handler_list` 起点算的**字节**偏移。

```text
encoded_catch_handler_list = { uleb128 size; encoded_catch_handler[size] }
    // tries_size 为奇数时，列表末尾再补 1 个字节 00
encoded_catch_handler = { sleb128 size; encoded_type_addr_pair[abs(size)]; [uleb128 catch_all_addr] }
    // size > 0 : 只有 typed catch
    // size == 0: 只有 catch-all
    // size < 0 : abs(size) 个 typed catch + catch-all
encoded_type_addr_pair = { uleb128 type_idx; uleb128 addr }
```

---

## 5. map_list（权威目录）

```text
MapList : { u32 size; MapItem list[size] }
MapItem : { u16 type; u16 unused; u32 size; u32 offset }   // 每项 12 字节
```

| type | 名称 | 元素尺寸 |
| --- | --- | --- |
| 0x0000 | `header_item` | 0x70 / 0x78 |
| 0x0001 | `string_id_item` | 4 |
| 0x0002 | `type_id_item` | 4 |
| 0x0003 | `proto_id_item` | 12 |
| 0x0004 | `field_id_item` | 8 |
| 0x0005 | `method_id_item` | 8 |
| 0x0006 | `class_def_item` | 32 |
| 0x0007 | `call_site_id_item`（038+） | 4 |
| 0x0008 | `method_handle_item`（038+） | 8 |
| 0x1000 | `map_list` | 4 + 12×size |
| 0x1001 | `type_list` | 4 + 2×size |
| 0x1002 | `annotation_set_ref_list` | 4 + 4×size |
| 0x1003 | `annotation_set_item` | 4 + 4×size |
| 0x2000 | `class_data_item` | 隐式 |
| 0x2001 | `code_item` | 隐式 |
| 0x2002 | `string_data_item` | 隐式 |
| 0x2003 | `debug_info_item` | 隐式 |
| 0x2004 | `annotation_item` | 隐式 |
| 0x2005 | `encoded_array_item` | 隐式 |
| 0x2006 | `annotations_directory_item` | 隐式 |
| **0xF000** | `hiddenapi_class_data_item`（039+） | 隐式 |

`0xF000` **在 0x1000/0x2000 区间之外**，与本表其它项不连续 —— 不要用"区间"判断。

- `map_off == 0` 是合法的（无 map），此时只能靠 header 的 size/off 导航。
- map 的 `size`/`offset` 与 header 不符时**以 header 为准**并记 `notes`。
- map 是拿到 `call_site_ids`、`method_handles`、`hiddenapi_class_data` 的**唯一**途径。

---

## 6. 其余结构

- `type_list = { u32 size; u16 type_idx[size] }`（align 4）。
- `annotation_set_item = { u32 size; u32 annotation_off[size] }`，条目按被引用 annotation 的 `type_idx` 升序。
- `annotation_set_ref_list = { u32 size; u32 annotations_off[size] }`（`0` = 该参数无注解）。
- `annotation_item = { u8 visibility; encoded_annotation }`；`0x00 BUILD / 0x01 RUNTIME / 0x02 SYSTEM`。
- `annotations_directory_item`：`u32 class_annotations_off`、`u32 fields_size`、
  `u32 annotated_methods_size`、`u32 annotated_parameters_size`，随后三组
  `{ u32 idx; u32 annotations_off }`（按 `field_idx`/`method_idx` 升序）。
  `parameter_annotation.annotations_off` 指向 **`annotation_set_ref_list`**（不是 set）。
- `encoded_annotation = { uleb128 type_idx; uleb128 size; annotation_element[size] }`，
  元素按 `string_id` 升序；`annotation_element.name_idx` 是**直接索引，不是 diff**。
- `encoded_value`：头字节 = `(value_arg << 5) | value_type`，**value 字节序恒为 little-endian**。

| type | 名称 | value_arg | 说明 |
| --- | --- | --- | --- |
| 0x00 | BYTE | 0 | 有符号一字节 |
| 0x02 | SHORT | size-1 | 符号扩展 |
| 0x03 | CHAR | size-1 | 零扩展 |
| 0x04 | INT | size-1 | 符号扩展 |
| 0x06 | LONG | size-1 | 符号扩展 |
| 0x10 | FLOAT | size-1 | 位模式右补零，IEEE754 32 |
| 0x11 | DOUBLE | size-1 | 位模式右补零，IEEE754 64 |
| 0x15 | METHOD_TYPE（038+） | size-1 | → `proto_ids` |
| 0x16 | METHOD_HANDLE（038+） | size-1 | → `method_handles` |
| 0x17 | STRING | size-1 | → `string_ids` |
| 0x18 | TYPE | size-1 | → `type_ids` |
| 0x19 | FIELD | size-1 | → `field_ids` |
| 0x1a | METHOD | size-1 | → `method_ids` |
| 0x1b | ENUM | size-1 | → `field_ids` |
| 0x1c | ARRAY | 0 | `encoded_array` |
| 0x1d | ANNOTATION | 0 | `encoded_annotation` |
| 0x1e | NULL | 0 | 无 |
| 0x1f | BOOLEAN | 就是值 0/1 | 无 |

（0x01/0x05/0x07…0x0f、0x12…0x14 无定义；遇到即报错，**不要猜**。）

### `debug_info_item`（无对齐，uleb128 状态机）

```text
uleb128 line_start
uleb128 parameters_size
uleb128p1 parameter_names[parameters_size]     // 0 = 无名
state machine 字节流 ...
```

状态寄存器：`address`（**code unit**，单调增）、`line`（≥1）、`source_file`、
`prologue_end`、`epilogue_begin`。

| opcode | 名称 | 操作数 |
| --- | --- | --- |
| 0x00 | `DBG_END_SEQUENCE` | — |
| 0x01 | `DBG_ADVANCE_PC` | uleb128 addr_diff |
| 0x02 | `DBG_ADVANCE_LINE` | sleb128 line_diff |
| 0x03 | `DBG_START_LOCAL` | uleb128 reg, uleb128p1 name_idx, uleb128p1 type_idx |
| 0x04 | `DBG_START_LOCAL_EXTENDED` | 同上 + uleb128p1 sig_idx |
| 0x05 | `DBG_END_LOCAL` | uleb128 reg |
| 0x06 | `DBG_RESTART_LOCAL` | uleb128 reg |
| 0x07 | `DBG_SET_PROLOGUE_END` | — |
| 0x08 | `DBG_SET_EPILOGUE_BEGIN` | — |
| 0x09 | `DBG_SET_FILE` | uleb128p1 name_idx |
| 0x0a…0xff | special opcode | 见下 |

- **`uleb128p1`：磁盘值 = "索引 + 1"，原始 0 表示"无"。** 写错会让所有
  `DBG_SET_FILE`/局部变量名**偏移一位**。
- special opcode：`adjusted = op - 0x0a`；
  `line += DBG_LINE_BASE + (adjusted % DBG_LINE_RANGE)`；
  `address += adjusted / DBG_LINE_RANGE`（`DBG_LINE_BASE = -4`、`DBG_LINE_RANGE = 15`）。
  每个 special opcode 会清 `prologue_end`/`epilogue_begin`。
- 若只要行号，可跳过无 `address` 变化的 opcode，但**仍必须完整解码流**以定位下一条
  （长度依赖 uleb128p1 的字节数）。

### 版本差异

| ver | header_size | 变化 |
| --- | --- | --- |
| 035 | 0x70 | 基线 |
| 036 | — | **从未发布**，被故意跳过 |
| 037 | 0x70 | default 方法；**class_def 强制按 class_idx 排序** |
| 038 | 0x70 | `call_site_id_item`(0x0007) + `method_handle_item`(0x0008)；encoded_value 0x15/0x16；`invoke-custom`/`invoke-polymorphic`/`const-method-handle`/`const-method-type` |
| 039 | 0x70 | `hiddenapi_class_data_item`（map type **0xF000**） |
| 040 | 0x70 | `UNVERIFIED`（未找到任何内容变化证据；**没有**改成 SHA-256 —— `kSha1DigestSize` 无条件为 20） |
| 041 | **0x78** | 容器 DEX：`container_size`/`header_offset` |

**另需识别并明确拒绝**：`.cdex`（CompactDex）、vdex、oat。它们的 magic 原文本次未取得
→ 在代码里按"magic 不匹配任一已知 DEX 版本"报错并注明，**不要抄网上的 magic 字符串**。

### v041 容器 DEX（本次样本没用到，但设计要留位）

**所有 section 的 `*_off` 都相对"容器起点"，不是相对本 DEX 头。**

```text
容器内任意 DEX 的某 off_ 字段的绝对地址 = container_start + off_
                              container_start = this_header_addr - header_offset
```

- **只有 `header_offset == 0` 的第一个 DEX 才与单文件行为一致** —— 这正是
  "单文件测试全绿、第二个 DEX 全错"的坑。
- 容器 DEX 的 `data_size == data_off == 0`（`Header::SetDexContainer()` 显式清零）。
- **v041 没有"共享 data 段"**：那是 CompactDex(`.cdex`) 的概念。
- 遍历：`pos` 从 0 起，读 `file_size`/`header_offset`（必须 `== pos`），
  下一个 DEX 在 `pos + file_size`；`pos + file_size >= container_size` 即最后一个。
  **不要"向后搜索下一个 magic"**（data 段里可能恰好出现 `dex\n`）。

---

## 7. DEX 指令集

**DEX ≠ JVM 字节码**：JVM 是栈式、需 class 文件常量池；DEX 是**寄存器式**、
定长 16 位 code unit、索引指向 DEX 的四张 id 表。两者没有可复用的解码器。
**所有"地址"都是 code unit 索引**，不是字节偏移，也不是虚拟地址。

### 格式 ID → 长度（纯查表）

| format | units | 操作数形态 |
| --- | --- | --- |
| `10x` | 1 | `op` |
| `12x` | 1 | `op vA, vB` |
| `11n` | 1 | `op vA, #+B` |
| `11x` | 1 | `op vAA` |
| `10t` | 1 | `op +AA` |
| `20t` | 2 | `op +AAAA` |
| `22x` | 2 | `op vAA, vBBBB` |
| `21t` | 2 | `op vAA, +BBBB` |
| `21s` | 2 | `op vAA, #+BBBB` |
| `21h` | 2 | `op vAA, #+BBBB00000…` |
| `21c` | 2 | `op vAA, thing@BBBB` |
| `23x` | 2 | `op vAA, vBB, vCC` |
| `22b` | 2 | `op vAA, vBB, #+CC` |
| `22t` | 2 | `op vA, vB, +CCCC` |
| `22s` | 2 | `op vA, vB, #+CCCC` |
| `22c` | 2 | `op vA, vB, thing@CCCC` |
| `32x` | 3 | `op vAAAA, vBBBB` |
| `30t` | 3 | `op +AAAAAAAA` |
| `31t` | 3 | `op vAA, +BBBBBBBB` |
| `31i` | 3 | `op vAA, #+BBBBBBBB` |
| `31c` | 3 | `op vAA, thing@BBBBBBBB` |
| `35c` | 3 | `op {vC..vG}, thing@BBBB`（A: count） |
| `3rc` | 3 | `op {vCCCC..v(CCCC+AA-1)}, meth@BBBB` |
| `45cc` | 4 | `op {vC..vG}, meth@BBBB, proto@HHHH`；布局 `AG op BBBB FEDC HHHH` |
| `4rcc` | 4 | `op {VCCCC..}, meth@BBBB, proto@HHHH`；布局 `AA op BBBB CCCC HHHH` |
| `51l` | 5 | `op vAA, #+BBBBBBBBBBBBBBBB` |

位级取法：

```text
unit0  = u16[0]
opcode = unit0 & 0xFF
InstA  = (unit0 >> 8) & 0x0F     # 12x/11n/22c/22s/22t/35c/45cc
InstB  = (unit0 >> 12) & 0x0F    # 12x
InstAA = (unit0 >> 8) & 0xFF     # 11x/10t/21*/22x/23x/31*/51l/3rc（10t 当有符号）
```

**`NOP`（0x00）是唯一例外**，长度是"复杂"的 —— 见下。

### opcode 全表（名称 + 格式）

| op | 名称 (fmt) | op | 名称 (fmt) | op | 名称 (fmt) | op | 名称 (fmt) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 00 | nop (10x) | 01 | move (12x) | 02 | move/from16 (22x) | 03 | move/16 (32x) |
| 04 | move-wide (12x) | 05 | move-wide/from16 (22x) | 06 | move-wide/16 (32x) | 07 | move-object (12x) |
| 08 | move-object/from16 (22x) | 09 | move-object/16 (32x) | 0a | move-result (11x) | 0b | move-result-wide (11x) |
| 0c | move-result-object (11x) | 0d | move-exception (11x) | 0e | return-void (10x) | 0f | return (11x) |
| 10 | return-wide (11x) | 11 | return-object (11x) | 12 | const/4 (11n) | 13 | const/16 (21s) |
| 14 | const (31i) | 15 | const/high16 (21h) | 16 | const-wide/16 (21s) | 17 | const-wide/32 (31i) |
| 18 | const-wide (51l) | 19 | const-wide/high16 (21h) | 1a | const-string (21c) | 1b | const-string/jumbo (31c) |
| 1c | const-class (21c) | 1d | monitor-enter (11x) | 1e | monitor-exit (11x) | 1f | check-cast (21c) |
| 20 | instance-of (22c) | 21 | array-length (12x) | 22 | new-instance (21c) | 23 | new-array (22c) |
| 24 | filled-new-array (35c) | 25 | filled-new-array/range (3rc) | 26 | fill-array-data (31t) | 27 | throw (11x) |
| 28 | goto (10t) | 29 | goto/16 (20t) | 2a | goto/32 (30t) | 2b | packed-switch (31t) |
| 2c | sparse-switch (31t) | 2d | cmpl-float (23x) | 2e | cmpg-float (23x) | 2f | cmpl-double (23x) |
| 30 | cmpg-double (23x) | 31 | cmp-long (23x) | 32 | if-eq (22t) | 33 | if-ne (22t) |
| 34 | if-lt (22t) | 35 | if-ge (22t) | 36 | if-gt (22t) | 37 | if-le (22t) |
| 38 | if-eqz (21t) | 39 | if-nez (21t) | 3a | if-ltz (21t) | 3b | if-gez (21t) |
| 3c | if-gtz (21t) | 3d | if-lez (21t) | **3e–43** | **unused (10x)** | 44 | aget (23x) |
| 45 | aget-wide (23x) | 46 | aget-object (23x) | 47 | aget-boolean (23x) | 48 | aget-byte (23x) |
| 49 | aget-char (23x) | 4a | aget-short (23x) | 4b | aput (23x) | 4c | aput-wide (23x) |
| 4d | aput-object (23x) | 4e | aput-boolean (23x) | 4f | aput-byte (23x) | 50 | aput-char (23x) |
| 51 | aput-short (23x) | 52 | iget (22c) | 53 | iget-wide (22c) | 54 | iget-object (22c) |
| 55 | iget-boolean (22c) | 56 | iget-byte (22c) | 57 | iget-char (22c) | 58 | iget-short (22c) |
| 59 | iput (22c) | 5a | iput-wide (22c) | 5b | iput-object (22c) | 5c | iput-boolean (22c) |
| 5d | iput-byte (22c) | 5e | iput-char (22c) | 5f | iput-short (22c) | 60 | sget (21c) |
| 61 | sget-wide (21c) | 62 | sget-object (21c) | 63 | sget-boolean (21c) | 64 | sget-byte (21c) |
| 65 | sget-char (21c) | 66 | sget-short (21c) | 67 | sput (21c) | 68 | sput-wide (21c) |
| 69 | sput-object (21c) | 6a | sput-boolean (21c) | 6b | sput-byte (21c) | 6c | sput-char (21c) |
| 6d | sput-short (21c) | 6e | invoke-virtual (35c) | 6f | invoke-super (35c) | 70 | invoke-direct (35c) |
| 71 | invoke-static (35c) | 72 | invoke-interface (35c) | **73** | **unused (10x)** | 74 | invoke-virtual/range (3rc) |
| 75 | invoke-super/range (3rc) | 76 | invoke-direct/range (3rc) | 77 | invoke-static/range (3rc) | 78 | invoke-interface/range (3rc) |
| **79,7a** | **unused (10x)** | 7b | neg-int (12x) | 7c | not-int (12x) | 7d | neg-long (12x) |
| 7e | not-long (12x) | 7f | neg-float (12x) | 80 | neg-double (12x) | 81 | int-to-long (12x) |
| 82 | int-to-float (12x) | 83 | int-to-double (12x) | 84 | long-to-int (12x) | 85 | long-to-float (12x) |
| 86 | long-to-double (12x) | 87 | float-to-int (12x) | 88 | float-to-long (12x) | 89 | float-to-double (12x) |
| 8a | double-to-int (12x) | 8b | double-to-long (12x) | 8c | double-to-float (12x) | 8d | int-to-byte (12x) |
| 8e | int-to-char (12x) | 8f | int-to-short (12x) | 90 | add-int (23x) | 91 | sub-int (23x) |
| 92 | mul-int (23x) | 93 | div-int (23x) | 94 | rem-int (23x) | 95 | and-int (23x) |
| 96 | or-int (23x) | 97 | xor-int (23x) | 98 | shl-int (23x) | 99 | shr-int (23x) |
| 9a | ushr-int (23x) | 9b | add-long (23x) | 9c | sub-long (23x) | 9d | mul-long (23x) |
| 9e | div-long (23x) | 9f | rem-long (23x) | a0 | and-long (23x) | a1 | or-long (23x) |
| a2 | xor-long (23x) | a3 | shl-long (23x) | a4 | shr-long (23x) | a5 | ushr-long (23x) |
| a6 | add-float (23x) | a7 | sub-float (23x) | a8 | mul-float (23x) | a9 | div-float (23x) |
| aa | rem-float (23x) | ab | add-double (23x) | ac | sub-double (23x) | ad | mul-double (23x) |
| ae | div-double (23x) | af | rem-double (23x) | b0 | add-int/2addr (12x) | b1 | sub-int/2addr (12x) |
| b2 | mul-int/2addr (12x) | b3 | div-int/2addr (12x) | b4 | rem-int/2addr (12x) | b5 | and-int/2addr (12x) |
| b6 | or-int/2addr (12x) | b7 | xor-int/2addr (12x) | b8 | shl-int/2addr (12x) | b9 | shr-int/2addr (12x) |
| ba | ushr-int/2addr (12x) | bb | add-long/2addr (12x) | bc | sub-long/2addr (12x) | bd | mul-long/2addr (12x) |
| be | div-long/2addr (12x) | bf | rem-long/2addr (12x) | c0 | and-long/2addr (12x) | c1 | or-long/2addr (12x) |
| c2 | xor-long/2addr (12x) | c3 | shl-long/2addr (12x) | c4 | shr-long/2addr (12x) | c5 | ushr-long/2addr (12x) |
| c6 | add-float/2addr (12x) | c7 | sub-float/2addr (12x) | c8 | mul-float/2addr (12x) | c9 | div-float/2addr (12x) |
| ca | rem-float/2addr (12x) | cb | add-double/2addr (12x) | cc | sub-double/2addr (12x) | cd | mul-double/2addr (12x) |
| ce | div-double/2addr (12x) | cf | rem-double/2addr (12x) | d0 | add-int/lit16 (22s) | d1 | rsub-int (22s) |
| d2 | mul-int/lit16 (22s) | d3 | div-int/lit16 (22s) | d4 | rem-int/lit16 (22s) | d5 | and-int/lit16 (22s) |
| d6 | or-int/lit16 (22s) | d7 | xor-int/lit16 (22s) | d8 | add-int/lit8 (22b) | d9 | rsub-int/lit8 (22b) |
| da | mul-int/lit8 (22b) | db | div-int/lit8 (22b) | dc | rem-int/lit8 (22b) | dd | and-int/lit8 (22b) |
| de | or-int/lit8 (22b) | df | xor-int/lit8 (22b) | e0 | shl-int/lit8 (22b) | e1 | shr-int/lit8 (22b) |
| e2 | ushr-int/lit8 (22b) | **e3–f9** | **unused (10x)** | | | | |
| fa | invoke-polymorphic (45cc) | fb | invoke-polymorphic/range (4rcc) | fc | invoke-custom (35c) | fd | invoke-custom/range (3rc) |
| fe | const-method-handle (21c) | ff | const-method-type (21c) | | | | |

> **更正两处流传很广的错误说法**：
> 1. **`0xe3–0xf9` 不是"多字节 odex 指令"**。在现行 DEX 里它们是 `10x` 的 **unused 槽位**。
>    Dalvik 时代这些编号确实被 ODEX/quick 指令占用，但那些指令**格式仍是标准宽度**
>    （`22cs`/`35ms`/`35mi`/`3rms`/`3rmi`），既非多字节，也**从未出现在标准 DEX**。
> 2. **4.0 规范里的 "`ff` = expanded opcode" 机制在 ART 中不存在**。`0xff` 现在是
>    `const-method-type` (21c)。

**`kNumPackedOpcodes = 0x100`；opcode 就是 `unit0 & 0xFF`**（没有 expanded-opcode 机制）。

### 分类区间（写解码器的骨架）

| 区间 | 内容 |
| --- | --- |
| 0x00–0x09 | move 系列 |
| 0x0a–0x11 | move-result / return |
| 0x12–0x19 | const / const-wide（含 51l） |
| 0x1a–0x1c | const-string/jumbo/class |
| 0x1d–0x1f | monitor / check-cast |
| 0x20–0x26 | 对象/数组创建与填充 |
| 0x27–0x2c | throw / goto / switch |
| 0x2d–0x31 | 比较 |
| 0x32–0x3d | if-* |
| **0x3e–0x43** | **未用** |
| 0x44–0x51 | 数组读写 |
| 0x52–0x5f | 实例字段读写 |
| 0x60–0x6d | 静态字段读写 |
| 0x6e–0x72, 0x74–0x78 | invoke |
| **0x73, 0x79, 0x7a** | **未用** |
| 0x7b–0x8f | 一元运算/类型转换 |
| 0x90–0xaf | 二元运算（23x） |
| 0xb0–0xcf | 二元运算 /2addr（12x） |
| 0xd0–0xd7 | lit16 |
| 0xd8–0xe2 | lit8 |
| **0xe3–0xf9** | **未用** |
| 0xfa–0xff | invoke-polymorphic/custom + const-method-handle/type（038+） |

### payload 伪指令（由 `nop` 的高位字节承载）

```text
kPackedSwitchSignature = 0x0100
kSparseSwitchSignature = 0x0200
kArrayDataSignature    = 0x0300
```

一段 payload 的**第一个 code unit 是 `0x0100` / `0x0200` / `0x0300`**
（低字节 = `nop`，高位字节承载签名）。**这就是 `NOP` 长度"复杂"的原因：
识别 payload 只能靠 `unit0 >> 8 != 0`。**

```text
packed-switch-payload : 4 + case_count*2   code units
    u16 ident, u16 case_count, i32 first_key, i32 targets[case_count]
    （keys 是 first_key + i 等间距，所以不存 keys）
sparse-switch-payload : 2 + case_count*4   code units
    u16 ident, u16 case_count, i32 keys[case_count], i32 targets[case_count]
    （keys 必须严格递增）
array-data-payload    : 4 + (element_count*element_width + 1)/2   code units
    u16 ident, u16 element_width, u32 element_count, u8 data[...]
    element_width ∈ {1,2,4,8}；data 按字节紧排，最后一个 code unit 高字节填 0
```

- `targets[i]` 是 **i32 偏移，单位 code unit，相对承载它的那条
  `packed-switch`/`sparse-switch` 指令的地址**（不是相对 payload）。
- `31t` 指令本身固定占 3 code units，**payload 另算**，不包含在 3 里。
- payload 必须 4 字节对齐（相对 `insns` 起点）—— **UNVERIFIED**（规范原文未取得；
  证据是 `PACKED(4)` 结构体与编译器行为）。**实现建议：期待 4 字节对齐，
  但允许未对齐并记 `notes`，不要因此拒绝文件。**

### CFG 可用的指令标志（ART `InstructionDescriptor::flags`）

```text
kBranch 0x01  kContinue 0x02  kSwitch 0x04  kThrow 0x08
kReturn 0x10  kInvoke 0x20    kUnconditional 0x40  kExperimental 0x80
```

可直接照抄为 Rust 位标志：`IsBasicBlockEnd() = IsBranch() || IsReturn() || opcode == THROW`。

---

## 8. APK 容器

### ZIP 关键常量（来自 apksig）

```text
ZIP_EOCD_REC_SIG            = 0x06054b50
ZIP_EOCD_REC_MIN_SIZE       = 22
EOCD: +10 u16 总记录数, +12 u32 CD 大小, +16 u32 CD 偏移, +20 u16 注释长度
COMPRESSION_METHOD_STORED   = 0
COMPRESSION_METHOD_DEFLATED = 8
GP_FLAG_DATA_DESCRIPTOR_USED = 0x08
ZIP64_RECORD_ID             = 0x0001   (extra field)
```

定位：从文件尾向前扫 `0x06054b50`；`cdStart = eocd+16`；`cdEnd = cdStart + cdSize`；
要求 `cdStart <= eocd` 且 `cdEnd <= eocd`。

**Zip64**：apksig 只处理 Zip64 **extra field**，不解析 Zip64 EOCD/locator
（其签名值本次 **UNVERIFIED**）。遇到 `0xffffffff` 占位应显式报告"疑似 Zip64，未支持"
（符合"未实现的能力明确报错"）。

### APK Signing Block（v2/v3 的**纯检测**）

```text
1. cdEnd != eocdStart            -> 无签名块（CD 必须紧邻 EOCD）
2. cdStart < 32                  -> 无签名块
3. footer = file[cdStart-24 .. cdStart)
   footer[8..16]  != 0x20676953204b5041 ("APK Sig Block 42" 前半)
   或 footer[16..24] != 0x3234206b636f6c42 ("APK Sig Block 42" 后半) -> 无签名块
4. size = footer.u64(0)；size < 24 或 > i32::MAX-8 -> 无签名块
   blockOffset = cdStart - (size + 8)；< 0 -> 无签名块
5. file[blockOffset..+8].u64 != size -> 无签名块（首尾 size 必须一致）
```

块内格式：`u64 size` + 若干 `{u64 size; u32 ID; value[size-4]}` + `u64 size` + `u128 magic`。

| ID | 含义 |
| --- | --- |
| `0x7109871a` | APK Signature Scheme **v2** |
| `0xf05368c0` | **v3** |
| `0x1b93ad61` | **v3.1** |
| `0xbeeff00d` | v2 的 stripping-protection attribute |
| `0x42726577` | verity padding（把块补到 4096 倍数） |
| `0x6dff800d` / `0x2b09189e` | source stamp v2 / v1 |
| `0x3ba06f8c` / `0x559f8b02` / `0xc2a6b3ba` | v3 rotation attribute |

**v1（JAR 签名）检测**：只看 ZIP 条目名 —— `META-INF/MANIFEST.MF`、`INDEX.LIST`、
`<x>.SF`、`<x>.DSA`、`services/`。`SIG-*` 前缀与大小写/子目录细节 **UNVERIFIED**
（检测时建议对 `META-INF/` 做大小写不敏感匹配并一并报告，避免漏判）。

**不校验**：只做"是否存在 v1/v2/v3、块偏移、ID 列表、证书链存在性"这类**结构检测**，
不做 SHA-256/签名**验证**。结论里必须区分"存在 v2 块"与"已验证 v2 签名"
（后者未实现，按 §7 报 `NotYetImplemented`）。

### binary XML（`AndroidManifest.xml`）

所有 chunk 的头：`struct ResChunk_header { u16 type; u16 headerSize; u32 size; }`（8 字节）。

| type | 名称 |
| --- | --- |
| 0x0000 | `RES_NULL_TYPE` |
| 0x0001 | `RES_STRING_POOL_TYPE` |
| 0x0002 | `RES_TABLE_TYPE`（arsc 顶层） |
| 0x0003 | `RES_XML_TYPE`（AXML 顶层）✅ 实测 |
| 0x0100/0x0101 | `START_NAMESPACE` / `END_NAMESPACE` |
| 0x0102/0x0103/0x0104 | `START_ELEMENT` / `END_ELEMENT` / `CDATA` |
| 0x0180 | `RES_XML_RESOURCE_MAP_TYPE` |
| 0x0200 | `RES_TABLE_PACKAGE_TYPE` |
| 0x0201/0x0202 | `RES_TABLE_TYPE_TYPE` / `TYPE_SPEC_TYPE` |
| 0x0203 | `RES_TABLE_LIBRARY_TYPE` |
| 0x0204/0x0205 | `RES_TABLE_OVERLAYABLE_TYPE` / `_POLICY_TYPE` |
| 0x0206 | `RES_TABLE_STAGED_ALIAS_TYPE` |

字符串池（AXML 与 arsc 共用）：

```text
struct ResStringPool_header {
  ResChunk_header header;   // headerSize 通常 0x1C
  u32 stringCount; u32 styleCount;
  u32 flags;                // SORTED_FLAG = 1<<0 ; UTF8_FLAG = 1<<8
  u32 stringsStart; u32 stylesStart;
};
```

串数据两种编码：**UTF-16**（u16 序列，必须以 `0x0000` 结束；长度前缀 1 个 u16，
≥0x8000 时用"高位置 1 的 u16 + 第二个 u16"凑 32 位）与 **UTF-8**（**两个长度前缀**：
先 UTF-16 长度、再 UTF-8 字节长度，各 1 或 2 字节；`len = ((len & 0x7F) << 8) | next`）。
AXML 的 UTF-8 池是否**就是** MUTF-8 **UNVERIFIED**（只验证了长度编码）
→ 按"UTF-8 + 保留代理对"处理最稳。

```text
struct ResXMLTree_node { ResChunk_header header; u32 lineNumber; u32 comment; }
    // comment == 0xffffffff 表示无注释
struct ResXMLTree_attrExt {                       // 20 字节，跟在 START_ELEMENT node 后
  u32 ns; u32 name;                                // ns == 0xffffffff 表示无命名空间
  u16 attributeStart; u16 attributeSize;           // 通常 20
  u16 attributeCount; u16 idIndex; u16 classIndex; u16 styleIndex;   // 1-based，0 = 无
};
struct ResXMLTree_attribute { u32 ns; u32 name; u32 rawValue; Res_value typedValue; };  // 20 字节
struct Res_value { u16 size /*=8*/; u8 res0 /*=0*/; u8 dataType; u32 data; };           // 8 字节
```

`Res_value.dataType`：`TYPE_NULL 0x00`（data 0=undefined / 1=empty）、`TYPE_REFERENCE 0x01`、
`TYPE_ATTRIBUTE 0x02`、`TYPE_STRING 0x03`、`TYPE_FLOAT 0x04`、`TYPE_DIMENSION 0x05`、
`TYPE_FRACTION 0x06`、`TYPE_DYNAMIC_REFERENCE 0x07`、`TYPE_DYNAMIC_ATTRIBUTE 0x08`、
`TYPE_INT_DEC 0x10`、`TYPE_INT_HEX 0x11`、`TYPE_INT_BOOLEAN 0x12`、`TYPE_INT_COLOR_* 0x1c…0x1f`。

**属性名 → Android 属性资源 ID**（如 `android:versionCode`）靠 `0x0180` resource-map chunk：
`id = getAttributeNameID(idx)`，`resId = mResIds[id]`，
`mNumResIds = (chunk->size - chunk->headerSize) / sizeof(uint32_t)`
（项数由该 chunk 自身大小推出）。

**常用属性资源 ID**：`versionCode = 0x0101021b`、`versionName = 0x0101021c`、
`minSdkVersion = 0x0101020c`、`debuggable = 0x0101000f`。

`0xffffffff` 哨兵：`ResXMLTree_node.comment`（无注释）、`attribute.ns`（无命名空间）、
`ResStringPool_ref`（无此字符串）、`ResTable_type::NO_ENTRY`。

### `resources.arsc`

```text
struct ResTable_header { ResChunk_header header; u32 packageCount; }   // headerSize = 0x0C  ✅ 实测
struct ResTable_package {
  ResChunk_header header;      // 通常 headerSize = 0x120
  u32 id;                      // 1 起；0 = 非 base package
  u16 name[128];               // UTF-16，\0 结尾，**定长 256 字节** ← 最容易漏读
  u32 typeStrings; u32 lastPublicType;
  u32 keyStrings;  u32 lastPublicKey;
  u32 typeIdOffset;            // split APK 用
};
struct ResTable_typeSpec { ResChunk_header header; u8 id; u8 res0; u16 res1; u32 entryCount;
  // 随后 entryCount 个 u32 配置掩码
  enum { SPEC_PUBLIC = 0x40000000, SPEC_STAGED_API = 0x20000000 };
};
struct ResTable_type { ResChunk_header header; u8 id; u8 flags; u16 reserved;
  u32 entryCount; u32 entriesStart; ResTable_config config;  /* 必须是最后一个字段 */
  enum { FLAG_SPARSE = 0x01, FLAG_OFFSET16 = 0x02 };  NO_ENTRY = 0xFFFFFFFF; };
struct ResTable_sparseTypeEntry { u16 idx; u16 offset; };  // offset 相对 entriesStart，单位 4 字节
struct ResTable_entry { u16 size; u16 flags; u32 key; };   // FLAG_COMPLEX=0x0001, FLAG_PUBLIC=0x0002
struct ResTable_map { u32 name; Res_value value; };
```

- `config` 变长且**必须是 `ResTable_type` 最后一个字段**；读够 `config.size` 就行，
  多余的尾部字段是新版本加的前向兼容数据，跳过。
- 无 `FLAG_SPARSE`：`entriesStart` 之后是 `entryCount` 个 u32 索引，`NO_ENTRY` 表示不存在，
  **索引值是相对 `entriesStart` 的字节偏移**。
- 有 `FLAG_SPARSE`：`ResTable_sparseTypeEntry` 数组（按 `idx` 升序，可二分），
  `offset` 单位是 **4 字节**。
- 有 `FLAG_OFFSET16`：条目偏移是 u16，`0xffff → NO_ENTRY`，否则 `off16 * 4`。
- `ResTable_map[]` 的数量计算规则（`entry.size` 相关）**UNVERIFIED** ——
  实现时按 `entry.size` 与 map 结构自洽解析并做边界校验。

### `lib/<abi>` 与对齐

- ✅ **实测：本机两个真实 APK 的 `.so` 全部是 DEFLATE（method=8），没有一个 STORED。**
  所以**必须解压**才能拿到 ELF 字节。
- ABI 名集合 —— 文档里 Soong 的列表（`arm64-v8a / armeabi-v7a / riscv64 / x86_64 / x86`）
  **不完整**：✅ 实测还有 legacy **`armeabi`**。解析时按"已知 ABI 集合"识别，
  未知目录名记 `notes` 而不是丢弃。
- 解包落盘后的目录用的是 **ISA 名**（`arm64`），与 APK 内的 ABI 名（`arm64-v8a`）不同：
  `VMRuntime.getInstructionSet("arm64-v8a") == "arm64"`，`LIB_DIR_NAME = "lib"`、
  `LIB64_DIR_NAME = "lib64"`。**提取器应同时报告两个名字，别混用。**
- zipalign 只为**未压缩且非目录**的条目加 padding，且 `getAlignment()` 只在扩展名
  **恰为 `.so`** 时返回页大小（否则返回 `<align>`，典型 4）。`-p` = 4096，`-P 4|16|64`（KB）。
  目的（README 逐字）：让未压缩数据能**直接 mmap**。
  → 对**压缩**条目（本机实测的全部情况）这些都不适用。
- 16 KB 页：Soong 给 arm64 追加 `-Wl,-z,max-page-size=...`，即 `.so` 的 `p_align`
  也要合规。Play/Android 15 的官方措辞 **UNVERIFIED**。

### `classes.dex` 命名

`classes.dex` + `classes2.dex`、`classes3.dex`…（按名称字典序即加载顺序）。
✅ 实测两个 APK 都是 3 个 dex。精确命名规则的官方原文 **UNVERIFIED**
（建议实现为"`classes.dex` + `classes<N>.dex`，N 从 2 连续递增"，不符合的成员记 `notes`）。

---

## 9. 实现陷阱（逐条给正确做法）

1. **ULEB128/SLEB128 的字节上限**。ART：`max_bytes = (num_bits + 6) / 7` → 32 位 = **5 字节**。
   绝不能写成 `while (b & 0x80) { ... }`（构造的全 `0x80` 流会越界读）。

   ```rust
   #[inline]
   pub fn uleb128(buf: &[u8], pos: &mut usize) -> Result<u32, DexError> {
       let mut result: u32 = 0;
       for i in 0..5usize {
           let b = *buf.get(*pos).ok_or(DexError::TruncatedLeb)?;
           *pos += 1;
           if i == 4 && (b & 0xF0) != 0 { return Err(DexError::Leb128Overflow); }
           result |= ((b & 0x7F) as u32) << (i * 7);
           if b & 0x80 == 0 { return Ok(result); }
       }
       Err(DexError::Leb128TooLong)
   }

   #[inline]
   pub fn sleb128(buf: &[u8], pos: &mut usize) -> Result<i32, DexError> {
       let mut result: i32 = 0;
       let mut shift = 0u32;
       for i in 0..5usize {
           let b = *buf.get(*pos).ok_or(DexError::TruncatedLeb)?;
           *pos += 1;
           result |= ((b & 0x7F) as i32) << shift;
           shift += 7;
           if b & 0x80 == 0 {
               if shift < 32 && (b & 0x40) != 0 { result |= -1i32 << shift; }  // 符号扩展
               return Ok(result);
           }
           if i == 4 { return Err(DexError::Leb128TooLong); }
       }
       unreachable!()
   }

   /// uleb128p1：磁盘值 = 索引 + 1；原始 0 表示"无"（None）。
   pub fn uleb128p1(buf: &[u8], pos: &mut usize) -> Result<Option<u32>, DexError> {
       Ok(match uleb128(buf, pos)? { 0 => None, v => Some(v - 1) })
   }
   ```

2. **NO_INDEX 与"0 表示无"**。32 位域用 `0xFFFFFFFF`，16 位域用 `0xFFFF`。
   **所有 off 字段：0 = 不存在**（ART `DataPointer(offset) { return offset != 0 ? data+offset : nullptr; }`）
   —— `annotations_off`/`class_data_off`/`static_values_off`/`debug_info_off`/`parameters_off`/
   `interfaces_off` 都要按 `Option<T>` 处理，不要解析出"偏移 0 的对象"
   （那会把 header 当 `code_item` 读）。

3. **diff 编码只在两处**：`class_data_item` 的 `field_idx_diff`/`method_idx_diff`。
   `annotation_element.name_idx` **不是 diff**；`annotations_directory` 的
   `field_idx`/`method_idx` 也不是 diff（但必须升序）。

4. **MUTF-8 ≠ UTF-8**。DEX 的 `string_data_item` 是 MUTF-8：只有 1/2/3 字节编码，
   `U+10000`–`U+10FFFF` 写成 **CESU-8 风格的两个 3 字节代理对**，
   `U+0000` 写成 `0xC0 0x80`，而**裸 `0x00` 是串终止符**。
   因此 `strcmp` 排序不可靠（规范明说）。

   ```rust
   /// MUTF-8 → UTF-8(String)。裸 0x00 视为终止（调用方负责定位末尾）。
   pub fn mutf8_to_string(mut b: &[u8]) -> Result<String, DexError> {
       let mut out = String::new();
       let mut pending_hi: Option<u16> = None;
       while let Some(&c) = b.first() {
           let (cp, n): (u32, usize) = match c {
               0x00 => break,                                     // 串终止
               0x01..=0x7F => (c as u32, 1),
               0xC0..=0xDF => {
                   let c2 = *b.get(1).ok_or(DexError::BadMutf8)?;
                   ((((c & 0x1F) as u32) << 6) | (c2 & 0x3F) as u32, 2)
               }
               0xE0..=0xEF => {
                   let c2 = *b.get(1).ok_or(DexError::BadMutf8)?;
                   let c3 = *b.get(2).ok_or(DexError::BadMutf8)?;
                   ((((c & 0x0F) as u32) << 12)
                       | (((c2 & 0x3F) as u32) << 6)
                       | (c3 & 0x3F) as u32, 3)
               }
               _ => return Err(DexError::BadMutf8),
           };
           b = &b[n..];
           match (0xD800..=0xDBFF).contains(&cp), (0xDC00..=0xDFFF).contains(&cp) {
               (true, _) => { pending_hi = Some(cp as u16); continue; }
               (_, true) => {
                   let hi = pending_hi.take().ok_or(DexError::BadMutf8)?;
                   let sc = 0x10000 + (((hi as u32 - 0xD800) << 10) | (cp - 0xDC00));
                   out.push(char::from_u32(sc).ok_or(DexError::BadMutf8)?);
               }
               _ => {
                   pending_hi = None;
                   out.push(char::from_u32(cp).ok_or(DexError::BadMutf8)?);
               }
           }
       }
       Ok(out)
   }
   ```

5. **`string_data_item` 的 `utf16_size` 是"解出来的 UTF-16 code unit 个数"，不是字节数**，
   且必须与串内容一致（不一致就记 `notes`，**不要用它当长度去截断** —— 长度靠 `0x00` 终止符定位）。
   `string_ids` 与 `string_data` 是**两套东西**：前者是"索引 → 偏移"表，后者是实际字节。

6. **checksum/signature 不一致只报告不拒绝**（见 §1）。

7. **`tries_size != 0` 隐含 4 字节对齐**：`insns_size` 为奇数时先跳 2 字节 padding；
   `tries_size` 为奇数时 `encoded_catch_handler_list` 末尾还有一个补位字节 `00`。
   这两处是最常见的"整体错位 2 字节"来源。

8. **端序**：见 §1 的 reverse-endian 说明。

9. **每一项解析都要有边界与自洽校验**：`off + size*elemsize <= limit`；
   `insns_size` 与 `insns` 实际字节数一致；`type_ids_size/proto_ids_size <= 0xFFFF`；
   分支目标落在 `[0, insns_size)`；`try_item` 区间不重叠且升序。
   任何一条不满足 → 记 `notes` + 局部放弃，**不要 panic、不要整体拒绝**。

10. **宽度表的实现要点**：`instr_width(insns, pc)` 需要至少 2 个 code unit 才能判断 payload；
    payload 的长度字段可能被恶意写成 `0xFFFF`，**必须做溢出与越界检查**；
    `insns` 长度也必须校验，不能信任 `insns_size`。

    ```rust
    pub fn instr_width(insns: &[u16], pc: usize, table: &OpcodeTable) -> Result<(u8, bool), DexError> {
        let unit0 = *insns.get(pc).ok_or(DexError::TruncatedInsns)?;
        let op = (unit0 & 0xFF) as u8;
        if op == 0x00 {                                   // NOP，可能是 payload
            return match unit0 & 0xFF00 {
                0x0000 => Ok((1, false)),
                0x0100 => Ok((4u8.wrapping_add(u16le(insns, pc + 1)? as u8 * 2), true)),
                0x0200 => Ok((2u8.wrapping_add(u16le(insns, pc + 1)? as u8 * 4), true)),
                0x0300 => {
                    let width = u16le(insns, pc + 1)? as u32;
                    let count = u32le(insns, pc + 2)?;
                    Ok((((count * width + 1) / 2) as u8 + 4, true))
                }
                _ => Err(DexError::UnknownPayloadSignature(unit0)),
            };
        }
        let f = table.format_of(op).ok_or(DexError::UnknownOpcode(op))?;   // 未用槽位 → 错误
        Ok((fmt_units(f), false))
    }
    ```

11. **标准 DEX 之外**：`0xE3–0xF9` 一律视为"未用/非标准"，报 `UnknownOpcode` 并附
    "可能是 ODEX quick 指令（已废弃）"的 `notes`；**不要**把它们解码成 Dalvik quick 语义。
    将来若支持 ODEX/VDEX，应作为**独立后端 + 独立 opcode 表**。

---

## 10. UNVERIFIED 清单（实现时必须"取原文验证"或"在结论里标未知"）

1. DEX **v040** 到底改了什么（无证据；也**没有** SHA-256 化）。
2. ~~现网 APK 是否真的发布 `dex\n041\0`~~ → ✅ **已测：本机两个 APK 都是 035**。
   但更大范围的现网分布仍未知。
3. ART verifier 对 **map 排序 / map 与 header 一致性**的具体检查条目。
4. `lib/<abi>` 前缀在 AOSP 里的**原文出处**（ABI 名集合已由 Soong 验证；前缀本身未取到原文）。
5. `extractNativeLibs=false ⇒ 必须未压缩 + 页对齐`的**规范措辞**。
6. Play/Android 15 的 **16 KB 页要求**官方措辞。
7. **Zip64 EOCD/locator** 的签名与结构。
8. AXML 的 UTF-8 串池是否**就是** MUTF-8。
9. **payload 必须 4 字节对齐**的规范原文。
10. `.cdex` / `.vdex` / `.oat` 的 magic 与头结构（**不要抄网上的字符串**）。
11. `classes<N>.dex` 命名规则的官方原文。
12. `ResTable_map[]` 的数量计算规则原文。
13. `dex_file_loader.cc` 的容器遍历循环（本文的遍历算法是从几何断言**推导**的，标 INFERRED）。

---

## 11. 参考来源

- DEX 规范（4.0 镜像，完整可读）：
  `https://www.dre.vanderbilt.edu/~schmidt/android/android-4.0/dalvik/docs/dex-format.html`
  （现行版 `https://source.android.com/docs/core/runtime/dex-format`）
- AOSP ART（本沙箱经 `raw.githubusercontent.com/LineageOS/android_art@lineage-22.2/<path>` 取得）：
  `dex_file.h`、`dex_file.cc`、`dex_instruction.h`、`dex_instruction_list.h`、
  `dex_file_structs.h`、`dex_file_types.h`、`libartbase/base/leb128.h`、
  `standard_dex_file.cc`、`compact_dex_file.h`（未取得）
- `LineageOS/android_frameworks_base@lineage-22.2`：`NativeLibraryHelper`、`VMRuntime`
- `LineageOS/android_tools_apksig@lineage-20.0`：`internal/zip/ZipUtils.java`、
  `ApkUtilsLite.java`、`ApkSigningBlockUtils.java`、`v2/V2SchemeConstants.java`、
  `v3/V3SchemeConstants.java`、`stamp/SourceStampConstants.java`
- `LineageOS/android_build@lineage-22.2`：`tools/zipalign/README.txt`
- `LineageOS/android_build_soong@lineage-22.2`：`cc/config/arm64_device.go`
- `ResourceTypes.h` / `ResourceTypes.cpp`（AOSP frameworks/base/libs/androidfw）
- apktool 文档：`https://apktool.org/wiki/advanced/resources-arsc/`

**本沙箱网络限制**：`source.android.com`、`android.googlesource.com`、`cs.android.com`、
`developer.android.com`、`en.wikipedia.org` 在本机 DNS 不可达；`api.github.com` 有速率限制。
`curl`/`Invoke-WebRequest` 无网络，必须走 `web_fetch`。
