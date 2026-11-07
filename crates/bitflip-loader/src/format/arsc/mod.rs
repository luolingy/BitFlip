//! `resources.arsc`（Android 资源表）—— M3 的第二片：**结构快照**（A 方案）。
//!
//! # A 方案的边界：只报"表里有什么"，不解"值是什么"
//!
//! 资源表的完整形态是"包 → 类型 → 条目 → 配置 → 值"五层，其中值一层
//! （字符串池解码、引用链、`Res_value` 类型分派）复杂度最高，而用户最先要
//! 回答的问题是**结构性的**：这个 APK 有几个资源包、多少种类型、每种类型
//! 多少条目、为多少种配置各存了一份。这一片只回答这些 —— **值解码留给下一片**
//! （届时 `ARSC::get_resource_value` 是现成的）。
//!
//! # 解析交给 `apk-info-axml`，本模块只做遍历与计数
//!
//! 与 AXML 那边同一条边界：只借它的**事实层**（`ARSC::new` 已在清单那边被
//! 真实 APK 验证过），不自己写第二份二进制解析器 —— 那等于把"库解析错了"
//! 变成"我们解析错了"。本模块做的是：把库的遍历面组织成**稳定、可序列化、
//! 带账目**的形状。
//!
//! # 账目必须闭合（与 DEX 视图同一条铁律）
//!
//! 每层都报计数：包数、类型数、配置数、条目数。合计与逐项之和要能对上；
//! 拿不到的（例如某个包的类型字符串池索引越界，类型名解不出）报 `None`
//! 并计数，**不编占位符**。

use apk_info_axml::errors::ARCSError;
use apk_info_axml::structs::{ResTableConfig, ResTableEntry, ResTablePackage};
use apk_info_axml::ARSC;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 资源表结构快照的解析错误。
#[derive(Debug, Error)]
pub enum ArscError {
    /// 字节超过 [`MAX_ARSC_BYTES`]。
    #[error("这份 resources.arsc 有 {size} 字节，超过上限 {limit} 字节：没有解析它")]
    TooLarge {
        /// 实际字节数。
        size: usize,
        /// 上限（[`MAX_ARSC_BYTES`]）。
        limit: usize,
    },
    /// 库拒绝了解析（分类原因在文本里）。
    #[error("resources.arsc 解析失败：{source}")]
    Parse {
        /// 库的原始错误。
        source: ARCSError,
    },
    /// 库"成功"了但解出 **0 个包**。
    ///
    /// 库是容忍式的：`package_count == 0` 只记日志不报错，全零字节也能"解析
    /// 成功"产出一支空表（实测）。但对**调用方**来说，"0 个包的资源表"与
    /// "这不是资源表"在结果上长得一模一样 —— 而后者才是真相（资源表协议
    /// 要求 `package_count >= 1`）。报错，把"容忍式跳过了什么"留在大门之外。
    #[error("这份 resources.arsc 解析出 0 个资源包：它多半不是资源表（或被破坏到库只能整段跳过）")]
    NoPackages,
}

/// 单份 `resources.arsc` 的字节上限：256 MiB。
///
/// 理由见 `format::axml::MAX_ARSC_BYTES`（同一条线，同一句话）。
pub const MAX_ARSC_BYTES: usize = 256 * 1024 * 1024;

/// 一个资源包的类型（资源种类，如 `drawable` / `string`）在该配置下的条目组。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArscTypeSnapshot {
    /// 类型 id（资源 id 的第二字节；从 1 起，0 无效）。
    pub type_id: u8,
    /// 类型名（如 `drawable`；类型字符串池里解不出时是 `None`，**不是占位符**）。
    pub type_name: Option<String>,
    /// 这个类型在**这份配置**下的条目数（含 `NoEntry` 占位 —— 规范允许
    /// "offset 表里有位置但条目无效"，如实报数，不假装它们不存在也不丢弃）。
    pub entry_count: u64,
    /// 其中 `NoEntry`（位置在表里、条目本身无效）的个数。
    pub no_entry_count: u64,
}

/// 一个资源包在一种配置下的完整切面。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArscConfigSnapshot {
    /// 配置标识：AOSP `ResTable_config` 的原始判定字段（每个 u32 字段一个
    /// 十六进制串，顺序与 AOSP 结构体字段序一致）。**报原始字段而不是解出的
    /// 限定符文本**（A 方案不解值层）：两个配置只有字段值能区分 —— 实测同一张
    /// 真实表里有两份 `screen_size_dp` 维度相同、字段值不同的配置，只报掩码
    /// 会让它们看起来一模一样。
    ///
    /// 缺省字段（该配置 chunk 的 `size` 没覆盖到的）是 `None` —— "没写"与
    /// "写了 0"在协议里不是一个意思。
    pub config: ArscConfigIdentity,
    /// 这份配置下的类型切面，按 type_id 升序。
    pub types: Vec<ArscTypeSnapshot>,
}

/// 一种配置的原始判定字段（AOSP `ResTable_config` 的字段摘录）。
///
/// 只收**判定相关**的字段：`size`（chunk 声明的自身大小，决定哪些字段有效）
/// 与各 union 字段。`locale_script` 等字节数组在 A 方案不解码，按**是否全零**
/// 报 `None`/十六进制串 —— 全零是"未设置"，不是"设置了零"。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArscConfigIdentity {
    /// chunk 声明的大小（决定后面哪些字段有效）。
    pub size: u32,
    /// IMSI（MCC/MNC 打包 u32）；未设置时 `None`。
    pub imsi: Option<String>,
    /// locale（语言/国家打包 u32）；未设置时 `None`。
    pub locale: Option<String>,
    /// 屏幕类型（density 等）；未设置时 `None`。
    pub screen_type: Option<String>,
    /// 泛用字段（AOSP 文档标记 reserved）；未设置时 `None`。
    pub generic_purpose_field: Option<String>,
    /// 屏幕尺寸；未设置时 `None`。
    pub screen_size: Option<String>,
    /// SDK 版本；未设置时 `None`。
    pub version: Option<String>,
    /// 屏幕布局打包字段；未设置时 `None`。
    pub screen_config: Option<String>,
    /// dp 屏幕尺寸；未设置时 `None`。
    pub screen_size_dp: Option<String>,
    /// locale script（4 字节）；未设置（全零）时 `None`。
    pub locale_script: Option<String>,
    /// locale variant（8 字节）；未设置（全零）时 `None`。
    pub locale_variant: Option<String>,
    /// 屏幕布局第二打包字段；未设置时 `None`。
    pub screen_config_2: Option<String>,
}

/// `Option<String>` 的便捷构造：0 视为"未设置"，非 0 报十六进制。
fn hex_or_zero(value: u32) -> Option<String> {
    (value != 0).then(|| format!("{value:#010x}"))
}

/// 字节数组版本：全零视为"未设置"。
fn hex_or_zero_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.iter().all(|&b| b == 0) {
        None
    } else {
        Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// 从库的配置结构抽判定字段（`size` 之后的字段是否有效由 `size` 决定 ——
/// 按 AOSP 的增量读取规则，未覆盖的字段报 `None`）。
fn config_identity(config: &ResTableConfig) -> ArscConfigIdentity {
    let set = |covered: bool, value: Option<String>| covered.then_some(value).flatten();
    // 库的 parse 按 size 增量覆盖字段；边界与它一致（AOSP ResTable_config）。
    let imsi = set(config.size >= 8, hex_or_zero(config.imsi));
    let locale = set(config.size >= 12, hex_or_zero(config.locale));
    let screen_type = set(config.size >= 16, hex_or_zero(config.screen_type));
    let generic = set(config.size >= 20, hex_or_zero(config.generic_purpose_field));
    let screen_size = set(config.size >= 24, hex_or_zero(config.screen_size));
    let version = set(config.size >= 28, hex_or_zero(config.version));
    let screen_config = set(config.size >= 32, hex_or_zero(config.screen_config));
    let screen_size_dp = set(config.size >= 36, hex_or_zero(config.screen_size_dp));
    let script = set(config.size >= 40, hex_or_zero_bytes(&config.locale_script));
    let variant = set(config.size >= 48, hex_or_zero_bytes(&config.locale_variant));
    let screen_config_2 = set(config.size >= 52, hex_or_zero(config.screen_config_2));
    ArscConfigIdentity {
        size: config.size,
        imsi,
        locale,
        screen_type,
        generic_purpose_field: generic,
        screen_size,
        version,
        screen_config,
        screen_size_dp,
        locale_script: script,
        locale_variant: variant,
        screen_config_2,
    }
}

/// 一个资源包的结构快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArscPackageSnapshot {
    /// 包 id（资源 id 的最高字节；`0x7f` 是应用自己的包，`0x01` 是 framework）。
    pub package_id: u8,
    /// 包名（`ResTablePackage` 头里的 256 字节名称，库已解成 `String`）。
    pub name: String,
    /// 类型字符串池条数。
    pub type_strings: u64,
    /// 键字符串池条数。
    pub key_strings: u64,
    /// 这份包里出现过的**配置**数（每种配置一套完整的类型切面）。
    pub config_count: u64,
    /// 配置切面，按配置掩码升序（BTreeMap 遍历序，确定性有保证）。
    pub configs: Vec<ArscConfigSnapshot>,
    /// 条目总数（所有配置所有类型的 `entry_count` 之和 —— 账目锚点）。
    pub entry_count: u64,
    /// 其中 `NoEntry` 占位的总数。
    pub no_entry_count: u64,
}

/// 资源表的整体结构快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArscStructure {
    /// 包快照，按包 id 升序。
    pub packages: Vec<ArscPackageSnapshot>,
    /// 全表条目总数（各包 `entry_count` 之和 —— 账目锚点）。
    pub entry_count: u64,
    /// 全表 `NoEntry` 总数。
    pub no_entry_count: u64,
}

impl ArscStructure {
    /// 解析并拍快照。
    ///
    /// # Errors
    ///
    /// 字节超过 [`MAX_ARSC_BYTES`]，或库拒绝这份表（原因在错误文本里）。
    pub fn parse(bytes: &[u8]) -> Result<Self, ArscError> {
        if bytes.len() > MAX_ARSC_BYTES {
            return Err(ArscError::TooLarge {
                size: bytes.len(),
                limit: MAX_ARSC_BYTES,
            });
        }
        let mut cursor = bytes;
        let arsc = ARSC::new(&mut cursor).map_err(|source| ArscError::Parse { source })?;
        let structure = Self::snapshot(&arsc);
        if structure.packages.is_empty() {
            return Err(ArscError::NoPackages);
        }
        Ok(structure)
    }

    /// 解析成**带值查询能力**的表（M3 第三片）。
    ///
    /// 结构快照（[`Self::parse`]）是"拍完就走"的一次性产物；这个入口保留
    /// 库的 `ARSC` 实例本身，让调用方能按资源 id 查值与名字。要**缓存复用**
    /// 的场合（HTTP 服务端）用它。
    ///
    /// # Errors
    ///
    /// 与 [`Self::parse`] 相同。
    pub fn parse_table(bytes: &[u8]) -> Result<ArscTable, ArscError> {
        if bytes.len() > MAX_ARSC_BYTES {
            return Err(ArscError::TooLarge {
                size: bytes.len(),
                limit: MAX_ARSC_BYTES,
            });
        }
        let mut cursor = bytes;
        let inner = ARSC::new(&mut cursor).map_err(|source| ArscError::Parse { source })?;
        let structure = Self::snapshot(&inner);
        if structure.packages.is_empty() {
            return Err(ArscError::NoPackages);
        }
        Ok(ArscTable { structure, inner })
    }

    fn snapshot(arsc: &ARSC) -> Self {
        let mut packages: Vec<ArscPackageSnapshot> = Vec::new();
        let mut total_entries = 0u64;
        let mut total_no_entry = 0u64;

        // `ARSC::packages()` 是 HashMap 迭代 —— 顺序不稳。**先收再排**：
        // 按 (package_id) 排序，同一个输入两次快照必须相同。
        let mut pkgs: Vec<&ResTablePackage> = arsc.packages().collect();
        pkgs.sort_by_key(|package| package.header.id);

        for package in pkgs {
            // 包 id 取 `header.id` 的**低字节**（AOSP 里 `ResTable_package.id`
            // 存的就是 0x7f 这种小值；资源 id 的最高字节 = 这个值）。与库的
            // `ARSC::new` 分包键（`id & 0xff`）同一语义 —— 不自创第二套口径。
            let package_id = (package.header.id & 0xff) as u8;
            let package_name = package.header.name();
            let mut configs: Vec<ArscConfigSnapshot> = Vec::new();
            let mut package_entries = 0u64;
            let mut package_no_entry = 0u64;

            // `resources` 是 BTreeMap<ResTableConfig, _>：遍历序按 config 的
            // Ord（库实现的字段序），确定性由 BTreeMap 保证，不需要再排。
            for (config, type_map) in &package.resources {
                // 类型 id → 切面；HashMap 也要先收再排。
                let mut type_ids: Vec<&u8> = type_map.keys().collect();
                type_ids.sort_by_key(|id| **id);

                let mut snapshot_types: Vec<ArscTypeSnapshot> = Vec::new();
                let mut config_entries = 0u64;
                let mut config_no_entry = 0u64;
                for type_id in type_ids {
                    let Some(entries) = type_map.get(type_id) else {
                        continue;
                    };
                    let no_entry = entries
                        .entries
                        .iter()
                        .filter(|entry| matches!(entry, ResTableEntry::NoEntry))
                        .count() as u64;
                    let count = entries.entries.len() as u64;
                    config_entries += count;
                    config_no_entry += no_entry;
                    snapshot_types.push(ArscTypeSnapshot {
                        type_id: *type_id,
                        // 类型名来自类型字符串池（type_id - 1 是池下标；type_id_offset
                        // 通常为 0，AOSP 里包内 type_id 从 1 对池下标 0）。解不出是
                        // `None` —— 不是"unknown"占位。
                        type_name: package
                            .type_strings
                            .get(u32::from(type_id.wrapping_sub(1)))
                            .cloned(),
                        entry_count: count,
                        no_entry_count: no_entry,
                    });
                }

                package_entries += config_entries;
                package_no_entry += config_no_entry;
                configs.push(ArscConfigSnapshot {
                    config: config_identity(config),
                    types: snapshot_types,
                });
            }

            total_entries += package_entries;
            total_no_entry += package_no_entry;
            packages.push(ArscPackageSnapshot {
                package_id,
                name: package_name,
                type_strings: package.type_strings.strings.len() as u64,
                key_strings: package.key_strings.strings.len() as u64,
                config_count: configs.len() as u64,
                configs,
                entry_count: package_entries,
                no_entry_count: package_no_entry,
            });
        }

        Self {
            packages,
            entry_count: total_entries,
            no_entry_count: total_no_entry,
        }
    }
}

/// 一份**可查询**的资源表：结构快照 + 库的 `ARSC` 实例（值层入口）。
#[derive(Debug)]
pub struct ArscTable {
    /// 结构快照（与 [`ArscStructure::parse`] 产出同形，确定性有保证）。
    pub structure: ArscStructure,
    inner: ARSC,
}

impl ArscTable {
    /// 按资源 id 查**名字**（`0x7f0d0001` → `string/app_name`）。
    ///
    /// 查不到（包/类型/条目任一层不存在）是 `None` —— 不是错误，也不是占位符。
    #[must_use]
    pub fn resource_name(&self, id: u32) -> Option<String> {
        self.inner.get_resource_name(id)
    }

    /// 按资源 id 查**值**（字符串 / 颜色 / 布尔等，库已解成可读文本）。
    ///
    /// 引用链会被库递归解析；`Complex`（批量值）与查不到的条目是 `None`。
    #[must_use]
    pub fn resource_value(&self, id: u32) -> Option<String> {
        self.inner.get_resource_value(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 没有现成的合成 arsc fixture —— 第一版用**真实样本**（`#[ignore]`，
    /// 与 DEX 结构测试同一条规矩：二进制 fixture 造起来比真样本还费）。
    /// 合成 fixture 是后续任务（见 ledger 的 todo）。
    const REAL_APK: &str = r"C:\Users\Administrator\Downloads\ah-app-release.apk";

    fn real_arsc_bytes() -> Option<Vec<u8>> {
        let apk = std::fs::read(REAL_APK).ok()?;
        let listing = crate::format::zip::list_members(&apk).ok()?;
        let index = listing
            .members
            .iter()
            .position(|member| member.name == "resources.arsc")?;
        crate::format::zip::read_member(&apk, index).ok()
    }

    #[test]
    #[ignore = "需要本机真实 APK（32MB）；用 -- --ignored 手动跑"]
    fn real_apk_structure_snapshot_is_consistent() {
        let Some(bytes) = real_arsc_bytes() else {
            panic!("真实 APK 不在 {REAL_APK}");
        };
        let structure = ArscStructure::parse(&bytes).expect("真实资源表应可解析");
        assert!(
            !structure.packages.is_empty(),
            "至少有一个包（0x7f 应用包）"
        );
        // 账目闭合：全表合计 = 各包之和。
        let sum: u64 = structure.packages.iter().map(|p| p.entry_count).sum();
        assert_eq!(sum, structure.entry_count, "条目账目必须闭合");
        let no_entry_sum: u64 = structure.packages.iter().map(|p| p.no_entry_count).sum();
        assert_eq!(no_entry_sum, structure.no_entry_count);
        // 应用包 0x7f 应该在，类型名应该解得出来（type_strings 池非空）。
        let app = structure
            .packages
            .iter()
            .find(|p| p.package_id == 0x7f)
            .expect("应用包 0x7f 必在");
        assert!(app.config_count > 0, "应用包至少有一种配置");
        assert!(
            app.configs
                .iter()
                .any(|c| c.types.iter().any(|t| t.type_name.is_some())),
            "至少一个类型名能从类型字符串池解出"
        );
        // 确定性：两次快照一致。
        let again = ArscStructure::parse(&bytes).expect("第二次解析");
        assert_eq!(structure, again);
    }

    #[test]
    fn garbage_is_rejected_loudly() {
        // 全零字节不是资源表：库必须拒绝，错误要能报出来 —— 不是"0 个包的空表"。
        let zeros = vec![0u8; 64];
        let result = ArscStructure::parse(&zeros);
        assert!(result.is_err(), "垃圾输入必须报错，不能当空表");
    }

    #[test]
    #[ignore = "需要本机真实 APK（32MB）；用 -- --ignored 手动跑"]
    fn real_apk_value_lookup_resolves_strings() {
        let Some(bytes) = real_arsc_bytes() else {
            panic!("真实 APK 不在 {REAL_APK}");
        };
        let table = ArscStructure::parse_table(&bytes).expect("真实资源表应可解析");
        // 结构快照与 parse() 同形。
        assert_eq!(table.structure.entry_count, 72_285);

        // **从结构快照里取真实存在的 (包, 类型, 条目) 组合**去查值 —— 不能
        // 假设 entry_id 从 0 连续铺满（这张真实表是稀疏 id：0x7f00xxxx 窗口
        // 逐 id 扫描一个名字都解不出，而条目明明存在）。快照里的 config 切面
        // 恰好给出了真实的 type_id 与条目数，拼成 id 去查。
        let mut named = 0u64;
        let mut valued = 0u64;
        let mut first_pair: Option<(u32, String, Option<String>)> = None;
        for package in &table.structure.packages {
            let base = u32::from(package.package_id) << 24;
            for config in &package.configs {
                for ty in &config.types {
                    for entry_id in 0..ty.entry_count.min(16) {
                        let id = base
                            | (u32::from(ty.type_id) << 16)
                            | u32::try_from(entry_id).expect("16 位以内");
                        let name = table.resource_name(id);
                        let value = table.resource_value(id);
                        if name.is_some() {
                            named += 1;
                        }
                        if value.is_some() {
                            valued += 1;
                        }
                        if first_pair.is_none() && name.is_some() && value.is_some() {
                            first_pair = Some((id, name.clone().expect("刚判过"), value));
                        }
                    }
                }
            }
        }
        assert!(named > 0, "真实存在的条目里应有可解名字的");
        assert!(valued > 0, "真实存在的条目里应有可解值的");
        let (id, name, _value) = first_pair.expect("至少一组全解析");
        assert!(name.contains('/'), "名字形状是 type/key：{name}");

        // 查不到的 id 是 None（不是错误、不是占位符）。
        assert_eq!(table.resource_name(0x7fff_ffff), None);
        assert_eq!(table.resource_value(0x7fff_ffff), None);

        // 确定性：同一 id 两次查询结果一致（库有名字缓存，缓存不得改变结果）。
        assert_eq!(table.resource_name(id), Some(name));
    }
}
