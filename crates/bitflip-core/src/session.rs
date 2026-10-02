//! 会话：一个被打开的目标及其识别结论。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitflip_analyze::{JobHandle, NullSink, StageId};
use bitflip_arch::ArchSpec;
use bitflip_loader::{sniff_file, ContainerKind, Guess, ObjectKind};
use serde::Serialize;

use crate::error::BitflipError;

/// 地址的 wire 表示：定长小写 16 位十六进制（CLAUDE.md §4）。
fn hex16(value: u64) -> String {
    format!("{value:016x}")
}

/// 打开目标时的选项。M0 只有占位字段，M2 起加入 raw 二进制的基址/架构覆写。
#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    /// 视作原始二进制（忽略格式嗅探），M2 实现。
    pub force_raw: bool,
}

/// 目标识别结论的对外表示（JSON wire 契约）。
///
/// 所有"未知"都显式表达为 `null` + `notes` 里的原因，不用 0 / 空串冒充。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetInfo {
    /// 目标路径。
    pub path: String,
    /// 文件大小（字节）。
    pub file_size: u64,
    /// 容器短名（`plain` / `ar` / `msvc-lib` / `fat`）。
    pub container: String,
    /// 容器中文名。
    pub container_label: String,
    /// 对象格式短名（`pe` / `coff` / `elf` / `macho` / `raw`）。
    pub object: String,
    /// 对象格式中文名。
    pub object_label: String,
    /// 归档成员格式（短名）。
    pub member_kind: Option<String>,
    /// 架构规格（`x86_64/64/le` 形式）。
    pub arch: Option<String>,
    /// 架构族（`x86_64`）。
    pub arch_family: Option<String>,
    /// 位宽（0 = 未知）。
    pub bits: u8,
    /// 端序（`le` / `be`）。
    pub endian: Option<String>,
    /// 入口点（定长 hex）。
    pub entry: Option<String>,
    /// 镜像基址（定长 hex，PE 有）。
    pub image_base: Option<String>,
    /// 节数。
    pub sections: Option<u16>,
    /// 归档成员数。
    pub member_count: usize,
    /// 成员列表是否被截断。
    pub members_truncated: bool,
    /// 一行中文摘要。
    pub summary: String,
    /// 判定依据与限制说明。
    pub notes: Vec<String>,
    /// 参与嗅探的字节数。
    pub sniffed_bytes: usize,
    /// 文件是否大于嗅探窗口。
    pub file_truncated: bool,
}

impl TargetInfo {
    fn from_guess(path: &Path, file_size: u64, guess: &Guess) -> Self {
        Self {
            path: path.display().to_string(),
            file_size,
            container: guess.container.as_str().to_string(),
            container_label: guess.container.label_zh().to_string(),
            object: guess.object.as_str().to_string(),
            object_label: guess.object.label_zh().to_string(),
            member_kind: guess.member_kind.map(|k| k.as_str().to_string()),
            arch: guess.arch.map(|a| a.to_string()),
            arch_family: guess.arch.map(|a: ArchSpec| a.arch.as_str().to_string()),
            bits: guess.bits,
            endian: guess.endian.map(|e| e.as_str().to_string()),
            entry: guess.entry.map(hex16),
            image_base: guess.image_base.map(hex16),
            sections: guess.sections,
            member_count: guess.members.len(),
            members_truncated: guess.members_truncated,
            summary: guess.summary_zh(),
            notes: guess.notes.clone(),
            sniffed_bytes: guess.sniffed_bytes,
            file_truncated: guess.file_truncated,
        }
    }

    /// 是否为归档容器（ar / MSVC `.lib`）。
    #[must_use]
    pub fn is_archive(&self) -> bool {
        self.container == ContainerKind::Ar.as_str()
            || self.container == ContainerKind::MsvcLib.as_str()
    }

    /// 是否已识别出对象格式（非 raw）。
    #[must_use]
    pub fn object_identified(&self) -> bool {
        self.object != ObjectKind::Raw.as_str()
    }
}

/// 分析结果摘要（M0 占位；M2 起填入真实计数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct AnalysisSummary {
    /// 已解码指令数。
    pub instructions: usize,
    /// 已识别函数数。
    pub functions: usize,
    /// 基本块数。
    pub basic_blocks: usize,
    /// 交叉引用数。
    pub xrefs: usize,
}

/// 一个打开的目标。
///
/// `Session` 是 `bitflip-core` 的核心类型，也是被其他项目嵌入时的入口。
/// 它是 `Send + Sync` 且可廉价共享（服务层用 `Arc<Session>`）。
#[derive(Debug, Clone)]
pub struct Session {
    path: PathBuf,
    guess: Guess,
    info: TargetInfo,
}

impl Session {
    /// 打开目标：检查路径、读取识别的结论。
    ///
    /// 只做嗅探（前 8 MiB），不解析全文件 —— M1 起才做完整格式解析。
    pub fn open(path: impl AsRef<Path>, _opts: OpenOptions) -> Result<Self, BitflipError> {
        let path = path.as_ref().to_path_buf();
        let guess = sniff_file(&path)?;
        let file_size = std::fs::metadata(&path).map_or(guess.sniffed_bytes as u64, |m| m.len());
        let info = TargetInfo::from_guess(&path, file_size, &guess);
        Ok(Self { path, guess, info })
    }

    /// 目标路径。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 原始识别结论（loader 层类型）。
    #[must_use]
    pub fn guess(&self) -> &Guess {
        &self.guess
    }

    /// 识别结论（wire 类型）。
    #[must_use]
    pub fn info(&self) -> &TargetInfo {
        &self.info
    }

    /// 克隆一份识别结论（服务层把它放进响应）。
    #[must_use]
    pub fn target_info(&self) -> TargetInfo {
        self.info.clone()
    }

    /// 新建一个丢弃事件的分析作业（无 UI 场景）。
    #[must_use]
    pub fn detached_job(&self) -> JobHandle {
        JobHandle::new(Arc::new(NullSink))
    }

    /// 运行分析。
    ///
    /// M0 明确返回 [`BitflipError::NotYetImplemented`]：宁可让调用方拿到"还没做"，
    /// 也不返回一个空的结果集让 UI 显示"分析完成但什么都没有"。
    pub fn analyze(&self, job: &JobHandle) -> Result<AnalysisSummary, BitflipError> {
        job.set_stage(StageId::Segments, 1.0, "分析流水线尚未接入（计划：M2）");
        Err(BitflipError::not_implemented(
            "分析流水线 S1–S9（计划：M2 起，见 docs/PLAN.md）",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小的 64 位 x86_64 ELF 头（与 loader 的测试保持一致）。
    fn elf64_x86_64() -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 2;
        v[5] = 1;
        v[6] = 1;
        v[16..18].copy_from_slice(&2u16.to_le_bytes());
        v[18..20].copy_from_slice(&62u16.to_le_bytes());
        v[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        v[60..62].copy_from_slice(&5u16.to_le_bytes());
        v
    }

    #[test]
    fn open_elf_reports_identified_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sample.elf");
        std::fs::write(&path, elf64_x86_64()).expect("write");

        let session = Session::open(&path, OpenOptions::default()).expect("打开");
        let info = session.info();
        assert_eq!(info.object, "elf");
        assert_eq!(info.object_label, "ELF");
        assert_eq!(info.arch.as_deref(), Some("x86_64/64/le"));
        assert_eq!(info.arch_family.as_deref(), Some("x86_64"));
        assert_eq!(info.bits, 64);
        assert_eq!(info.endian.as_deref(), Some("le"));
        assert_eq!(info.entry.as_deref(), Some("0000000000401000"));
        assert_eq!(info.image_base, None);
        assert_eq!(info.sections, Some(5));
        assert!(info.object_identified());
        assert!(!info.is_archive());
        assert!(info.summary.contains("ELF"));

        // wire 契约：地址必须是定长 16 位
        assert_eq!(info.entry.as_ref().map(String::len), Some(16));
        let json = serde_json::to_value(info).expect("序列化");
        assert_eq!(json["object"], "elf");
        assert!(json["image_base"].is_null());
    }

    #[test]
    fn open_missing_path_is_a_clear_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err =
            Session::open(dir.path().join("nope"), OpenOptions::default()).expect_err("应报错");
        assert!(matches!(err, BitflipError::Loader(_)));
        assert!(err.to_string().contains("读取目标失败"));
    }

    #[test]
    fn open_directory_points_at_m10_plan() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = Session::open(dir.path(), OpenOptions::default()).expect_err("应报错");
        assert!(err.to_string().contains(".app"));
    }

    #[test]
    fn analyze_is_honest_about_not_being_implemented() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sample.elf");
        std::fs::write(&path, elf64_x86_64()).expect("write");
        let session = Session::open(&path, OpenOptions::default()).expect("打开");
        let job = session.detached_job();

        let err = session.analyze(&job).expect_err("M0 必须明确拒绝");
        assert!(matches!(err, BitflipError::NotYetImplemented { .. }));
        assert!(err.to_string().contains("M2"));
        // 即便拒绝，进度也应反映"停在第一个阶段"
        assert_eq!(job.progress().stage, StageId::Segments);
    }
}
