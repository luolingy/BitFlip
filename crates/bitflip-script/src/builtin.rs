//! 内置示例脚本集（PLAN §M7 交付物 4）。
//!
//! # 为什么示例脚本要编译进二进制，而不是放在文档里
//!
//! 文档里的示例会腐烂：API 改了，没人会去改文档里那段没有编译过、没有跑过的
//! 代码。放进来之后它至少能被测试**执行**一遍 ——
//! `crates/bitflip-script/tests/builtin.rs` 会把这里的每一份源码真的跑一次。
//! 一个跑不起来的示例比没有示例更糟：用户会先怀疑自己的环境。
//!
//! 验收标准 1（"识别所有调用 `memcpy` 的位置并写参数注释"）指向的
//! **就是** [`MEMCPY_ARGS`] 这一份源码。测试直接取这里的字符串去跑，
//! 不再在测试文件里另抄一份 —— 否则"测试通过"与"发出去的示例能跑"
//! 是两件事，而前者会掩盖后者。
//!
//! # 每个脚本都必须自己说清可信度
//!
//! `CLAUDE.md` §7 禁止用假名冒充识别结果。这些脚本处在最容易违反该条的位置
//! （它们正打算批量写名字），所以：
//!
//! - 不覆盖任何**已有**名字；
//! - 推断出来的名字带 `str_` 前缀，并在注释里写明依据；
//! - 只给候选清单、不做结论的脚本（[`LIBRARY_PATTERNS`]）明确写"这只是候选"；
//! - 导出类脚本一律把 `bitflip.notes()` 里的降级说明一并带上。

/// 一份内置脚本。
#[derive(Debug, Clone, Copy)]
pub struct BuiltinScript {
    /// 稳定标识（供 UI 选中与测试引用；不要随文案改动）。
    pub id: &'static str,
    /// 显示名。
    pub name: &'static str,
    /// 一句话说明它做什么、以及它**不**做什么。
    pub description: &'static str,
    /// 该脚本写就时依据的脚本 API 版本。
    pub api_version: u32,
    /// 源码。
    pub source: &'static str,
}

/// 按字符串引用批量重命名。
///
/// 只处理"函数内恰好引用了一个字符串"的情形并**跳过其余**：两个以上字符串时
/// 挑哪一个都是猜，而猜出来的名字会被用户当成识别结果。
const RENAME_BY_STRING: &str = r#"
// 按字符串引用批量重命名（推断，不是识别结论）
//
// 依据：一个函数如果只引用了一个字符串，那个字符串往往透露了这个函数的用途
//      （错误信息、格式串、日志前缀）。
//
// 这个脚本**不覆盖任何已有名字**，并且：
//   * 只处理"恰好引用一个字符串"的函数 —— 两个以上时挑哪个都是猜；
//   * 新名字带 `str_` 前缀，一眼能看出是推断来的，不是符号表里的真名；
//   * 同时在注释里写明依据，方便日后核对。
//
// 字符串提取本身可能是降级的（例如只扫了可打印字符），所以结论的可靠性
// 取决于 bitflip.notes() 里那几条说明 —— 脚本最后会把它们打出来。

const MAX_NAME = 40;
const CHUNK = 512;

function sanitize(text) {
  let out = '';
  for (const ch of text) {
    const code = ch.codePointAt(0);
    const ok = (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
    out += ok ? ch : '_';
  }
  out = out.replace(/_+/g, '_').replace(/^_|_$/g, '');
  return out.slice(0, MAX_NAME);
}

// 1) 字符串地址表
const textByAddress = new Map();
const stringTotal = bitflip.strings.count();
for (let off = 0; off < stringTotal; off += CHUNK) {
  for (const s of bitflip.strings.page(off, CHUNK).items) {
    textByAddress.set(s.address, s.text);
  }
  bitflip.progress(off + CHUNK, stringTotal, '建立字符串地址表');
}
bitflip.log('字符串总数=' + stringTotal);

// 2) 函数 → 它引用的字符串集合
const refsByFunction = new Map();
let scanned = 0;
let offset = 0;
for (;;) {
  const page = bitflip.xrefs.search({ offset: offset, count: 4096 });
  for (const x of page.items) {
    const text = textByAddress.get(x.to);
    if (text === undefined) { continue; }
    const fn = bitflip.functions.containing(x.from);
    if (fn === null) { continue; }
    let set = refsByFunction.get(fn.start);
    if (set === undefined) { set = new Set(); refsByFunction.set(fn.start, set); }
    set.add(text);
  }
  scanned += page.returned;
  bitflip.progress(scanned, page.total, '扫描交叉引用');
  if (page.truncated <= 0 || page.returned === 0) { break; }
  offset += page.returned;
}

// 3) 只给"恰好一个字符串"且尚未命名的函数写名字
const used = new Set();
let renamed = 0;
let skippedNamed = 0;
let skippedAmbiguous = 0;

for (const [start, texts] of refsByFunction) {
  if (texts.size !== 1) { skippedAmbiguous += 1; continue; }
  const fn = bitflip.functions.at(start);
  if (fn === null) { continue; }
  if (fn.named) { skippedNamed += 1; continue; }

  const text = [...texts][0];
  let stem = sanitize(text);
  if (stem.length < 3) { skippedAmbiguous += 1; continue; }

  let name = 'str_' + stem;
  if (used.has(name)) {
    // 重名不覆盖、也不静默丢弃：拿地址后缀区分开，名字仍然可读。
    name = name + '_' + start.slice(-4);
  }
  if (used.has(name)) { continue; }
  used.add(name);

  bitflip.setName(start, name);
  bitflip.setComment(start, '名字由脚本按字符串引用推断：' + JSON.stringify(text));
  renamed += 1;
}

bitflip.log('重命名=' + renamed);
bitflip.log('跳过（已有名字）=' + skippedNamed);
bitflip.log('跳过（引用不唯一或字符串太短）=' + skippedAmbiguous);
for (const note of bitflip.notes()) {
  bitflip.log('降级说明：' + note);
}
"#;

/// 导出函数清单。
const EXPORT_FUNCTIONS: &str = r#"
// 导出函数清单（制表符分隔，可直接粘进表格软件）
//
// 列：起始地址 / 名字 / 名字来源 / 置信度 / 大小
//
// 两件必须如实做的事：
//   * 未命名的函数写 `(未命名)`，**不生成占位名**让清单看起来完整；
//   * 把 bitflip.notes() 的降级说明一并导出 —— 一份"函数边界靠线性扫描"
//     得出的清单，和一份有 .eh_frame 支撑的清单，可信度不是一回事。
//
// 篇幅控制：每 200 行作为一条日志发出，避免单条日志过大；
// 最后一条是总计。

const CHUNK = 200;
let buffer = [];
let exported = 0;
const total = bitflip.functions.count();

for (let off = 0; off < total; off += 512) {
  for (const f of bitflip.functions.page(off, 512).items) {
    const name = f.named ? f.name : '(未命名)';
    const size = f.size === null ? '?' : String(f.size);
    buffer.push([f.start, name, f.source_label, String(f.confidence), size].join('\t'));
    exported += 1;
    if (buffer.length >= CHUNK) { bitflip.log(buffer.join('\n')); buffer = []; }
  }
  bitflip.progress(exported, total, '导出函数清单');
}
if (buffer.length > 0) { bitflip.log(buffer.join('\n')); }

bitflip.log('# 函数总数=' + total + ' 已导出=' + exported);
for (const note of bitflip.notes()) {
  bitflip.log('# 降级说明：' + note);
}
"#;

/// 识别常见库调用模式（候选清单）。
const LIBRARY_PATTERNS: &str = r#"
// 识别常见库调用模式 —— 输出**候选清单**，不下结论
//
// 思路：编译器会把 memcpy / memset / strlen 这类例程以"小型、未命名、
//       被大量调用"的形式留在二进制里。所以统计每个被调用目标的调用次数，
//       把其中**未命名**的按次数排序列出来。
//
// 为什么不直接给它们起名：在没有签名库（M8）的情况下，"这个 20 字节的函数
// 是 memcpy"只是一条**假设**。给它起名 memcpy 会把假设伪装成事实，
// 后面所有基于这个名字的判断都会跟着错。所以这里只列候选，由人来看。

const CHUNK = 4096;
const TOP = 25;

// 1) 统计调用次数
const callCount = new Map();
let scanned = 0;
let offset = 0;
for (;;) {
  const page = bitflip.xrefs.search({ kinds: ['call'], offset: offset, count: CHUNK });
  for (const x of page.items) {
    callCount.set(x.to, (callCount.get(x.to) || 0) + 1);
  }
  scanned += page.returned;
  bitflip.progress(scanned, page.total, '统计调用次数');
  if (page.truncated <= 0 || page.returned === 0) { break; }
  offset += page.returned;
}
bitflip.log('调用引用总数=' + scanned + '，被调用目标数=' + callCount.size);

// 2) 只保留未命名的目标
const candidates = [];
for (const [address, count] of callCount) {
  const fn = bitflip.functions.at(address);
  if (fn === null) { continue; }   // 调到数据/外部：不是候选
  if (fn.named) { continue; }      // 已经有名字（符号表/导出/用户），不必猜
  candidates.push({ address: address, count: count, size: fn.size, confidence: fn.confidence });
}
candidates.sort((a, b) => b.count - a.count);

bitflip.log('# 未命名且被多处调用的函数（前 ' + TOP + ' 名）');
bitflip.log('# 调用次数\t大小\t边界置信度\t起始地址');
for (const item of candidates.slice(0, TOP)) {
  const size = item.size === null ? '?' : String(item.size);
  bitflip.log(item.count + '\t' + size + '\t' + item.confidence + '\t' + item.address);
}

bitflip.log('候选总数=' + candidates.length);
bitflip.log('# 这些只是候选：大小小、被调用多，符合编译器辅助例程的特征，但不构成识别结论。');
for (const note of bitflip.notes()) {
  bitflip.log('# 降级说明：' + note);
}
"#;

/// 内置脚本集（顺序即 UI 中的展示顺序）。
pub static BUILTIN: &[BuiltinScript] = &[
    BuiltinScript {
        id: "memcpy-args",
        name: "识别 memcpy 调用并写参数注释",
        description: "找到 memcpy，给每一个调用点写一条 `memcpy(dst, src, n)` 参数注释。\
                      找不到名为 memcpy 的函数时明确报错，不会静默什么都不做。",
        api_version: super::SCRIPT_API_VERSION,
        source: MEMCPY_ARGS,
    },
    BuiltinScript {
        id: "rename-by-string",
        name: "按字符串引用批量重命名",
        description: "给\"只引用了一个字符串\"且尚未命名的函数起一个 `str_` 前缀的推断名，\
                      并写明依据。已有名字的一律跳过；不唯一、太短的也跳过。",
        api_version: super::SCRIPT_API_VERSION,
        source: RENAME_BY_STRING,
    },
    BuiltinScript {
        id: "export-functions",
        name: "导出函数清单",
        description: "按\"地址 / 名字 / 来源 / 置信度 / 大小\"导出全部函数，未命名的如实写\
                      `(未命名)`，并连带导出 bitflip.notes() 里的降级说明。",
        api_version: super::SCRIPT_API_VERSION,
        source: EXPORT_FUNCTIONS,
    },
    BuiltinScript {
        id: "library-patterns",
        name: "识别常见库调用模式（候选）",
        description: "按调用次数列出未命名的小函数，作为编译器辅助例程（memcpy/memset 之类）\
                      的**候选**。只给候选，不下结论 —— 没有签名库时那只是假设。",
        api_version: super::SCRIPT_API_VERSION,
        source: LIBRARY_PATTERNS,
    },
];

/// 验收标准 1 的那份脚本。
///
/// 放在 `BUILTIN` 之外单独命名，是因为它被 `docs/PLAN.md` §M7 的验收标准
/// 直接引用；用具名常量可以让"验收跑的是哪一份"在代码里一眼可见。
pub const MEMCPY_ARGS: &str = r#"
// 识别所有调用 memcpy 的位置，并给每个调用点写参数注释。
//
// 这是 PLAN §M7 验收标准 1 的那一份脚本。用它当示例而不是另写一个更花哨的，
// 是因为它同时覆盖了脚本层最难的三件事：
//   * 分页遍历（不一次物化全部函数/xref）；
//   * 用过滤器代替全表扫描（toRange + kinds）；
//   * 写注释 —— 走暂存、由宿主在脚本正常结束后统一提交（见 docs/M7-SCRIPTING.md §5）。
//
// 找不到 memcpy 时明确报错：剥离过的目标上确实会找不到，
// 此时"什么都没发生"是最差的回答。

const NAME = 'memcpy';
const PAGE = 4096;

// 1) 找到 memcpy 的入口地址（分页遍历，一次只物化一页）
let target = null;
const fnTotal = bitflip.functions.count();
for (let off = 0; off < fnTotal && target === null; off += 512) {
  for (const f of bitflip.functions.page(off, 512).items) {
    if (f.name === NAME) { target = f; break; }
  }
}
if (target === null) {
  throw new Error(
    '目标里没有名为 ' + NAME + ' 的函数（共 ' + fnTotal + ' 个函数）。' +
    '剥离过符号表的目标上这是正常的：这属于签名识别（M8）的课题，不是脚本能补的。'
  );
}

// 2) 只取"调用 memcpy"的引用。
//    区间是左闭右开，所以上界取 start + 1；地址是 64 位，
//    用 BigInt 而不是 parseInt —— 后者超过 2^53 就不再精确。
const lo = target.start;
const hi = (BigInt('0x' + lo) + 1n).toString(16).padStart(16, '0');

let annotated = 0;
let offset = 0;
for (;;) {
  const page = bitflip.xrefs.search({ kinds: ['call'], toRange: [lo, hi], offset: offset, count: PAGE });
  for (const x of page.items) {
    bitflip.setComment(x.from, 'memcpy(dst, src, n)');
    annotated += 1;
  }
  if (page.truncated <= 0 || page.returned === 0) { break; }
  offset += page.returned;
  bitflip.progress(annotated, page.total, '标注调用点');
}

// 前两条日志是对外契约（验收测试读它们），不要插到前面。
bitflip.log('memcpy@' + lo);
bitflip.log('annotated=' + annotated);

if (annotated === 0) {
  bitflip.warn('找到了 memcpy 但没有任何调用点 —— 检查目标的调用引用是否被识别。');
}
for (const note of bitflip.notes()) {
  bitflip.log('降级说明：' + note);
}
"#;

/// 全部内置脚本。
#[must_use]
pub fn builtin_scripts() -> &'static [BuiltinScript] {
    BUILTIN
}

/// 按标识取一份内置脚本。
#[must_use]
pub fn builtin_script(id: &str) -> Option<&'static BuiltinScript> {
    BUILTIN.iter().find(|script| script.id == id)
}
