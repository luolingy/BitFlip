//! 脚本产出的**具名表格**：`bitflip.table(...)`。
//!
//! 这是 M7 交付物里的"自定义视图数据源"：脚本算出来的东西，界面按**声明的**
//! 形状渲染成一张表，可以被反复查看、切换。
//!
//! # 为什么是"声明"而不是"从日志里猜"
//!
//! 在加这个 API 之前，控制台里已经有一张表 —— 它是**从日志文本里解析出来的**
//! （脚本 `log('a\tb\tc')`，前端按制表符切成表格）。那条路有两个问题：
//!
//! 1. **列的含义是猜的。** 前端只能看到一串字符串，于是它按"定长十六进制"
//!    猜哪一列是地址。猜对了没奖励，猜错了就是把不是地址的东西当地址渲染 ——
//!    而用户以为那是脚本声明的。
//! 2. **只有一张表。** 一次运行的**全部**制表符日志被拼成一张表，于是
//!    "这次运行还产出过另一份清单"无处安放，脚本只能自己加标题行凑合。
//!
//! 所以这里把协议前置到脚本侧：每张表有名字、有列（带类型）、有行。界面不再
//! 推断任何东西，它只渲染脚本声明过的形状。
//!
//! # 单元格只允许标量
//!
//! 表格视图的基本要求是"每个格子都画得出来"。允许嵌套对象就会立刻遇到
//! "这一格该显示什么"的问题，而任何答案都是界面在替脚本编。所以单元格只接受
//! `string` / `number` / `boolean` / `null`，遇到对象或数组**报错并指出位置**，
//! 而不是显示 `[object Object]`。
//!
//! # 地址列存的是整数，渲染的是本项目的地址格式
//!
//! 全项目只有一种地址字符串格式（定长小写 16 位十六进制，见 CLAUDE.md §4），
//! 所以 `type: 'address'` 的列在内部存 `u64`、在 wire 上按那个格式输出 ——
//! 既不是让脚本自己拼字符串（十个脚本会有三种写法），也不是让界面去猜。
//!
//! # 表与"暂存"同生命周期
//!
//! 表的提交/丢弃与标注完全一致（见 [`crate::stage`]）：脚本正常结束才留下，
//! 中断、超时或抛异常时**一张都不留**。否则一个跑到一半被掐断的脚本会留下一张
//! "看起来完成了"的半截表 —— 那正是 CLAUDE.md §7 禁止的失效模式。
//!
//! 与标注不同的是，表**不落工程库**：它是本次分析会话的派生物（和函数列表、
//! xref 一样），分析结果本身不落库，落一张依赖它的表会让"表比分析活得久"，
//! 于是下次打开时它描述的是一份已经不存在的分析结论。

use rquickjs::{Array, Coerced, Ctx, Exception, Object, Value};
use serde::{Serialize, Serializer};

/// 一次运行最多产出多少张表。
///
/// 上限的意义不是防呆，而是防"脚本把界面变成表动物园"：视图列表是要人看的。
pub const MAX_TABLES_PER_RUN: usize = 16;

/// 一张表最多多少列。
pub const MAX_TABLE_COLUMNS: usize = 64;

/// 一次运行产出的全部表合计最多多少单元格。
///
/// 200k 格（约 7000 行 × 28 列）远超任何"给人看的清单"，
/// 但远小于"把整个 .text 逐字节铺开"的量级 —— 后者是脚本写错了。
pub const MAX_TABLE_CELLS: usize = 200_000;

/// 表名与列名的最大字符数。
pub const MAX_NAME_CHARS: usize = 128;

/// 说明文字的最大字符数。
pub const MAX_DESCRIPTION_CHARS: usize = 512;

/// 单个文本单元格的最大字符数。
///
/// 单元格是给人看的，不是用来装文件内容的。超限**报错**而不是截断：
/// 截断会让用户以为看到的是全部。
pub const MAX_CELL_TEXT_CHARS: usize = 4096;

/// 列的类型。它决定单元格怎么被读取与渲染。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnKind {
    /// 文本。
    Text,
    /// 数字。
    Number,
    /// 地址：内部存 `u64`，wire 上是定长十六进制。
    Address,
    /// 布尔。
    Bool,
}

impl ColumnKind {
    /// wire 与脚本里使用的名字。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Number => "number",
            Self::Address => "address",
            Self::Bool => "bool",
        }
    }

    /// 全部可选值，用于报错时列出。
    #[must_use]
    pub const fn all() -> &'static [&'static str] {
        &["text", "number", "address", "bool"]
    }

    /// 解析类型名。
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "text" => Some(Self::Text),
            "number" => Some(Self::Number),
            "address" => Some(Self::Address),
            "bool" => Some(Self::Bool),
            _ => None,
        }
    }
}

/// 一列。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TableColumn {
    /// 列名（显示用，脚本自己定）。
    pub name: String,
    /// 类型。
    pub kind: ColumnKind,
}

impl TableColumn {
    /// 构造。
    #[must_use]
    pub fn new(name: impl Into<String>, kind: ColumnKind) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }
}

/// 一个单元格。
#[derive(Debug, Clone, PartialEq)]
pub enum TableCell {
    /// 空（脚本给了 `null` / `undefined`）。
    Empty,
    /// 布尔。
    Bool(bool),
    /// 数字。
    Number(f64),
    /// 地址（wire 上是定长十六进制）。
    Address(u64),
    /// 文本。
    Text(String),
}

impl Serialize for TableCell {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // 手写而不是 `#[serde(untagged)]`：`untagged` 的反序列化是歧义的
        // （字符串到底是文本还是地址？），而这里的每种取值都必须有明确的
        // wire 表示 —— 地址必须是十六进制字符串，不是数字。
        match self {
            Self::Empty => serializer.serialize_none(),
            Self::Bool(flag) => serializer.serialize_bool(*flag),
            Self::Number(number) => serializer.serialize_f64(*number),
            Self::Address(address) => serializer.serialize_str(&bitflip_core::hex16(*address)),
            Self::Text(text) => serializer.serialize_str(text),
        }
    }
}

/// 一张脚本表。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScriptTable {
    /// 表名（视图列表里显示的就是它，一次运行内唯一）。
    pub name: String,
    /// 可选说明。
    pub description: Option<String>,
    /// 列定义。
    pub columns: Vec<TableColumn>,
    /// 数据行；每行长度等于 `columns.len()`。
    pub rows: Vec<Vec<TableCell>>,
}

impl ScriptTable {
    /// 行数。
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// 单元格总数。
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.rows.iter().map(Vec::len).sum()
    }

    /// 摘要（不含数据行）。
    ///
    /// 界面轮询状态时会反复取它，所以这里**不克隆数据行** —— 一张 20 万格的表
    /// 每 300 毫秒克隆一次，光内存流量就够把界面拖慢。
    #[must_use]
    pub fn summary(&self) -> TableSummary {
        TableSummary {
            name: self.name.clone(),
            description: self.description.clone(),
            columns: self.columns.clone(),
            row_count: self.row_count(),
        }
    }
}

/// 表摘要的 wire 形状（`status` 里用的是它）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TableSummary {
    /// 表名。
    pub name: String,
    /// 说明。
    pub description: Option<String>,
    /// 列定义。
    pub columns: Vec<TableColumn>,
    /// 行数。
    pub row_count: usize,
}

// ---------------------------------------------------------------------------
// JS → Rust
// ---------------------------------------------------------------------------

/// 报错（带上调用方给的位置说明）。
fn fail<T>(ctx: &Ctx<'_>, message: String) -> rquickjs::Result<T> {
    Err(Exception::throw_message(ctx, &message))
}

/// 位置说明：`第 3 行「大小」列`。给用户看的行号是**1 起**的。
fn location(row: usize, column: &str) -> String {
    format!("第 {} 行「{column}」列", row + 1)
}

/// 解析一个可选字符串字段。
fn optional_text(
    ctx: &Ctx<'_>,
    object: &Object<'_>,
    key: &str,
    limit: usize,
    what: &str,
) -> rquickjs::Result<Option<String>> {
    let Some(value) = object.get::<_, Option<Value<'_>>>(key)? else {
        return Ok(None);
    };
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    if !value.is_string() {
        return fail(
            ctx,
            format!("{what}必须是字符串，收到 {}", value.type_name()),
        );
    }
    let text: String = value.get()?;
    if text.chars().count() > limit {
        return fail(
            ctx,
            format!(
                "{what}最长 {limit} 个字符，收到 {} 个",
                text.chars().count()
            ),
        );
    }
    Ok(Some(text))
}

/// 解析列定义：`列名` 或 `{ name, type }`。
fn parse_columns(ctx: &Ctx<'_>, value: &Value<'_>) -> rquickjs::Result<Vec<TableColumn>> {
    if !value.is_array() {
        return fail(
            ctx,
            format!(
                "bitflip.table 的列定义必须是数组（如 ['地址', '名字'] 或 \
                 [{{name: '地址', type: 'address'}}]），收到 {}",
                value.type_name()
            ),
        );
    }
    let array = Array::from_value(value.clone())?;
    let count = array.len();
    if count == 0 {
        return fail(ctx, "bitflip.table 至少要有一列".to_string());
    }
    if count > MAX_TABLE_COLUMNS {
        return fail(
            ctx,
            format!("一张表最多 {MAX_TABLE_COLUMNS} 列，收到 {count} 列"),
        );
    }

    let mut columns: Vec<TableColumn> = Vec::with_capacity(count);
    for index in 0..count {
        let item: Value<'_> = array.get(index)?;
        let column = if item.is_string() {
            TableColumn::new(item.get::<String>()?, ColumnKind::Text)
        } else if item.is_object() && !item.is_array() {
            let object = Object::from_value(item.clone())?;
            let name =
                optional_text(ctx, &object, "name", MAX_NAME_CHARS, "列名")?.ok_or_else(|| {
                    Exception::throw_message(
                        ctx,
                        &format!(
                            "第 {} 列缺少 name（列定义要写成 {{name: '地址', type: 'address'}}）",
                            index + 1
                        ),
                    )
                })?;
            let raw_kind = optional_text(ctx, &object, "type", MAX_NAME_CHARS, "列类型")?;
            let kind = match raw_kind.as_deref() {
                None => ColumnKind::Text,
                Some(raw) => ColumnKind::parse(raw).ok_or_else(|| {
                    Exception::throw_message(
                        ctx,
                        &format!(
                            "第 {} 列「{name}」的类型 {raw:?} 不认识；可选：{}",
                            index + 1,
                            ColumnKind::all().join(" / ")
                        ),
                    )
                })?,
            };
            TableColumn::new(name, kind)
        } else {
            return fail(
                ctx,
                format!(
                    "第 {} 列的列定义只能是字符串或 {{name, type}} 对象，收到 {}",
                    index + 1,
                    item.type_name()
                ),
            );
        };

        if column.name.trim().is_empty() {
            return fail(ctx, format!("第 {} 列的列名不能为空", index + 1));
        }
        if columns.iter().any(|existing| existing.name == column.name) {
            // 重名列会让"这一格属于哪一列"变成歧义，而歧义到了界面上
            // 就表现为"某一列的数据莫名少了几格"。
            return fail(
                ctx,
                format!("列名「{}」重复了；列名在一次运行内必须唯一", column.name),
            );
        }
        columns.push(column);
    }
    Ok(columns)
}

/// 把一个单元格从 JS 值读成 [`TableCell`]。
fn parse_cell(
    ctx: &Ctx<'_>,
    value: &Value<'_>,
    column: &TableColumn,
    row: usize,
) -> rquickjs::Result<TableCell> {
    // `null` / `undefined` 一律是"空"：脚本用一个可能不存在的字段填格子是最
    // 常见的写法，把它当错误会逼所有脚本写一堆三元表达式。
    if value.is_null() || value.is_undefined() {
        return Ok(TableCell::Empty);
    }
    let where_ = location(row, &column.name);

    match column.kind {
        ColumnKind::Address => {
            if value.is_string() {
                let raw: String = value.get()?;
                return bitflip_core::parse_address(&raw)
                    .map(TableCell::Address)
                    .ok_or_else(|| {
                        Exception::throw_message(
                            ctx,
                            &format!(
                                "{where_}：地址无法解析 {raw:?}；\
                                 需要十六进制（如 0x140009218 或 \"0000000140009218\"）"
                            ),
                        )
                    });
            }
            if value.is_number() {
                let number: f64 = value.get()?;
                return address_from_number(ctx, number, &where_);
            }
            fail(
                ctx,
                format!(
                    "{where_}：地址列只接受数字或十六进制字符串，收到 {}",
                    value.type_name()
                ),
            )
        }
        ColumnKind::Number => {
            if value.is_number() {
                let number: f64 = value.get()?;
                if !number.is_finite() {
                    return fail(
                        ctx,
                        format!("{where_}：数字必须是有限值（NaN 与 Infinity 无法显示）"),
                    );
                }
                return Ok(TableCell::Number(number));
            }
            if value.is_string() {
                // 允许数字字符串：脚本经常是"把一列文本里能当数字的算出来"。
                let raw: String = value.get()?;
                return raw.trim().parse::<f64>().map_or_else(
                    |_| {
                        fail(
                            ctx,
                            format!("{where_}：{raw:?} 不是数字（这一列声明为 number）"),
                        )
                    },
                    |parsed| Ok(TableCell::Number(parsed)),
                );
            }
            fail(
                ctx,
                format!(
                    "{where_}：数字列只接受数字或数字字符串，收到 {}",
                    value.type_name()
                ),
            )
        }
        ColumnKind::Bool => {
            if let Some(flag) = value.as_bool() {
                return Ok(TableCell::Bool(flag));
            }
            if value.is_number() {
                let number: f64 = value.get()?;
                // 只接受 0/1：把任意非 0 当 true 会把"3"这种明显写错的输入
                // 悄悄变成 true。
                if number == 0.0 {
                    return Ok(TableCell::Bool(false));
                }
                if number == 1.0 {
                    return Ok(TableCell::Bool(true));
                }
                return fail(
                    ctx,
                    format!("{where_}：布尔列只接受 true/false 或 0/1，收到 {number}"),
                );
            }
            fail(
                ctx,
                format!(
                    "{where_}：布尔列只接受 true/false 或 0/1，收到 {}",
                    value.type_name()
                ),
            )
        }
        ColumnKind::Text => {
            // 只接受标量。对象/数组一律报错 —— 显示 `[object Object]`
            // 等于把"脚本给错了"伪装成"格子里就是这个字符串"。
            if !(value.is_string() || value.is_number() || value.is_bool()) {
                return fail(
                    ctx,
                    format!(
                        "{where_}：单元格只能是标量（字符串/数字/布尔/null），收到 {}；\
                         请让脚本把它转成字符串",
                        value.type_name()
                    ),
                );
            }
            // 用 JS 自己的 `String(v)` 做转换：这样格子里的文本与脚本
            // 自己 `String(v)` 得到的结果**逐字相同**，不存在两套数字格式化。
            let text: Coerced<String> = value.get()?;
            if text.0.chars().count() > MAX_CELL_TEXT_CHARS {
                return fail(
                    ctx,
                    format!(
                        "{where_}：单元格文本最长 {MAX_CELL_TEXT_CHARS} 个字符，\
                         收到 {} 个",
                        text.0.chars().count()
                    ),
                );
            }
            Ok(TableCell::Text(text.0))
        }
    }
}

/// 数字形式的地址：必须是精确的非负整数，且在 JS 安全整数范围内。
fn address_from_number(ctx: &Ctx<'_>, number: f64, where_: &str) -> rquickjs::Result<TableCell> {
    if !number.is_finite() || number < 0.0 || number.fract() != 0.0 {
        return fail(ctx, format!("{where_}：地址必须是整数，收到 {number}"));
    }
    if number > JS_MAX_SAFE_INTEGER {
        // 与 `bitflip.setName` 同一条底线：到了这里精度已经丢了，静默截断会
        // 把行指向另一个地址，而表面看起来完全正常。
        return fail(
            ctx,
            format!(
                "{where_}：地址超过 JavaScript 安全整数范围（2^53-1）；\
                 请改用十六进制字符串"
            ),
        );
    }
    Ok(TableCell::Address(number as u64))
}

/// JS 能精确表示的最大整数。
const JS_MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// 从 `bitflip.table(...)` 的实参构造一张表（含全部校验）。
///
/// `cell_budget` 是本次运行**还剩多少**单元格额度：上限是跨全部表合计的，
/// 单张表看不出别的表已经用掉多少，所以由调用方算好传进来。
pub(crate) fn table_from_js(
    ctx: &Ctx<'_>,
    name: Value<'_>,
    columns: Value<'_>,
    rows: Value<'_>,
    options: Option<Value<'_>>,
    cell_budget: usize,
) -> rquickjs::Result<ScriptTable> {
    if !name.is_string() {
        return fail(
            ctx,
            format!(
                "bitflip.table 的表名必须是字符串，收到 {}；\
                 用法：bitflip.table('表名', ['列'], [[值]])",
                name.type_name()
            ),
        );
    }
    let name: String = name.get()?;
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return fail(ctx, "bitflip.table 的表名不能为空".to_string());
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return fail(
            ctx,
            format!(
                "表名最长 {MAX_NAME_CHARS} 个字符，收到 {} 个",
                name.chars().count()
            ),
        );
    }

    let description = match options {
        None => None,
        Some(value) if value.is_null() || value.is_undefined() => None,
        Some(value) => {
            let object = Object::from_value(value).map_err(|_| {
                Exception::throw_message(
                    ctx,
                    "bitflip.table 的第四个参数（选项）必须是对象，如 {description: '...'}",
                )
            })?;
            optional_text(ctx, &object, "description", MAX_DESCRIPTION_CHARS, "说明")?
        }
    };

    let columns = parse_columns(ctx, &columns)?;

    if !rows.is_array() {
        return fail(
            ctx,
            format!(
                "bitflip.table 的数据行必须是数组（每行也是一个数组），收到 {}",
                rows.type_name()
            ),
        );
    }
    let array = Array::from_value(rows.clone())?;
    let row_count = array.len();

    // 先按行数做一次粗算并把超限报在"还没分配存储"之前：一张 100 万行的表
    // 如果先把每行都读进来再报错，脚本会先吃掉几百兆内存。
    let projected = row_count.saturating_mul(columns.len());
    if projected > cell_budget {
        return fail(
            ctx,
            format!(
                "表「{name}」有 {row_count} 行 × {} 列 = {projected} 个单元格，\
                 超过本次运行剩余额度 {cell_budget}（合计上限 {MAX_TABLE_CELLS}）；\
                 请缩小范围或分次运行",
                columns.len()
            ),
        );
    }

    let mut parsed_rows: Vec<Vec<TableCell>> = Vec::with_capacity(row_count);
    for index in 0..row_count {
        let item: Value<'_> = array.get(index)?;
        // 每行都必须**严格等长**：短一行会让后面的格子整体左移，
        // 界面看起来只是"某几列空着"，而数据已经串位了。
        if !item.is_array() {
            return fail(
                ctx,
                format!(
                    "第 {} 行不是数组，收到 {}；每行都必须是与列数等长的数组",
                    index + 1,
                    item.type_name()
                ),
            );
        }
        let row_array = Array::from_value(item)?;
        if row_array.len() != columns.len() {
            return fail(
                ctx,
                format!(
                    "第 {} 行有 {} 个单元格，但有 {} 列；每行必须与列数等长",
                    index + 1,
                    row_array.len(),
                    columns.len()
                ),
            );
        }
        let mut cells = Vec::with_capacity(columns.len());
        for (column, column_def) in columns.iter().enumerate() {
            let cell: Value<'_> = row_array.get(column)?;
            cells.push(parse_cell(ctx, &cell, column_def, index)?);
        }
        parsed_rows.push(cells);
    }

    Ok(ScriptTable {
        name,
        description,
        columns,
        rows: parsed_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 在真运行时里解析一段表达式（`{columns, rows, options}`）并交出结果。
    ///
    /// **这里只断言"接受还是拒绝"**：拒绝的**理由**是给用户看的，
    /// 它出现在 JS 异常对象里（Rust 侧的 `Display` 只有
    /// "Exception generated by QuickJS"）。逐字核对理由的测试放在
    /// `tests/tables.rs`，走引擎那条真实路径。
    fn parse(expression: &str) -> rquickjs::Result<ScriptTable> {
        parse_with_budget(expression, MAX_TABLE_CELLS)
    }

    fn parse_with_budget(expression: &str, budget: usize) -> rquickjs::Result<ScriptTable> {
        let runtime = rquickjs::Runtime::new().expect("运行时");
        let context = rquickjs::Context::full(&runtime).expect("上下文");
        context.with(|ctx| {
            table_from_js(
                &ctx,
                ctx.eval("'表'")?,
                ctx.eval(format!("({expression}).columns"))?,
                ctx.eval(format!("({expression}).rows"))?,
                None,
                budget,
            )
        })
    }

    /// 断言"必须拒绝"。
    fn rejects(expression: &str) {
        let outcome = parse(expression);
        assert!(
            outcome.is_err(),
            "这个形状必须被拒绝，却被接受了：{expression}"
        );
    }

    #[test]
    fn a_well_formed_table_is_read_cell_by_cell() {
        let table = parse(
            "({columns: [{name: '地址', type: 'address'}, {name: '名字'}, \
              {name: '大小', type: 'number'}, {name: '命中', type: 'bool'}], \
              rows: [[0x140009218, 'memcpy', 42, true], \
                     ['0000000000000010', 'main', '3.5', 0]]})",
        )
        .expect("应当解析成功");

        assert_eq!(table.columns.len(), 4);
        assert_eq!(table.columns[0].kind, ColumnKind::Address);
        assert_eq!(
            table.columns[1].kind,
            ColumnKind::Text,
            "不写 type 默认文本"
        );
        assert_eq!(table.row_count(), 2);
        assert_eq!(table.cell_count(), 8);
        assert_eq!(table.rows[0][0], TableCell::Address(0x0001_4000_9218));
        assert_eq!(table.rows[0][1], TableCell::Text("memcpy".into()));
        assert_eq!(table.rows[0][2], TableCell::Number(42.0));
        assert_eq!(table.rows[0][3], TableCell::Bool(true));
        // 字符串形式的地址与十进制数字必须落到同一格值上 —— 两种写法在
        // 项目里都是合法的，界面上不该因此变成两种东西。
        assert_eq!(table.rows[1][0], TableCell::Address(0x10));
        assert_eq!(table.rows[1][1], TableCell::Text("main".into()));
        assert_eq!(table.rows[1][2], TableCell::Number(3.5));
        assert_eq!(table.rows[1][3], TableCell::Bool(false));
    }

    #[test]
    fn null_and_undefined_become_empty_cells() {
        let table =
            parse("({columns: ['a', 'b', 'c'], rows: [[null, undefined, 'x']]})").expect("解析");
        assert_eq!(table.rows[0][0], TableCell::Empty);
        assert_eq!(table.rows[0][1], TableCell::Empty);
        assert_eq!(table.rows[0][2], TableCell::Text("x".into()));
    }

    #[test]
    fn text_cells_use_the_engines_own_string_conversion() {
        // 数字与布尔进文本列时按 JS 的 `String(v)` 转：`2` 是 "2" 而不是 "2.0"。
        let table = parse("({columns: ['a', 'b', 'c'], rows: [[2, 2.5, true]]})").expect("解析");
        assert_eq!(table.rows[0][0], TableCell::Text("2".into()));
        assert_eq!(table.rows[0][1], TableCell::Text("2.5".into()));
        assert_eq!(table.rows[0][2], TableCell::Text("true".into()));
    }

    #[test]
    fn an_empty_table_is_allowed() {
        // "查询无结果"是合法结论，不是错误。界面上会显示 0 行。
        let table = parse("({columns: ['a'], rows: []})").expect("空表应当允许");
        assert_eq!(table.row_count(), 0);
        assert!(table.rows.is_empty());
        assert_eq!(table.cell_count(), 0);
    }

    #[test]
    fn malformed_shapes_are_all_refused() {
        // 每一条都是一个"看起来能跑、结果却是错的"形状。
        for expression in [
            // 行比列多/少：格子在界面上会整体串位。
            "({columns: ['a', 'b'], rows: [['x', 'y'], ['only-one']]})",
            "({columns: ['a'], rows: [['x', 'y']]})",
            // 行不是数组。
            "({columns: ['a'], rows: ['不是数组']})",
            // 重名列：界面上"这一格属于哪一列"没有答案。
            "({columns: ['a', 'a'], rows: []})",
            // 没写 name 的列定义。
            "({columns: [{type: 'text'}], rows: []})",
            // 不认识的列类型。
            "({columns: [{name: 'a', type: 'hex'}], rows: []})",
            // 空列名与空列定义。
            "({columns: [''], rows: []})",
            "({columns: [], rows: []})",
            // 非标量单元格：显示成 `[object Object]` 等于替脚本编内容。
            "({columns: ['a'], rows: [[{x: 1}]]})",
            "({columns: ['a'], rows: [[[1, 2]]]})",
            "({columns: ['a'], rows: [[() => 1]]})",
            // 地址列拿到非整数 / 超出安全整数范围：静默取整会把行指到别处。
            "({columns: [{name: 'a', type: 'address'}], rows: [[1.5]]})",
            "({columns: [{name: 'a', type: 'address'}], rows: [[9007199254740994]]})",
            "({columns: [{name: 'a', type: 'address'}], rows: [[-1]]})",
            "({columns: [{name: 'a', type: 'address'}], rows: [['不是地址']]})",
            // 数字列拿到 NaN/Infinity：显示不出来。
            "({columns: [{name: 'a', type: 'number'}], rows: [[0/0]]})",
            "({columns: [{name: 'a', type: 'number'}], rows: [['abc']]})",
            // 布尔列拿到 3：把非 0 当 true 会把写错的值悄悄变成 true。
            "({columns: [{name: 'a', type: 'bool'}], rows: [[3]]})",
            // 列定义整段不是数组。
            "({columns: 'a', rows: []})",
            // 数据行整段不是数组。
            "({columns: ['a'], rows: 'x'})",
        ] {
            rejects(expression);
        }
    }

    #[test]
    fn the_cell_budget_is_shared_across_tables_of_one_run() {
        // 额度是跨表合计的：单张 3 格与"只剩 2 格"放在一起必须拒绝，
        // 否则 16 张表各自"不超限"就能把额度撑到 16 倍。
        let expression = "({columns: ['a'], rows: [['x'], ['y'], ['z']]})";
        assert!(
            parse_with_budget(expression, 3).is_ok(),
            "刚好用完额度应当允许"
        );
        assert!(
            parse_with_budget(expression, 2).is_err(),
            "超出剩余额度必须拒绝"
        );
    }

    #[test]
    fn a_table_beyond_the_cell_cap_is_refused() {
        rejects("({columns: ['a'], rows: new Array(200001).fill('x').map(v => [v])})");
    }

    #[test]
    fn the_description_comes_from_the_options_argument() {
        let runtime = rquickjs::Runtime::new().expect("运行时");
        let context = rquickjs::Context::full(&runtime).expect("上下文");
        context.with(|ctx| {
            let options: Value<'_> = ctx.eval("({description: '这就是说明'})").unwrap();
            let table = table_from_js(
                &ctx,
                ctx.eval("'表'").unwrap(),
                ctx.eval("['a']").unwrap(),
                ctx.eval("[['x']]").unwrap(),
                Some(options),
                MAX_TABLE_CELLS,
            )
            .expect("解析");
            assert_eq!(table.description.as_deref(), Some("这就是说明"));
        });
    }

    #[test]
    fn the_wire_shape_of_a_cell_keeps_addresses_in_hex() {
        // 这是给界面看的形状，也是全项目唯一的地址字符串规范
        // （定长小写 16 位十六进制，见 CLAUDE.md §4）：地址单元格在 wire 上
        // 必须是那个形状的**字符串**，不能是数字 —— 数字到前端就变成
        // `140009218`，与地址列的语义脱钩。
        let cells = vec![
            TableCell::Empty,
            TableCell::Bool(true),
            TableCell::Number(3.5),
            TableCell::Address(0x40_1000),
            TableCell::Address(0x0001_4000_9218),
            TableCell::Text("memcpy".into()),
        ];
        let json = serde_json::to_value(&cells).expect("序列化");
        assert_eq!(
            json,
            serde_json::json!([
                null,
                true,
                3.5,
                "0000000000401000",
                "0000000140009218",
                "memcpy"
            ])
        );
    }

    #[test]
    fn a_summary_carries_the_shape_without_the_rows() {
        let table =
            parse("({columns: [{name: '地址', type: 'address'}], rows: [[0x10]]})").expect("解析");
        let summary = table.summary();
        assert_eq!(summary.name, table.name);
        assert_eq!(summary.row_count, 1);
        assert_eq!(summary.columns, table.columns);
        let json = serde_json::to_value(&summary).expect("序列化");
        assert!(
            json.get("rows").is_none(),
            "摘要里不该有数据行（界面轮询用的就是它）：{json}"
        );
    }

    #[test]
    fn column_kinds_round_trip_through_their_names() {
        for kind in [
            ColumnKind::Text,
            ColumnKind::Number,
            ColumnKind::Address,
            ColumnKind::Bool,
        ] {
            assert_eq!(ColumnKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(ColumnKind::parse("hex"), None, "未知类型必须如实不识别");
    }
}
