//! `serde_json::Value` → QuickJS 值。
//!
//! # 为什么走 serde 而不是手写字段映射
//!
//! core 的 wire 结构（`FunctionWire` / `XrefWire` / `InsnWire` …）本身就是
//! 对外契约，全部实现了 `Serialize`。手写一遍"字段名 → JS 属性"等于把同一份
//! 形状抄第二遍：core 哪天加一个字段，脚本 API 会**静默**落后，而脚本拿到的
//! 对象少一个键时不会报错，只会 `undefined`。
//!
//! 走 serde 只有一份真相，代价是每次转换多一次中间 `Value` 分配 —— 对
//! 一页几百条的规模可以忽略。

use rquickjs::{Array, Ctx, IntoJs, Object, Value};

/// 把可序列化的值直接交给 JS。
///
/// 存在理由是生命周期：`Function::new` 的闭包**无法**返回 `Value<'js>`
/// （`Value` 对 `'js` 是不变量，闭包绑不住入参 `Ctx<'js>` 与返回值），
/// 但可以返回一个具体类型，由 `IntoJs` 在正确的 `'js` 上完成转换。
///
/// 顺带一个好性质：`Option<T>` 会走 serde 变成 `null`，于是"查不到"这件事
/// 不需要每个调用点各写一遍。
pub(crate) struct Wire<T>(pub(crate) T);

impl<'js, T: serde::Serialize> IntoJs<'js> for Wire<T> {
    fn into_js(self, ctx: &Ctx<'js>) -> rquickjs::Result<Value<'js>> {
        to_js(ctx, &self.0)
    }
}

/// 把任意可序列化的值转成 JS 值。
pub(crate) fn to_js<'js, T: serde::Serialize + ?Sized>(
    ctx: &Ctx<'js>,
    value: &T,
) -> rquickjs::Result<Value<'js>> {
    let json = serde_json::to_value(value).map_err(|err| {
        rquickjs::Error::new_from_js_message("T", "JS", format!("序列化失败：{err}"))
    })?;
    json_to_js(ctx, &json)
}

/// 递归转换。
fn json_to_js<'js>(ctx: &Ctx<'js>, value: &serde_json::Value) -> rquickjs::Result<Value<'js>> {
    Ok(match value {
        serde_json::Value::Null => Value::new_null(ctx.clone()),
        serde_json::Value::Bool(flag) => Value::new_bool(ctx.clone(), *flag),
        serde_json::Value::Number(number) => number_to_js(ctx, number)?,
        serde_json::Value::String(text) => {
            rquickjs::String::from_str(ctx.clone(), text)?.into_js(ctx)?
        }
        serde_json::Value::Array(items) => {
            let array = Array::new(ctx.clone())?;
            for (index, item) in items.iter().enumerate() {
                array.set(index, json_to_js(ctx, item)?)?;
            }
            array.into_value()
        }
        serde_json::Value::Object(fields) => {
            let object = Object::new(ctx.clone())?;
            for (key, item) in fields {
                object.set(key.as_str(), json_to_js(ctx, item)?)?;
            }
            object.into_value()
        }
    })
}

/// 数字转换。
///
/// JS 只有 f64 一种数字类型，所以这里最终都会经过 f64。**依赖 wire 契约**
/// 保证这一点是安全的：core 明确把可能超出 2^53 的值（地址、立即数）表示成
/// 字符串而不是数字（见 `ImmediateWire` 的注释），因此到达这里的数字都在
/// 安全整数范围内。
///
/// 万一将来有人往 wire 里塞了一个超范围的数字，这里**不会**报错 —— 那样
/// 太晚了，错误应当发生在 wire 定义处。这是有意的取舍：宁可让契约约束
/// 数据源头，也不在这里加一个永远不该触发的分支。
fn number_to_js<'js>(ctx: &Ctx<'js>, number: &serde_json::Number) -> rquickjs::Result<Value<'js>> {
    match number.as_f64() {
        Some(float) => Ok(Value::new_float(ctx.clone(), float)),
        None => Err(rquickjs::Error::new_from_js_message(
            "number",
            "JS",
            format!("无法把 {number} 表示成 JS 数字"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_structures_round_trip_through_json() {
        // 不需要真引擎：这里的价值是钉住"结构形状不丢"，
        // 交给一个最小的运行时跑一次比读代码可靠。
        let runtime = rquickjs::Runtime::new().expect("运行时");
        let context = rquickjs::Context::full(&runtime).expect("上下文");
        context.with(|ctx| {
            let value = serde_json::json!({
                "address": "0000000000401000",
                "size": 42,
                "end": null,
                "items": [1, 2, 3],
                "flag": true,
                "label": "名字"
            });
            let js = json_to_js(&ctx, &value).expect("转换");
            ctx.globals().set("probe", js).expect("挂到全局");

            let address: String = ctx.eval("probe.address").expect("address");
            assert_eq!(address, "0000000000401000");

            let size: i64 = ctx.eval("probe.size").expect("size");
            assert_eq!(size, 42);

            let is_null: bool = ctx.eval("probe.end === null").expect("end");
            assert!(is_null, "null 必须转成 JS 的 null，而不是 undefined");

            let third: i64 = ctx.eval("probe.items[2]").expect("items");
            assert_eq!(third, 3);

            let flag: bool = ctx.eval("probe.flag").expect("flag");
            assert!(flag);

            let label: String = ctx.eval("probe.label").expect("label");
            assert_eq!(label, "名字");
        });
    }

    #[test]
    fn a_json_object_becomes_a_plain_object_with_the_same_keys() {
        let runtime = rquickjs::Runtime::new().expect("运行时");
        let context = rquickjs::Context::full(&runtime).expect("上下文");
        context.with(|ctx| {
            let value = serde_json::json!({ "a": 1, "b": { "c": 2 } });
            let js = json_to_js(&ctx, &value).expect("转换");
            ctx.globals().set("probe", js).expect("挂到全局");
            let keys: String = ctx.eval("Object.keys(probe).sort().join(',')").expect("键");
            assert_eq!(keys, "a,b");
            let nested: i64 = ctx.eval("probe.b.c").expect("嵌套");
            assert_eq!(nested, 2);
        });
    }
}
