// DEX 视图 URL 状态（`web/src/dexUrl.ts`）的行为测试。
//
// 为什么不用浏览器点一遍：本仓库的验证环境里没有浏览器自动化，而"URL 状态"
// 恰好是最容易「看起来对、其实没写进去」的一类功能 —— 读不到、写不对、
// 或者写回时把启动参数一起删了，TypeScript 一个错误都不会报。
//
// 做法：用 Node 的类型剥离（`--experimental-strip-types`，Node >= 22.6）直接
// import 那个 `.ts` 模块，喂一个假的 `window`/`history`，断言真实行为。
// 跑的是**打包进 SPA 的同一份源码**，不是复制一份逻辑来测。
//
// 用法（仓库根目录）：
//   node --experimental-strip-types scripts/check-dex-url.mjs
//
// 失败即非零退出：这个脚本只判断"过"与"不过"，不做降级跳过（CLAUDE.md §7）。

import assert from "node:assert/strict";

/** 记录 history 调用次数：用来验证「状态没变就不碰 URL」。 */
let replaceCalls = 0;
const listeners = new Map();

globalThis.window = {
  location: { hash: "", pathname: "/app" },
  history: {
    replaceState(_state, _title, url) {
      replaceCalls += 1;
      const index = url.indexOf("#");
      globalThis.window.location.hash = index < 0 ? "" : url.slice(index);
    },
  },
  addEventListener(type, listener) {
    listeners.set(type, listener);
  },
  removeEventListener(type) {
    listeners.delete(type);
  },
};

const { readDexUrl, writeDexUrl, subscribeDexHash } = await import(
  "../web/src/dexUrl.ts"
);

/** 每个断言都带上场景名：失败时要能一眼看出是哪种 URL 出的问题。 */
function check(scenario, fn) {
  try {
    fn();
    console.log("  OK   " + scenario);
  } catch (error) {
    console.log("  FAIL " + scenario);
    console.log("       " + String(error && error.message ? error.message : error));
    process.exitCode = 1;
  }
}

function setHash(hash) {
  window.location.hash = hash;
}

console.log("DEX URL 状态检查（web/src/dexUrl.ts）");

// ── 空的 URL：什么也没有，且**不是**"DEX 视图的状态"
setHash("");
check("空 hash：不激活、没有任何状态", () => {
  assert.deepEqual(readDexUrl(), {
    active: false,
    member: null,
    descriptor: null,
    method: null,
    search: null,
  });
});

// ── 只有标记：说明"这条 hash 是 DEX 视图的"，其余都没有
setHash("#dex=1");
check("只有 dex=1：激活但没有选中项", () => {
  assert.deepEqual(readDexUrl(), {
    active: true,
    member: null,
    descriptor: null,
    method: null,
    search: null,
  });
});

// ── 完整状态：成员名、smali 描述符、smali 方法标识、搜索词
setHash(
  "#dex=1&member=classes2.dex&class=" +
    encodeURIComponent("Lcom/example/Foo;") +
    "&method=" +
    encodeURIComponent("Lcom/example/Foo;->bar([I)V") +
    "&search=Activity",
);
check("完整状态：五个字段都读出来", () => {
  assert.deepEqual(readDexUrl(), {
    active: true,
    member: "classes2.dex",
    descriptor: "Lcom/example/Foo;",
    method: "Lcom/example/Foo;->bar([I)V",
    search: "Activity",
  });
});

// ── 空串与缺失一视同仁：`search=` 不该被当成"搜空串"（那是"没有过滤条件"）
setHash("#dex=1&search=");
check("空串参数按缺失处理", () => {
  assert.equal(readDexUrl().search, null);
});

// ── 写回：设置、编码、并**保留别人的参数**（启动时 hash 里可能还有 token）
setHash("#token=abc");
replaceCalls = 0;
writeDexUrl({
  member: "classes.dex",
  descriptor: "Lcom/example/Foo;",
  method: null,
  search: null,
});
check("写回：设置状态、保留 token、按 URL 规则编码", () => {
  assert.equal(
    window.location.hash,
    "#token=abc&dex=1&member=classes.dex&class=Lcom%2Fexample%2FFoo%3B",
  );
  assert.equal(replaceCalls, 1, "应当写了一次 URL");
});

// ── 往返：写进去的状态读回来必须一模一样（类名与方法标识里全是特殊字符）
check("往返：写进去再读回来完全一致", () => {
  const state = {
    member: "classes3.dex",
    descriptor: "L_COROUTINE/ArtificialStackFrames;",
    method: "L_COROUTINE/ArtificialStackFrames;-><init>()V",
    search: "L_COROUTINE/",
  };
  writeDexUrl(state);
  const back = readDexUrl();
  assert.equal(back.member, state.member);
  assert.equal(back.descriptor, state.descriptor);
  assert.equal(back.method, state.method);
  assert.equal(back.search, state.search);
  assert.equal(back.active, true);
});

// ── 清空：`null` 要**删掉键**，不能留下 `class=` 这种空参数（读回来会是空串）
check("清空：null 删键，标记保留（这条 hash 仍然属于 DEX 视图）", () => {
  writeDexUrl({ member: null, descriptor: null, method: null, search: null });
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  assert.equal(params.has("member"), false);
  assert.equal(params.has("class"), false);
  assert.equal(params.has("method"), false);
  assert.equal(params.has("search"), false);
  assert.equal(params.get("dex"), "1");
});

// ── 状态没变就不碰 URL：否则每次渲染都是一次 history 操作
check("状态没变时不写 URL", () => {
  replaceCalls = 0;
  writeDexUrl({ member: null, descriptor: null, method: null, search: null });
  assert.equal(replaceCalls, 0, "没有变化就不应该调用 replaceState");
});

// ── 订阅：粘贴一条链接时要能收到通知，并且取消订阅后不再收到
setHash("#dex=1&member=classes.dex");
check("订阅 hashchange：能收到、能取消", () => {
  let hits = 0;
  const off = subscribeDexHash(() => {
    hits += 1;
  });
  assert.equal(listeners.has("hashchange"), true, "应当注册了 hashchange");
  listeners.get("hashchange")();
  assert.equal(hits, 1);
  off();
  assert.equal(listeners.has("hashchange"), false, "取消后不该残留监听");
});

// ── 反例：`active` 不能只靠"有 member"判断（没有标记就不是 DEX 视图的状态）
setHash("#member=classes.dex");
check("没有 dex=1 标记时不算激活", () => {
  assert.equal(readDexUrl().active, false);
  assert.equal(readDexUrl().member, "classes.dex");
});

if (process.exitCode === 1) {
  console.log("DEX URL 状态检查失败");
} else {
  console.log("DEX URL 状态检查通过");
}
