#!/usr/bin/env python3
"""检查 sandbox 策略文件（SBPL）的两个"会静默出错"的性质。

# 为什么需要这个脚本

一份 .sb 策略文件写错时有两种失败方式，而它们的表现完全不同：

1. **语法错** —— macOS 拒绝加载**整个**沙箱。这个还算好：报错直接指向行号。
2. **语法对但谓词写错** —— 沙箱加载成功，某条 `(subpath "/wrong/path")`
   匹配不到任何东西。**它不报错**，只是"什么都没被授权"，于是工具在别处
   报一个指向无关地方的权限错。测一条恒过的策略和一版正确的策略，在正常使用中
   表现完全一样，所以这种错可以一直留在仓库里。

本仓库在 Windows 上开发，**没有 macOS 可以验证这份策略**。所以这里守的是
"能在没有 macOS 的情况下检查的部分"：

* 括号配对（去掉 `;;` 注释之后）—— 捕获第 1 类错；
* 占位符是否还有残留（`__REPO__` / `__TMP__` / `__HOME__`）—— 捕获第 2 类错里
  最常见的一种：带着占位符就用，于是 subpath 指向一个字面上叫 `__REPO__`
  的路径，什么都匹配不到；
* 每条 `(allow file-write* ...)` 的子路径里不能出现明显过宽的目标（`/`、`/Users`、
  `/private`）—— 这些是"看起来收窄了、实际等于全放开"的写法。

**它检查不了**：谓词是否真的匹配到预期位置（需要 macOS）、策略是否真的在拦
（需要负向验证，见文件末尾 §验证）。这两条在脚本输出里会明确说"未检查"，
不会让人误以为绿了就是全对了。

用法：
    python scripts/check-sandbox-profile.py docs/macos-macho-fixture.sb.in
    python scripts/check-sandbox-profile.py docs/macos-macho-fixture.sb.in --allow-placeholders
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Windows 控制台的默认编码不是 UTF-8，中文输出会变乱码（本仓库踩过）。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass

PLACEHOLDER = re.compile(r"__[A-Z]+__")

# 这些子路径出现在 `file-write*` 里就等于没有收窄。
TOO_BROAD_FOR_WRITE = {
    "/",
    "/Users",
    "/home",
    "/private",
    "/var",
    "/tmp",
    "/Library",
    "/Applications",
    "/System",
    "/usr",
}


def strip_comment(line: str) -> str:
    """去掉 SBPL 的 `;` 注释。

    只处理行注释：本文件里没有 `;` 出现在字符串字面量中的情况，
    真出现了也不影响括号计数（那种字符是 `;`，不是括号）。
    """
    index = line.find(";")
    return line if index < 0 else line[:index]


def check(path: Path, require_placeholders: bool) -> tuple[list[str], list[str], int]:
    """返回 (错误, 未检查项, 规则条数)。"""
    errors: list[str] = []
    unchecked: list[str] = []
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    # --- 1. 括号配对（去掉注释后）------------------------------------------
    depth = 0
    rules = 0
    for number, raw in enumerate(lines, start=1):
        code = strip_comment(raw)
        for ch in code:
            if ch == "(":
                depth += 1
                if depth == 1:
                    rules += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    errors.append(f"{path.name}:{number}: 右括号多于左括号")
                    depth = 0
    if depth != 0:
        errors.append(f"{path.name}: 括号不配对（结束时差 {depth} 个）")

    # 顶层规则必须以 `(` 开头且整行结束于同一层。上面按"进入第 1 层"计数，
    # 所以 `(version 1)` 与 `(allow ...)` 都算一条。
    if rules == 0:
        errors.append(f"{path.name}: 没有解析出任何规则")

    # --- 2. 占位符 ---------------------------------------------------------
    for number, raw in enumerate(lines, start=1):
        code = strip_comment(raw)
        for match in PLACEHOLDER.finditer(code):
            if require_placeholders:
                continue
            errors.append(
                f"{path.name}:{number}: 还剩占位符 {match.group(0)} —— "
                f"带着它跑等于 subpath 指向一个不存在的路径，不会报错，只会什么都不授权"
            )
    if require_placeholders and not PLACEHOLDER.search(text):
        unchecked.append(
            "指定了 --allow-placeholders，但没有找到任何占位符："
            "确认这是刻意的（写死路径的版本在换机器时会静默指向错位置）"
        )

    # --- 3. file-write* 的范围 ---------------------------------------------
    for number, raw in enumerate(lines, start=1):
        code = strip_comment(raw)
        if "file-write*" not in code or "deny" in code:
            continue
        for target in re.findall(r'\((?:subpath|regex|literal)\s+"([^"]+)"\)', code):
            if target in TOO_BROAD_FOR_WRITE:
                errors.append(
                    f"{path.name}:{number}: file-write* 授权了 {target!r} —— "
                    f"这等于全放开，写权限是这份策略里唯一会实际破坏东西的一项"
                )

    # --- 明确声明没检查的部分 ----------------------------------------------
    unchecked.append(
        "谓词是否真的匹配到预期位置（需要 macOS 的 sandbox-exec 实跑）"
    )
    unchecked.append(
        "策略是否真的在拦（需要负向验证：写仓库外应当失败、写仓库内应当成功）"
    )
    if not sys.platform.startswith("darwin"):
        unchecked.append(
            f"当前平台是 {sys.platform}，不是 macOS：本次只做了静态检查"
        )

    return errors, unchecked, rules


def main() -> int:
    parser = argparse.ArgumentParser(description="检查 SBPL 沙箱策略的静态性质")
    parser.add_argument("profile", type=Path, help="策略文件路径（.sb / .sb.in）")
    parser.add_argument(
        "--allow-placeholders",
        action="store_true",
        help="允许残留 __XXX__ 占位符（模板文件用）",
    )
    args = parser.parse_args()

    if not args.profile.exists():
        print(f"找不到策略文件：{args.profile}", file=sys.stderr)
        return 1

    errors, unchecked, rules = check(args.profile, args.allow_placeholders)

    print(f"检查 {args.profile}：解析出 {rules} 条规则")
    if errors:
        print("")
        for error in errors:
            print(f"  错误  {error}")
    print("")
    print("未检查（本脚本查不了，需要在 macOS 上做）：")
    for item in unchecked:
        print(f"  - {item}")

    if errors:
        print("")
        print(f"检查失败：{len(errors)} 项")
        return 1

    print("")
    print("静态检查通过。**这不等于策略正确** —— 见上面的未检查项。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
