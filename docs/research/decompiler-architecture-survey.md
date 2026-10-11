# 反编译器架构与实现路径调研 / Decompiler Architecture Survey

> 面向 BitFlip 的反编译器决策调研。工程视角，非市场宣传。
> 所有结论附 URL 出处；**推断/不确定处显式标注** `[推断]` / `[不确定]`。

---

## 0. 给决策者的三十秒摘要

| 问题 | 结论 |
|---|---|
| 经典流水线有几个阶段？ | Ghidra 官方文档给出 **15 步**（step0–step14），其中 step5 是一个内含 6 个子 pass 的「主化简循环」 |
| 最难的部分？ | 控制流结构化（structuring）。**30 年未解**，2024 年仍是活跃论文主题 |
| 现成可嵌入的？ | **`koute/ghidra-decompiler`** —— Ghidra 反编译器 C++ 核心的**纯 Rust 移植**，Apache-2.0，零 C/C++/Java 依赖 |
| 工作量量级？ | RetDec ≈ 14.4 MB C++；Snowman ≈ 1.6 MB C++；Ghidra 反编译器核心移植到 Rust 后 ≈ **6.1 MB** Rust |
| 「80% 方案」存在吗？ | 不存在干净的 80%。实测：最好的反编译器+LLM 组合只有 **22.3% 程序级行为重合、1.2% 精确 stdout 匹配** |
| 对 BitFlip「说的就是真的」的建议 | 见 §8 与 §9。**若做，必须做成「可验证的局部」，而非「看起来完整的整体」** |

**对既有决策门的意见**：现有「默认不做」的判断在方向上是对的，但理由可以更精确——
真正的问题不是「工作量是其他所有东西的好几倍」（这是对的），
而是**反编译器的输出天然是一种「猜测」，与 BitFlip「说的就是真的」的立身之本存在结构性冲突**。
仓库 `CLAUDE.md` §7 明令禁止「用假名冒充识别结果」、「拿不到就说拿不到」——
这两条恰恰是**所有**反编译器的默认行为（`var_1`、`a1`、`int64_t` 兜底）。
因此 §8 的结论比 §5 的工作量估算更重要。

---

## 1. 经典流水线阶段

### 1.1 权威来源：Ghidra 自己的 15 步工作流

Ghidra 反编译器文档（`docmain.hh`，源码内嵌 Doxygen 主页）列出了**完整的 15 步流程**，
这是目前最详细的一手工程描述，也是本报告的主干：

来源：<https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/docmain.hh>

| 步 | 名称 | 要点 |
|---|---|---|
| step0 | Specify Entry Point | 用户指定函数起始地址 |
| step1 | **Generate Raw P-code** | SLEIGH 把机器码翻成 p-code；沿控制流追踪直至无新指令；处理 PIC 构造、内联函数 |
| step2 | **Generate Basic Blocks and the CFG** | **在 p-code 上**（不是机器指令上）切基本块；规范化出唯一入口块 |
| step3 | Inspect Sub-functions | 查数据库恢复参数信息；间接调用改直接调用；无原型者设默认原型 |
| step4 | Adjust/Annotate P-code | 注入已知内存初值、调用点额外 p-code、`INDIRECT` 表示未知栈指针变化、补充 call 的输入/输出、调整 `RETURN` |
| **step5** | **The Main Simplification Loop** | 见下 |
| step6 | Perform Final P-code Transformations | 为可读性做变换（如把补码加法还原成减法） |
| step7 | **Exit SSA Form and Merge Low-level Variables (phase 1)** | 消除 phi/indirect；合并须防「同一高层变量同时持有不同内存位置的值」（类似寄存器着色） |
| step8 | Determine Expressions and Temporary Variables | 决定哪些变量显式、哪些内联 |
| step9 | **Merge Low-level Variables (phase 2)** | 更激进的合并：copy 输入输出 → 一般算子 → 同类型变量；受寄存器着色约束 |
| step10 | Add Type Casts | 为让最终 C 语法合法 |
| step11 | Establish Function's Prototype | 按调用约定分析参数位置、定序 |
| step12 | Select Variable Names | 由符号表；**无名字则自动生成** |
| step13 | **Do Final Control Flow Structuring** | 排序组件、排序 switch case、判定哪些非结构化跳转是 break、其余插 label |
| step14 | Emit Final C Tokens | 每个 token 标注语法含义 + 关联机器指令地址（用于机器码/C 交叉高亮）；Oppen 漂亮打印算法决定换行缩进 |

**step5 的六个子 pass**（这是整个系统的核心）：

- **step5a Generate SSA Form** —— 基于支配树与支配边界（dominance frontier）的标准 phi 插入 + 重命名算法。但**有反编译特有的复杂性**：
  - 必须处理**部分重叠**的变量（如 `eax`/`ax`/`al` 别名）；
  - 必须防各种别名情况，而这些在编译器侧是显式的；
  - **算法是增量的**：许多栈引用要等主项重写跑过寄存器变量后才能解析；届时才把它们**提升为 SSA 树中的完整变量**，这常常要求**再跑 1 轮以上**才能建完 SSA 树；
  - 局部别名与跨子调用别名通过 `INDIRECT` p-code 在 SSA 结构中标注。
- **step5b Eliminate Dead Code** —— 死代码消除**至关重要**，因为大量机器指令（尤其改标志位的）对当前函数无意义。难点：不总能分清临时变量/局部/全局；编译器常把小变量（1–2 字节）映射进大寄存器，高位残留垃圾。**Ghidra 按 bit 粒度检测死代码**，以便正确截断变量。
- **step5c Propagate Local Types** —— 从指令用法推断（如浮点指令 ⇒ 浮点类型），结合头文件/用户输入，再在语法树上传播，推出相关变量类型。
- **step5d Perform Term Rewriting** —— 「**绝大多数的有意思的化简发生在这里**」。形式化方法风格的**项重写规则**长列表；每条规则匹配语法树某配置并指定编辑操作序列。目标**不是像编译器那样优化，而是化简/规范化以便人类分析师理解**。典型变换：copy propagation、常量传播、收集同类项、算子消去与代数化简、**撤销乘法/除法优化**、算子交换……
- **step5e Adjust Control Flow Graph** —— 识别不可达代码、无用分支、空基本块、冗余谓词，删边删块。
- **step5f Recover Control Flow Structure** —— 恢复 `loop` / `if-else` / `switch` 等高层控制流对象，**层级化构建整个函数控制流**；识别 `break` 等常见非结构化惯用法；**必要时用节点分裂（node-splitting）撤销编译器做的、妨碍结构化表示的流优化**。

> **对 BitFlip 的关键含义**：step5d 的「*不是优化，而是化简与规范化*」这句话点明了反编译器的本质——
> 它是一个**模式识别 + 重写系统**，其规则的完备性直接决定输出质量。这不是一个可以「先做完主干、再慢慢补规则」的模块：
> 规则集本身是数十年积累的产物。

### 1.2 统一的流水线心智模型

综合 Ghidra 的 15 步、SAILR 论文对现代反编译器的三阶段概括、以及 DeBench 论文的流程图，
可以归纳出一条**被业界共识认可的骨干**：

```
disassembly
  → lift to IR                      (§2)
  → basic blocks + CFG              (BitFlip 已有)
  → SSA construction                (§1.1 step5a)
  → data-flow analysis / 项重写      (§1.1 step5d)
  → type inference / recovery       (§4)
  → variable recovery + merging     (§1.1 step7/9)
  → control-flow structuring        (§3)  ← 最难
  → expression propagation
  → pretty-printing                 (§1.1 step14)
```

来源（三阶段概括，明确区分 CFG recovery / type inference / structuring）：
<https://yancomm.net/papers/2024%20-%20USENIX%20Security%20-%20SAILR.html>

来源（流水线图与「Further Optimization」阶段）：
<https://arxiv.org/html/2605.29490v1>

Decompilation Wiki 也确认类型恢复通常要求「良构的 CFG，通常是已 lift 的」，
且分析阶段是**两个渐进精化阶段**：变量识别 → 类型约束（且两者**迭代**进行）。
来源：<http://decompilation.wiki/fundamentals/type-recovery/overview/>

### 1.3 一个容易被低估的阶段：**表达式恢复**

step8 与 step9 说明了一件在架构选型时容易漏掉的事：
「一个变量在最终输出里是该显式声明，还是该内联成表达式」**本身就是一个独立决策**。
Ghidra 的规则：常量、输入等**必须**显式；某些变量因为**被读太多次**、
或者内联会导致另一个变量传播过远，也强制显式；剩下的标记为 implicit。
这个决策直接决定可读性，且有 `r2ghidra.maximplref` 之类的可调参数
（来源：<https://book.rada.re/arch/decompile.html>）。

---

## 2. 中间表示（IR）的实际选择与取舍

### 2.1 全景对照表

Decompilation Wiki 维护了一份很完整的分族群 IR 清单（**这是本节最有价值的单一出处**）：

来源：<http://decompilation.wiki/fundamentals/cfg-recovery/lifting>

| IR | 项目 | 备注 |
|---|---|---|
| **P-Code** | Ghidra | 配套 SLEIGH 处理器规格语言 |
| **BNIL** | Binary Ninja | **内部有 7 种 IL**：Low Level / Medium / High Level 及其 SSA 形式等 |
| **VEX** | Valgrind / angr | Valgrind 的 IR，angr 直接用 |
| **Microcode** | Hex-Rays | 注意与 Insight 的 Microcode **同名但不同物** |
| **BIL** | BAP | 另有 Core Theory |
| **REIL** | BinNavi | 经典教学用 IR |
| RREIL | Bindead | |
| ESIL | Radare | |
| Snowman IR | Snowman | |
| LowUIR | B2R2 | |
| Miasm IR | Miasm | |
| Falcon IL | Falcon | |
| GTIRB | GrammaTech | |
| DBA | BINSEC | |
| TSL | CodeSonar | |
| SSL | Jakstab | |
| VTIL | VTIL | **为二进制翻译设计**，最初用于对抗 VMProtect |
| Vine | BitBlaze | 基于 VEX |

同页还单列了 **LLVM IR 系**（RetDec、McSema/remill、rev.ng、mctoll、Dagger、fcd、Fracture、reopt、Rellume、bin2llvm、allin），
并给出一句很关键的判断：

> 「尽管许多反编译器/二进制分析平台曾尝试把 LLVM IR 作为主 IR，
> 但**这些方法的效果至今不明，因为它们既没有在工业界也没有在学术界获得大规模采用**。」

这是一个**很强的负面证据**，直接回应「能不能复用一个成熟 IR」（尤其 LLVM IR）。

### 2.2 抽象层级：BNIL 的「阶梯」是设计范本

Binary Ninja 官方文档把「多层级 IR」的设计动机讲得最清楚，值得作为选型参考：
BNIL 不是一种 IR，而是**一族协同工作的 IL，在不同抽象层提供能力**，且**是树状（tree-based）而非线性**的。

来源：<https://docs.binary.ninja/dev/bnil-overview.html>

官方给出的层级阶梯（每一层跑更多优化与分析 pass，抽象度逐级上升）：

| 层 | 内容 |
|---|---|
| **Lifted IL** | 机器指令语义到 LLIL 的直接翻译 |
| **LLIL** | 去 NOP、把标志位折进条件指令；算子与 Lifted IL 基本相同 |
| **LLIL SSA** | LLIL 的 SSA 形式 |
| **Mapped MLIL** | LLIL 到 MLIL 的翻译中间层，分析上很少直接用 |
| **MLIL** | **把寄存器与内存访问翻译成变量**，变量关联类型，用平台信息生成带类型（推断的 + 显式的）的调用点与参数，**计算数据流并传播常量** |
| **MLIL SSA** | MLIL 的 SSA 形式 |
| **HLIL** | 在 MLIL 之上加入高层控制流指令、死代码与变量 pass、其他化简/折叠；**包含 AST** |

官方还给出一个很实用的警告：**HLIL 是高度树状的，
LLIL/MLIL 用「简单遍历顶层指令」的范式要安全得多**。

> **对 BitFlip 的含义**：如果要做，BNIL 的**分层**思想比任何具体 IR 都更值得借鉴——
> 因为它允许「中层可用、高层不承诺」的渐进交付。这与 §6 的「有界子集」策略天然契合。

### 2.3 P-Code：抽象层级与「锁死」之处

P-Code 是**寄存器传输语言（RTL）**，明确「通用到足以建模多种处理器行为」，从而把不同处理器的分析放进统一框架。

来源：<https://ghidra.re/ghidra_docs/languages/html/pcoderef.html>

关键设计点：

- **地址空间（address space）**：RAM 的泛化；每个空间有名字、大小、**端序**、可选 `wordsize`。典型处理器有 `ram` 与 `register` 空间；**总有**一个 `constant` 空间；一般还有 `temporary` 空间（「无底的临时寄存器来源」）。
- **varnode**：`(地址空间, 偏移, 大小)` 三元组，**本身没有类型**。是 p-code 操作**强制**了三种类型解释之一：整数、布尔、浮点。
- **操作**：取若干 varnode 输入，可选产生**单个**输出 varnode；除伪操作外**只有输出 varnode 可被修改，无间接副作用**。
- **序列号**：`(原指令地址, 1-up 计数器)` 二元组，用于把 p-code op 关联回机器指令。
- **raw p-code vs 分析期 p-code**：`MULTIEQUAL`（phi）与 `INDIRECT` **只**在 graph 构建过程出现，不能出现在原始翻译中；`CALL`/`CALLIND`/`RETURN` 的输入输出 varnode **可能被分析过程改写**，从而不再匹配其 raw 形式。

**P-Code 锁死你的是什么**（这是本报告里最值得决策者注意的取舍）：

1. **SLEIGH 是一个完整的处理器规格 DSL**。Ghidra 有一整个子系统（官方文档用独立章节 `\subpage sleigh` 描述）来支撑它，
   且该部分「可以构建成独立的二进制翻译库」。**选用 P-Code 意味着要么实现 SLEIGH（巨大投入），要么接受 Ghidra 的处理器规格文件格式**。
2. **Constant 空间与「varnode 无类型」的设计**把类型完全推迟到分析期——
   这买到了通用性，代价是**类型信息在 IR 里没有任何落脚点**（对比 MLIL 的「变量关联类型」）。
3. `MULTIEQUAL`/`INDIRECT` 的存在说明：**P-Code 把「SSA 与别名」设计进了 IR 本身**，
   而不是当作一个可选的后续 pass。这会让「只做线性 lifting、不做 SSA」的路线变得别扭。

### 2.4 VEX：被 angr 大规模使用的对照项

angr 使用 Valgrind 的 VEX。Decompilation Wiki 给出了 VEX 输出 x86 的实例，
可直观看到**冗长程度**：一条 `mov` 被展开成多条（含 `IMark`、`PUT(rip)`、临时变量 `t*`），
且**每个 `t` 变量只被赋值一次，天然是 SSA**。

来源：<http://decompilation.wiki/fundamentals/cfg-recovery/lifting>

官方 IR 文档：<https://docs.angr.io/advanced-topics/ir>

> **含义**：VEX 的冗长是「简单、可机械化」的代价。对 BitFlip 而言，
> 从已有的 `DecodedInsn` 结构出发**做类似 VEX 的线性提升是相对可控的第一步**，
> 真正昂贵的是它之后的一切。

### 2.5 Snowman 的路线

Snowman 有自己的 IR（源码在 `src/nc/arch/x86/X86InstructionAnalyzer.cpp`），
定位是「native code to C/C++ decompiler」，x86/x86_64/ARM。

- 仓库（现存归档）：<https://github.com/ayesc9000/snowman-archive>
- 一个值得注意的事实：**原仓库已被作者抹除**，仅存第三方归档。
  见 <https://github.com/decompiler-explorer/decompiler-explorer/issues/94>（「snowman project was recently erased」，
  维护者关闭了所有 open PR）。
- 曾有「做反编译器界的 LLVM」的定位描述：
  <https://www.infoworld.com/article/2247562/snowman-seeks-to-be-llvm-for-decompilers.html>

> **含义（`[推断]`）**：Snowman 是「一个人/小团队做一个通用反编译器」的**最近的完整案例**，
> 其结局（项目被抹除、仅存归档）是一个应当纳入决策的**风险信号**，虽然公开信息不足以确定原因。

### 2.6 抽象层级的选型结论

| 层级 | 代表 | 买到什么 | 锁死什么 |
|---|---|---|---|
| 极低（RTL/无类型） | P-Code raw, VEX | 通用性、易建模新架构 | 类型无处安放；后续所有 pass 都要自己写；极易退化成一堆微操作 |
| 低 | LLIL | 与机器语义接近，便于仿真 | 仍无变量/类型概念 |
| **中（变量+类型）** | **MLIL, Microcode** | **类型可附着、数据流可算** | **需要先有变量识别与类型系统** |
| 高（含 AST/结构） | HLIL | 可直接打印 | 高度树状，API 脆弱；且结构化本身的正确性无法保证 |
| 编译器 IR | LLVM IR | 可复用海量优化器/后端 | 见下 |

**LLVM IR 作为反编译目标 IR 的具体问题**（`[推断，但有官方佐证]`）：
1. Wiki 明确指出该路线**未获大规模采用、效果不明**（上引）。
2. LLVM IR 为**编译方向的语义与不变量**设计（如 `nsw`/`nuw`、无 UB 假设、结构化 CFG 前提）。
   反编译的输入恰恰是**已丢失这些前提**的代码，回填这些前提就是一个不可判定/需猜测的过程。
3. **一个直接的反证**：RetDec 确实基于 LLVM，但它**在 limited maintenance mode**，
   且其体量（14.4 MB C++）并不比 Ghidra 那套「自研 IR」路线小。
   来源：<https://github.com/avast/retdec>（README 顶部 `Warning` 明文写 limited maintenance mode）。

---

## 3. 控制流结构化：公认最难的部分

### 3.1 为什么难：问题的形式化

SAILR 论文（2024 USENIX Security，ASU）给出了最清晰的问题陈述：

来源：<https://yancomm.net/papers/2024%20-%20USENIX%20Security%20-%20SAILR.html>

- 编译时，C 的控制流结构语义**被丢弃**，替换成简单的 jmp。
- 若编译器**只是**直译 + 拼接 jmp，结果就会**易结构化**，反编译器能产出高质量代码。
- 但现代编译器**优化并扭曲**代码结构，使结果变得 **unstructurable（不可结构化）**，
  从而阻止现有结构化算法恢复高层控制流。
- 结构化失败**表现为 goto**。

### 3.2 两大类算法

Decompilation Wiki 与 SAILR 论文都给出同样的**二分**：

**（a）Schema-based / 图模式匹配**——依据**编译器会产生的已知图模式**来构造代码。

- 只在**明确知道该子图对应某个源码结构**时才做结构化。
- 代表：Hex-Rays、Ghidra、Phoenix。
- **核心困难：未知图模式（unknown graph schemas）**。
  作者通常硬编码常见 C 控制流的图模式，
  **但编译器优化会创造新图模式，现实二进制中的图模式比能合理枚举的更多**。
  于是这些算法**必须「虚拟化」边**（删掉边、用 spurious goto 替代）以造出更多能匹配已知 schema 的子图——
  **这严重损害输出质量**。

**（b）Goto-less / 无 goto**——优先**消除所有非结构化区域**。

- 可能会先用 schema-based 方法，但**独特之处在于匹配可能不存在于源码中的结构**。
- 代表：DREAM、rev.ng（Combing）。
- **代价**：会**引入新代码或重复代码**。DREAM 在条件中**复制代码**；rev.ng **复制不完整结构中的代码**以使其匹配已知 schema。
- 依赖块条件信息来造无 goto 结构。

**两者最大差别**：**对已知编译器模式的依赖程度**（Wiki 原文）。

### 3.3 经典算法谱系

| 算法 | 出处 | 说明 |
|---|---|---|
| **Interval analysis** | Cocke 1970；Allen "Control flow analysis" 1970 | 把 CFG 划分成嵌套区间。**嵌套性保证数据流分析不重复做功** |
| **Structural analysis** | Sharir 1980, *Structural analysis: A new approach to flow analysis in optimizing compilers* | interval analysis 的扩展，允许「语法驱动」的数据流分析方法（本用于 AST）应用到低层 IR 上 |
| **Cifuentes 算法** | Cifuentes 1994 博士论文 *Reverse compilation techniques*；Cifuentes & Gough 1995 | **现代反编译器的学术基础**，基于 interval theory，实现在 dcc（80286/DOS to C） |
| **Semantics-Preserving Structural Analysis + 迭代结构化** | Schwartz et al., Phoenix, USENIX Security 2013 | 通过**迭代精化**减少 goto；结构化分析无法前进时用 goto 替换一条边 |
| **DREAM（No More Gotos）** | Yakdan et al., NDSS 2015 | **保证零 goto**，用布尔表达式与状态变量**强制排除** goto |
| **rev.ng / Control Flow Combing** | Gussoni et al., ASIA CCS 2020 | 「梳子」：通过**激进复制代码**消除 goto |
| **SAILR** | Basque et al., USENIX Security 2024 | **compiler-aware**：镜像 GCC 编译流水线，**精确反演**引入 goto 的变换 |

关键链接：
- Cifuentes 论文（PDF）：<https://www.cs.tufts.edu/~nr/cs257/archive/cristina-cifuentes/DCC_decompilation_thesis.pdf>
- Phoenix 论文（PDF）：<https://kilthub.cmu.edu/articles/Native_x86_Decompilation_using_Semantics-Preserving_Structural_Analysis_and_Iterative_Control-Flow_Structuring/6469064/files/11897618.pdf>
- DREAM 论文（PDF）：<https://www.ndss-symposium.org/wp-content/uploads/2017/09/11_4_2.pdf>
- 结构化总览：<http://decompilation.wiki/fundamentals/structuring/overview/>
- SAILR：<https://yancomm.net/papers/2024%20-%20USENIX%20Security%20-%20SAILR.html>

### 3.4 一个反直觉但极重要的结论：**「消除所有 goto」是错的**

SAILR 的核心论点（我认为这是本报告第二个最重要的发现）：

> 「与主流认知相反，我们认为**二进制反编译器成功的衡量标准不是消除所有 goto 或降低反编译代码的复杂度，
> 而是尽可能接近原始源码**。许多 goto 存在于原始源码中（**Linux kernel 6.1 含 3,754 个 goto**），
> 因此**在反编译过程中应当被保留**；只有 *spurious gotos*（伪 goto）才应被移除。」

**定量证据**（7,355 个函数 / 26 个 Debian 包）：

| 工具 | Gotos 总数 | 相对源码 | 平均 CFGED ↓ | 说明 |
|---|---|---|---|---|
| **Source（真值）** | 1,367 | — | 0 | 平均 0.19，中位 0.0 |
| **SAILR** | 2,673 | +95.5% | **22.64** | 去掉大量伪 goto 且结构未被破坏 |
| **Hex-Rays** | 6,115 | +347.3% | **22.52** | 商业标杆 |
| Ghidra | 6,575 | +380.9% | 25.5 | |
| Phoenix | 8,497 | +521.6% | 22.64 | |
| **DREAM** | **0** | −100% | **45.99** | **零 goto，但结构相似度最差（CFGED 翻倍）** |
| rev.ng | 0 | −100% | 71.29 | 最差 |

（CFGED = Control Flow Graph Edit Distance，越低越好。来源同上，Table 3。）

> **结论**：DREAM 消除了**全部** goto（含源码本来就有的），
> 结果 CFGED 从 22.52 恶化到 45.99（+104.3%）——
> **为了「好看」而牺牲了「像原代码」**。
> 而 SAILR 保留了 95.5% 的（相对增加量）goto，CFGED 仅比 Hex-Rays 差 0.5%。

（CFGED 是 GED 的近似，论文自己指出在 >200 节点的图上可能偏差极大——
曾观察到精确 GED 低至 4 而 CFGED 报 306。这也是论文的诚实之处。
另外论文坦承**剩余 goto 未清完**，原因包括：(a) 某些函数不返回但 angr 不知道，导致函数级 CFG 错误；
(b) 反编译器在多条候选边中挑错了要虚拟化的边；(c) SAILR 合并了未被 ISD 优化影响的块。）

### 3.5 理论极限：明确写在论文里的「不可判定」

SAILR 的 Discussion 章节给出了**最强的理论极限陈述**，我直接引用其实质：

> 「即使是 SAILR 完美反演了编译器引入的每一个 goto 引入优化，
> CFGED 分数**依然很高**。……第二，**CFGED 对结构差异极其敏感，
> 而反编译器做出的许多结构化选择（例如某个节点是否属于循环体）
> 在最终意义上是不可判定的（ultimately undecidable）**。
> 我们相信统计技术（如机器学习）在这些情形下会有巨大帮助。」

另有：

> 「（存在）从合法 C 源码到二进制代码的**多对一映射**（many-to-one mapping）……
> 我们相信自然解决方案是用机器学习方法，从二进制 CFG 及其上下文**预测最合适的结构化结果**。」

**这就是理论极限的准确表述**：
不是「算法还不够好」，而是**结构化目标是多对一映射的逆，
逆不唯一 ⇒ 无法确定「正确」答案，只能谈「更可能的」答案**。
任何声称「结构化问题已被解决」的说法都与这一陈述矛盾。

### 3.6 不可归约控制流（irreducible CFG）

- Wiki 把 irreducible 列为测试维度之一（DeBench 的 Control Flow 维度 45 个用例中含「irreducible loops」）。
  来源：<https://arxiv.org/html/2605.29490v1>
- Ghidra 承认需要**节点分裂（node-splitting）**来撤销妨碍结构化的编译器流优化
  （step5f，见 §1.1）——这本质上是在**修改 CFG 让它变得可结构化**。
- 实践者视角的一个补充：`pdc`（radare2 自带的伪反编译器）
  「**不实现任何控制流改进（如 switch、if/else、for/while）**，
  也不做代码优化或删除垃圾逻辑」——即它干脆**放弃结构化**，
  官方描述其输出「相当冗长嘈杂，但顺手、快」。
  来源：<https://book.rada.re/arch/decompile.html>

> **这条对 BitFlip 有实际价值**：radare2 官方**把「不结构化」作为一个正当的产品档位**，
> 并明确它「作为喂给语言模型的源」有用。
> 这是 §6「expression-only」路线存在的**官方先例**。

---

## 4. 类型恢复 / 类型推断

### 4.1 基本框架

Decompilation Wiki 的类型恢复页给出了清晰的两阶段模型：

来源：<http://decompilation.wiki/fundamentals/type-recovery/overview/>

1. **Variable Identification**：发现初始位置及其边界。
2. **Type Constraining**：利用变量在代码中的**用途**，为大小建立约束，选定类型。

> 「这个过程**经常在约束建立与变量识别之间迭代**。
> 变量识别还包括随着约束积累而**重新类型化/重新确定大小**。」

**类型汇（type sinks）**是关键概念：变量常有多个候选大小，
通常通过**具有显式类型的用途**（如调用参数）**归约到单一类型**。

Wiki 给出的完整示例很好地说明了机制（源码 `char* str = argv[1]; puts(str);`）：
- 朴素算法给出 `int main(int a1, long long a2)` + `long long v4`；
- 因为 `puts` 已知接受 `char*`，`v4` 可被约束为 `char*`；
- **反向传播**该约束 ⇒ 得到正确的 `int main(int a1, char** a2)` 与 `char *v4`。

### 4.2 主要技术路线

Wiki 列出的类型约束方法：

| 方法 | 说明 |
|---|---|
| **def-use analysis** | 经典数据流 |
| **Library awareness** | 用已知库函数签名（上例的 `puts`） |
| **Emulation** | 动态执行观察（Howard, MemPick） |
| **Lattice-solving / push-down typing** | **现代开源反编译器中最流行**的 |
| **Machine learning** | Osprey、DIRTY、VarCLR 等 |

**Lattice-based（格求解）的两个关键学术出处**：
- Lee, Avgerinos, Brumley, **TIE: Principled reverse engineering of types in binary programs**, NDSS 2011.
- Noonan, Loginov, Cok, **Polymorphic type inference for machine code**, PLDI 2016（即 retypd）。

Wiki 补充：**lattice-solving（push-down typing）在现代开源反编译器中最流行**。
另有「Constraint Simplification」专页：<http://decompilation.wiki/fundamentals/type-recovery/lattice-constraint-simp/>

**Ghidra 的实现**（step5c + step10）：
- 类型信息从指令用法推断；有些可从**头文件或用户**获得；
- 然后让初步类型信息**在语法树中传播**，从而推出其他相关变量的类型；
- 最后 step10 **加类型转换以保证 C 语法合法**——
  注意这个顺序：**先猜类型，再用 cast 把不匹配的地方强行圆回来**。

### 4.3 有调试信息时

BitFlip **已有** DWARF/PDB 支持，这是它的相对优势。需要注意：

- RetDec 明确把「Extraction and utilization of debugging information (DWARF, PDB)」列为特性：
  <https://github.com/avast/retdec>
- **但要小心一个陷阱**：DWARF 是**源码语言无关**的，
  这既是优点（能表达多种语言）也意味着**它不是「直接可用的 C 类型表」**，
  仍需要一层映射与重建。
  来源（DWARF 语言无关性）：<https://pdfs.semanticscholar.org/3f8e/8d73669cdbd06c6ffc9f768fe32c90ed9e38.pdf>
- 实践警告：有符号信息并不等于类型就对了。DeBench 的 motivating example 里
  **angr 把所有参数恢复成 `unsigned int` 而源码是 `int`**，
  导致有符号比较被**静默**变成无符号比较，**对含负数的输入域行为完全改变**——
  而**代码看起来很干净、可读性评分很高**（见 §6.2、§8）。

### 4.4 不可判定性如何被处理

**答案：不「解决」，而是用约束把不确定性收窄，再在无法收窄时给保守默认值。**

证据链：
1. **多对一映射**导致逆不唯一（SAILR，见 §3.5）——类型推断同构于此。
2. **类型汇**机制：优先用**有显式类型的用途**来定型（Wiki）。
3. 无法确定时的兜底：Ghidra step12「**若无名字则自动生成**」；
   r2ghidra 有 `r2ghidra.rawptr`：「**把未知全局显示为裸地址而不是变量**」——
   这是一个**显式的「我不知道」开关**。
   来源：<https://book.rada.re/arch/decompile.html>
4. DeBench 论文把 **"Semantic Loss Risk"** 列为难度的三个正交维度之一，原文：
   「该视角捕捉代码模式的固有歧义。某些构造（如空指针转换、union 访问）
   **在数学上是不可逆的或高度歧义的，在没有额外上下文时对反编译的正确性施加了内在上界**。」

> **这是「内在上界（intrinsic upper bound）」的官方措辞**，
> 是回答「反编译到底能不能做对」时最该引用的一句话。

---

## 5. 现实工作量估算（**决策最重要的输入**）

### 5.1 代码体量实测（我通过 GitHub API 直接读取的 `languages` 字节数）

| 项目 | 语言字节数 | 备注 |
|---|---|---|
| **RetDec** | **C++ 14,395,357** (+ YARA 4,570,488) | 另有 Python 285k。**已进入 limited maintenance mode** |
| **Snowman**（归档） | **C++ 1,638,220** | 另有 C 77k。**原仓库已被作者抹除** |
| **r2ghidra** | **C++ 330,910** + C 47,247 | 只是把 Ghidra 反编译器**接进 r2** 的胶水层 |
| **Ghidra 反编译器 → Rust 移植** | **Rust 6,125,019** vs C++ 77,445 | 见 §5.2，**这是最有信息量的一行** |
| radeco（Rust 反编译器实验） | 仓库 size 2,651 KB | 2015 起，**399 stars、91 open issues**，见 §7.3 |

获取方式示例（可复现）：
`https://api.github.com/repos/avast/retdec/languages`、
`https://api.github.com/repos/ayesc9000/snowman-archive/languages`、
`https://api.github.com/repos/radareorg/r2ghidra/languages`、
`https://api.github.com/repos/koute/ghidra-decompiler/languages`

### 5.2 最有信息量的一个数据点：Ghidra 反编译器核心的 Rust 移植

`koute/ghidra-decompiler` 自我描述：

> 「A pure Rust port of the Ghidra decompiler (Ghidra 12.2, `Ghidra/Features/Decompiler/src/decompile/cpp`).
> It has no C, C++ or Java dependencies. The output is **textually identical** to the C++ decompiler
> on the test corpora in `tests/data`.」
> **顶部有一行 DISCLAIMER：「This was automatically ported by an agent from Ghidra's C++ source code into Rust.」**

来源：<https://github.com/koute/ghidra-decompiler>

它的 GitHub `languages` 统计是 **Rust 6,125,019 字节 / C++ 77,445 字节**
（来源：`https://api.github.com/repos/koute/ghidra-decompiler/languages`）。

> **这 ~79× 的比例是有意义的**（`[推断]` 具体倍率受行/字节与代码风格影响，
> 但数量级方向可靠）：Ghidra 的反编译器核心（`decompile/cpp`，即你实际要写的那部分，
> **不包括** SLEIGH 规格、Java 前端、GUI）在移植到 Rust 后是**数百万字节量级**。
> 即便认为其中有自动移植的冗余，也**足以说明这不是「几个人月」的工程**。

其测试规模也间接说明了正确性验证的成本：
- `datatests`：**89 个** C++ 反编译器数据测试（**733 checks**）
- `decomp_corpus`：**1,222 个函数**、来自 **20 个 ELF 二进制**（x86-64, i686, ARM, Thumb, AArch64, MIPS BE/LE, PowerPC, RISC-V 32/64，各 `-O0` 与 `-O2`）
- `sleigh_corpus`：每个 language id 的反汇编与 raw p-code
- 另有 **differential fuzzing** 的 CI job

其规模控制手段值得注意：
「嵌入的 `.sla` 文件保留 Ghidra 的 `.sla` 头部，但**载荷改用 xz 而非 zlib**，
以让 crate 保持在 crates.io 体积上限内」——**即为了塞进 crates.io 都要专门做压缩取舍**。

### 5.3 Hex-Rays 的时间尺度

- IDA：**1990 年秋**产生想法，**1991 年 1 月**写下第一行代码，**1991 年 4 月**第一个程序被完整反汇编。
  1994 年 Ilfak 自述时「IDA 是 C++ 写的，约 **40,000 行**」。
  来源（Hex-Rays 官方 30 周年博客，含历史文件原文引用）：
  <https://hex-rays.com/blog/ida-celebrating-30-years-of-binary-analysis-innovation>
- **2005 年** Guilfanov 创立 Hex-Rays 公司以推进 Hex-Rays Decompiler。
  Hex-Rays 公司页：「Our history began in the 1990s with Ilfak Guilfanov's first multi-architecture binary
  disassembler. In 2005, he co-found…」<https://hex-rays.com/about-us>
- **2008 年 1 月**：Hex-Rays Decompiler 发布（首个商业反编译器）。
  来源（Hex-Rays 官方 30 周年博客时间线：「By 2008, the first commercial decompiler has been released」）
- **2009 年 10 月**的官方博客说「Hex-Rays Decompiler 1.0 发布**两年多**了」，
  可反推 1.0 ≈ 2007：<https://hex-rays.com/blog/hex-rays-decompiler-primer>（`[不确定]`：与「2008 年 1 月」的表述略有出入，
  可能是 beta/正式发布的差异；两个来源均为 Hex-Rays 官方）
- 但更重要的是**起点不是 2005 年**：反编译器建立在 IDA 的**分析引擎**之上，
  而后者自 1991 年就在积累。**净投入远超「2005→2008 的 3 年」。**

### 5.4 其他难度自述

- **SAILR 论文**（ASU，2024）自述其贡献之一是需要**为 angr 重建一个反编译器**，
  因为「现有结构化技术**要么未开源，要么已腐烂（bit-rotted）**，
  阻碍了该领域的研究」——他们不得不**重新实现** Phoenix、DREAM 与 rev.ng 的 Combing。
  来源：<https://yancomm.net/papers/2024%20-%20USENIX%20Security%20-%20SAILR.html>
- **RetDec** 现在的状态：README 顶部 Warning 写明 **limited maintenance mode due to a lack of resources**。
  来源：<https://github.com/avast/retdec>
- **snowman**：原仓库被作者抹除。
  来源：<https://github.com/decompiler-explorer/decompiler-explorer/issues/94>
- **Ghidra 自身的工程警告**（文档开头）：
  > 「尽管有这些相似之处，**反编译器与编译器的差异是实质性的，并贯穿整个过程**。
  > 这些差异都源于：通常，描述性要素与代码的更高层组织**只能**在高阶语言中被显式表达。
  > 所以反编译器，以低阶语言为输入，**只能推断**这些信息。」
  >
  > 并单列了**在编译器中没有任何真正对应物**的任务：
  > **变量合并**（与寄存器着色勉强相关）、**类型传播**、**控制流结构化**、
  > **函数原型恢复**、**表达式恢复**。
  来源：<https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/docmain.hh>

### 5.5 一个额外的「难度信号」：人本身有多难

DeBench 论文引用的用户研究（RE-Mind，USENIX Security 2022；Decomperson，USENIX Security 2022）
说明该领域已把「人类如何反编译」作为独立研究对象——
这从侧面反映**「输出是否可理解」不是随便能糊弄过去的指标**。
来源（引用见 SAILR 论文参考文献 [11][31]）：<https://yancomm.net/papers/2024%20-%20USENIX%20Security%20-%20SAILR.html>

### 5.6 工作量估算汇总（给决策用）

| 路线 | 现实体量 | 时间尺度（`[推断]`） |
|---|---|---|
| **从零做一个 Hex-Rays 级反编译器** | 数百万字节级别源码；数十年积累 | **不可行** |
| **从零做一个「能用」的 schema-based 反编译器** | 参考 Snowman 的 1.6 MB C++（但那是 2014 年水平、且项目已死） | **数人年**，且终点可能不如 2014 年的 Snowman |
| **嵌入式复用 Ghidra 反编译器** | 0 行自研核心逻辑，但要集成 | **数周–数月**（取决于 FFI/移植方式），见 §7 |
| **只做「单基本块表达式恢复」** | 可控 | **数周–数月**，但见 §6.3 的价值质疑 |

---

## 6. 有界子集能做到什么？（「80% 方案」评估）

### 6.1 先给出质量天花板

DeBench 论文（Ant Group / 清华 / 西电，2026）是目前**最新的、多维度的量化评测**。
其核心发现（我逐条引用其摘要）：

来源：<https://arxiv.org/html/2605.29490v1>

1. **「reusability cliff（可复用性悬崖）陡峭且可复现」**：
   **最好的反编译器–LLM 组合达到 22.3% 的 Exact+Partial 程序级行为重合，
   但只有 1.2% 的精确 stdout 匹配**——相对可编译性有**约 50 个百分点的悬崖**。
2. **「最大化可读性的编译选择不是最大化功能性的选择」**：
   激进 `-O3` 可读性最低但功能性最高；Clang 可读性低于 GCC 但**功能性高 2.6×**。
3. **「反编译器 vs LLM 的差距是不对称的」**：
   **跨反编译器的功能级波动（20×）远超跨 LLM 的波动（1.6×）**，
   所以**工程投入应针对反编译器引擎，而不是更大的修复模型**。
4. **失败分为三类，可修复性不同**：
   语法噪声（可修复）、**类型系统崩溃（约占所有修复错误的 19%，且是主导的非语法成本）**、
   以及**不可逆的上游损失（ARM64 重定位惯用法、C++ ABI 特性）——没有任何修复 LLM 能补偿**。

另外该论文的 motivating example（**极其贴合 BitFlip 的处境**）：

> **angr：可读但语义错误。** 输出视觉上干净，恢复了紧凑规则的 if-else if 链，
> 但**所有参数被恢复为 `unsigned int` 而非 `int`**，
> 导致有符号比较**被静默地转成无符号比较**；对含负值输入的行为**根本改变**。
> 换句话说，**代码看起来合理，但逻辑已不等价于源码**。
>
> **Ghidra：不可读但语义忠实。** 结构明显更难读（引入辅助变量、条件里带副作用的逗号表达式、
> 用布尔算术 `return (0 < e) + 4` 编码分支）。然而对齐后，**它正确保留了原语义，包括负数输入**。
>
> **含义：可读性与语义忠实度可以严重背离。看似精炼的输出可能语义错误；
> 看似丑陋的输出可能行为正确。而且即使反编译代码能被修复并重编译，
> 可编译性本身仍不保证语义正确。**

**这是对「80% 方案」最有力的否定证据**，因为 angr 的失败模式**恰恰就是 BitFlip 立身之本所禁止的那类**。

### 6.2 逐个子集评估

#### (a) Structure-only 恢复（if/while/for，无类型，变量全是 `int64_t` / `var_1`）

- **技术上**：这是**唯一**在理论上可达成的子集，因为结构化**只需要 CFG + 条件**，
  不需要类型系统。Wiki 明确：「控制流结构化需要**一个控制流图与条件**」。
  来源：<http://decompilation.wiki/fundamentals/structuring/overview/>
- **质量天花板**：**受 §3.5 的不可判定性直接限制**。
  你能做到的最好情况大致是「Hex-Rays 减掉类型推断」，
  即在 7,355 函数样本上产出 ~6,000 个 goto（源码只有 1,367 个）。
  **即：一个纯结构化反编译器，输出里会有约为源码 4 倍数量的 goto。**
  （数据推算自 SAILR Table 3 的 Hex-Rays 列，`[推断]`：Hex-Rays 的 goto 数不能全归因于缺类型，
  但类型缺失会显著影响条件表达，进而影响模式匹配成功率。）
- **何时变得误导**：**当 `var_1` 的分组与真实变量不一致时**。
  Ghidra 的 step9 明确说「即便 phase 1 合并后，变量数通常仍**远多于**正常 C 代码」，
  所以才要做**更投机的**合并。若不做这一步，读代码的人会以为 `var_1` 和 `var_2` 是两个东西，
  而它们其实是同一个。**这是「看起来对但读错了」的典型场景。**
- **另一个误导源**：**有符号 vs 无符号**。§4.3 的 angr 案例证明，
  仅这一项就能让含负数的分支完全错误，而代码**看起来完全正常**。

#### (b) Expression-only 单基本块反编译（一次一块，不结构化）

- **有官方先例**：radare2 的 `pdc`
  「**不实现任何控制流改进（如 switch、if/else、for/while）**，
  也不做代码优化或删除垃圾逻辑」，
  官方评价是「相当冗长嘈杂，但**顺手、快**」，
  并明确指出它「**作为喂给语言模型的源**」有用。
  来源：<https://book.rada.re/arch/decompile.html>
- **质量天花板**：单块内是**确定的**（无控制流歧义），
  所以**这一档的「说的是真的」属性最强**——这是它相对于其他子集的**决定性优势**。
  但它有一个真实的功能上限：**块间关系完全不表达**，读者必须自己回到 CFG 视图。
- **何时变得误导**：当用户以为这是「反编译结果」而不是「单块表达式视图」时。
  **命名与 UI 呈现是这一档成败的关键**。

#### (c) 有调试信息时做类型恢复，但不做推断

- **这是投入产出比最高的子集**，理由：当 DWARF/PDB 存在时，类型**不是猜的，是读的**，
  因此完全符合 BitFlip §7「不用假名冒充识别结果」。
- **质量天花板**：受**调试信息本身的完整性**限制。即便有 DWARF，
  也存在（i）被 strip 的情况，（ii）优化后变量被消除/合并导致 DWARF 位置表达式无法解析，
  （iii）不像 C 类型表那样直接可用（语言无关，见 §4.3）。
- **诚实做法**：**明确标注「类型来自 DWARF」还是「推断」**（见 §8）。
  这样即使退化到推断，用户也知道自己在看什么。

#### (d) 伪代码作为辅助而非可编译产物

- **这是唯一与「说的就是真的」可能兼容的定位**，但**前提是显式的降级披露**。
- **必须有**：明确告诉用户「这是**推断**，不是**识别**」，
  且**推断结果不可作为可编译代码使用**。
- **量化依据**：DeBench 的 1.2% 精确 stdout 匹配率说明——
  **任何暗示「这可以拿去编译运行」的产品承诺都是不诚实的**。
  即便加上 50 轮 LLM 修复，程序级期望行为重合也只有 22.3%。
- 反过来说，**`pdc` 作为「喂 LLM 的源」的用法**（官方定位）
  是一个**诚实的、有明确边界**的用途，值得借鉴。

### 6.3 「80% 方案」的总判断

**不存在干净的「80% 反编译器」。** 原因：

1. **反编译器的质量不是线性叠加的**。SAILR 的 Discussion 指出，
   即便**完美地**反演了每一个 goto 引入优化，CFGED 依然很高——
   因为这些选择「在最终意义上是不可判定的」（§3.5）。
2. **各部分高度耦合**：Ghidra 的 step5a 明说「SSA 是**增量**的，
   许多栈引用要等主项重写跑过寄存器变量之后才能解析，
   届时才提升为完整变量，**这常常要求再跑 1 轮以上**」——
   即你不能「先做 lift 就交付」，各 pass 互为输入。
3. **最危险的失败模式恰好在「80%」处**：DeBench 的 angr 案例说明
   **好看的输出 + 错误的类型 = 静默错误**。这不是「80% 正确」，
   而是**「80% 正确 + 隐藏的 20% 错误」**，比明显不可用更危险。

**真正可行的「有界」形态不是「做 80% 的反编译器」，
而是「做 100% 可靠的、范围明确更小的功能」**——见 §8 与 §9。

---

## 7. Rust 生态选项

### 7.1 【最重要】`koute/ghidra-decompiler` —— Ghidra 反编译器的纯 Rust 移植

**这是本节的决定性发现。**

来源：<https://github.com/koute/ghidra-decompiler>
（我另外直接读取了其 GitHub API 元数据与 README/Cargo.toml）

| 维度 | 实测值 | 出处 |
|---|---|---|
| 描述 | Pure Rust port of the Ghidra decompiler (Ghidra 12.2, `decompile/cpp`) | README |
| **依赖** | **无 C / C++ / Java 依赖** | README |
| **许可** | **Apache-2.0**（与 Ghidra 一致） | 仓库 API `license` 字段 + README |
| 语言构成 | **Rust 6,125,019** / C++ 77,445 / Python 61,603 / C 17,602 | `.../languages` |
| 输出保真 | 「**textually identical** to the C++ decompiler on 测试语料」 | README |
| edition / MSRV | edition 2024, **rust-version 1.88** | Cargo.toml |
| 体积 | 仓库 ~20.9 MB | 仓库 API `size` |
| 创建时间 | 2026-09-25（`[注意]` 该项目很新） | 仓库 API `created_at` |
| 星标 | 6（`[警告]` 极低，几乎没有社区验证） | 仓库 API |
| **免责声明** | **「DISCLAIMER: This was automatically ported by an agent from Ghidra's C++ source code into Rust.」** | README 首行 |

**依赖清单（极少，对嵌入极友好）**：
`cpp_demangle`(optional)、`lzma-rs`、`miniz_oxide`、`object 0.37`(read_core/std/elf/pe/macho/unaligned)、
`regex`、`rustc-demangle`(optional)。**没有 LLVM、没有 libclang、没有 C 运行时。**

**架构覆盖**：default features 为 `x86, arm, aarch64, mips, powerpc, riscv`
——**与 BitFlip 现有 capstone 支持的架构几乎完全重合**（x86/x64, ARM64, ARM/Thumb, RISC-V, MIPS），
且额外有 powerpc；`all-processors` feature 覆盖 39 个处理器。

**API 形态**（README 示例，从二进制到 C 只需几行）：
```rust
let mut program = Program::open(Path::new("a.out"), None)?;
let main = program.functions()?.into_iter().find(|f| f.name == "main").expect("no main");
let instructions = program.disassemble(main.address, 4)?;
let pcode = program.pcode(main.address, 1)?;
let c_code = program.decompile(main.address)?;
let edges = program.call_graph()?;
```

**测试规模**：`datatests`（89 个 C++ 数据测试 / 733 checks）、
`decomp_corpus`（1,222 函数 / 20 个 ELF 二进制，覆盖 x86-64, i686, ARM, Thumb, AArch64, MIPS BE/LE, PowerPC, RISC-V 32/64，各 `-O0`/`-O2`）、
`sleigh_corpus`、以及各模块的差分测试与 **differential fuzzing** CI job。

**它还修了上游 bug**（说明是认真的移植而非玩具）：
operand handle 数据残留、>16 字节指令越界读、raw p-code 写 constant 空间、
重复 action group 死循环（改为 100 次后报 `Exceeded maximum repeat count for action <name>`）、
CSE 自身匹配导致规则永远报「有变化」、符号查找越界、
Heritage 删除无读者的 free join varnode 等。

**风险（必须诚实指出）**：
1. **星标 6、创建于 2025 年 9 月、单人项目**——**没有任何社区验证**。
2. **README 自述「由 agent 自动移植」**——意味着可能包含大量机械翻译的冗余代码，
   可维护性未知（6.1 MB Rust 对 77 KB C++ 的来源差异也暗示这一点）。
3. 无 license 之外的支持承诺。
4. **`[不确定]`**：我**没有**实际编译或运行该项目，无法验证其 README 声称的「输出与 C++ 版本逐字相同」。

**结论**：这是目前**唯一**同时满足「Rust 原生 / 许可宽松 / 无重型 FFI / 覆盖 BitFlip 架构」的选项。
但它**新到需要先做一次可信度验证（spike）**才能纳入决策——见 §9。

### 7.2 其他 Rust 反编译/提升相关项目

| 项目 | 说明 | 关键事实 |
|---|---|---|
| **`rsleigh`**（含 `pcode-ir`, `rsleigh-generate`） | 「pure-Rust **SLEIGH**-driven multi-arch decoder/lifter，带实验性反编译器与恶意软件分析启发式」 | **从 Ghidra SLEIGH 规格在 Rust 中解码并 lift 到 P-code** |
| **`pcode`** crate | 「实现 SLEIGH 的 binary lifter」 | 同上族 |
| **`libsla`** | **Rust 绑定到 Ghidra 的 SLEIGH 库 `libsla`** | 这是 **FFI 绑定**，会引入 C++ |
| **`r2smt-pcode`** | r2SMT 用的 Ghidra/SLEIGH P-code lifter | 通过 r2ghidra 的 `pd` 输出 p-code |
| **`r2sleigh`** | radare2 插件：把 Ghidra P-code 规格编译成 r2il | 也是 SLEIGH 路线 |
| **`retdec`** (crates.io) | ⚠️ **只是个 REST API 客户端！** | 「providing easy access to the **retdec.com decompilation service** through their public REST API」——**不是本地反编译器** |
| **`decomp`** | 「The decomp project 的 Rust 重实现」 | 依赖 `llvm-ir ^0.11.1` |
| **radeco** | radare2 的 Rust 反编译器框架 | 见下 |

来源：
<https://lib.rs/crates/pcode-ir>、<https://docs.rs/libsla>、
<https://github.com/ShaneBreazeale/rsleigh>、<https://lib.rs/crates/rsleigh>、
<https://lib.rs/crates/r2smt-pcode>、<https://github.com/radareorg/r2sleigh>、
<https://docs.rs/retdec/latest/retdec/>、<https://crates.io/crates/decomp>

> ⚠️ **重要提醒**：如果 BitFlip 想「用 crate 一把梭」，**`retdec` crate 是一个陷阱**——
> 名字看起来对，实际是**远程服务客户端**（会把二进制发给 retdec.com），
> 对本地逆向工具是**不可接受的**（数据外泄）。

### 7.3 radeco：Rust 反编译器的**失败案例研究**

radeco 是 radare 团队的 Rust 反编译器框架，**2015 年**借 GSoC 启动。

来源：
- 仓库：<https://github.com/radareorg/radeco>（**2015-05-17 创建，399 stars，51 forks，
  open issues 91，无 license**；最后一次 push 2026-05，但见下）
- 2015-09 进度报告：<https://radareorg.github.io/blog/posts/update-on-radeco/>
- 2018 GSoC「Radeco 伪 C 代码生成」：<https://radareorg.github.io/blog/posts/gsoc_2018_radeco_pseudo_c_code_generation/>
- 2018 GSoC 控制流结构化：<https://radareorg.github.io/blog/posts/gsoc_2018_radeco_cfs/>
- 2018 GSoC 类型推断：<https://radareorg.github.io/blog/posts/type_inference/>

**从官方博客可提取的时间线（这是最有价值的部分）**：

- **2015 年 9 月**后的状态：「radeco 处于**重度开发中，距离成为完整反编译器框架还有很长的路**」，
  且**未来步骤**清单里赫然写着：类型推断、类型传播、更多分析、
  「**一个完整的 C-Writer 模块以输出可读的 C 类伪代码**」、
  「**控制流结构化与重建**」（来源：2015-09 报告）。
  → **即到那时，反编译器的「输出」与「结构化」两个核心模块都还没开始。**
- **2018 年**（3 年后）：GSoC 才分别做「伪 C 代码生成」与「控制流结构化」与「类型推断」。
- radare2 官方书籍现在把 radeco 描述为
  「**experimental and abandoned**（实验性且已废弃）的基于 esil 的反编译器」。
  来源：<https://book.rada.re/arch/decompile.html>
- **官方书籍中的 pdc 对比表述**进一步佐证：`pdc`（不做任何控制流改进）
  是**默认随 radare2 发布的**，而 radeco 已废弃。

**radeco 的技术自述也很有参考价值**（说明「IR 选型」的实际困难）：
- 他们**评估过 REIL、RREIL、Vine IL、BAP IL**，试图融合各家优点；
- 选 ESIL 作为提升源（因为 r2 已支持很多架构，避免为每个架构重写 lifter），
  **但明确说「ESIL 并不真正适合静态分析，它是为仿真与动态分析造的」**；
- **挑战之一是「为存储 SSA 形式设计内部表示」**，
  因为 ESIL 有内部变量（`$` 前缀）用于按需计算标志位，
  解析器必须跟踪 `cur` / `old` / `lastsz` 并替换成正确算子序列；
- 另一个挑战是**架构性的**：为了可复用性「几乎所有东西都用 trait 实现」，
  **代价是「灵活性 vs 时间」的权衡**，最后不得不「限制自己」。

> **对本项目的直接教训**：radeco 是**「用 Rust 从零做反编译器」的最接近的先例**，
> 投入了 **4 年以上**（2015→2018+ 多个 GSoC）、有组织支持、**最终被官方标记为 abandoned**。
> 在 radare2 的对比框架里，它的位置被「不做结构化的 pdc」取代。

### 7.4 嵌入性分析（许可 / 体积 / FFI 复杂度 / 运行时）

| 选项 | 许可 | 体积 | FFI 复杂度 | 语言运行时 | 可行性 |
|---|---|---|---|---|---|
| **`koute/ghidra-decompiler`** | **Apache-2.0** | 仓库 ~21 MB（可裁 feature） | **零 FFI**（纯 Rust） | 无 | ✅ **最佳**（待验证） |
| **Ghidra `libdecompiler`**（C++ 静态库） | Apache-2.0 | 大 | **高**：须自建 C ABI 包装层 | C++ 运行时 | ⚠️ 可行但重 |
| **r2ghidra** | 见仓库 | C++ 330 KB + C 47 KB（**仅胶水层**） | 中 | C++ | ⚠️ 它是 r2 插件，不面向嵌入 |
| **RetDec**（C++ 库） | **MIT** | **C++ 14.4 MB** + 用户需 ~5–6 GB 磁盘 | 高 | C++ / LLVM | ❌ 体积与依赖不可接受；且 maintenance mode |
| **radeco** | **无 license** | — | — | Rust | ❌ 无许可 + 已废弃 |
| **`retdec` crate** | — | — | — | — | ❌ **是远程服务客户端** |
| **`libsla`** | 绑定到 Ghidra | — | 中（引入 `libsla`） | C++ | ⚠️ 仅 SLEIGH 部分 |

**关于 r2ghidra 的一个官方警告**（对「移植 Ghidra 反编译器」的风险很重要）：

> 「注意 **r2ghidra 的反编译质量与 Ghidra 相比并不相同**，
> 因为 r2ghidra 不提供 Ghidra 会提供的相同分析结果，且其他元数据也不同，
> **这导致引擎表现不同，在处理结构体与其他复杂特性时很可能漏掉相当多细节**。」

来源：<https://book.rada.re/arch/decompile.html>

> **含义**：**Ghidra 反编译器的输出质量**高度依赖**Ghidra 前端（Java 侧）的分析结果**。
> 所以「把 Ghidra 反编译器抠出来单独用」**不等于**得到 Ghidra 的质量。
> 这一点对 `koute/ghidra-decompiler` 同样适用——它移植了 `decompile/cpp`，
> 但 README 说它自己**也做了**符号加载、函数发现、PLT 桩命名、字符串字面量识别等前端工作
> （甚至「比 C++ loader 加载更多符号」），这是一个**加分项**，但也说明集成工作不止于粘合。

---

## 8. 诚实性问题（对 BitFlip 最关键的一节）

### 8.1 问题的本质

BitFlip 的立身之本是「**说的就是真的**」（`CLAUDE.md` §7），且有明确禁令：
**不用假名冒充识别结果**、**拿不到就说拿不到**。

而反编译器的**工作方式本身就是推断**。Ghidra 官方文档的措辞是最权威的证据：

> 「反编译器，以低阶语言为输入，**只能推断**这些信息。」
> 并把这些列为「在编译器中没有真正对应物」的任务：
> 变量合并、类型传播、控制流结构化、函数原型恢复、表达式恢复。

来源：<https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/docmain.hh>

**即：反编译器的核心输出，按其定义，就是「推断结果」而非「识别结果」。**
这与「说的就是真的」存在**结构性张力**，必须靠**产品设计**解决，而不是靠「做得更好」。

### 8.2 静默错误的实证

**（a）DeBench / angr 案例**（已在 §4.3、§6.1 详述）：
`unsigned int` vs `int` 的静默漂移使含负数的分支**根本改变行为**，
而代码**看起来干净、可读性评分高**。论文原话：
「**代码看起来合理，但逻辑不再等价于源码**。」

来源：<https://arxiv.org/html/2605.29490v1>

**（b）RET2 Systems「Dangers of the Decompiler」**（2017，反反编译技术）：

来源：<https://blog.ret2.io/2017/11/16/dangers-of-the-decompiler/>

该文演示了三种让反编译器**静默隐藏代码**的手法——注意这些**不是崩溃或报错，而是无声的错误**：

1. **Positive SP Value**：用不透明谓词制造栈指针不平衡，
   IDA 会**拒绝反编译**该函数（这个是**好消息**：报错而非撒谎）。
2. **Return Hijacking**：在返回前**栈枢轴（stack pivot）**到嵌入二进制的 ROP 链。
   反编译器的设计目标是「抽象掉函数序言/尾声这类低层簿记」，
   但**副作用**是：**反编译器不会给出任何警告或异常迹象**。
   作者原话：「**只盯着反编译器输出的人必然会漏掉它**（Those focused solely on decompiler output are guaranteed to miss it）。」
3. **Abusing `noreturn`**：让 IDA 相信一个函数是 `noreturn`（实际不是），
   于是反编译器**丢弃该调用之后的所有代码**——代码被**静默隐藏**。

作者的结论句值得直接引用：

> 「反编译器是令人印象深刻但**不完美**的技术。它们**在不完整的信息上运作，尽其所能地为我们人类做近似**。
> 恶意行为者可以（并且会）利用这些不对称性作为欺骗手段。」

**（c）「Don't trust the decompilers」**（2021，实战案例）：

来源：<http://allthingsreversed.io/20210517-dont-trust-the-decompilers.html>

Ghidra 因栈帧过大（3 MB）而**静默没能定义那些栈变量**（只显示 `in_stack_ffffffffffc7fcc0` 之类），
结果**反编译输出里整条 `xor` 运算消失了**。这条 `xor` 恰恰是拿 flag 的关键。
修正栈帧大小后，`xor` 才出现。作者结论：「**不要盲信你的反编译器。**」

> **这条案例特别贴合 BitFlip**：反编译器**不是报错**，而是**少给了数据**，
> 而 BitFlip 的 `CLAUDE.md` §7 恰恰有「**降级要写在界面上**……不能悄悄少给数据」的要求。
> 反编译器的默认行为与之**直接冲突**。

**（d）学术上的系统性证据**：
- **A Taxonomy of C Decompiler Fidelity Issues**（Dramko et al., USENIX Security 2024）：
  「不幸的是，反编译代码含有……（fidelity 问题）」
  <https://www.usenix.org/system/files/usenixsecurity24-dramko.pdf>
- **Bin2Wrong**（USENIX ATC 2025）：一个**统一 fuzzing 框架，用于发现 binary-to-C 反编译器中的语义错误**。
  <https://www.usenix.org/system/files/atc25-yang-zao.pdf>
- **How Far We Have Come: Testing Decompilation Correctness of C Decompilers**（ISSTA 2020）
  <https://dlnext.acm.org/doi/pdf/10.1145/3395363.3397370>
- **Decompiling for Constant-Time Analysis**：指出 Decompile-then-Analyze 方法**根本上的 soundness 问题**
  ——**反编译步骤会破坏原程序的安全属性**。
  <https://arxiv.org/html/2501.04183>

**（e）实践手册的告诫**（面向嵌入式 RE 的教材）：

> 「**在验证之前，不要相信反编译器输出去做法律证据或生产补丁。**
> 反编译器是启发式的。它们产出的 C **常常看起来**与汇编等价，但**在微妙之处不同**
> （类型提升、未定义行为假设、被省略的副作用）。**依赖前先验证。**」

来源：<https://datanoisetv.github.io/practical-reverse-engineering/part5/30-caveats>

该章还列举了大量**具体的错法**（对 BitFlip 的多架构场景极实用）：
ARM 硬浮点 vs 软浮点 ABI 搞错 ⇒ **浮点参数的反编译就是错的**；
Xtensa windowed 寄存器 ⇒ 「如果某函数反编译出 7 个参数而它只接受 1 个，多半是调用约定没被识别」；
**RISC-V 压缩指令被当作基础指令解码 ⇒ 每隔一条指令都是错的**；
MIPS 端序搞错 ⇒ 「**看似合理的胡说**（plausible nonsense）」；
MIPS 分支延迟槽；8051 寄存器组等。

> 「**看似合理的胡说（plausible nonsense）**」是本节最好的短语。

### 8.3 真实工具如何传达不确定性

**a. 显式的「我不知道」开关**
- `r2ghidra.rawptr`：「**把未知全局显示为裸地址而不是变量**」
  ——即「与其猜一个变量名，不如给地址」。
- Ghidra 的 `.bss` 类问题也提示：**缺失数据应以缺失呈现，而非补零**。
  来源：<https://book.rada.re/arch/decompile.html>

**b. 类型置信度**
- 学术与工业界已知的做法：**lattice / push-down typing** 天然产出「类型未能收敛到具体类型」
  的状态（保持在格的较高层，如 `top`）。
- **BTIGhidra**（Trail of Bits，2024）是一个 **Ghidra 扩展，用于从二进制推断类型信息**
  ——其存在本身说明类型推断是需要**外挂**的独立能力，而非内建确定信息。
  来源：<https://blog.trailofbits.com/2024/02/07/binary-type-inference-in-ghidra/>

**c. 命名策略**
- Ghidra step12：**若无名字则自动生成**。
- 注意这与 BitFlip §7 的禁令**直接冲突**（「不要生成 `func_xxx` 之类的占位名」）。
  → **若 BitFlip 做反编译，必须覆盖这个默认行为**：保留原始位置（如 `[rbp-0x14]`）或标记「未命名」。

**d. 交叉高亮与地址回链**（**这是最值得 BitFlip 借鉴的机制**）
- Ghidra step14：**每个 token 都标注其语法含义**（用于语法高亮），
  且**大多数 token 还被标注与其最相关的机器指令地址**——
  「**这是机器码/C 代码交叉高亮能力的基础**」。
- 这意味着：**每一个可疑的推断，用户都能一键跳回原始机器指令自查**。
  这是把「不可信的输出」变成「可验证的输出」的**关键工程手段**。

> **这是本报告对 BitFlip 最有操作价值的建议**（见 §9）：
> 反编译输出中的**每一个标识符、每一处类型、每一段控制流结构都携带来源地址**，
> 让用户能随时验证「这个 `int` 是从哪儿推出来的」。

**e. 显式失败优于静默降级**
- RET2 的 Positive SP Value 案例中，**IDA 拒绝反编译**——
  这是**正确的**行为（宁可不说，不要瞎说）。
- 与之对比，`noreturn` 与栈枢轴案例是**静默错误**。
- **对 BitFlip 的启示**：宁可「这个函数无法反编译，原因：栈指针不平衡」，
  也不要输出一份看起来完整的错误伪代码。

**f. DeBench 的 URAF 五级量表本身就是「不确定性分类法」**
（可作为 BitFlip 的降级披露等级参考）：
Lexical Clarity → Structural Intelligibility → **Type-System Fidelity** → Semantic Transparency → Contextual Coherence，
每级再拆成 18 个子维度（其中 **Type-System Fidelity 含 type precision、composite-type recovery、type safety**）。
来源：<https://arxiv.org/html/2605.29490v1>

---

## 9. 给小团队（BitFlip）的底线结论

### 9.1 对既有决策门的意见

现有决策门写的是：「**decompiler: default to NOT doing it; it is several times the work of everything else combined.**」

**工作量判断：方向上对，量级上可能还偏保守。**

支撑：
- RetDec（14.4 MB C++）→ limited maintenance；Snowman（1.6 MB C++）→ 被抹除；
  radeco（Rust，4+ 年、有组织支持）→ **官方标记 abandoned**；
- Ghidra 反编译器核心移植到 Rust 后 **6.1 MB**；
- 结构化问题 **30 年未解**，且论文明确其核心选择「**最终意义上不可判定**」。

**但真正应该写进决策门的，是比工作量更强的理由：**

> **反编译器的输出按其定义就是「推断」，而 BitFlip 的核心价值是「说的就是真的」。
> 这不是一个可以用更多工作量解决的问题，而是一个需要产品设计来解决的结构性冲突。**
> （Ghidra 官方：「反编译器…只能推断这些信息」）

而 §8.2 的实证说明，**最危险的失败模式恰恰是「看起来合理的错误输出」**——
这正是 BitFlip 最不能接受的那类失败。

### 9.2 如果要推进：分层路线（建议）

我认为**不应该**把「做反编译器」当成一个二元决策。建议改为**四个独立的、各自可停止的决策**：

**第 0 步（必须先做，且本身就是决策输入）—— 验证 `koute/ghidra-decompiler` 是否真的能用**

这是**唯一一件能显著改变结论的事**。理由：
- 若它真的可靠，则「从零做反编译器」这个问题**根本不成立**——
  你可以直接嵌入一个 Apache-2.0、纯 Rust、零 FFI、架构完全匹配的反编译器。
- 若它不可靠（星标 6、agent 自动移植、无社区验证），则回到「不做」。

**具体做法（一个 spike，不应超过 1–2 周）**：
1. `cargo add ghidra-decompiler`（或 vendor 源码），**只开 `x86`/`aarch64` feature** 控制体积。
2. 在 **BitFlip 自己的 fixtures** 上跑：对若干 `-O0`/`-O2` 的测试二进制反编译，
   **与真实 Ghidra 输出逐字对比**（用 `decomp_corpus` 同款方法）。
3. **关键验证**：确认它的输出**不违反 BitFlip §7**——即检查它是否
   会生成 `func_xxx` 占位名、是否会把未知字段当 0、是否会静默少给数据。
   **几乎肯定会违反**，因此第 3 步的产出物是**一份必须做的适配/包装清单**。
4. 验证「哪些函数它会反编译失败」，以及失败时是否**明确报错**（而非静默降级）。

**第 1 步（若第 0 步通过）—— 只做「单基本块表达式视图」，明确不叫「反编译」**

- **官方先例**：radare2 的 `pdc` 就是这个档位，官方定位为「顺手、快」，
  并明确「**作为喂给语言模型的源**」有用。
- **为什么从这开始**：单块内**无控制流歧义**，是唯一能做到「确定的、可验证的」子集。
  这**最贴合 BitFlip「说的就是真的」**。
- **硬性要求**：
  - UI 与文档**不得**称其为「反编译」或「伪代码」，应叫「**表达式视图**」或「单块求值视图」。
  - 明确标注**不含控制流结构**，并提示用户回到 CFG 视图看块间关系。
  - 复用 BitFlip 已有的 `DecodedInsn` 的寄存器读/写与内存操作数信息——
    **这部分是确定性数据，不需要推断**。

**第 2 步 —— 只做「有调试信息时的类型展示」，不做推断**

- **这是投入产出比最高、且最诚实的子集**：有 DWARF/PDB 时，类型是**读来的**，不是**猜的**。
- BitFlip **已有** ELF/DWARF/PDB 符号解析，这是既有优势的直接延伸。
- **硬性要求**（对齐 §8.3）：
  - **每个类型标注来源**：`from_dwarf` / `from_pdb` / `inferred` / `unknown`。
  - 无调试信息时，**不推断、不猜**，显示 `[unknown]` + 原因（对齐 §7「拿不到就说拿不到」）。
  - **优先展示原始位置**（`[rbp-0x14]`、寄存器名）而非捏造变量名（对齐 §7 禁止假名）。

**第 3 步（可选，且应最晚做）—— 控制流结构化**

- 只有当第 1、2 步的用户价值被验证后才考虑。
- **必须接受的前提**：结构化在理论上不可判定（§3.5），
  因此**输出必然包含 goto**，且**不可能消除**。
- **不要**追求「零 goto」（SAILR 已证明这是**有害的**：DREAM 零 goto 但 CFGED 恶化 104%）。
- **可以**先做**最保守**的结构化：只识别**明确无歧义**的模式
  （单入口单出口的 if-then、简单的前置条件循环），
  其余**一律退回 goto + label**，并在 UI 上标注「未能结构化的区域」。

### 9.3 无论做哪一步，都建议先建立的「诚实性基础设施」

这部分**独立于反编译器决策**，本身就有价值，且**可能应该先于反编译做**：

1. **每个推断值携带来源地址（provenance）**。
   借鉴 Ghidra step14：**每个 token 关联其最相关的机器指令地址**，
   以实现机器码/C 交叉高亮。对 BitFlip：**任何反编译/推断输出都应可一键跳回原始指令**。
2. **推断 ≠ 识别，必须在数据模型与 UI 里分开**。
   当前 `docs/PLAN.md` 里「未识别」的概念可以直接扩展为
   `identified | inferred | unknown`，并在 UI 用不同视觉语言呈现。
   这与 `CLAUDE.md` §7 的精神完全一致，且**不需要反编译器就能落地**。
3. **失败要显式**。反编译失败时返回明确的错误（对齐 §7 的
   `BitFlipError::NotYetImplemented { feature }` 模式），**绝不返回看起来完整的空壳**。
   RET2 的 Positive SP Value 案例（IDA 拒绝反编译）是**正确的产品行为**。
4. **降级必须可见**。§8.2(c) 的 Ghidra 3MB 栈帧案例是反面教材：
   它**静默丢失了整条 `xor`**。BitFlip §7 已要求「降级要写在界面上」——
   在反编译场景下，这意味着**「本函数有 N 个位置未能解析」必须出现在结论里**。

### 9.4 一句话总结

> **不要把「反编译器」当成一个要做的功能，把它拆成
> 「可信的单块表达式视图」+「带来源标注的类型展示」+「可选的、承认会留 goto 的结构化」三件事。
> 先花 1–2 周验证 `koute/ghidra-decompiler` 是否可用——它是唯一能改变这个决策的变量。
> 如果它可用，重心从「写反编译器」变成「给反编译器输出套一层诚实性外壳」；
> 如果不可用，「不做」的判断应当维持，并把它记为
> 「不是工作量问题，而是输出本质上是推断，与项目核心价值冲突」。**

---

## 10. 出处清单（按主题）

### 一手项目文档 / 源码
- Ghidra 反编译器 15 步工作流（源码内嵌文档）：
  <https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/docmain.hh>
- Ghidra P-Code 参考手册：<https://ghidra.re/ghidra_docs/languages/html/pcoderef.html>
- Ghidra Decompiler Concepts：<https://www.ghidradocs.com/11.4_PUBLIC/help/Decompiler/help/topics/DecompilePlugin/DecompilerConcepts.html>
- Binary Ninja BNIL 总览（IL 阶梯）：<https://docs.binary.ninja/dev/bnil-overview.html>
- Binary Ninja BNIL LLIL：<https://docs.binary.ninja/dev/bnil-llil.html>
- RetDec README（含 limited maintenance mode 警告）：<https://github.com/avast/retdec>
- RetDec Capstone2LlvmIr：<https://github.com/avast/retdec/wiki/Capstone2LlvmIr>
- angr IR 文档：<https://docs.angr.io/advanced-topics/ir>
- radare2 官方书籍「Decompilers」章（含 r2ghidra 质量警告、pdc 定位、radeco abandoned）：
  <https://book.rada.re/arch/decompile.html>
- radeco 仓库：<https://github.com/radareorg/radeco>
- **Ghidra 反编译器纯 Rust 移植**：<https://github.com/koute/ghidra-decompiler>
- snowman 归档：<https://github.com/ayesc9000/snowman-archive>
- snowman 被抹除的 issue：<https://github.com/decompiler-explorer/decompiler-explorer/issues/94>

### 论文
- Cifuentes, *Reverse Compilation Techniques*（1994 博士论文）：
  <https://www.cs.tufts.edu/~nr/cs257/archive/cristina-cifuentes/DCC_decompilation_thesis.pdf>
- Brumley et al., *Native x86 Decompilation using Semantics-Preserving Structural Analysis and
  Iterative Control-Flow Structuring*（Phoenix, USENIX Security 2013）：
  <https://kilthub.cmu.edu/articles/Native_x86_Decompilation_using_Semantics-Preserving_Structural_Analysis_and_Iterative_Control-Flow_Structuring/6469064/files/11897618.pdf>
- Yakdan et al., *No More Gotos*（DREAM, NDSS 2015）：
  <https://www.ndss-symposium.org/wp-content/uploads/2017/09/11_4_2.pdf>
- **Basque et al., *Ahoy SAILR!*（USENIX Security 2024）**：
  <https://yancomm.net/papers/2024%20-%20USENIX%20Security%20-%20SAILR.html>
  · 评测框架：<https://github.com/mahaloz/sailr-eval>
- **Liu et al., *CODEFUSE-DeBench*（2026）**：<https://arxiv.org/html/2605.29490v1>
- Dramko et al., *A Taxonomy of C Decompiler Fidelity Issues*（USENIX Security 2024）：
  <https://www.usenix.org/system/files/usenixsecurity24-dramko.pdf>
- *Bin2Wrong*（USENIX ATC 2025）：<https://www.usenix.org/system/files/atc25-yang-zao.pdf>
- *Decompiling for Constant-Time Analysis*（soundness 问题）：<https://arxiv.org/html/2501.04183>
- Lee/Avgerinos/Brumley, *TIE*（NDSS 2011）；Noonan et al., *Polymorphic type inference for machine code*（PLDI 2016）
  —— 均经 Decompilation Wiki 类型恢复页引用
- Schwartz/Hex-Rays 结构化讨论（文献引用见 SAILR §10 Related Work）

### 知识库 / 综述
- **Decompilation Wiki（最系统的二手整理）**：
  - 结构化总览：<http://decompilation.wiki/fundamentals/structuring/overview/>
  - 程序提升 / IR 全景表：<http://decompilation.wiki/fundamentals/cfg-recovery/lifting>
  - 类型恢复总览：<http://decompilation.wiki/fundamentals/type-recovery/overview/>
  - 仓库：<https://github.com/mahaloz/decompilation-wiki>
- mahaloz, *30 Years of Decompilation and the Unsolved Structuring Problem: Part 1*：
  <https://mahaloz.re/dec-history-pt1>
- Ghidra DeepWiki（**注**：本次访问被 Vercel 反爬拦截，未能读取原文，仅由搜索摘要推断其内容，未经核实）：
  <https://deepwiki.com/NationalSecurityAgency/ghidra/2.1-core-decompilation-process>

### 工程博客 / 实践
- **RET2 Systems, *Dangers of the Decompiler*（2017）**：<https://blog.ret2.io/2017/11/16/dangers-of-the-decompiler/>
- ***Don't trust the decompilers*（2021）**：<http://allthingsreversed.io/20210517-dont-trust-the-decompilers.html>
- Hex-Rays, *IDA: celebrating 30 years*（含 1991 年历史文件原文）：<https://hex-rays.com/blog/ida-celebrating-30-years-of-binary-analysis-innovation>
- Hex-Rays, *Decompiler primer*（2009）：<https://hex-rays.com/blog/hex-rays-decompiler-primer>
- Hex-Rays About：<https://hex-rays.com/about-us>
- **Trail of Bits, *Binary type inference in Ghidra*（2024）**：<https://blog.trailofbits.com/2024/02/07/binary-type-inference-in-ghidra/>
- Elastic Security Labs, *Introduction to Hex-Rays decompilation internals*：
  <https://www.elastic.co/security-labs/threat-command/introduction-to-hexrays-decompilation-internals>
- Practical Reverse Engineering, *Caveats, Gotchas, and Pitfalls*：
  <https://datanoisetv.github.io/practical-reverse-engineering/part5/30-caveats>
- radare2, *Update on Radeco*（2015）：<https://radareorg.github.io/blog/posts/update-on-radeco/>
- radare2 GSoC 2018 三篇（伪 C 生成 / 控制流结构化 / 类型推断）：
  <https://radareorg.github.io/blog/posts/gsoc_2018_radeco_pseudo_c_code_generation/>、
  <https://radareorg.github.io/blog/posts/gsoc_2018_radeco_cfs/>、
  <https://radareorg.github.io/blog/posts/type_inference/>
- Snowman「LLVM for decompilers」定位：<https://www.infoworld.com/article/2247562/snowman-seeks-to-be-llvm-for-decompilers.html>

### Rust 生态
- `ghidra-decompiler` Rust 移植：<https://github.com/koute/ghidra-decompiler>
- `rsleigh`（SLEIGH → P-code 纯 Rust）：<https://github.com/ShaneBreazeale/rsleigh> · <https://lib.rs/crates/rsleigh>
- `pcode-ir`：<https://lib.rs/crates/pcode-ir> · `pcode`：<https://lib.rs/crates/pcode>
- `libsla`（Ghidra SLEIGH 的 Rust 绑定）：<https://docs.rs/libsla>
- `r2sleigh`：<https://github.com/radareorg/r2sleigh> · `r2smt-pcode`：<https://lib.rs/crates/r2smt-pcode>
- ⚠️ `retdec` crate（**实为 REST 客户端，非本地反编译器**）：<https://docs.rs/retdec/latest/retdec/>
- `decomp` crate：<https://crates.io/crates/decomp>

### 代码体量（GitHub API `languages`，本次实测）
- RetDec：<https://api.github.com/repos/avast/retdec/languages> → C++ 14,395,357
- Snowman 归档：<https://api.github.com/repos/ayesc9000/snowman-archive/languages> → C++ 1,638,220
- r2ghidra：<https://api.github.com/repos/radareorg/r2ghidra/languages> → C++ 330,910
- ghidra-decompiler：<https://api.github.com/repos/koute/ghidra-decompiler/languages> → Rust 6,125,019

---

## 附录：本报告的可靠性说明

**高置信度（多源一手佐证）**：
- Ghidra 15 步流程与 step5 细节（官方源码文档原文）
- P-Code 设计（官方参考手册原文）
- BNIL 分层（Binary Ninja 官方文档原文）
- 结构化两大类划分与「不可判定」结论（SAILR 论文 + Decompilation Wiki 双源）
- SAILR Table 3 的 goto/CFGED 定量对比（论文原文表格）
- DeBench 的 22.3% / 1.2% / 19% / 20× / 1.6× 等数字（论文摘要与正文原文）
- RetDec limited maintenance mode（官方 README 原文）
- radeco abandoned（radare2 官方书籍原文）
- 各项目代码体量（GitHub API 实测）
- `koute/ghidra-decompiler` 的属性（README / Cargo.toml / 仓库 API 实测）

**中等置信度（单一来源或需注意语境）**：
- Hex-Rays 1.0 的精确发布日期：官方博客时间线说「2008 年首个商业反编译器发布」，
  但 2009-10 博客又说「1.0 发布两年多」，两者略有张力，可能是 beta/正式发布的差异。
- Snowman 被抹除的原因：官方未说明，本报告**未作推测**。

**`[推断]` / 未能核实**：
- 「Rust 移植 6.1 MB vs C++ 77 KB ≈ 79×」的**具体倍率**受代码风格与字节/行统计影响，
  数量级方向可靠，精确倍率不宜引用。
- Ghidra DeepWiki 的内容：**本次访问被 Vercel 反爬拦截（HTTP 429）**，
  报告中未使用其内容（搜索结果摘要亦未采信）。
- **`koute/ghidra-decompiler` 的实际可用性**：本次**未编译、未运行**，
  其「输出与 C++ 版本逐字相同」的说法**未经独立验证**。这正是 §9.2 建议做 spike 的原因。
- 所有「时间尺度」估算（§5.6 表格右列）均为推断，非出处结论。
- Cifuentes 论文 PDF 与若干 USENIX/NDSS PDF 因**工具不支持 `application/pdf`** 而未能直接读取正文，
  相关事实均改由 SAILR 论文的 Related Work、Decompilation Wiki 的脚注引用、
  以及可读的 HTML 版本（SAILR、DeBench）交叉获取。
