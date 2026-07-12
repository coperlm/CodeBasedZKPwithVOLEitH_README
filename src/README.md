# Code-Based Zero-Knowledge from VOLE-in-the-Head: 核心代码与架构解析报告

## 📑 报告导读

本报告旨在详细解析本项目在代码工程层面对 **“基于 VOLE-in-the-Head (VOLEitH) 范式的码基零知识证明及其高级隐私保护应用”** 的完整实现。

由于本项目采用 Rust 编写，包含约上万行代码，为便于您审查理论公式与代码逻辑的准确映射，本报告以**“自底向上，化整为零”**的策略，将整个系统拆分为 **5 个核心逻辑模块**。

报告尽可能剥离了编程语言的繁文缛节，**聚焦于密码学理论、代数约束的构建、以及底层数学公式的代码级映射**，并全面阐述了为达到极优 Benchmark 数据所做出的硬件加速与并发工程优化。

---

## 🏗️ 系统架构与模块导航

### 📦 模块一：基础密码学与数学原语 (Primitives & Math)
**对应论文**：Section 2.1 (Boolean Functions), 2.2 (AFS Hash), 2.5 (Randomized McEliece)
**模块概述**：本模块是整个 ZKP 系统的数学基石，实现了极其高效的底层有限域算术，并构建了基于编码的经典困难问题（如 2-RNSD, RSD）。
**核心亮点**：
*   **$GF(2^{128})$ 硬件加速**：直接利用 CPU 的 CLMUL / PMULL 无进位乘法指令，实现亚纳秒级域乘法。
*   **列流式零物化矩阵**：对于极其庞大的公开伪随机矩阵 $B \in \mathbb{F}_2^{n \times m}$，采用按需列流式（Column-streaming）生成与掩码 XOR，彻底消除 OOM 风险并防御侧信道泄漏。
*   **正则噪声参数对齐**：精准实现 McEliece 加密公式 $c = G \cdot \binom{u}{m} \oplus \text{RE}(e')$，并采用专为正则噪声优化的参数集（$n_e = 4096, k_e = 3328, t_e = 64$）。

**包含文件**：
*   `src/finite_field.rs`, `src/bitvec_ops.rs`
*   `src/primitives/afs_hash.rs`, `src/primitives/streaming_matrix.rs`
*   `src/mceliece.rs`
*   👉 **[点击查看详细报告：1_基础密码学与数学原语.md](./1_基础密码学与数学原语.md)**

---

### 📦 模块二：VOLEitH 底层框架集成 (VOLEitH Framework Integration)
**对应论文**：Section 2.7 (VOLE-in-the-Head)
**模块概述**：本模块实现了 VOLE-in-the-Head 范式所需的**延迟 VOLE 功能（Delayed VOLE functionality $\mathcal{F}_{\text{sVOLE}}$）**。
**核心亮点**：
*   **跨语言 FFI 安全封装**：为了极致性能，系统并未重复造轮子，而是通过 Rust FFI 安全地集成了 FAEST 的 C 核心代码，完美复用了其经过 NIST 审查的高效 GGM-based 二叉辅助向量承诺树（BAVC）。
*   **严格的状态机生命周期**：通过 Rust 的所有权模型与 Drop 机制，安全管理 C 层的 Prover / Verifier 证明树状态，避免内存泄漏。

**包含文件**：
*   `src/faest_abi.c`, `src/faest_ffi.rs`
*   👉 **[点击查看详细报告：2_VOLEitH底层框架集成.md](./2_VOLEitH底层框架集成.md)**

---

### 📦 模块三：ZK 核心约束引擎 (Core ZK Protocol Engine)
**对应论文**：Section 3 (New Techniques for Proving Regular Encoding Process)
**模块概述**：这是**整个系统的代数灵魂**，负责将非线性的编码操作编译为布尔多项式，并基于 VOPE 完成零知识证明。
**核心亮点**：
*   **非线性正则编码的多项式转化**：利用拉格朗日插值/Möbius 变换，将查表式的正则编码（Regular Encoding）巧妙转化为 degree-$c$ 的 ANF 约束系统 $f(X_1, \dots, X_c) = \prod_{i=1}^c (1 + j_i + X_i)$。
*   **线性因子乘积盲化（VOPE）**：在 $\Pi^t_{dD-Rep}$ 协议中，创新性地采用 $\prod_h (v_h + u_h \cdot Y)$ 等价于验证端 $\prod_h q_{\text{aux}, h}$ 的技术对多项式系数进行安全盲化。
*   **Fiat-Shamir 变换**：利用 SHA-3 Keccak-256 海绵结构吸收承诺并挤出挑战值，实现完美 NIZK。

**包含文件**：
*   `src/core/constraint_gen.rs`, `src/core/implicit_eval.rs`
*   `src/core/protocol_dd_rep.rs`, `src/core/voleith.rs`, `src/core/transcript.rs`
*   👉 **[点击查看详细报告：3_ZK核心约束引擎.md](./3_ZK核心约束引擎.md)**

---

### 📦 模块四：高级密码学应用层 (Advanced Cryptographic Applications)
**对应论文**：Section 4, 5, 6 (RS, GS, FDABS, ReSolveD+)
**模块概述**：本模块将上述底层的 ZK 引擎转化为四种开箱即用的顶尖后量子隐私保护签名方案。
**核心亮点**：
*   **ReSolveD+ 标准签名**：基于 RSD 困难问题构建 $y = B \cdot \text{RE}(x)$ 约束。
*   **零知识环签名 (RS)**：通过证明哈希链方程 $v_\ell = B_0 \cdot \text{RE}(x_0) \oplus B_1 \cdot \text{RE}(x_1)$ 完成 Merkle 树累加器成员资格认证。
*   **群签名 (GS)**：在环签名的基础上，额外将 McEliece 身份密文运算注入 ANF 约束系统，实现“可控追踪”。
*   **属性基签名 (FDABS)**：极具创新地使用**图灵完备的 NAND 门约束**（$x_{\text{out}} + x_{\text{in1}} \cdot x_{\text{in2}} + 1 = 0 \pmod 2$）来表达任意复杂的布尔电路策略，并辅以奇偶性校验确保叶子节点合法性。

**包含文件**：
*   `src/apps/` 目录下的 `resolved_plus.rs`, `ring_signature.rs`, `group_signature.rs`, `fdabs.rs` 及其 `_sig.rs` 实现。
*   👉 **[点击查看详细报告：4_高级密码学应用层.md](./4_高级密码学应用层.md)**

---

### 📦 模块五：实验参数、序列化与性能评估 (Engineering, CLI & Evaluation)
**对应论文**：Table 3, 4, 5, 7, 8 (Benchmarking & Performance)
**模块概述**：向您汇报代码在参数选择、序列化体积及并发执行上的极致工程榨取。
**核心亮点**：
*   **代数边界严谨性**：严格确保全局挑战 $\Delta$ 驻留在 128-bit 域，并结合 $w_{\text{grind}}=8$ 比特的 Fiat-Shamir 工作量证明（Grinding），在兼顾性能的同时死守 128-bit 等效安全强度。
*   **KB 级序列化奇迹**：通过 PRG 种子替换大型随机矩阵、极致位宽截断等手段，将传统基于 Stern 范式的“兆字节（MB）级”签名体积暴降至几 **KB**。
*   **多核并发压榨**：在基准测试（Benchmarking）中，大量使用 `rayon` 数据并行化框架。在多项式隐式求值、多层哈希树的节点配对等热点路径上实现了接近线性的多核加速比。

**包含文件**：
*   `src/core/security.rs`, `src/artifact_bundle.rs`
*   `benches/paper_benchmarks.rs`, `scripts/`
*   👉 **[点击查看详细报告：5_实验参数与性能评估.md](./5_实验参数与性能评估.md)**

---
*注：本系列报告由开发者深度提炼，详细的函数证明、结构体拆解与多项式推导请点击各模块对应的子文档查看。*