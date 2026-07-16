# Code-Based ZK / VOLEitH 代码与协议说明

本文档只记录两类可以从源码或论文直接核对的事实：

1. 源码实际执行的数学关系、证明流程和数据布局；
2. 论文 *Code-Based Zero-Knowledge from VOLE-in-the-Head and Their Applications: Simpler, Faster, and Smaller* 中与这些实现对应的协议设计。

源码优先。论文中的安全定理、参数表和应用生命周期不能自动视为本仓库已经实现的功能。特别是，当前仓库的可执行证明域为 `F128b = GF(2^128)`，256-bit 论文表格没有对应的可执行 profile。

## 论文与实现的关系

论文为 Ying Ouyang、Deng Tang、Yanhong Xu，*Code-Based Zero-Knowledge from VOLE-in-the-Head and Their Applications: Simpler, Faster, and Smaller*，ASIACRYPT 2024，LNCS 15488，2025，DOI: [10.1007/978-981-96-0935-2_14](https://doi.org/10.1007/978-981-96-0935-2_14)。

论文提出 RingSig、GroupSig 和 FDABS 等完整方案；本仓库实现的是这些方案的关系证明、在线签名/验证和本地线缆格式。群成员注册、群签名开封/解密与撤销、FDABS 属性机构和策略分发等系统生命周期不在当前实现范围内。完整边界以仓库根目录的 `LIMITATIONS.md` 为准。

## 证明对象的共同形式

应用层最终都把待证明语句写成

\[
  f_i(w)=0,\qquad i=1,\ldots,t,
\]

其中 (w\in\mathbb F_2^l) 是秘密比特 witness，(f_i) 是在 `F128b` 上计算的、次数至多为 (d) 的多项式。VOLEitH 为 (w) 提供认证式隐藏，`protocol_dd_rep.rs` 将全部约束折叠为一个关于 \(Y\) 的低次数多项式，再在 verifier 的 \(\Delta\) 点检查。

源码中的关键恒等式是：

\[
  q_i+(w_i\oplus u_i)\Delta
  =v_i+w_i\Delta,
\]

因为 FAEST 重构得到的相关量满足 \(q_i=v_i+u_i\Delta\)。右侧正是 prover 在插值点上使用的仿射变量。

## 阅读顺序

| 文档 | 重点 |
|---|---|
| [1_底层数学与矩阵运算](./1_底层数学与矩阵运算.md) | \(\mathbb F_{2^{128}}\)、正则编码输入的位表示、流式矩阵 |
| [2_核心密码学原语](./2_核心密码学原语.md) | AFS 双输入哈希、正则噪声型 McEliece 关系 |
| [3_VOLEitH状态机与FFI](./3_VOLEitH状态机与FFI.md) | FAEST commit/reconstruct、BAVC opening、Fiat-Shamir 绑定 |
| [4_多项式约束生成](./4_多项式约束生成.md) | ANF、正则编码约束和各应用的关系方程 |
| [5_ZK核心证明协议](./5_ZK核心证明协议.md) | \(\Pi^t_{dD\text{-}Rep}\) 的 prover/verifier 数学流程 |
| [6_基础应用层签名](./6_基础应用层签名.md) | ReSolveD+ 与论文环签名关系 |
| [7_高级应用层签名](./7_高级应用层签名.md) | GroupSig、FDABS、Scope-LRS 扩展 |
| [8_参数优化与基准测试](./8_参数优化与基准测试.md) | soundness 计算、序列化和实验口径 |
| [9_创新点对接](./9_创新点对接.md) | 论文/实现差异与当前边界 |
| [10_原始数据](./10_原始数据.md) | 当前实验记录的参数与结果索引 |

## 不应从本文档推出的结论

- 单元测试通过不等于完成密码学安全证明或生产审计。
- 使用 `F128b` 不等于当前实现具有严格 128-bit soundness；具体上界见模块八和模块九。
- `GroupSig`、`FDABS` 的签名验证路径不等于已经实现注册、撤销、开示、解密或机构管理。
- Scope-LRS 和 batch Scope-LRS 是源码扩展，不是论文主方案。
