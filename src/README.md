# Code-Based ZK / VOLEitH 代码与协议说明

本文档说明本项目如何将 VOLE-in-the-Head 零知识证明用于 ReSolveD+、环签名、群签名和属性基签名：从有限域与矩阵运算出发，经由 VOLEitH 证明协议，最终形成可运行的签名与验证流程。

## 论文与实现的关系

论文为 Ying Ouyang、Deng Tang、Yanhong Xu，*Code-Based Zero-Knowledge from VOLE-in-the-Head and Their Applications: Simpler, Faster, and Smaller*，ASIACRYPT 2024，LNCS 15488，2025，DOI: [10.1007/978-981-96-0935-2_14](https://doi.org/10.1007/978-981-96-0935-2_14)。

当前版本实现了关系证明、在线签名/验证及其序列化格式。其中，群签名的成员注册、开封和撤销，以及 FDABS 的属性机构、注册、更新和撤销流程属于完整系统的管理功能，后续可在现有签名验证接口上继续扩展。代码类型 `F128b` 对应数学有限域 $\mathbb F_{2^{128}}$；完整实现边界见仓库根目录的 `LIMITATIONS.md`。

## 证明对象的共同形式

应用层最终都把待证明语句写成

$$
  f_i(w)=0,\qquad i=1,\ldots,t,
$$

其中，$w\in\mathbb F_2^l$ 是秘密见证，$f_i$ 是在 $\mathbb F_{2^{128}}$ 上计算、次数至多为 $d$ 的多项式。VOLEitH 为 $w$ 提供认证式隐藏，`protocol_dd_rep.rs` 将全部约束折叠为一个关于 $Y$ 的低次数多项式，再在验证者给出的 $\Delta$ 点检查。

源码中的关键恒等式是：

$$
  q_i+(w_i\oplus u_i)\Delta
  =v_i+w_i\Delta,
$$

因为 FAEST 重构得到的相关量满足 $q_i=v_i+u_i\Delta$。右侧正是 prover 在插值点上使用的仿射变量。

## 阅读顺序

| 文档 | 重点 |
|---|---|
| [1_底层数学与矩阵运算](./1_底层数学与矩阵运算.md) | $\mathbb F_{2^{128}}$、正则编码输入的位表示、流式矩阵 |
| [2_核心密码学原语](./2_核心密码学原语.md) | AFS 双输入哈希、正则噪声型 McEliece 关系 |
| [3_VOLEitH状态机与FFI](./3_VOLEitH状态机与FFI.md) | FAEST commit/reconstruct、BAVC opening、Fiat-Shamir 绑定 |
| [4_多项式约束生成](./4_多项式约束生成.md) | ANF、正则编码约束和各应用的关系方程 |
| [5_ZK核心证明协议](./5_ZK核心证明协议.md) | $\Pi^t_{dD\text{-}Rep}$ 的 prover/verifier 数学流程 |
| [6_基础应用层签名](./6_基础应用层签名.md) | ReSolveD+ 与论文环签名关系 |
| [7_高级应用层签名](./7_高级应用层签名.md) | GroupSig、FDABS 与 Scope-LRS 工程扩展 |
| [8_参数优化与基准测试](./8_参数优化与基准测试.md) | soundness 计算、序列化和实验口径 |
| [9_创新点对接](./9_创新点对接.md) | 论文/实现差异与当前边界 |
| [10_原始数据](./10_原始数据.md) | 当前实验记录的参数与结果索引 |

Scope-LRS 与 batch Scope-LRS 为本仓库在论文方案基础上的工程扩展；其设计和数据在模块七、模块十中单独说明。
