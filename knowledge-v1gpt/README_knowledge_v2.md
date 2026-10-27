# 全量修复对证据化知识（候选版 v2.0）

- 数据源：maoyu222/knowledge-guided-vulnerability-detection / `data/high_quality_repair_pairs.json`。
- 源版本：`fed7fde1c40425b1455f5db7ab28face4d2024d2`（main；本次读取快照）。
- 覆盖：**1279/1279** 组修复对；样本来源：MegaVul: 369；PrimeVul: 417；CleanVul: 475；ReposVul: 18。
- 结构：每条保留 **危险操作 / 适用前提 / 漏洞触发条件 / 安全反证 / 证据需求 / 适用边界** 六部分，并附源码锚点、CWE、提交、原始样本标识、质量标志。
- 分类：共 **87** 个（漏洞类型 × 修复模式）分组，但**没有将不同来源/不同触发机理的知识归并覆盖**。
- 复核：提供48条按修复模式分层的复核候选；这不代表这些条目已通过人工审查。

## 文件

| 文件 | 内容 |
|---|---|
| `knowledge_by_dataset/knowledge_v2_megavul.json` | 369 条独立六字段候选知识 |
| `knowledge_by_dataset/knowledge_v2_primevul.json` | 417 条独立六字段候选知识 |
| `knowledge_by_dataset/knowledge_v2_cleanvul.json` | 475 条独立六字段候选知识 |
| `knowledge_by_dataset/knowledge_v2_reposvul.json` | 18 条独立六字段候选知识 |
| `knowledge_groups.json` | 87 个模式组及每组完整样本ID |
| `knowledge_index.csv` | 1,279行索引，便于定位和筛选 |
| `stratified_quality_review_48.json` | 分层复核样本 | 

## 生成方法与重要限制

本次是**基于原数据已有的 unsafe_behavior、security_change、keep_reason、review_annotations 与修复前后代码的确定性迁移和候选知识归类**。新字段给出了中文类型指引、原始机制、代码证据及审查准则；**没有使用逐条大语言模型推理，也没有以测试、静态分析或人审验证1,279条新结构内容**。例如：安全反证字段记录的是需查验的保护条件与修复样例，**不能把 after 有检查直接等价于任意被检测代码是安全的**。

- 源文件中的完整源码仍以原始 `code_before/code_after/function_diff` 为准；本知识库保存精确的行号和关键证据片段，不重复存储整份源码。
- 每条 `quality.review_flags` 应用于后续人工抽样；其中缺少CVE、父提交信息并不代表知识错误，但减少了独立追溯材料。
- 源锚点去空白匹配修复前：1279/1279；修复后：1279/1279。两个结果不意味着机制成立、路径可达或可利用性已证实。
- 缺失CVE：475；缺失父提交：791；带自动复核标志：852。

## 应用于检测

先基于代码及数据流定位危险操作，再逐一验证适用前提与漏洞触发条件；主动检索可否推翻风险的真实校验、容量、所有权和失败分支，再根据可核验证据给出漏洞/非漏洞/证据不足结论。**严禁仅凭CWE、API或修复模式直接宣判漏洞**。
