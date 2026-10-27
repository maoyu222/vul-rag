# C/C++ 修复对来源证据化知识库 v3.1（1279 条纠错版）

## 文件来源与边界

本知识库的全部记录由用户上传的 `high_quality_repair_pairs.json` 生成，源文件 SHA-256：

`28ef4aee849e02c8f9876f918968126abf4ab4e415522031c1390b53bf75aad4`

**1,279 个 sample_id 完全覆盖且互不重复。** 4 个来源依次是 MegaVul 369、PrimeVul 417、CleanVul 475、ReposVul 18。每条原始 `code_before`、`code_after`、`unsafe_behavior`、`security_change`、`keep_reason`、审核片段及补丁差异均原样保留。原文件没有被修改。

**本版是逐样本源证据解析及原文从属条件分类，不是 1,279 条经过独立 LLM、静态分析或人工语义证明的规则。** 对源材料未提供的调用者契约、结构容量、宏取值、保护条件支配关系、漏洞可达性，保持 `not_independently_reviewed` 和 `not_proven`；不得把不确定条件当作已证实的充分防护。

## 对用户提出三项意见的修正

### 1. C/C++ 字符串及嵌入脚本不能作为宿主语言调用

`build.py` 新增保留文本下标的词法屏蔽过程。只在**注释、普通字符串、字符字面量、识别到的 C++ 原始字符串之外**查找函数调用和 `if/while/for` 等条件；分割参数时使用同样的语法掩码判断括号与逗号位置，然后从原文中读取参数（包括合法字符串参数），不修改源码。源材料包含宏、嵌入式 DSL 或复杂 C++ 语法，词法解析仍不是完整 AST；候选解析不能代替真正编译器分析。

对 5 条报告样本合计删除 **14 个**错误调用候选，未新添调用候选。`primevul_train_002652` 增加嵌入 PHP 在 C/C++ 字符串内的语言层级提示；其他样本不假装已穷尽所有嵌入语言。

两条合成回归探针：`puts("memcpy(dst,src,n)");`、`puts("if (n > cap) return;");`，均不得产生真实的 C/C++ `memcpy` 或 `if`。这两条合成探针不纳入原始数据样本计数。对真实 1,279 条变更投影比对，新增条件候选与删除条件候选均为零；这只说明本次集合上没有投影变更，不能宣称所有实际控制流条件经过语义验证。

### 2. 原始容量与其他前提不可漏掉

修复了 `on the condition that`、`Assume`、`assumes`、`assumptions` 等抽取；取消“缺少前提时从上下文任选一句”的危险回退。`megavul_295294` 的 
`on the condition that os_errbuflen is no greater than the actual writable capacity` 现在出现在 `qualified_assumptions_from_boundary` 中。保留 `keep_reason` 的全部原文，并增加：

- `applicability_and_origin.all_boundary_source_clauses[]`：逐句陈列，保留 `provenance_field`、`source_span_index` 与原始分类线索。
- `applicability_boundary_and_unknowns.all_boundary_source_clauses[]`：同一完整列表，用于边界核查。
- `applicability_boundary_and_unknowns.unclassified_boundary_clauses[]`：没有可靠触发词时不做语义强行归类。

和 v3 比较：恢复的前提候选语句 **541** 条（涉及 **460** 个样本），移除旧版可能误分类或随意回退的前提候选 **1,183** 条。此计数是**归类投影的变化**，不是经人工确认的 541 个正确安全前提；完整原文始终存在。

### 3. 检索正文去掉类别与 CWE 元数据

`build_accessory.py` 重建全部检索条目。`retrieval_text` 由每条**真实原始机制**、语法操作角色、触发陈述、实际补丁说明、观察到的代码条件、前提和边界共同组成，不再直接拼接 `vulnerability_type`/`cwe` 元数据；即使来源文本本身含明确 `CWE-编号` 或下划线类别标注，也只从**检索投影**中去掉，完整记录中原文保持不变。全量检索正文扫描：CWE 标记及非通用下划线类别泄漏 = **0**。

`metadata` 仍包含原始 `cwe` 与 `vulnerability_type` 供评估分层统计，检索系统必须只向 BM25/向量模型传入 `retrieval_text`，不能把整个 JSON 文档序列化后一起做索引。

## 文件说明

| 文件 | 用途 |
|---|---|
| `knowledge_v3_all.jsonl` | **推荐主文件**，1,279 行各一条完整 JSON，含源代码与审核证据 |
| `knowledge_v3_all.json` | 完整知识库的 JSON 数组形式 |
| `knowledge_v3_{megavul,primevul,cleanvul,reposvul}.json` | 四个数据集独立文件，外层 `knowledge` 数组 |
| `knowledge_v3_retrieval.jsonl` | 不以 CWE、漏洞类型作为检索文本的检索知识视图 |
| `knowledge_v3_index.csv` | 逐条索引与证据、候选条件统计 |
| `change_log_1279.jsonl` | **逐条修订日志**：实际删除/新增的调用、条件和重新分类的前提，1279 行 |
| `correction_audit.json` | 对比旧版的修订统计及指定问题案例的回归证据 |
| `quality_report.json` | 原始质量报告补充纠错核验 |
| `critical_case_examples.json` | 七条重点示例的完整知识 |
| `alignment_findings.json` | 源片段行号/空白对齐异常，不篡改源证据 |
| `build.py`、`build_accessory.py` | 全量再生程序，标准库运行，无需调用模型 |
| `audit_corrections.py`、`validate.py` | 旧新差异审计、原始输入核验 |
| `tests/test_corrections.py` | 字符串与注释掩码、容量前提及真实样本回归测试 |
| `read_knowledge.py` | 按样本 ID 输出完整 JSON 或提示词 |
| `FILE_MANIFEST.json` | 各文件字节数与 SHA-256 |

## 验证方式

将原始 `high_quality_repair_pairs.json` 放在知识目录的上级（或显式指定 `--input`）后运行：

```bash
python build.py --input ../high_quality_repair_pairs.json --output .
python build_accessory.py
python validate.py --source ../high_quality_repair_pairs.json
python -m unittest discover -s tests -v
```

若保留旧版目录 `../knowledge_v3_complete`，可运行 `python audit_corrections.py` 重建旧版与 v3.1 对比。否则直接查看已生成的 `change_log_1279.jsonl`、`correction_audit.json`。**审计对比不影响知识库正常使用**。

读取：

```bash
python read_knowledge.py --id megavul_295294 --format json
python read_knowledge.py --id primevul_train_002652 --format prompt
```

## 使用限制

这些文件可直接用于**知识候选检索、证据提示、审稿抽样与后续验证**，但不是全部安全条件已证实的知识库。尤其结构中的 `observed_call_sites` 是宿主 C/C++ 层的**词法语法候选**，复杂语法不保证完整；`after_guards_observed_in_added_source` 不是“已证明支配危险操作”的结论。任何漏洞/非漏洞判断均需检查实际函数语义、路径、别名、容量、生命周期、类型、外部契约。**不可仅凭检索命中或 CWE 标签给出诊断。**
