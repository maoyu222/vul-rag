# C/C++ 修复对逐样本证据化机制知识库 v3

## 内容与真实完成状态

本目录使用用户上传的 `high_quality_repair_pairs.json` **实际处理全部 1,279 组修复对**，生成可检索、可追溯、可独立读取的结构化记录。每条是从它自己的 **code_before / code_after / function_diff / unsafe_behavior / security_change / keep_reason / review_annotations** 生成，不按 CWE 或 vulnerability_type 自动套用危险机制、安全目标等自然语言模板。保留了所有原始英文描述、全部审核片段和完整的修复前后函数源码。

**重要诚实性标记**：本版通过逐样本的来源陈述拆分、源代码差异比较、调用参数位置分析以及条件解析进行自动结构化；**没有对 1,279 组逐条进行独立的大语言模型语义验证、人工审查、编译测试或控制流证明**。因此 `semantic_review_status = not_independently_reviewed`，代码条件只是观察到的补丁候选，不能直接作为“已证明安全/漏洞”的结论。尤其 `security_change` 对某个补丁的解释不意味着在别的代码上也充分安全。

## 下载文件与接口

- `knowledge_v3_all.jsonl`：推荐主文件。每行一个独立 JSON 对象，共 **1279 行**；流式读取方便；含全部原始源码、审核证据与结构化字段。
- `knowledge_v3_all.json`：同样完整，**顶层是 JSON 数组**，方便 `json.load`。
- `knowledge_v3_{megavul,primevul,cleanvul,reposvul}.json`：按数据集拆分；顶层为包含 `knowledge` 数组的对象。
- `knowledge_v3_retrieval.jsonl`：检索/提示词轻量版，**不是完整的证据存储**，包含来源机制、关键片段、修复条件、假设和元数据。
- `knowledge_v3_index.csv`：样本 ID、数据集、CWE、漏洞类型、修复模式与核查统计。
- `critical_case_examples.json`：旧版指出问题的样本等关键案例，供人工审核。
- `alignment_findings.json`：源审核片段与源码行定位的异常；原文不作静默更正。
- `quality_report.json`：全量结果覆盖和检查统计。
- `read_knowledge.py`：按样本 ID 输出完整结构或面向检测的提示词文本。
- `validate.py`：在用户提供的原始 JSON 文件在场时，重新核验无损性及证据引用。
- `build.py`：本次确实运行过的完整提取脚本，标准库运行，无需调用 API。

## 单条 JSON 结构

```text
schema_version / sample_id
source
  metadata / pair_provenance
  original_descriptions: unsafe_behavior, security_change, keep_reason
  original_annotation_lines
  source_content_sha256
  full_original_code: code_before, code_after
危险操作 dangerous_operation_and_variable_roles
  case_specific_mechanism
  observed_call_sites (callee, arguments, syntactic roles)
  source_named_symbols_in_changed_code
适用前提 applicability_and_origin
  specific_preconditions_from_case
  qualified_assumptions_from_boundary
  observed_original_branch_conditions
漏洞触发 vulnerability_trigger_logic
  precise_mechanism_reported_by_source
  case_specific_trigger_or_failure_statements
  original_changed_conditions
安全反证 safety_counterevidence_and_equivalent_protection
  actual_patch_mechanism
  after_guards_observed_in_added_source
  patch_transformations (original and patched code per changed range)
  equivalent_protection: candidate_unverified
证据需求 evidence_requirements_and_analysis_methods
  required_target_facts (operation, reachability, counterevidence, boundary)
适用边界 applicability_boundary_and_unknowns
  original_boundary / explicit_source_limitations / unknown_or_conditional_facts
evidence
  reviewed_before[] / reviewed_after[]  (preserve ALL fragments)
  patch_changes[] / function_diff_original / source_alignment_findings
audit
  semantic_review_status / metadata_flags / guard_domination_verified
```

## 本次全量统计

- 1279 条、1279 个不同 `sample_id`，四数据集分别 MegaVul 369、PrimeVul 417、CleanVul 475、ReposVul 18。
- **审核证据全部保留**：修复前 2007 段，修复后 1994 段；另提取代码修改证据（见 quality_report.json）。
- 个别审核片段与函数源码仅有空白/缩进差异、记录行号与源码匹配位置不一致，已放入 `alignment_findings.json`；不是擅自修改源文件。
- 部分补丁没有新增显式 `if` 条件，例如类型更改、资源释放、函数替换。相应 `after_guards_observed_in_added_source` 可以为空，补丁的真实改动仍在 `patch_transformations`。
- 所有 `equivalent_protection.status` 都是 `candidate_unverified`；单个补丁不能证明完整函数安全。

## 读取示例

```bash
python read_knowledge.py --id megavul_248517 --format prompt
python read_knowledge.py --id cleanvul_s4_003483 --format json
python validate.py --source /path/to/high_quality_repair_pairs.json
```

```python
import json
with open('knowledge_v3_all.jsonl', encoding='utf-8') as f:
    for line in f:
        item = json.loads(line)
        print(item['sample_id'])
```

## 如何正确接入漏洞检测

1. 用轻量检索文件搜索候选机制，不能直接把匹配的知识当作诊断。
2. 加载同 ID 的完整记录，对照该条危险操作及变量角色、原始风险条件、完整审核片段和补丁差异。
3. 在目标代码重新核实变量来源、类型与容量、可达路径和所有相关防护；外部 API/宏/调用者不明时可返回“证据不足”。
4. 只有实质证据支持时才报漏洞；不能仅凭 CWE、函数名、补丁有 `if`、返回值 `false` 或字符串模板宣判。
5. 论文实验中须将“源数据原有解释”和“程序从解释中重组的信息”与“经过独立人工/工具证明的结论”严格区分。

## 部分已知边界示例

- `megavul_248517`：CAN/CAN-FD `memcpy` 写入二进制帧，**不能**要求字符串 `NUL` 终止；两个分支分别验证长度上界，宏与结构定义未提供。
- `cleanvul_s4_003483`：`X509_check_host(...) == 1` 仅决定本地 PKI 认可路径；证书摘要白名单仍是独立接受途径，不能泛化为“任何校验失败必须全函数拒绝”。
- `cleanvul_s4_001219`：`unlink` 加 `O_EXCL` 与目标文件身份/独占创建相关，**不能**称为路径规范化修复；新参数不开启时有不同路径，且清理竞态风险仍被源说明指出。
- `megavul_291580`：必须保存 `strlen(STATIC_FILE_FOLDER) + n >= MAX_PATH_SIZE` 的拒绝分支，且该样本还存在 `n==0`、长度相加溢出等未处理边界。

## 可复现与责任边界

数据的语义真伪仍依赖原始人工描述质量与更深入的源码/程序语义审核。本知识库属于 **full-coverage, source-grounded extraction**，**不是 1279 条经过模型逐例推理且逐条验证的正式知识**。这是可直接用于检索、抽样评审和后续分析的可用候选知识文件；不应把它作为已证明的漏洞推理规则集用于自动下结论。
