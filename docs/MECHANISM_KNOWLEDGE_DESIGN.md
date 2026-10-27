# 面向安全反证与程序证据验证的知识表示

本模块独立于五字段知识和检测器。入口为 `build_mechanism_knowledge.py` 或
`run_mechanism_pilot.py`，两者调用同一个有样本上限的实现。所有新增模块只依赖
Python 3.10+ 标准库；没有增加训练、GPU、Joern 或智能体依赖。

## 数据模型

`vul_pipeline/mechanism_schema.py` 定义 `VulnerabilityMechanismKnowledge`，以及完整嵌套
JSON Schema。每次试验导出 `knowledge_schema.json`。主类支持严格解析、深拷贝和
JSON 往返；对象字段闭合，禁止悄悄忽略拼错字段，未知值用明确声明表达。

元数据是 `schema_version`（当前 1.0）、`knowledge_id`、`source_sample_id`、
`mechanism_type`、`extraction_model`、`extraction_status`、`validation_status`。
`knowledge_id` 根据样本 ID、原始样本指纹和模式版本确定；模型变化记录在提取日志和模型元数据中。
失败不伪造知识记录：保存在逐样本日志和验证结果里。

| 核心字段 | 内容及提取来源 | 自动验证范围 |
|---|---|---|
| `dangerous_operation` | 第一阶段根据 before/after 和审核说明提取类别、操作语义、角色 `id/meaning/bindings/claim` | 角色绑定表达式和关联引文在同一源码版本中存在；语义是否正确待审 |
| `applicability_conditions` | 第一阶段提取 `id/category/claim`；类别为操作、类型范围、对象状态、执行路径、函数契约 | 状态、来源、未知原因和信息需求；不能把外部依赖标为已确认 |
| `trigger_conditions` | 第一阶段提取行为声明、数值/状态/路径/别名/时序/结构化自然语言关系、角色和前提引用、形式化程度及表达式 | 引用有效性；数值形式化须关联类型范围前提；不强制统一公式，不执行求解 |
| `safety_counterevidence` | 第二阶段结合差分提取安全性质、实际补丁、推导候选和未验证防护、前提、证据任务及无效表面防护 | 实际补丁必须引用 after；候选必须有前提和推导；触发和任务必须能关联；具体语句被声称必要时告警 |
| `required_program_evidence` | 第二阶段生成未来分析任务：`id/evidence_type/role_refs/trigger_refs/question/suggested_analysis/function_source_sufficient/missing_evidence_action` | 类型枚举、任务与角色/约束连接、证据不足必须 `keep_unknown`；不执行这些分析 |
| `provenance_and_boundaries` | 程序直接复制 ID、项目、数据集、CVE/CWE、提交、函数、文件、完整源码、审核标注、来源信息和原样 `keep_reason`；第二阶段只生成边界声明 | 与原样本逐字段比较、整个样本指纹、人工审核范围、不可适用和不可判定边界；人工标注不是证明 |

共有引文数组 `evidence`，包含 `id/version/source_text/origin`。`version` 只能是
`before/after`。程序预装 `review_before_N/review_after_N`，保留审核原文，不剥离空格。
模型可补充 `model_quote`，不能覆盖已存在的引文 ID。证据、角色、触发、前提、任务的 ID
分别属于独立命名空间；在各自空间内唯一，引用必须存在。

每个 `Claim` 都包含：

- `description`、`status`（`confirmed/inferred/unknown`）、`origin`
  （`source_code/review_annotation/derivation/external_context`）。
- `condition_kind`（`necessary/sufficient/candidate/descriptive`）、`evidence_refs`。
- `assumptions`、`rationale`、`unknown_reason`、`depends_on_external_context`、`additional_information`。

`confirmed` 必须是附源码引用的直接事实，而且不能依赖缺失外部上下文。
审核自然语言作为上下文或推导依据，不自动升级为源码事实。
`inferred` 必须记录推导依据；`unknown` 必须解释原因并列出待补信息。
一条合法知识可以包含很多未知项，不能因为未知而被算作模型错误。

防护的 `origin` 与声明状态相互约束：

| 防护来源 | 声明要求 | 含义 |
|---|---|---|
| `actual_patch` | 非未知项必须引用修复版本 | 历史代码实际采用的局部实现；安全有效性可能依赖未知前提 |
| `derived_candidate` | `inferred` + `derivation` + 非空前提 | 从安全性质推导出的待验证候选，不是历史事实或已证等价 |
| `unverified` | `unknown` + 非空前提 | 当前不能验证的其他实现 |

证据任务覆盖全部 11 类：`source_location`、`variable_definition`、`def_use_relation`、
`data_flow`、`control_flow`、`path_condition`、`type_and_range`、`alias_relation`、
`object_lifetime`、`function_contract`、`synchronization`。

## 构建与失败处理

1. 复用原构建器 `validate_source_samples`，检查 schema=2、已审核原始数据、隔离集零重叠、
   样本唯一性、必填字段及 before/after 审核引文存在性；不重新筛选或修改原数据。
2. seed=42 的抽样先覆盖漏洞机制，再在层内优先覆盖修复模式、CWE、项目和数据集；
   剩余名额按 `sqrt(层样本数)/(已选数+1)` 分配。先按样本 ID 排序再打乱，保证输入顺序不影响结果。
   这是机制多样性试验，不是总体分布的无偏估计；缺失标签不推测，也不获得覆盖奖励。
3. 第一阶段提取操作、前提、触发；第二阶段提取反证、证据任务和边界。
   完整源码与实际计算的 diff 都是模型输入；不可信注释只作为数据。
4. 每次可能计费的调用之前原子保存 intent，之后保存原始输出、用量、耗时、请求 ID、返回模型和错误。
   输出截断仍保留接口已返回的 token 用量。格式失败和暂时性网络失败在上限内重试；
   HTTP 400/401/403/404/422 不重试。HTTP 错误正文不写入日志，防止服务端回显密钥。
5. 每阶段完成立即保存。成功记录逐样本原子保存；失败/无效输出只进日志。
   续跑绑定源码指纹、模型、端点、token 上限、超时、提示词和 schema；不匹配时要求新输出目录。
   上次完成的阶段复用；样本失败后默认跳过，显式 `--retry-failed --resume` 才重新请求。
6. 固定集合先跑前 2 或 3 组，全部通过自动校验才继续余下集合。每次最多 40 组，
   每阶段最多 3 次尝试；不允许参数触发 1,279 组全量调用。

输入超过 `max_input_chars` 时拒绝该样本并记录原因，不默默截断源码。
用户显式重新尝试失败样本会新增费用，累计日志保留历史尝试。
原子写入使用同目录临时文件、flush/fsync 和 replace，避免中断损坏已有 JSON。
逐样本日志完成而聚合文件尚未落盘的中断可以从日志恢复。
不支持多个进程同时写入同一个输出目录。

## 校验和质量评价的界限

`mechanism_validator.py` 检查结构、版本归属、原样片段、角色绑定、各类引用、状态约束、
数值公式类型前提和相同触发/安全命题冲突。差分关联只检查实际补丁引文是否与变更行重叠，
结果为 `changed_patch_quote_present/unknown`，不证明该变化充分修复机制。
没有求解任意逻辑矛盾，没有实现 CFG、范围、别名、生命周期或跨函数静态分析。
坐标由实际引文位置计算，原始审核坐标仍保留；重复片段可能存在多处，不能据此确定语义位置。

状态分为 `valid_complete`、`valid_partial_unknown`、`invalid`；评价文件另外区分
`extraction_failed` 和 `not_extracted`。`valid_complete` 只表示结构/引用及显式未知字段的状态，
不代表漏洞或修复被形式化证明。`inferred` 也不会被自动视为事实。

质量代理统计操作是否已描述、角色、关联触发、类型前提、空泛触发措辞标志、
防护来源、分析任务类型和未知项。不会按输出长度打分，所有语义正确性、
无依据断言总数和优胜方法保持待人工审核。

旧基线优先从原知识库按同一 ID 提取并检查元数据；缺失时可使用
`mechanism_baseline.py` 调用原 `_extract_condition_fields/_build_record`，不改原提示词，
不从新表示派生五字段结果。两种方法可观测量分别报告，旧表示没有新字段不算错误。
所有比较维度保留人工填写空间。现有基线没有日志时历史费用未知；token 和费用账本
包含失败/重试调用；接口未返回用量时不能声称总费用为零。

人工表使用 `old_/new_` 前缀填写相同语义比较维度，`review_status=reviewed` 才计入审核数。
重新生成保留人工填写内容；源样本或知识内容变化后旧评分标记 `stale_needs_review`，
保留评分备注但不继续计为已审核。系统不生成模型分数冒充人工结果。
