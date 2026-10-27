# 真实数据只读检查与转换契约

原始根目录已确认存在：`/home/PublicData/PHY-data/vul_detect/data`。本模块从不在该目录写入文件。检查记录在 `inspection/dataset_inventory.json`：各文件只采样两条记录，包含大小、字段结构、预览以及读取前后的 size/mtime 比较；它不是全量标签统计，也不能证明所有记录都满足同一结构。后续全量检查/转换会另行产生真实计数，不能把采样数当作数据集大小。

| 目录及文件 | 实际格式、主要字段 | 本阶段处理 |
| --- | --- | --- |
| `PrimeVul_v0.1/primevul_{train,valid,test}.jsonl`，同名 `_paired.jsonl` | JSONL；`idx, project, commit_id, target, func, file_name, cwe, cve` 等；`target` 为 0/1 | 原生普通/配对适配器，显式指定 `v0.1`；保留官方划分 |
| `PrimeVul_original/primevul_{train,valid,test}.jsonl`，同名 `_paired.jsonl` | JSONL；`idx, project, commit_id, target, func, cwe, big_vul_idx, hash` 等；通常缺少 CVE/文件路径 | 原生普通/配对适配器，显式指定 `original`；不与 v0.1 混合 |
| `megavul/megavul.json` | 约 2.67 GB 的顶层函数记录 JSON 数组；`is_vul` 为 JSON 布尔值；`func_before, func, repo_name, commit_hash, parent_commit_hash, file_path, func_name, cve_id, cwe_ids` | 原生普通/配对适配器，流式读取；本实验派生划分 |
| `bigvul/MSR_data_cleaned.csv` | 约 10.8 GB CSV；`vul, func_before, func_after, project, commit_id, lang, file_name, CVE ID, CWE ID` | 提供显式映射框架；未自动推断普通负样本或修复配对 |
| `diversevul/diversevul_20230702.json` | 扩展名 `.json`，实际 JSONL；`func, target, cwe, project, commit_id, hash` | 提供待用户确认的映射示例；不臆造官方 test 划分 |
| `devign/dataset.json` | JSON 数组；`func, target, project, commit_id` | 可用显式映射；无本模块已验证的官方配对键 |
| `reveal/{vulnerables,non-vulnerables}.json` | JSON 数组；`code, hash, project, size`，记录内没有标签字段 | 可显式使用文件级 `label_constant`，必须逐文件确认含义；两个文件需明确命名空间避免 ID 冲突 |
| `cleanvul/vulnerability_score_[0..4].csv` | CSV；`func_before, func_after, vulnerability_score, commit_url, cve_id, cwe_id, extension` 等 | 评分不是已核实的二分类标签，不自动转换 |
| `reposvul/ReposVul_c.jsonl` | 嵌套 JSONL；文件记录的 `details` 中有 `function_before/function_after` 等列表与局部 target | 文件级 target 不向函数继承；不按位置 zip 两个函数列表；原生转换暂未启用 |
| `SecVulEval` | 本地有 parquet 文件 | 未引入 pandas/pyarrow；不声称已验证行内字段 |
| `sven` | 上下文/任务和生成评估相关结构 | 不把生成任务自动当作带二分类标签的独立函数 |

## PrimeVul 配对

普通文件和配对文件是两个独立评估设置，必须分别准备、分别运行。本地配对 test 文件只读逐行检查得到 v0.1 为 870 条、original 为 1,128 条；它们是原始记录数，最终保留多少完整配对以转换报告为准。

配对适配器以官方配对文件相邻两条为候选，再核验标签集合 `{0,1}`、非空 project/commit、相同保守函数名，以及双方都有值时的 filename、big_vul_idx、CVE。并非仅凭偶数行就认定配对。v0.1 中存在一侧 filename=`"None"` 的情况，缺失值不会被拿来制造不相等，也不会被填充成另一侧的值。函数名提取是保守词法提示，复杂声明可能被拒绝；拒绝整个候选对并记录原因，不能静默错配。

`sample_id` 包含数据集版本、官方 split 和原生 idx。旧知识来源的行号 ID 只有在 `pair_provenance.source_path` 与当前源路径后缀一致时才参与 alias 比较，防止 original/v0.1 或普通/paired 文件之间错误对齐。

## MegaVul 标签与划分

普通设置：`is_vul=true → func_before, label=1`；`is_vul=false → func, label=0`。不会将 true 记录的修复后 `func` 再加入普通负样本。

配对设置：仅 true 记录产生 before/after 两个函数，标签为 1/0，`label_scope=linked_repair`；普通负样本在配对设置中明确记录为“不属于漏洞修复对”。after=0 仅代表关联目标漏洞已修复，不能据此证明不存在任何其他漏洞。

MegaVul 不冒充官方 test。按共享项目（默认）/提交、规范化代码哈希、pair_id 建立连接分量，再以固定 seed 和 SHA256 划分 train/valid/test，默认概率 0.8/0.1/0.1。分量不拆分，实际比例可能偏离目标；项目少、连接分量大时甚至可能有空集合，报告会如实保留空文件。`--group-by commit` 是另一个实验设置，不能事后为追求分数切换。

普通与配对转换的样本全集不同，连接分量也可能不同，分别记录各自划分与版本，不能把二者的 split 当作相同样本集合；跨设置的统一 held-out 研究需先冻结共同划分方案。未来 RAG 比较直接复用已冻结的同一 `samples.jsonl`，无需再次划分。

## 质量与隔离

- 源码只在哈希时做词法规范化；传给模型的 `code` 不重写、不删注释、不做 AST 修复。哈希保留字符串内容，删除注释及 token 间空白；它是版本化词法指纹，不是语义等价证明，预处理器等边界仍需审阅候选。
- 空代码、非法标签、明确非 C/C++ 语言会被拒绝并写入 `rejected.jsonl`。原始记录不变。NVD 无 CWE 信息/Other 记为 CWE 缺失，原始注释字段仍保留；没有可靠 CVE/项目等元数据时留空，不编造。
- 默认 `--deduplicate keep` 保持合法官方样本及标签；重复与标签冲突只报告。严格视图额外排除规范化代码标签冲突及其完整配对。可显式选择 within-split 去重普通样本，此时应称“去重派生视图”，不能与未过滤官方指标混写。
- `official/` 表示保留官方标签/划分的可用记录；原始格式或配对校验失败仍会拒绝，必须同时报告原始/保留数量与拒绝原因。MegaVul 的该目录只是未做知识隔离的派生基准视图。
- `strict/` 排除与 `data/high_quality_repair_pairs.json` 匹配的 sample_id、CVE、fix_commit、project、规范化 before/after 代码哈希，默认启用全部五项。任何一侧匹配会排除完整配对。报告分别列出直接匹配和配对闭包后的各规则计数，规则之间可重叠，不能相加作为总数。
- `--isolation-rules` 可配置；`none` 显式关闭知识排除。关闭规则后的结果不能称为同一严格隔离设置。读取知识来源仅用于离线排除，绝不进入推理提示词。
- 项目名只做 URL 路径、大小写和 `.git` 规范化，不擅自把 `repo` 与 `owner/repo` 认作同一项目。可在许可目录维护经核实的 `--project-aliases` JSON（键和值均用规范化名称）。例如确认后才添加 `"ffmpeg/ffmpeg": "ffmpeg"`。元数据缺失、提交缩写和项目别名可能造成漏检；“没有检测到重叠”不等于证明没有泄漏，更不能保证模型预训练数据不重叠。
- 转换的 `--reference` 对其他标准化文件做 CVE/提交/代码交叉审计，不自动改写官方划分。`audit_dataset.py` 可对多个数据集或官方 train/valid/test 文件集中核验跨集合重复与修复对完整性。普通/配对、official/strict 应分别审计，不要把同一 cohort 的两个视图并成一个数据集。
- 近重复审计使用 5-token shingles、bottom-32 sketch、0.8 候选阈值；最多索引前 20,000 个可构造 sketch 的函数，每桶最多 100 个 ID，最多输出 5,000 个候选。后续函数仍与已索引候选比较。报告包含未索引数和桶丢弃数；该审计有明确覆盖限制，不自动删除近重复，不能声称已完成全量语义去重。设 limit=0 会禁用该候选审计。

转换按记录流式读取源码，但分组、隔离和候选索引需要 O(n) 元数据内存；SQLite 暂存及标准化双视图需要额外磁盘空间。它没有把数 GB 原始 JSON 一次性加载到内存，也不会复制原始文件。所有暂存、索引和转换结果均在本实验目录中。
