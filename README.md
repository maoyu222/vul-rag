# Vulnerability Detection from Curated Repair Pairs

## 六层漏洞机制知识试验（独立模块）

新增的安全反证与程序证据需求试验保持原五字段知识和检测决策逻辑不变。
只使用 Python 标准库，固定种子抽样、每次最多 40 组，支持两阶段 DeepSeek 提取、
源码引用校验、断点续跑、同集合原始五字段基线、人工审核表及中文报告。

```bash
conda run -n vul-rag python run_mechanism_pilot.py --precheck --count 40 --seed 42
conda run -n vul-rag python -m unittest discover -s tests -v
```

完整说明见 [表示设计](docs/MECHANISM_KNOWLEDGE_DESIGN.md) 和
[运行指南](docs/MECHANISM_PILOT_GUIDE.md)。实际提取需配置 `DEEPSEEK_API_KEY` 和可访问模型，
运行 `--resume --model <model> --build-baseline`；程序先验证 3 组冒烟，再继续固定集合。
未配置密钥时仅生成预检查和待审核文件，不伪造提取结果或准确率。

This repository uses reviewed C/C++ vulnerability repair pairs to help a code model judge new functions.

The current implementation does **not** use CPG, Joern, graph similarity, or program slices. The method focuses on security conditions that can be transferred from reviewed historical repairs to new source code.

Run the commands below from the repository root with Python 3.10 or newer. Install the local-model dependencies with:

```bash
pip install -r requirements.txt
```

DeepSeek is required only when building the knowledge base. Detection uses the local Qwen model by default, or an OpenAI-compatible local endpoint when `--endpoint` is supplied. If that endpoint exposes more than one model, pass `--endpoint-model` explicitly; the program does not silently choose the first server model.

## Knowledge source

`data/high_quality_repair_pairs.json` is the final curated knowledge-source file.

The current file contains **1,279 repair pairs**. These 1,279 records have already completed the earlier review and selection process, so the builder does **not** filter them again. Every record in `samples` is treated as a knowledge-source sample.

The builder checks only source integrity requirements that are still relevant at build time:

```text
schema_version == 2
rag_knowledge_text_generated == false
heldout_exclusion.final_overlap_counts.CVE == 0
heldout_exclusion.final_overlap_counts.fix_commit == 0
heldout_exclusion.final_overlap_counts.project == 0
sample_id values are unique
required reviewed fields are present
reviewed before/after excerpts occur in code_before/code_after
```

There is no `function_pair_audit` admission step in the current builder. The current source file is already the result of that earlier curation process.

Each sample already contains concise English descriptions of the reviewed local mechanism:

```text
vulnerability_type
unsafe_behavior
security_change
keep_reason
review_annotations.repair_pattern
review_annotations.locations.before/after
```

`keep_reason` records the scope, caveats, and assumptions of the reviewed conclusion. It is copied directly into the generated knowledge record and is **not rewritten by DeepSeek**. A repair pair documents a local security-relevant change; it does **not** imply that the entire patched function is free of every possible vulnerability.

## What one knowledge record means

Each historical repair pair is converted into one reusable **security condition**.

A security condition is the relation that must hold when a security-relevant operation executes. For example:

```text
operation: copy bytes into a destination buffer
roles: copy length, destination capacity
unsafe_when: copy length can exceed destination capacity
security_condition: copy length <= destination capacity
```

A new function does not need to use the same repair syntax. Any visible code that enforces the same relation can satisfy the condition.

The generated knowledge record contains only fields used by the current method:

```text
operation
roles
unsafe_when
security_condition
required_target_facts
assumptions
before_evidence
after_evidence
```

Here, `assumptions` is the original reviewed `keep_reason`, preserved verbatim as one list item. Source ID, project, commit, CVE/CWE, vulnerability type, and repair category are retained as metadata for inspection. They are not used as BM25 retrieval features.

## Build the knowledge base

DeepSeek is used only to extract five structured fields from the already-reviewed English mechanism description:

```text
operation
roles
unsafe_when
security_condition
required_target_facts
```

It is **not** asked to translate the source descriptions, re-decide whether the repair pair is valid, or rewrite the reviewed scope and assumptions.

The model receives only this compact input for each repair pair:

```text
vulnerability_type
repair_pattern
unsafe_behavior
security_change
scope_and_assumptions
before_evidence
after_evidence
```

The builder does not send `function_diff`, full `code_before`, full `code_after`, provenance fields, project metadata, or CVE/CWE metadata to DeepSeek. Full functions are retained in the source file only so the program can verify that every reviewed evidence excerpt is actually present.

Run:

```bash
export DEEPSEEK_API_KEY=...

python build_vulnerability_knowledge.py \
  --input data/high_quality_repair_pairs.json \
  --output artifacts/security_condition_knowledge.json
```

For an initial small run:

```bash
python build_vulnerability_knowledge.py \
  --input data/high_quality_repair_pairs.json \
  --output artifacts/security_condition_knowledge.json \
  --limit 100
```

Use `--resume` to continue an interrupted build. A saved record is reused only when its previously saved compact source input and directly copied metadata still match the current source record.

## Detection flow

For a new function, the detector performs four steps.

### 1. Extract target code facts

The model lists only source-visible facts in four groups:

- `operations`: reads, writes, copies, indexing, arithmetic, calls, allocation/free, locks, permissions, or state operations;
- `value_relations`: visible relations among indexes, lengths, counts, capacities, pointers, offsets, sizes, or states;
- `checks`: visible guards, validation, bounds checks, null/result checks, loop conditions, or early exits;
- `state_changes`: visible lifetime, ownership, lock, permission, or persistent-state changes.

Every fact must include a source excerpt. The program checks that the excerpt is present in the target function before the fact can be used for retrieval. Fact descriptions use concise English; source excerpts remain unchanged.

### 2. Retrieve related historical conditions

BM25 retrieves historical security conditions using the extracted target-code facts.

Retrieval does **not** use function purpose, project name, CVE/CWE, vulnerability label, repair category, or raw historical vulnerable code.

### 3. Check whether each retrieved condition applies

For every retrieved condition, the model must identify the corresponding target operation and map **every historical role** to a target expression.

The program verifies that the quoted operation is present in the target source, that the role mapping contains exactly the historical roles required by that condition, and that every mapped expression is present in the target source. If the same operation and all required roles cannot be established, that historical condition cannot be accepted as `applicable`.

### 4. Check every applicable security condition

Every condition judged applicable is checked; applicable conditions are not silently truncated to a smaller set.

For each applicable condition, the model returns:

```text
violated   - the target visibly allows the unsafe relation
satisfied  - the target visibly enforces the security condition
unknown    - the function alone is insufficient to decide
```

A `violated` or `satisfied` decision must quote target-source evidence, which is checked by the program.

The final label is computed by code:

```text
any applicable condition is violated                      -> vulnerable
no violation, but any applicability decision is uncertain -> unknown
no violation, but any applicable condition is unresolved  -> unknown
one or more conditions apply and all are satisfied         -> benign
no retrieved condition can be shown to apply               -> unknown
```

A condition explicitly judged `not_applicable` does not count against a benign result. A condition whose applicability is still `uncertain` does.

The model does not choose the final label and does not output an uncalibrated confidence number.

The final JSON uses `condition_results` for traceability. It contains one entry for every retrieved condition, including its source sample, CVE when available, operation, security condition, applicability decision, and condition check. `check` is `null` only when the condition was not applicable or remained uncertain.

Therefore an `unknown` final label caused by uncertain applicability remains visible in the normal result JSON, not only in debug files. The final `explanation` is also generated by program logic from these statuses rather than copied from a model-written summary.

## Detect one function

Default local model:

```text
~/models/Qwen2.5-Coder-7B-Instruct
```

Run:

```bash
CUDA_VISIBLE_DEVICES=0 python detect_vulnerability.py \
  --code-file path/to/function.c \
  --knowledge-base artifacts/security_condition_knowledge.json \
  --debug-dir artifacts/detection_debug
```

`--retrieve-k` controls how many historical conditions are retrieved and then checked for applicability. The default is 10.

## Paired evaluation

The repository keeps a small vulnerable/patched diagnostic set:

```bash
CUDA_VISIBLE_DEVICES=0 python evaluate_pairs.py \
  --knowledge artifacts/security_condition_knowledge.json \
  --compare-code-only
```

Before evaluation starts, the program verifies that the case list and metadata list have the same length, that `sample_id` values are unique, that each parallel pair has the same CVE/CWE identifiers, and that the metadata function name occurs in both source variants. Empty CVE IDs are allowed when both files agree. These checks prevent a reordered metadata file from silently evaluating the wrong function pair.

The pair metric requires the vulnerable version to be predicted `vulnerable` and the patched version to be predicted `benign`.

This diagnostic treats the patched version as the expected negative for the **linked repaired vulnerability**. It must not be interpreted as proof that the entire patched function contains no other vulnerability.

The counterpart function, target patch, expected label, and repository context are not sent to the detection model.
