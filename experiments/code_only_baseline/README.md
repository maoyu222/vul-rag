# 无知识增强 C/C++ 函数漏洞检测二分类基线

本模块是独立的零样本基线：每次只发送一个函数源码以及固定中文提示词，使用已运行的 OpenAI-compatible vLLM 服务，不启动服务、不下载或加载模型、不训练、不检索知识。没有导入现有 RAG 推理流程，也不修改原有 qwen.py、知识库、1,279 组修复对或旧实验结果。

设计沿用 `qwen_vuln_batch_eval_bundle/qwen_vuln_batch_eval.py` 已有的 httpx 异步请求、有限队列、逐条 JSONL/fsync 和配置记录思路；在独立模块中补上真实数据适配、严格二分类 JSON 输出语义、样本指纹、冻结 cohort、全样本失败统计和配对指标。旧脚本的提示词、结果格式与本模块不同，不直接混合结果文件。

本模块仅保留严格二分类：模型只能输出 `vulnerable → 1` 或 `benign → 0`，没有 unknown 类。提示词名称为 `code_only`，文件为 `prompts/system.txt` 和 `prompts/user.txt`；即使信息不完整也必须二选一，证据局限写入 reason。

接口失败、无效 JSON、第三种标签和截断均属于运行错误 `error`，不是预测类别，不会强制映射为 0 或 1；可通过失败重试入口处理。已有标准化测试数据可以直接复用。运行配置、提示词或协议发生变化时使用新目录，不能将不匹配的预测混入同一次实验。

交付阶段只完成代码、只读数据检查、文档和测试代码；**没有执行单元测试、真实模型推理或正式转换实验**。下面命令供用户后续手动执行。

## 环境与写入边界

已检查的环境：

```text
Conda 名称: vul-rag
Python: /home/luoxiao/miniconda3/envs/vul-rag/bin/python
环境目录: /home/luoxiao/miniconda3/envs/vul-rag
唯一第三方必需依赖: httpx（现有 0.28.1）
```

Python 要求 3.11+（使用 asyncio.TaskGroup）；数据、配置、指标及测试其余部分均使用标准库，不需要 pandas、sklearn、torch、transformers 或本地模型文件。现有 httpx 满足要求，本次没有安装/升级软件，也没有修改 Conda 环境。

所有输出被限制在 `experiments/code_only_baseline/` 内。入口在导入项目模块前关闭 bytecode 写入，并将临时目录与缓存定位到模块的 `.runtime/`；SQLite 临时存储使用内存。不要将本模块移动到授权目录外，也不要把输出路径指向原始数据目录。原始数据仅以只读模式打开。

先在终端设置：

```bash
conda activate vul-rag
cd /home/PublicData/LX-data/vul-rag
export EXP=/home/PublicData/LX-data/vul-rag/experiments/code_only_baseline
export DATA_ROOT=/home/PublicData/PHY-data/vul_detect/data
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$EXP/.runtime/tmp" "$EXP/.runtime/cache" "$EXP/.runtime/pip-cache"
export TMPDIR="$EXP/.runtime/tmp"
export XDG_CACHE_HOME="$EXP/.runtime/cache"
export PIP_CACHE_DIR="$EXP/.runtime/pip-cache"
python -c 'import sys,httpx,pip; print(sys.executable); print(sys.prefix); print(pip.__file__); print(httpx.__version__)'
```

如环境以后变化，先确认 Python/pip 均属于以上环境。当前无需执行 pip install。`requirements.txt` 只列出 httpx；不要为运行此基线安装 GPU 推理包或更换环境。

## 1. 只读检查

```bash
python "$EXP/inspect_datasets.py" --data-root "$DATA_ROOT" \
  --sample-records 3 --output "$EXP/inspection/manual_schema.json"
```

默认只采样字段，完整已核实结构、标签边界和适配范围见 [DATASETS.md](DATASETS.md)。需要准确数量、原始标签频次及规范化重复数时，显式进行全量流式扫描（不请求模型）：

```bash
python "$EXP/inspect_datasets.py" --data-root "$DATA_ROOT" --dataset PrimeVul_v0.1 \
  --full-counts --output "$EXP/inspection/primevul_v01_full.json"
```

不选择 dataset 而启用 full-counts 会读取所有配置文件，包含很大的 BigVul/MegaVul。原始标签频次不代表已确认标签语义；CleanVul score、ReposVul 文件级 target 不会因此被当作函数二分类标签。

## 2. 准备 PrimeVul

每个输出目录必须是新目录。以下普通和配对 test 分别生成 `official/test.jsonl`、`strict/test.jsonl`、冻结 sample_manifest、隔离及质量报告。正式原始文件不复制、不修改。

```bash
python "$EXP/prepare_dataset.py" --dataset PrimeVul --version v0.1 \
  --data-root "$DATA_ROOT" --split test --mode ordinary \
  --output "$EXP/data/primevul_v01_ordinary"

python "$EXP/prepare_dataset.py" --dataset PrimeVul --version v0.1 \
  --data-root "$DATA_ROOT" --split test --mode paired \
  --output "$EXP/data/primevul_v01_paired"
```

original 版改为 `--version original` 并使用另一个输出目录。不要混合版本。训练/验证数据需要时显式使用 `--split train` 或 `--split valid`，各自单独输出；test 转换不会随机混入训练样本。

默认严格隔离启用 sample_id、CVE、fix_commit、project、code_hash 五项，对知识来源任一侧命中都会排除整对。自定义时显式记录，例如：

```bash
python "$EXP/prepare_dataset.py" --dataset PrimeVul --version v0.1 --mode ordinary \
  --isolation-rules sample_id,cve,fix_commit,project,code_hash \
  --project-aliases "$EXP/mappings/project_aliases.example.json" \
  --output "$EXP/data/primevul_v01_alias_reviewed"
```

空 aliases 示例不会自动推断项目对应关系；请在审阅后维护规范化别名。`none` 关闭知识排除，不应再声称与默认严格隔离设置等价。合法官方标签冲突默认在 official 中保留、strict 中排除；空代码等原始不可用记录会记录拒绝原因和数量。先审阅 `data_quality_report.json`，如果严格集合为空，应如实报告并检查隔离规则，不能为提高结果临时放宽。

## 3. 准备 MegaVul

`--version` 是用户确定的快照名；程序还会保存原始文件 SHA256，因此同名快照内容变化可以被发现。

```bash
python "$EXP/prepare_dataset.py" --dataset MegaVul --version local_snapshot_20261027 \
  --data-root "$DATA_ROOT" --mode ordinary --seed 42 --group-by project \
  --ratios 0.8 0.1 0.1 --output "$EXP/data/megavul_ordinary"

python "$EXP/prepare_dataset.py" --dataset MegaVul --version local_snapshot_20261027 \
  --data-root "$DATA_ROOT" --mode paired --seed 42 --group-by project \
  --ratios 0.8 0.1 0.1 --output "$EXP/data/megavul_paired"
```

该 test 是实验派生划分，不是官方测试集。普通设置不把已修复代码自动当作新的普通负样本。配对设置的 after=0 只针对关联漏洞。转换/分组需要一定内存及磁盘；不会一次性加载整个 2.67 GB 原始 JSON。

其他数据集必须使用明确映射，示例 `mappings/diversevul.example.json` 默认 `verified_by_user=false`，确认字段、语言范围和标签定义后才改为 true。指定 `--input`、`--mapping`、`--version` 和明确 split；非原生适配器不会猜测官方划分或修复配对。

## 4. 跨数据集/划分审计

转换时可重复传入 `--reference 标准化文件`，审计已准备好的其他数据。也可以独立运行：

```bash
python "$EXP/audit_dataset.py" \
  --input "$EXP/data/primevul_v01_ordinary/official/test.jsonl" \
  --input "$EXP/data/megavul_ordinary/official/test.jsonl" \
  --output "$EXP/audits/ordinary_cross_dataset"
```

要核验官方 train/valid/test 间精确重复和配对跨集合问题，先分别准备对应官方 split，再在同一 audit 命令中提供这些标准化文件。近重复仅为有覆盖限制的词法候选，详见 DATASETS。审计发现的问题不会自动改变官方标签或划分，需要在实验报告中说明处理设置。

## 5. 配置双服务器 API

项目位于 `192.168.31.237`；模型文件 `/home/phy/models/Qwen2.5-Coder-7B-Instruct` 位于 `192.168.31.238`。本模块只通过网络调用模型服务，不把这个路径当作当前机器的本地文件。

本次没有探测或更改模型服务。先在模型服务器只读核实实际监听端口与 served model ID；**不要假定端口是 8000**。将确认后的完整 API 前缀写入环境变量，例如在 shell 中把占位符替换为实际值：

可先在 `192.168.31.238` 的终端执行只读命令 `ss -ltnp` 核实监听地址与端口。

```bash
export VLLM_BASE_URL='http://192.168.31.238:实际端口/v1'
export VLLM_API_KEY='由服务配置决定，没有鉴权时可以不设置此变量'
```

没有鉴权时请 `unset VLLM_API_KEY`，不要发送示例文字作为 Key。也可使用 `--base-url`、`--model`、`--api-key`；推荐 Key 通过环境变量传入，避免写入 shell 历史。配置和日志不保存 Key。

设置完实际地址和鉴权变量后，可在项目服务器执行只读 GET 核实 API 连通性及 advertised ID（不生成推理）：

```bash
python -c 'import os,httpx; key=os.getenv("VLLM_API_KEY", ""); r=httpx.get(os.environ["VLLM_BASE_URL"].rstrip("/")+"/models", headers={"Authorization":"Bearer "+key} if key else {}, timeout=10, trust_env=False); r.raise_for_status(); print([m["id"] for m in r.json()["data"]])'
```

`config.json` 默认 base_url=null，地址未确认时程序会拒绝运行。正式执行时先 GET `/models` 校验模型 ID，再 POST `/chat/completions`；若服务确实不支持 models 端点，可显式 `--skip-model-check`。默认 JSON 模式为 json_object；服务不支持时可在**新运行目录**显式改为 `--json-mode none`，解析仍严格执行相同 schema；不自动改变配置或降级。

支持 `--base-url --model --api-key --concurrency --timeout --max-retries --temperature --max-tokens --seed --max-code-chars --json-mode`。默认温度 0、并发 4、每次请求超时 120 秒、最多额外重试 2 次、输出上限 1024 tokens。超时、网络异常和 408/409/429/部分 5xx 有界重试，普通 4xx、格式错误不自动反复请求。若输出被 length 截断，记 error，不能当 benign。

固定超长策略：超过 30,000 个 Unicode 字符就记 `error/input_too_long`，不截断、不 POST。这是明确的字符预算而非 tokenizer 的上下文保证；字符预算内仍可能超过服务 token 限制，此时保留 HTTP 错误和原始响应。改变预算或 max_tokens 应新建运行，不应逐样本按真值调整。

## 6. 先运行少量样本

以下命令会调用模型，属于用户后续手动执行步骤；交付时没有执行。

```bash
python "$EXP/run_baseline.py" \
  --input "$EXP/data/primevul_v01_ordinary/strict/test.jsonl" \
  --output "$EXP/runs/primevul_v01/strict/Qwen2.5-Coder-7B-Instruct/code_only/pilot_seed42" \
  --model Qwen2.5-Coder-7B-Instruct --dataset PrimeVul --seed 42 --limit 20 \
  --temperature 0 --concurrency 2 --timeout 120 --max-retries 2 --max-tokens 1024
```

若 `/models` 公布的是其他 served ID，以实际 ID 替换 `--model`。选择基于 seed 和 sample/pair ID 的稳定哈希，不读取真值决定抽样；limit 是函数数上限，配对总是整对选取，奇数上限可能少一个函数，配对 limit=1 会明确失败。默认只选择 `split=test`；其他 split 需要显式指定。该 cohort 的 `samples.jsonl` 将保存实际选中样本。

配对试运行换成 paired 输入和新的输出目录即可；不要将普通与配对文件传入同一 run。不同数据集可用多个 `--input` 合并，但有 sample_id 重复会拒绝；评估仍按数据集和版本分开报告。

## 7. 完整运行、续跑、失败重试

全量运行使用新目录，并去掉 limit；pilot 目录不能直接变成 full，cohort 改变会被拒绝。

```bash
python "$EXP/run_baseline.py" \
  --input "$EXP/data/primevul_v01_ordinary/strict/test.jsonl" \
  --output "$EXP/runs/primevul_v01/strict/Qwen2.5-Coder-7B-Instruct/code_only/full_seed42" \
  --model Qwen2.5-Coder-7B-Instruct --seed 42
```

中断后重复**完全相同**的原命令并追加 `--resume`。程序核验输入文件全量 SHA256、冻结 cohort、模型与生成配置、提示词及实现源码指纹；任何改变都拒绝复用，要求新建目录。每个运行持有独占文件锁，避免两个进程写同一结果。

已成功的二分类预测不会重复调用；默认 resume 只处理尚未完成的样本，已有 error 保留。要同时重试 error：

```bash
python "$EXP/retry_failed.py" \
  --input "$EXP/data/primevul_v01_ordinary/strict/test.jsonl" \
  --output "$EXP/runs/primevul_v01/strict/Qwen2.5-Coder-7B-Instruct/code_only/full_seed42" \
  --model Qwen2.5-Coder-7B-Instruct --seed 42
```

重试 pilot 时还要保留原来的 limit、concurrency 等参数。error 重试是新记录追加，旧记录不删；指标取每个 ID 的最后记录。模型若仍返回第三种标签，按 `error/invalid_label` 保存，可单独重试，不接受为完成的分类结果。

程序在 POST 前记录 started，在响应后记录 finished，每条完成预测 fsync。若 finished 已落盘而结果尚未来得及写入，会在 resume 时从日志恢复已接受的回答。只有 JSONL 最后一条未完成记录允许恢复，先将其原始字节存为 recovery 文件再处理尾部；中间损坏直接报错。已发送但尚无 finished 日志的请求可能仍在服务器运行，HTTP 接口没有跨进程 exactly-once 保证，恢复后可能需要重新请求；不会声称这些请求没有 token 成本。

## 8. 离线评估

停止写入后执行，不调用模型：

```bash
python "$EXP/evaluate.py" \
  --run-dir "$EXP/runs/primevul_v01/strict/Qwen2.5-Coder-7B-Instruct/code_only/full_seed42"
```

默认写该运行自己的 metrics.json，可指定模块内部的 `--output`。程序从冻结的 samples.jsonl 取金标与元数据，将缺失预测计为 not_completed，而非丢弃。普通函数和配对函数分别报告，按数据集/版本、CWE 及 dataset+CWE 细分；支持数小于 20 时标注 small_support。多 CWE 是重叠统计，不能相加作为总体样本数。

- 全样本：accuracy=(TP+TN)/全部样本；error/not_completed 均不算正确；报告扩展运行状态表、二分类覆盖率及失败比例，不报告 unknown 类别或比例。
- 类别召回与 F1 将该类的失败/未完成视为漏检，报告 `f1_with_positive_failures_as_misses` 和 `macro_f1_with_class_failures_as_misses`；FPR=FP/全部负类，FNR=FN/全部正类，并另外报告漏检或执行失败合并比例。
- 有效二分类预测：完整 Accuracy、Precision、Recall、F1、Macro-F1、MCC、Balanced Accuracy、FPR、FNR、TP/FP/TN/FN，标为 conditional_binary_only，同时必须展示全样本完成率和失败数。执行失败尚未解决时全样本 MCC 为 null；所有请求成功后，两种口径一致。
- 配对：before 正确、after 正确、整对完全正确、合理 1→0 变化、同时 1、同时 0、反向 0→1、未完成/失败比例。分母为全部 pair groups，不丢弃失败、缺失或异常配对。合理变化与完全正确在离散二分类定义下相同。
- 不计算伪造的 ROC-AUC。token 费用从所有请求日志累计，包括重试；服务缺失 usage 或请求中断时，只报告可观察下界，total_tokens 为 null。请求平均耗时是已完成 HTTP 请求的平均值，不冒充整个实验墙钟时间。

解析接受严格 JSON 或包围整个 JSON 的 Markdown fence；label 仅允许 vulnerable/benign。缺字段、非法标签（包括 unknown）、额外字段、类型错误、截断、非源码 evidence 均记 error。evidence 仅作字面摘录存在性验证，不证明推理正确；空 evidence 被显式标记，不增加用户未要求的强制拒绝规则。若现有 vLLM 版本支持 `--json-mode guided_json` 对应接口，可显式开启 schema 约束生成；默认 json_object 仍由本地解析器严格核验标签。

## 文件含义与复用

| 文件 | 含义 |
| --- | --- |
| `preparation_manifest.json` / `data_quality_report.json` | 原始文件哈希、版本、转换规则、计数、拒绝与隔离统计 |
| `official/*.jsonl` / `strict/*.jsonl` | 两种明确分离的评估视图；空集合也保留空文件 |
| `sample_manifest.jsonl` | 转换后的 ID、标签、pair、哈希及 strict 是否保留 |
| `rejected.jsonl` / `exact_duplicates.jsonl` / `near_duplicate_candidates.jsonl` | 数据质量与配对拒绝、精确重复及近重复候选 |
| `knowledge_overlap.jsonl` / `reference_overlap.jsonl` | 知识来源匹配及已指定其他数据集/划分重叠 |
| `normalized_cache.sqlite3` | 转换工作索引，不是原始文件副本 |
| `run_config.json` / `runtime.json` / `service_check.json` | 冻结配置、提示词及实现指纹、Python/httpx 版本、实际服务模型检查 |
| `samples.jsonl` | 本运行实际 cohort；复用这个文件进行后续逐样本比较 |
| `requests.jsonl` | 每次 HTTP 尝试的 started/finished、原始回答、usage、耗时与失败原因 |
| `results.jsonl` | 逐样本预测；重试追加历史，按 sample_id 取最新版本 |
| `run_cache.sqlite3` / `run.lock` | 可从冻结样本和日志重建的索引、进程独占锁 |
| `run_summary.json` / `metrics.json` | 完成进度、包含缺失预测的离线统一指标 |
| `recovery_*.json` | 中断时不完整 JSONL 尾部的原始字节备份 |

原始源码与标签只在管理文件中保存；网络请求中没有真实标签、CVE/CWE、配对关系、另一版本或知识内容。源码自身已有的注释/字符串按原样保留，不向其中注入字段提示。

未来 RAG 方法应只读复用本运行的 samples.jsonl、sample_id、sample_hash、samples_sha256 和 pair_id，在新目录保存 RAG 结果，再按 ID 一对一比较；不得重新按预测正确与否筛选样本、改标签或覆盖本基线。official 与 strict 的比较必须分别进行，不能合并成同一实验设置。RAG 的模型输入投影也必须排除金标及配对补丁，本模块没有替未来 RAG 自动实施该逻辑。

## 测试与建议执行顺序

测试只使用合成 fixture 和 httpx.MockTransport，不会读取正式数据或请求 GPU。本次按任务要求只编写、不执行。后续可手动执行：

```bash
python -B -m unittest discover -s "$EXP/tests" -v
```

测试临时目录由 bootstrap 固定到 `$EXP/.runtime/tmp`，没有新增 pytest 依赖。建议顺序：环境只读核验 → 手动离线单元测试 → 数据结构检查 → 转换 → 审阅隔离/跨集合审计 → 确认已有 API 地址与模型 ID → 20 个函数 pilot → 离线评估和原始回答检查 → 新目录全量实验 → 冻结供 RAG 对照。

所有入口支持 `--help`。本次未启动/停止 vLLM、未训练或微调、未下载模型、未执行真实推理、未安装依赖、未修改正式数据及既有实验。
