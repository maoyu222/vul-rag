# 复现六层漏洞机制知识试验

在现有项目根目录 `/home/PublicData/LX-data/vul-rag` 执行。新模块只用标准库，
无需安装 `requirements.txt` 中用于本地 Qwen 推理的 torch/transformers/accelerate。
原有五字段和检测决策逻辑保留。

## 环境与离线预检查

```bash
conda run -n vul-rag python --version
conda run -n vul-rag python run_mechanism_pilot.py --precheck --count 40 --seed 42
conda run -n vul-rag python -m unittest discover -s tests -v
```

开始时 `vul-rag` 环境只有创建记录，没有 Python；本次使用本机 Conda 缓存给已有环境
安装了 Python 3.12，没有新建环境，也没有安装或升级模型依赖。
如果在其他机器环境中 Python 已存在，无需执行任何安装步骤。

预检查会验证全部原始数据的完整性，只选择 40 组，写出固定 ID、总体/样本分布、
源数据检查、导出的 JSON Schema、供旧构建器使用的 `selected_source.json` 和待审核报告。
不会生成模拟知识。没有密钥时真实提取未执行，不把这个状态算作模型失败。

## 实际提取

先在本地终端设置环境变量（不要把密钥写进源码或日志），模型名选择账户实际可访问的模型：

```bash
export DEEPSEEK_API_KEY='<your-key>'
conda run --no-capture-output -n vul-rag python run_mechanism_pilot.py \
  --count 40 --seed 42 --model '<accessible-model>' \
  --selected-ids artifacts/mechanism_pilot/selected_samples.json \
  --resume --build-baseline
```

程序先提取固定集合的前 3 组。只有三组均返回完整结构并通过自动校验，才继续后 37 组；
任何冒烟失败都会停止剩余集合及基线请求，保留已得到的记录和错误。
这只检验接口和输出稳定性，不能替代人工语义审核。
可用 `--smoke-count 2` 调整冒烟规模。

默认每组新知识 2 次调用，额外重试上限为每阶段 1 次；40 组新知识正常需 80 次，
默认最坏上限为 160 次。缺失旧基线正常需 40 次，默认最坏上限为 80 次。
上限不是实际调用数；实际次数、失败尝试和 token 用量见 comparison_results.json。
`--retries` 只接受 0..2，`--count` 只接受 1..40。`--build-baseline` 才会额外请求缺失基线。
该参数复用原五字段提示词，基线绝不由新知识转换。

独立入口和其他配置：

```bash
conda run --no-capture-output -n vul-rag python build_mechanism_knowledge.py \
  --input data/high_quality_repair_pairs.json \
  --output-dir artifacts/mechanism_pilot \
  --count 40 --seed 42 --model '<accessible-model>' \
  --base-url https://api.deepseek.com --api-key-env DEEPSEEK_API_KEY \
  --timeout 90 --max-tokens 6000 --max-input-chars 180000 \
  --retries 1 --resume
```

端点配置不能携带 URL 用户名、密码、query 或 fragment，以免凭据进入日志。
单次超时上限 180 秒；前台运行时可按样本进度观察。
不自动探测其他模型或更换模型，模型不可访问时保存错误并停止冒烟扩展。
可把 `--model` 指定为原构建器使用的模型，但是否能访问须以真实接口响应为准。

## 断点续跑和失败重试

```bash
conda run --no-capture-output -n vul-rag python run_mechanism_pilot.py \
  --model '<same-model>' --resume --build-baseline

conda run --no-capture-output -n vul-rag python run_mechanism_pilot.py \
  --model '<same-model>' --resume --retry-failed --build-baseline
```

续跑保持模型、端点、token 上限、超时、重试配置、源码和提示词不变；改变这些配置时
请选择新的 artifacts 子目录，避免混合不同试验。失败默认跳过，第二条命令才新增请求。
已成功的机制阶段可复用，第二阶段失败不会强制重做第一阶段。
同一输出目录的样本 ID、种子或源文件 SHA-256 不匹配时拒绝覆盖。

如果已经存在完整旧库，可指定：

```bash
conda run --no-capture-output -n vul-rag python run_mechanism_pilot.py \
  --model '<same-model>' --resume --baseline artifacts/security_condition_knowledge.json
```

也可以单独运行未经改造的原构建器（无新版逐次 token 日志；若需要完整费用账本，使用上面的 `--build-baseline`）：

```bash
conda run --no-capture-output -n vul-rag python build_vulnerability_knowledge.py \
  --input artifacts/mechanism_pilot/selected_source.json \
  --output artifacts/mechanism_pilot/original_baseline.json \
  --debug-dir artifacts/mechanism_pilot/original_baseline_logs \
  --model '<accessible-model>' --limit 40

conda run -n vul-rag python run_mechanism_pilot.py --validate-only \
  --baseline artifacts/mechanism_pilot/original_baseline.json
```

这两个方式都只处理已固定的同一 40 组；不要对全量数据调用原构建器。

## 校验、人工审核与费用

```bash
conda run -n vul-rag python run_mechanism_pilot.py --validate-only
```

`--precheck` 与 `--validate-only` 都禁止调用 API，即使密钥已配置。
仅验证模式重新读取原始源码校验现有知识，并输出缺失/无效项。修改了固定样本清单时必须
通过 `--selected-ids` 传回相同清单；样本数用 `--count` 匹配。

编辑 `manual_review.csv` 的 old_/new_ 评分、`better_knowledge`、`reviewer`、`review_notes`，
实际审核完成后将 `review_status` 改为 `reviewed`，再运行仅验证命令更新报告。
推荐评分值为 `correct/partial/incorrect/unknown`；无依据断言项填写数量和备注。
不要把模型意见当作人工评分。若知识内容变化，表内原评分保留但标记为 `stale_needs_review`。

`--input-price-per-million` 与 `--output-price-per-million` 可接受账户实际单价；
程序不猜测实时价格或货币。仅对有用量的请求求小计，未报告 token 的请求仍可能计费。
统一输入价不区分缓存折扣，原始缓存命中/未命中 token 另行保留。

## 结果文件

| 文件 | 用途 |
|---|---|
| `selected_samples.json` | seed、源文件哈希和有序固定 ID 清单 |
| `sample_distribution.json` | 抽样算法、总体与样本的机制/CWE/项目/修复/数据集计数、缺失元数据、原始审核证据统计 |
| `selected_source.json` | 原始格式的只读源副本子集，用于公平生成基线；不修改原始数据 |
| `knowledge_schema.json` | 完整六层 JSON Schema |
| `mechanism_knowledge.json` | 实际通过自动验证的知识；未提取时是空数组 |
| `extraction_logs/*.json` | 原始输入、每阶段输出、尝试、usage、失败、校验结果；文件名为样本 ID 的 SHA-256 前 24 位 |
| `baseline_knowledge.json`、`baseline_logs/` | 同一集合的五字段基线及本程序产生的调用账本 |
| `validation_results.json` | 每样本结构/引用/状态检查、未知或失败原因 |
| `comparison_results.json` | 自动代理统计、独立待审语义维度、实际调用和 token、费用基础信息 |
| `manual_review.csv` | 关键 before/after 代码、新旧摘要及保持空白的人工评分 |
| `quality_report.md` | 中文报告，只采用真实运行数字，明确未执行及未审核内容 |
| `runtime.json` | 模式、阻塞原因、冒烟状态、调用上限、源文件未变核验 |

本次环境没有 `DEEPSEEK_API_KEY`，因此已完成代码、离线测试和固定 40 组的预检查，
尚未完成真实 API 提取、旧知识生成和人工语义比较。测试中的合成响应仅用于临时目录，
不写入真实试验 artifacts。也没有运行本地 Qwen 权重推理；相关检测逻辑由现有单元测试回归验证。
