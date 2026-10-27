# Qwen2.5-Coder-7B-Instruct：C/C++ 漏洞检测批量评估

适用于已经在 `192.168.31.237` 启动的 **vLLM 0.7.0** 本地服务，地址为 `http://127.0.0.1:8000/v1`。这是**独立的评估客户端**，不会修改你现有的 `vul-rag` 代码或推理服务参数。

## 1. 准备

把 `qwen_vuln_batch_eval.py` 和示例 `qwen_vuln_sample.jsonl` 放到 `/home/PublicData/LX-data/`，例如使用 VS Code 文件上传。

打开新的终端（原来运行 `vllm serve` 的终端保持开启），**可以使用 `vul-rag` Conda 环境运行评估客户端**：

```bash
conda activate vul-rag
python -m pip install 'httpx>=0.24,<1' -i https://pypi.tuna.tsinghua.edu.cn/simple
cd /home/PublicData/LX-data
curl http://127.0.0.1:8000/v1/models
```

> 运行脚本的客户端环境不需要 CUDA 或 PyTorch；模型由另外一个正在运行的 `qwen-vllm` 进程负责。

## 2. 输入数据 JSONL

每行必须是一个 JSON 对象，包含：

- `id`：唯一的字符串或整数样本编号，推荐字符串；
- `label`：真实标签，`1` = 有漏洞，`0` = 无漏洞；
- `code`：对应函数或代码片段，必须是字符串，包含换行时使用 JSON 转义 `\n`。

例如：

```json
{"id":"vul_001","label":1,"code":"void copy(char *src) { char buf[16]; strcpy(buf, src); }"}
{"id":"safe_001","label":0,"code":"int f(int x) { return x + 1; }"}
```

模型**不会收到真实标签**。标签只在客户端汇总指标时使用。

## 3. 首次小规模试运行

```bash
python qwen_vuln_batch_eval.py \
  --input qwen_vuln_sample.jsonl \
  --output-dir qwen_eval_runs/smoke_test \
  --concurrency 2
```

如果示例成功，再运行真实数据集：

```bash
python qwen_vuln_batch_eval.py \
  --input /home/PublicData/LX-data/your_dataset.jsonl \
  --output-dir /home/PublicData/LX-data/qwen_eval_runs/dataset_v1 \
  --concurrency 4 \
  --max-tokens 512 \
  --max-code-chars 7000 \
  --limit 50
```

检查 `results.jsonl` 后，**原样重新执行上述命令并去掉 `--limit 50`**，会跳过已完成且状态为 `ok` 的样本，继续处理其他样本。对于失败、格式错误、过长样本，会在下次运行时重试或重新记录状态；同一个 `id` 的最新结果用于指标计算。

> 默认最大并发 4，与你目前 vLLM 启动参数 `--max-num-seqs 4` 对齐，方便初始稳定性测试；这不是吞吐优化的唯一最佳值。正式评估可以逐渐测试不同并发度和上下文限制。

## 4. 输出文件

输出目录中有三个主要文件：

- `results.jsonl`：追加式明细日志，记录 id、真实标签、预测标签、漏洞类型、代码证据、触发条件、安全反证、分析理由、原始文本、状态、请求耗时、token 用量、错误等。
- `metrics.json`：TP、FP、FN、TN、Precision、Recall、F1、Accuracy、FPR、有效样本覆盖率、各状态数量。
- `run_config.json`：模型、提示词、结构化约束、生成参数和配置指纹。

`prediction=1` 是漏洞，`prediction=0` 是无漏洞，`prediction=null` 是不确定或失败。只有 `status=ok` 且预测为 0/1 的样本参与指标计算。

**论文实验报告必须同时报告覆盖率**；不能因为忽略不确定和错误样本而夸大准确率。

## 5. 断点续跑与论文复现

- 同一个 `--output-dir` 且配置未变化时自动断点续跑。
- 输入样本 `id` 和代码/标签的哈希用于检查是否改动；若不一致则拒绝覆盖旧记录。
- 调整 `--max-tokens`、`--max-code-chars`、`--no-guided-json`、模型或提示词后，应新建输出目录，避免混合不同实验配置。
- 每个完成的结果写入并同步到 `results.jsonl`，可在运行中读取；正常停止后更新 `metrics.json`。
- `--limit` 和 `--concurrency` 可以在续跑时变化，不改变模型输入/生成配置。

## 6. 常见问题

- **无法访问本地 API**：检查原终端的 `vllm serve` 是否还在运行，以及 `curl http://127.0.0.1:8000/v1/models`。
- **服务报告显存不足**：先把 `--concurrency` 降为 `1` 或 `2`，适当缩短提示词；必要时重新启动 vLLM 调整最大上下文/显存参数。
- **API 返回 400，并提示 guided_json/xgrammar**：试用 `--no-guided-json`，同时必须换一个 `--output-dir`；关闭强制结构约束后仍有本地解析校验，无效输出不会自动当作安全样本。
- **请求提示超过最大上下文长度 4096 Token**：目前字符上限只是粗略保护，并不是严格 Token 计数。不要静默截断源码；先标记错误，后续选择更长上下文的服务或经过可复现的上下文筛选流程。
- **请求被中断**：重新运行同一命令，已记录的 `ok` 会自动跳过。
- **NVML 报警**：模型服务端之前存在异常的 GPU 0；客户端脚本不访问显卡，也不修改驱动。

## 7. 测试说明

代码已通过 Python 语法检查，并在本地模拟的 OpenAI 兼容 HTTP 服务上测试了并发调用、结构化解析、追加记录、分批处理、自动跳过成功样本以及指标计算。**未连接或测试你 `192.168.31.237` 上的真实 Qwen 服务**，因此首次请用示例数据小规模验证。
