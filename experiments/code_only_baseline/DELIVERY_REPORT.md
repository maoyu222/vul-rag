# 基线模块交付记录

基线代码与文档位于 `/home/PublicData/LX-data/vul-rag/experiments/code_only_baseline/`，仅保留严格二分类实现。没有修改模块以外的既有项目文件，包括 `vul_pipeline/qwen.py`、知识检索逻辑、知识库、1,279 组修复对、`qwen_eval_runs/` 和旧批量检测 bundle。没有提交/推送代码，没有访问或修改模型服务器配置。

## 严格二分类

只接受 `vulnerable=1`、`benign=0`。提示词为 `prompts/system.txt`、`prompts/user.txt`，名称为 `code_only`。允许第三种预测标签的提示词已删除，不保留多套提示词或编号命名。

schema 枚举、解析器、断点恢复与指标均只接受二分类成功结果；第三种标签记 error/invalid_label，可重试，绝不伪造为某个二分类标签。请求异常和未完成仅作为运行状态统计，不作为第三预测类别。代码引用、单元测试和文档均已同步。

运行协议名称为 `code_only_baseline`，指标 schema 名称为 `code_only_metrics`。配置、提示词和协议指纹用于校验实验一致性，不匹配时拒绝复用结果。已准备的标准化数据无须改标签或重建。此次清理未执行单元测试或真实推理，也未重新读取正式数据；仅进行源码静态检查。

27 个 Python 文件及 3 个配置/映射 JSON 语法检查通过，20 项测试仅编写未执行；二分类 schema 声明只有 vulnerable/benign。静态检查统一记录在 `inspection/static_validation.json`。

## 环境与依赖

只读核实的 Python 为 `/home/luoxiao/miniconda3/envs/vul-rag/bin/python`，版本 3.12.14，prefix 为 `/home/luoxiao/miniconda3/envs/vul-rag`。pip 位于该环境的 `lib/python3.12/site-packages/pip/__init__.py`。必需的 httpx 0.28.1 已在该环境的 site-packages 内，未安装、升级或删除任何依赖，没有实际使用目录外写入例外。

没有创建 Conda 环境，没有修改系统 Python、其他环境、用户/系统 pip/Conda 配置，没有使用 sudo。运行期临时目录和缓存由模块 bootstrap 固定在本模块 `.runtime/`；此次工具命令也使用该处 TMPDIR 并禁用 Python bytecode 写入。

## 数据访问与执行边界

已只读检查正式根目录 `/home/PublicData/PHY-data/vul_detect/data` 的实际文件、代表记录及 PrimeVul 配对上下文。字段预览见 `inspection/dataset_inventory.json`；该检查是采样，不是全量正式转换。另只读检查现有项目脚本与知识来源 schema，用于兼容设计和隔离索引字段确认。

本次没有对原始数据执行写入、覆盖、删除、重命名或移动，没有在原始目录创建任何日志、索引、缓存、转换文件或临时文件。检查记录包含被采样文件读取前后 size/mtime 未变的结果。所有新增代码及输出都在授权的 LX-data 内。

没有运行真实推理、小规模 GPU 试验、正式批量检测、训练或微调；没有启动/停止/重启 vLLM，没有下载模型。没有执行单元测试，遵守原始开发任务“只编写测试代码，不执行测试”的要求。

静态检查仅用 `ast.parse` 读取 Python 源码并解析配置 JSON，不导入或执行新实验模块。27 个 Python 文件、3 个配置/映射 JSON 无语法错误，环境信息与执行边界记录在 `inspection/static_validation.json`。静态语法通过不等于测试通过或正式实验可用性已经验证。

## 新增文件清单

```text
README.md                          中文分阶段命令、配置、指标定义、恢复与公平比较说明
DATASETS.md                        真实数据结构、标签/配对/划分/隔离边界
DELIVERY_REPORT.md                 本记录
requirements.txt                  唯一必需第三方依赖 httpx
config.json                       可覆盖的推理参数；服务地址未假定
_bootstrap.py                     关闭 bytecode，限制缓存和临时文件位置
inspect_datasets.py               小样本字段检查；可选全量计数/原始标签/重复扫描
prepare_dataset.py                原始数据只读转换，分别输出 official/strict
audit_dataset.py                  多文件跨数据集/划分与完整配对审计
run_baseline.py                   并发零样本请求入口
retry_failed.py                   错误/未完成任务续跑入口
evaluate.py                       独立离线指标入口
prompts/system.txt                严格二分类系统提示词
prompts/user.txt                  严格二分类用户模板，只插入 code
mappings/diversevul.example.json   默认禁用、需要确认的显式字段映射示例
mappings/project_aliases.example.json  默认空的项目别名配置
src/__init__.py
src/io_utils.py                   写入边界、原子 JSON、fsync 追加、哈希
src/readers.py                    流式 JSON 数组/JSONL/CSV
src/normalization.py              C/C++ 词法指纹、元数据规范化
src/schemas.py                    统一样本及标签验证
src/leakage_check.py              五项知识隔离、连通分组、有限近重复候选
src/preparation.py                转换、质量报告、双视图及冻结样本 manifest
src/prompts.py                    独立提示词加载及 SHA256
src/output_parser.py              JSON/围栏/非法/截断与源码 evidence 核验
src/vllm_client.py                httpx 异步 API、超时、限流、退避、usage
src/checkpoint.py                 锁、冻结 cohort、配置校验、日志恢复与断点索引
src/runner.py                     有限队列 producer/worker/writer
src/metrics.py                    全样本/条件二分类、CWE/数据集/配对指标
src/adapters/__init__.py
src/adapters/base.py
src/adapters/primevul.py           v0.1/original 官方普通及配对文件
src/adapters/megavul.py            实际 flat is_vul/func_before/func 契约
src/adapters/mapped.py             明确用户确认的其他数据映射，不猜测修复对
tests/__init__.py
tests/test_baseline.py            合成离线单测及 MockTransport，不访问真实 GPU
inspection/dataset_inventory.json 只读数据字段检查结果
inspection/static_validation.json 静态语法和实际环境核验记录
```

另创建 `.runtime/tmp`、`.runtime/cache`、`.runtime/pip-cache` 等本模块内部运行目录，未生成实际推理结果。

## 用户后续手动执行

完整可复制命令在 README。建议先激活 `vul-rag`，设置 `$EXP`、`$TMPDIR` 及 `PYTHONDONTWRITEBYTECODE=1`，再按以下顺序执行：

1. 运行离线 unittest；本次未代为执行。
2. 只读检查/计数，转换 PrimeVul 普通与 paired，各自独立输出。
3. 审阅质量、知识重叠和跨集合候选；确认项目别名、缺失元数据及实际保留数量。
4. 在模型服务器只读核实监听端口；在项目服务器 GET `/models`，配置实际 `VLLM_BASE_URL` 与 served ID。模型路径位于 192.168.31.238，不在当前项目服务器加载。
5. 用户手动运行 20 个函数 pilot，然后独立 evaluate 并审阅 raw_response。
6. 需要时使用全新输出目录运行 full；续跑保持全部参数不变并加 resume，失败重试用 retry_failed。
7. 保存 frozen samples.jsonl/hash，后续 RAG 复用同一 cohort，在新结果目录逐 ID 对照。

当前代码与依赖交付不需要进一步安装授权。实际端口、served model ID、真实推理输出质量，以及单元测试/数据全量转换的运行结果仍待用户手动确认；未将它们宣称为已验证。非原生数据集标签与复杂配对未经确认的，保留显式适配框架而没有伪造支持。
