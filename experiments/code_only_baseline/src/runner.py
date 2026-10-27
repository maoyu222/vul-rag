"""Bounded producer/worker/writer pipeline, based on the existing batch bundle pattern."""
import asyncio
import platform

from .checkpoint import RunStore
from .io_utils import atomic_json, utc_now
from .prompts import Prompt
from .vllm_client import VLLMClient


async def execute(inputs, directory, settings, api_key="", resume=False, retry_failed=False,
                  limit=None, datasets=(), splits=("test",), skip_model_check=False):
    import httpx
    prompt = Prompt()
    with RunStore(directory, inputs, settings, prompt, resume, limit, datasets, splits) as store:
        atomic_json(store.directory / "runtime.json", {"python": platform.python_version(), "httpx": httpx.__version__,
            "updated_at": utc_now(), "api_key_present": bool(api_key), "skip_model_check": skip_model_check})
        queue, output = asyncio.Queue(settings.concurrency * 2), asyncio.Queue(settings.concurrency * 2)
        sent = 0
        async with VLLMClient(settings, prompt, api_key) as client:
            # Do not contact the service if everything has already completed.
            pending = iter(store.pending(retry_failed))
            first = next(pending, None)
            if first is None:
                atomic_json(store.directory / "run_summary.json", {"counts": store.counts(), "updated_at": utc_now()})
                return store.counts()
            if not skip_model_check:
                atomic_json(store.directory / "service_check.json", client.redact(await client.check_model()))

            async def producer():
                nonlocal sent
                await queue.put(first)
                sent += 1
                for sample in pending:
                    await queue.put(sample)
                    sent += 1
                for _ in range(settings.concurrency):
                    await queue.put(None)

            async def worker():
                while True:
                    sample = await queue.get()
                    if sample is None:
                        return
                    prediction = await client.predict(sample, store.log_attempt)
                    result = {key: sample.get(key) for key in ("sample_id", "dataset", "dataset_version", "split", "pair_id", "variant", "cwe_ids", "sample_hash", "normalized_code_hash")}
                    result.update(prediction)
                    result.update(true_label=sample["label"], model=settings.model, prompt_version=prompt.version,
                                  config_hash=store.config_hash, finished_at=utc_now())
                    await output.put(result)

            async def writer():
                while True:
                    result = await output.get()
                    if result is None:
                        return
                    store.save(result)

            try:
                # Structured cancellation: writer errors cancel workers and producer.
                async with asyncio.TaskGroup() as tasks:
                    tasks.create_task(writer())
                    workers = [tasks.create_task(worker()) for _ in range(settings.concurrency)]
                    producing = tasks.create_task(producer())
                    await producing
                    await asyncio.gather(*workers)
                    await output.put(None)
            finally:
                atomic_json(store.directory / "run_summary.json", {"updated_at": utc_now(),
                    "scheduled_this_invocation": sent, "counts": store.counts(),
                    "note": "Interrupted started requests may have consumed remote tokens; inspect requests.jsonl."})
        return store.counts()
