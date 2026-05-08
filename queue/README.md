# `@hanzo/zap-queue` — Durable task queue for long-running ZAP jobs

SQLite-backed FIFO queue for tasks the ZAP layer needs to run across
process restarts (e.g. "walk 42 Porkbun domains and flip NS"). One file,
no daemons, no Redis.

## Why

- Tasks like the Porkbun NS-swap walk take dozens of round-trips and need
  to survive: MCP restart, browser tab close/reopen, intermittent ZAP
  disconnects.
- In-memory state evaporates with the python process.
- A regular DB is overkill — a single SQLite file gives us durability
  + atomic transactions + zero-config.

## API

```python
from hanzo_zap_queue import Queue, TaskRunner

queue = Queue('~/.hanzo/zap-queue.db')

# 1. Submit a job
task_id = queue.enqueue('porkbun-ns-swap', {
    'domains': ['osage.group', 'osage.tech', ...],
    'nameservers': ['hattie.ns.cloudflare.com', 'quinton.ns.cloudflare.com'],
})

# 2. Run worker (one-shot or loop)
runner = TaskRunner(queue)

@runner.handler('porkbun-ns-swap')
async def porkbun_walker(task, ctx):
    start = task.progress.get('idx', 0)
    for i, domain in enumerate(task.payload['domains'][start:], start):
        await drive_browser_to_flip_ns(domain, task.payload['nameservers'])
        ctx.checkpoint({'idx': i + 1})

await runner.run_forever()
```

## Status

- v0.1.0: SQLite backend, single-process FIFO, checkpointing, retries
- v0.2.0 (planned): multi-process locking, web UI, scheduled tasks
