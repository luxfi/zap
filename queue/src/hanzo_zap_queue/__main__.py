"""CLI: `hanzo-zap-queue list | enqueue | status <id> | drain`."""
import argparse
import json
import sys

from . import Queue, TaskStatus


def main() -> int:
    p = argparse.ArgumentParser(prog="hanzo-zap-queue")
    p.add_argument("--db", default="~/.hanzo/zap-queue.db", help="Queue database path")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp_list = sub.add_parser("list")
    sp_list.add_argument("--kind"); sp_list.add_argument("--status")

    sp_enq = sub.add_parser("enqueue")
    sp_enq.add_argument("kind")
    sp_enq.add_argument("payload_json", help="JSON object string")

    sp_st = sub.add_parser("status"); sp_st.add_argument("task_id")
    sub.add_parser("drain")  # delete done/failed tasks

    args = p.parse_args()
    q = Queue(args.db)

    if args.cmd == "list":
        st = TaskStatus(args.status) if args.status else None
        for t in q.list(kind=args.kind, status=st):
            print(f"{t.id}  {t.kind:20s}  {t.status.value:8s}  attempts={t.attempts}/{t.max_attempts}  progress={t.progress}")
    elif args.cmd == "enqueue":
        payload = json.loads(args.payload_json)
        tid = q.enqueue(args.kind, payload)
        print(tid)
    elif args.cmd == "status":
        t = q.get(args.task_id)
        if not t:
            print(f"no such task: {args.task_id}", file=sys.stderr); return 1
        print(json.dumps({
            "id": t.id, "kind": t.kind, "status": t.status.value,
            "attempts": t.attempts, "max_attempts": t.max_attempts,
            "progress": t.progress, "error": t.error, "result": t.result,
        }, indent=2))
    elif args.cmd == "drain":
        n = 0
        for t in q.list(status=TaskStatus.DONE) + q.list(status=TaskStatus.FAILED):
            q.delete(t.id); n += 1
        print(f"deleted {n} tasks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
