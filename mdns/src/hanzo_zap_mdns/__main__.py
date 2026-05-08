"""CLI: `hanzo-zap-mdns browse [role]` to list every live ZAP service."""
import sys
from . import browse


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "browse":
        services = browse(timeout=2.0)
        for s in services:
            caps = ",".join(s.capabilities or [])
            print(f"{s.server_id:32s} {s.url:32s} agent={s.agent_label} ver={s.version} caps={caps}")
        return 0
    print("usage: hanzo-zap-mdns browse")
    return 2


if __name__ == "__main__":
    sys.exit(main())
