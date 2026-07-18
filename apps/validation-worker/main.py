from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE_SRC = ROOT / "apps" / "control-plane" / "src"
if str(CONTROL_PLANE_SRC) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE_SRC))

from vulnlab.api.services import build_services  # noqa: E402
from vulnlab.config import Settings  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the P9 validation execution worker")
    parser.add_argument("--once", action="store_true", help="consume at most one queued message")
    parser.add_argument(
        "--dispatch-outbox",
        action="store_true",
        help="publish validation outbox messages to the configured transport",
    )
    parser.add_argument(
        "--dispatch-outbox-once",
        action="store_true",
        help="publish at most one validation outbox message and exit",
    )
    parser.add_argument("--worker-id", default="validation-worker", help="stable worker identity")
    parser.add_argument(
        "--idle-sleep", type=float, default=1.0, help="seconds to sleep between empty polls"
    )
    args = parser.parse_args()

    services = build_services(Settings.from_env())
    try:
        while True:
            if args.dispatch_outbox or args.dispatch_outbox_once:
                result = services.validation_execution.dispatch_outbox_once()
                if result is not None:
                    print(
                        f"{result['queue_message_id']} {result.get('transport', 'unknown')}",
                        flush=True,
                    )
                if args.dispatch_outbox_once:
                    return 0
            else:
                result = services.validation_execution.run_worker_once(args.worker_id)
                if result is not None:
                    print(f"{result['id']} {result['status']}", flush=True)
            if result is not None:
                continue
            if args.once:
                return 0
            time.sleep(max(args.idle_sleep, 0.1))
    finally:
        services.close()


if __name__ == "__main__":
    raise SystemExit(main())
