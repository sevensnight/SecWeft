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
    parser.add_argument("--worker-id", default="validation-worker", help="stable worker identity")
    parser.add_argument(
        "--idle-sleep", type=float, default=1.0, help="seconds to sleep between empty polls"
    )
    args = parser.parse_args()

    services = build_services(Settings.from_env())
    try:
        while True:
            result = services.validation_execution.run_worker_once(args.worker_id)
            if result is not None:
                print(f"{result['id']} {result['status']}", flush=True)
            if args.once:
                return 0
            if result is None:
                time.sleep(max(args.idle_sleep, 0.1))
    finally:
        services.close()


if __name__ == "__main__":
    raise SystemExit(main())
