from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .app import run
from .config import ConfigError


def main() -> None:
    parser = argparse.ArgumentParser(prog="roost")
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="Path to config.yaml (default: ./config.yaml)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with made-up data. Nothing is scanned and no config is read.",
    )
    args = parser.parse_args()
    if args.demo:
        from .demo import run_demo

        run_demo()
        return
    try:
        run(config_path=args.config)
    except ConfigError as exc:
        print(f"roost: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
