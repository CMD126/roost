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
    args = parser.parse_args()
    try:
        run(config_path=args.config)
    except ConfigError as exc:
        print(f"roost: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
