from __future__ import annotations

import argparse
from pathlib import Path

from .app import run


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
    run(config_path=args.config)


if __name__ == "__main__":
    main()
