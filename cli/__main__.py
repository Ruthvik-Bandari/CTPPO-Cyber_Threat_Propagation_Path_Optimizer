"""Allow `python3 -m cli ...` as well as the `ctppo-cli` console entry point."""

from cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
