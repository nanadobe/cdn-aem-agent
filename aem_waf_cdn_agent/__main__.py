"""Executable entrypoint for python -m aem_waf_cdn_agent."""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
