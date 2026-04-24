"""Command-line interface for local goggles-ai scans."""

from __future__ import annotations

import argparse
import json
import sys

from goggles_ai import scan, scan_file, scan_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="goggles-ai",
        description="Scan content before it reaches an AI agent.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    url_parser = subparsers.add_parser("url", help="Scan a URL")
    url_parser.add_argument("url", help="URL to fetch and inspect")
    url_parser.add_argument("--deep", action="store_true", help="Enable deep image analysis")

    file_parser = subparsers.add_parser("file", help="Scan a local file")
    file_parser.add_argument("path", help="Path to the file to inspect")
    file_parser.add_argument("--deep", action="store_true", help="Enable deep image analysis")

    content_parser = subparsers.add_parser("content", help="Scan inline content")
    content_parser.add_argument("content", help="Inline content to inspect")
    content_parser.add_argument(
        "--content-type",
        default="text/html",
        help="MIME type hint such as text/html or text/plain",
    )
    content_parser.add_argument("--filename", default="", help="Optional filename hint")
    content_parser.add_argument("--deep", action="store_true", help="Enable deep image analysis")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "url":
        result = scan_url(args.url, deep=args.deep)
    elif args.command == "file":
        result = scan_file(args.path, deep=args.deep)
    else:
        result = scan(
            args.content,
            content_type=args.content_type,
            filename=args.filename,
            deep=args.deep,
        )

    json.dump(result.model_dump(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
