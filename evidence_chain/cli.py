from __future__ import annotations

import argparse
from wsgiref.simple_server import make_server

from .web import App


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evidence-chain", description="Offline evidence chain web application")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5203)
    parser.add_argument("--db", default="instance/evidence.db")
    parser.add_argument("--no-demo", action="store_true", help="do not seed an empty database with demo data")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    app = App(db_path=args.db, demo=not args.no_demo)
    with make_server(args.host, args.port, app) as httpd:
        print(f"Evidence chain running at http://{args.host}:{args.port}")
        print(f"SQLite database: {args.db}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
