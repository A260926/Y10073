from __future__ import annotations

import argparse

from .demo import seed_if_empty
from .web import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="实验样本证据链离线 Web 应用")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5203)
    parser.add_argument("--database", default="evidence_chain.db")
    parser.add_argument(
        "--no-seed",
        action="store_true",
        help="不创建首次启动的演示数据",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    server = create_app(args.host, args.port, args.database)
    if not args.no_seed:
        if seed_if_empty(server.store):  # type: ignore[attr-defined]
            print("已创建演示站点、并行事实、correction、隔离补齐和篡改隔离示例")
    print(f"实验样本证据链运行在 http://{args.host}:{args.port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
