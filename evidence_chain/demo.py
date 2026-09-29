from __future__ import annotations

import copy
import tempfile
from pathlib import Path

from .store import Store


def _initial_public_key(store: Store, site_id: str) -> str:
    return store.get_site(site_id)["public_keys"][0]["public_key_b64"]


def seed_if_empty(store: Store) -> bool:
    if store.list_sites():
        return False

    with tempfile.TemporaryDirectory(prefix="evidence-seed-") as directory:
        s1 = Store(str(Path(directory) / "s1.db"))
        s2 = Store(str(Path(directory) / "s2.db"))
        gap = Store(str(Path(directory) / "gap.db"))
        key_site = Store(str(Path(directory) / "key.db"))
        tamper_site = Store(str(Path(directory) / "tamper.db"))

        s1.create_site("S1", "一号采集站")
        s2.create_site("S2", "二号采集站")
        store.create_site("C", "中心仲裁站")
        gap.create_site("GAP", "隔离补齐站")
        key_site.create_site("KEY", "密钥轮换站")
        tamper_site.create_site("TAM", "篡改示例站")

        for source, name in (
            (s1, "一号采集站"),
            (s2, "二号采集站"),
            (gap, "隔离补齐站"),
            (key_site, "密钥轮换站"),
            (tamper_site, "篡改示例站"),
        ):
            site_id = next(site["site_id"] for site in source.list_sites())
            store.register_remote_site(
                site_id,
                _initial_public_key(source, site_id),
                name,
            )

        s1.add_event(
            "S1",
            "X-001",
            "sample_collected",
            {"sample_type": "全血", "location": "冷柜 A1", "collector": "陈一"},
            "2026-09-01T08:00:00Z",
            "2026-09-01T09:10:00Z",
            "evt-seed-s1-collect",
        )
        s2.add_event(
            "S2",
            "X-001",
            "sample_collected",
            {"sample_type": "全血", "location": "冷链箱 B2", "collector": "林二"},
            "2026-09-01T08:05:00Z",
            "2026-09-01T09:05:00Z",
            "evt-seed-s2-collect",
        )
        s1.add_event(
            "S1",
            "X-001",
            "sample_processed",
            {"process": "离心", "operator": "陈一", "location": "处理室 1"},
            "2026-09-01T10:00:00Z",
            "2026-09-01T11:30:00Z",
            "evt-seed-s1-process",
        )
        s2.add_event(
            "S2",
            "X-002",
            "sample_collected",
            {"sample_type": "尿液", "location": "旧标签位置", "collector": "林二"},
            "2026-09-02T08:00:00Z",
            "2026-09-02T08:30:00Z",
            "evt-seed-x002-collect",
        )
        s2.add_event(
            "S2",
            "X-002",
            "correction",
            {
                "original_event_id": "evt-seed-x002-collect",
                "corrects_type": "sample_collected",
                "corrected_payload": {
                    "sample_type": "尿液",
                    "location": "冷柜 C3",
                    "collector": "林二",
                },
                "corrected_effective_at": "2026-09-02T08:00:00Z",
            },
            "2026-09-02T09:00:00Z",
            "2026-09-02T09:20:00Z",
            "evt-seed-x002-correction",
        )

        for index in range(1, 4):
            gap.add_event(
                "GAP",
                "G-001",
                "sample_processed" if index == 2 else "sample_collected",
                {
                    "process": "分装准备",
                    "operator": f"补齐站操作员 {index}",
                    "location": f"移动实验室 {index}",
                    "sample_type": "拭子",
                    "collector": f"补齐站操作员 {index}",
                },
                f"2026-09-03T0{index}:00:00Z",
                f"2026-09-03T0{index}:15:00Z",
                f"evt-seed-gap-{index}",
            )

        key_site.add_event(
            "KEY",
            "K-001",
            "sample_collected",
            {"sample_type": "组织", "location": "现场袋 1", "collector": "密钥站"},
            "2026-09-04T08:00:00Z",
            "2026-09-04T08:10:00Z",
            "evt-seed-key-1",
        )
        key_site.rotate_key(
            "KEY",
            "2026-09-04T09:00:00Z",
            "2026-09-04T09:05:00Z",
            "evt-seed-key-rotation",
        )
        key_site.add_event(
            "KEY",
            "K-001",
            "sample_processed",
            {"process": "切片", "operator": "密钥站", "location": "移动实验室"},
            "2026-09-04T10:00:00Z",
            "2026-09-04T10:10:00Z",
            "evt-seed-key-3",
        )

        tamper_site.add_event(
            "TAM",
            "T-001",
            "sample_collected",
            {"sample_type": "血浆", "location": "站点实验室", "collector": "安全员"},
            "2026-09-05T08:00:00Z",
            "2026-09-05T08:10:00Z",
            "evt-seed-tampered",
        )

        s1_pkg = s1.export_package("S1", 1, 2)
        s2_pkg = s2.export_package("S2", 1, 2)
        gap_one = gap.export_package("GAP", 1, 1)
        gap_two = gap.export_package("GAP", 2, 2)
        gap_three = gap.export_package("GAP", 3, 3)
        key_one = key_site.export_package("KEY", 1, 1)
        key_rotation = key_site.export_package("KEY", 2, 2)
        key_three = key_site.export_package("KEY", 3, 3)
        tampered = tamper_site.export_package("TAM", 1, 1)
        tampered["events"][0]["payload"]["location"] = "被篡改位置"

        for envelope in (s1_pkg, s2_pkg, key_one):
            assert store.import_package(envelope)["status"] == "accepted"
        store.add_event(
            "C",
            "X-001",
            "reconciliation",
            {
                "candidate_event_ids": [
                    "evt-seed-s1-collect",
                    "evt-seed-s2-collect",
                ],
                "adopted_event_id": "evt-seed-s1-collect",
                "reason": "冷链交接记录确认冷柜 A1 为有效采集位置",
            },
            "2026-09-01T12:00:00Z",
            "2026-09-01T12:20:00Z",
            "evt-seed-reconcile",
        )
        assert store.import_package(gap_three)["status"] == "quarantined"
        assert store.import_package(gap_one)["status"] == "accepted"
        assert store.import_package(gap_two)["status"] == "accepted"
        waiting_new_key = store.import_package(key_three)
        assert waiting_new_key["status"] == "quarantined"
        assert store.import_package(key_rotation)["status"] == "accepted"
        assert store.retry_package(waiting_new_key["package_id"])["status"] == "accepted"
        assert store.import_package(tampered)["reason"] == "hash_mismatch"

    return True
