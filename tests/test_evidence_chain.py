from __future__ import annotations

import copy
import json
import threading
from http.client import HTTPConnection
from pathlib import Path

import pytest

from evidence_chain import crypto
from evidence_chain.demo import seed_if_empty
from evidence_chain.web import create_app
from evidence_chain.store import ALGORITHM, EvidenceError, Store


def make_center(tmp_path: Path, site: Store, site_id: str, name: str = "远端") -> Store:
    center = Store(tmp_path / f"center-{site_id}.db")
    public = site.get_site(site_id)["public_keys"][0]["public_key_b64"]
    center.register_remote_site(site_id, public, name)
    return center


def collect(site: Store, site_id: str, sample: str = "X1", event_id: str = "c1") -> dict:
    return site.add_event(
        site_id,
        sample,
        "sample_collected",
        {"sample_type": "血液", "location": "A 柜", "collector": "甲"},
        "2026-01-01T08:00:00Z",
        "2026-01-01T09:00:00Z",
        event_id,
    )


def test_duplicate_package_is_idempotent(tmp_path: Path) -> None:
    source = Store(tmp_path / "source.db")
    source.create_site("S1")
    collect(source, "S1")
    package = source.export_package("S1", 1, 1)
    center = make_center(tmp_path, source, "S1")

    first = center.import_package(package)
    second = center.import_package(copy.deepcopy(package))

    assert first == second
    assert len(center.list_events()) == 1


def test_out_of_order_packages_then_missing_segment_completes_chain(tmp_path: Path) -> None:
    source = Store(tmp_path / "source.db")
    source.create_site("S1")
    collect(source, "S1", event_id="e1")
    source.add_event(
        "S1",
        "X1",
        "sample_processed",
        {"process": "离心", "operator": "甲", "location": "实验室"},
        "2026-01-01T10:00:00Z",
        "2026-01-01T10:30:00Z",
        "e2",
    )
    source.add_event(
        "S1",
        "X1",
        "sample_destroyed",
        {"method": "高压灭菌", "operator": "甲", "location": "销毁间"},
        "2026-01-01T12:00:00Z",
        "2026-01-01T12:10:00Z",
        "e3",
    )
    first = source.export_package("S1", 1, 1)
    second = source.export_package("S1", 2, 2)
    third = source.export_package("S1", 3, 3)
    center = make_center(tmp_path, source, "S1")

    assert center.import_package(third)["reason"] == "missing_gap"
    assert center.list_events() == []
    assert center.import_package(first)["status"] == "accepted"
    result = center.import_package(second)

    assert result["status"] == "accepted"
    assert [event["sequence"] for event in center.list_events(site_id="S1")] == [1, 2, 3]
    assert all(package["status"] == "accepted" for package in center.list_packages())


def test_tampered_event_hash_enters_quarantine_and_does_not_merge(tmp_path: Path) -> None:
    source = Store(tmp_path / "source.db")
    source.create_site("S1")
    collect(source, "S1")
    package = source.export_package("S1", 1, 1)
    package["events"][0]["payload"]["location"] = "被篡改"
    center = make_center(tmp_path, source, "S1")

    result = center.import_package(package)

    assert result["status"] == "quarantined"
    assert result["reason"] == "hash_mismatch"
    assert center.list_events() == []
    assert center.list_packages(True)[0]["event_count"] == 1


def test_fork_by_prev_hash_is_quarantined(tmp_path: Path) -> None:
    left = Store(tmp_path / "left.db")
    right = Store(tmp_path / "right.db")
    left.create_site("S1")
    right.create_site("S1")
    collect(left, "S1", event_id="left1")
    collect(right, "S1", event_id="right1")
    center = make_center(tmp_path, left, "S1")
    center.register_remote_site(
        "S1", right.get_site("S1")["public_keys"][0]["public_key_b64"], "右支测试密钥"
    )

    assert center.import_package(left.export_package("S1", 1, 1))["status"] == "accepted"
    left.add_event(
        "S1",
        "X1",
        "sample_processed",
        {"process": "左支", "operator": "甲", "location": "L"},
        "2026-01-01T10:00:00Z",
        "2026-01-01T10:05:00Z",
        "left2",
    )
    right.add_event(
        "S1",
        "X1",
        "sample_processed",
        {"process": "右支", "operator": "乙", "location": "R"},
        "2026-01-01T10:01:00Z",
        "2026-01-01T10:06:00Z",
        "right2",
    )

    assert center.import_package(left.export_package("S1", 2, 2))["status"] == "accepted"
    fork = center.import_package(right.export_package("S1", 2, 2))
    assert fork["status"] == "quarantined"
    assert fork["reason"] == "fork_detected"


def test_parallel_facts_remain_until_explicit_reconciliation(tmp_path: Path) -> None:
    s1 = Store(tmp_path / "s1.db")
    s2 = Store(tmp_path / "s2.db")
    s1.create_site("S1")
    s2.create_site("S2")
    center = Store(tmp_path / "center.db")
    center.register_remote_site(
        "S1", s1.get_site("S1")["public_keys"][0]["public_key_b64"]
    )
    center.register_remote_site(
        "S2", s2.get_site("S2")["public_keys"][0]["public_key_b64"]
    )
    collect(s1, "S1", event_id="a")
    collect(s2, "S2", event_id="b")
    center.import_package(s1.export_package("S1", 1, 1))
    center.import_package(s2.export_package("S2", 1, 1))

    before = center.derive_state("X1")
    assert before["has_conflict"] is True
    assert len(before["facts"]) == 2

    center.create_site("C", "中心")
    reconciliation = center.add_event(
        "C",
        "X1",
        "reconciliation",
        {
            "candidate_event_ids": ["a", "b"],
            "adopted_event_id": "a",
            "reason": "采用 S1",
        },
        "2026-01-01T11:00:00Z",
        "2026-01-01T11:05:00Z",
    )
    after = center.derive_state("X1")
    assert after["has_conflict"] is False
    assert after["current_fact"]["event_id"] == "a"
    assert len(after["reconciliations"]) == 1
    assert reconciliation["event_type"] == "reconciliation"


def test_correction_is_append_only_and_changes_derived_state(tmp_path: Path) -> None:
    store = Store(tmp_path / "local.db")
    store.create_site("S1")
    original = collect(store, "S1")
    store.add_event(
        "S1",
        "X1",
        "correction",
        {
            "original_event_id": original["event_id"],
            "corrects_type": "sample_collected",
            "corrected_payload": {
                "sample_type": "血液",
                "location": "B 柜",
                "collector": "甲",
            },
            "corrected_effective_at": "2026-01-01T08:00:00Z",
        },
        "2026-01-01T12:00:00Z",
        "2026-01-01T12:20:00Z",
        "corr1",
    )

    provenance = store.provenance("X1")
    assert provenance["events_chain_order"][0]["payload"]["location"] == "A 柜"
    assert store.derive_state("X1")["current_fact"]["payload"]["location"] == "B 柜"
    state_before_effective = store.derive_state(
        "X1", "2026-01-01T11:59:59Z"
    )
    assert state_before_effective["current_fact"]["payload"]["location"] == "A 柜"


def test_key_rotation_package_and_subsequent_new_key_signature(tmp_path: Path) -> None:
    source = Store(tmp_path / "source.db")
    center = Store(tmp_path / "center.db")
    source.create_site("S1")
    initial_fingerprint = source.get_site("S1")["public_keys"][0]["fingerprint"]
    collect(source, "S1")
    rotation = source.rotate_key(
        "S1", "2026-01-01T11:00:00Z", "2026-01-01T11:02:00Z", "rot1"
    )
    source.add_event(
        "S1",
        "X1",
        "sample_processed",
        {"process": "复核", "operator": "甲", "location": "实验室"},
        "2026-01-01T12:00:00Z",
        "2026-01-01T12:05:00Z",
        "after-rotation",
    )
    center.register_remote_site(
        "S1", source.get_site("S1")["public_keys"][0]["public_key_b64"]
    )
    first = source.export_package("S1", 1, 1)
    rotation_package = source.export_package("S1", 2, 2)
    after = source.export_package("S1", 3, 3)

    assert first["signer_key_fingerprint"] == initial_fingerprint
    assert rotation_package["signer_key_fingerprint"] == initial_fingerprint
    assert after["signer_key_fingerprint"] == rotation["payload"]["new_key_fingerprint"]
    assert "private" not in after
    assert center.import_package(first)["status"] == "accepted"
    waiting = center.import_package(after)
    assert waiting["reason"] == "unknown_key"
    assert center.import_package(rotation_package)["status"] == "accepted"
    assert center.retry_package(waiting["package_id"])["status"] == "accepted"


def test_concurrent_adjacent_imports_do_not_create_gap(tmp_path: Path) -> None:
    source = Store(tmp_path / "source.db")
    source.create_site("S1")
    for index in range(1, 7):
        collect(source, "S1", f"X{index}", f"e{index}")
    center = make_center(tmp_path, source, "S1")
    packages = [source.export_package("S1", index, index) for index in range(1, 7)]
    errors: list[BaseException] = []

    def worker(package: dict, barrier: threading.Barrier) -> None:
        try:
            barrier.wait()
            result = center.import_package(package)
            assert result["status"] == "accepted"
        except BaseException as exc:  # noqa: PT028
            errors.append(exc)

    barrier = threading.Barrier(len(packages))
    threads = [threading.Thread(target=worker, args=(package, barrier)) for package in packages]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert [event["sequence"] for event in center.list_events(site_id="S1")] == list(
        range(1, 7)
    )


def test_seed_demo_has_accepted_gap_and_remaining_tamper_quarantine(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "demo.db")
    assert seed_if_empty(store) is True
    packages = {(package["site_id"], package["start_sequence"]): package for package in store.list_packages()}
    assert packages[("GAP", 3)]["status"] == "accepted"
    assert packages[("TAM", 1)]["status"] == "quarantined"
    assert "实验样本证据链"


def test_event_id_same_but_different_content_is_rejected(tmp_path: Path) -> None:
    first_store = Store(tmp_path / "a.db")
    second_store = Store(tmp_path / "b.db")
    first_store.create_site("S1")
    second_store.create_site("S1")
    collect(first_store, "S1", "X1", "same")
    second_store.add_event(
        "S1",
        "X1",
        "sample_collected",
        {"sample_type": "血液", "location": "不同", "collector": "乙"},
        "2026-01-01T08:00:00Z",
        "2026-01-01T09:00:00Z",
        "same",
    )
    center = make_center(tmp_path, first_store, "S1")
    center.register_remote_site(
        "S1", second_store.get_site("S1")["public_keys"][0]["public_key_b64"], "重复 ID 测试密钥"
    )
    assert center.import_package(first_store.export_package("S1", 1, 1))["status"] == "accepted"
    result = center.import_package(second_store.export_package("S1", 1, 1))
    assert result["reason"] in {"event_id_conflict", "fork_detected"}


def test_web_page_and_json_api(tmp_path: Path) -> None:
    database = tmp_path / "web.db"
    seed_store = Store(database)
    assert seed_if_empty(seed_store) is True
    server = create_app("127.0.0.1", 0, str(database))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/")
        response = conn.getresponse()
        page = response.read().decode("utf-8")
        assert response.status == 200
        assert "实验样本证据链" in page
        assert "预置隔离后补齐示例" in page

        conn.request("GET", "/api/samples/X-001/state")
        response = conn.getresponse()
        state = json.loads(response.read().decode("utf-8"))
        assert response.status == 200
        assert state["current_stage"] == "sample_processed"

        body = json.dumps(
            {"site_id": "WEB", "display_name": "网页测试站"}
        ).encode("utf-8")
        conn.request(
            "POST",
            "/api/sites",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        created = json.loads(response.read().decode("utf-8"))
        assert response.status == 201
        assert created["site_id"] == "WEB"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_reconciliation_can_adopt_corrected_fact(tmp_path: Path) -> None:
    store = Store(tmp_path / "corrected-choice.db")
    store.create_site("S1")
    store.create_site("S2")
    store.create_site("C")
    store.add_event(
        "S1",
        "X9",
        "sample_collected",
        {"sample_type": "血液", "location": "旧位置", "collector": "甲"},
        "2026-02-01T08:00:00Z",
        "2026-02-01T08:30:00Z",
        "raw-a",
    )
    store.add_event(
        "S2",
        "X9",
        "sample_collected",
        {"sample_type": "血液", "location": "乙位置", "collector": "乙"},
        "2026-02-01T08:05:00Z",
        "2026-02-01T08:25:00Z",
        "raw-b",
    )
    store.add_event(
        "S1",
        "X9",
        "correction",
        {
            "original_event_id": "raw-a",
            "corrects_type": "sample_collected",
            "corrected_payload": {
                "sample_type": "血液",
                "location": "新位置",
                "collector": "甲",
            },
            "corrected_effective_at": "2026-02-01T08:00:00Z",
        },
        "2026-02-01T09:00:00Z",
        "2026-02-01T09:10:00Z",
        "corrected-a",
    )
    store.add_event(
        "C",
        "X9",
        "reconciliation",
        {
            "candidate_event_ids": ["corrected-a", "raw-b"],
            "adopted_event_id": "corrected-a",
            "reason": "采用纠错后的 S1 事实",
        },
        "2026-02-01T10:00:00Z",
        "2026-02-01T10:05:00Z",
        "reconcile-x9",
    )

    state = store.derive_state("X9")
    assert state["has_conflict"] is False
    assert state["current_fact"]["event_id"] == "raw-a"
    assert state["current_fact"]["corrected_by_event_id"] == "corrected-a"
    assert state["current_fact"]["payload"]["location"] == "新位置"
