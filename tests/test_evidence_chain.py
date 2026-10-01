from __future__ import annotations

import copy
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from evidence_chain.canonical import canonical_json
from evidence_chain.demo import seed_demo
from evidence_chain.ed25519 import public_key, sign, verify
from evidence_chain.packages import GENESIS_HASH
from evidence_chain.storage import Store
from evidence_chain.timeutils import utc_text


def t(hour: int, minute: int = 0) -> str:
    return utc_text(datetime(2026, 9, 30, hour, minute, tzinfo=timezone.utc))


def physical(site: str, seq: int, sample: str, kind: str, hour: int, **extra):
    base = {
        "collected": {"sample_type": "blood", "location": f"{site} bench", "operator": "op"},
        "processed": {"process": "spin", "location": f"{site} bench", "operator": "op"},
        "aliquoted": {"aliquot_id": f"{sample}-{site}", "volume_ml": 1.0, "location": "box", "operator": "op"},
        "destroyed": {"reason": "expired", "location": "furnace", "operator": "op"},
    }[kind]
    return {
        "event_id": f"{site}-e{seq}",
        "site_id": site,
        "seq": seq,
        "sample_id": sample,
        "type": kind,
        "payload": {**base, **extra},
        "effective_at": t(hour),
        "recorded_at": t(hour, 5),
    }


def make_pair(tmp_path, name: str = "AA"):
    src = Store(":memory:")
    central = Store(tmp_path / f"central-{name}.db")
    info = src.create_site(name, name)
    central.register_remote_site(name, name, info["kid"], info["public_key"])
    return src, central


def package(source: Store, site: str, max_events: int | None = None):
    return source.export_next_package(site, max_events=max_events)


def test_ed25519_rfc8032_vector():
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    expected_pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    assert public_key(seed).hex() == expected_pk
    signature = sign(seed, b"")
    assert signature.hex() == expected_sig
    verify(bytes.fromhex(expected_pk), b"", signature)


def test_duplicate_package_returns_same_result_and_keeps_idempotent_state(tmp_path):
    src, central = make_pair(tmp_path)
    src.record_event(physical("AA", 1, "S1", "collected", 8))
    pkg = package(src, "AA")
    first = central.import_package(pkg)
    second = central.import_package(copy.deepcopy(pkg))
    assert first["status"] == "accepted"
    assert second["status"] == "accepted"
    assert second["batch_id"] == first["batch_id"]
    assert second["repeated"] is True
    assert len(central.list_events()) == 1


def test_out_of_order_gap_is_quarantined_then_completed_atomically(tmp_path):
    src, central = make_pair(tmp_path, "BB")
    src.record_event(physical("BB", 1, "S1", "collected", 8))
    src.record_event(physical("BB", 2, "S1", "processed", 9))
    first = package(src, "BB", 1)
    second = package(src, "BB")
    delayed = central.import_package(second)
    assert delayed["status"] == "quarantined"
    assert "missing segment" in delayed["reason"]
    assert central.list_events() == []
    completed = central.import_package(first)
    assert completed["status"] == "accepted"
    assert completed["released"][0]["batch_id"] == delayed["batch_id"]
    assert [event["seq"] for event in central.list_events()] == [1, 2]
    released = [row for row in central.list_quarantine() if row["id"] == delayed["batch_id"]][0]
    assert released["status"] == "accepted" and released["released_at"]


def test_manual_retry_replays_gap_without_duplicate_when_predecessor_exists(tmp_path):
    src, central = make_pair(tmp_path, "MR")
    src.record_event(physical("MR", 1, "S1", "collected", 8))
    src.record_event(physical("MR", 2, "S1", "processed", 9))
    first = package(src, "MR", 1)
    second = package(src, "MR")
    delayed = central.import_package(second)
    assert central.import_package(first)["status"] == "accepted"
    central.conn.execute("UPDATE import_batches SET status='quarantined', reason=NULL, released_at=NULL WHERE id=?", (delayed["batch_id"],))
    manual = central.retry_quarantine(delayed["batch_id"])
    assert manual["status"] == "accepted"
    assert central.retry_quarantine(delayed["batch_id"])["repeated"] is True
    assert [(event["seq"], event["event_id"]) for event in central.list_events()] == [(1, "MR-e1"), (2, "MR-e2")]


def test_multiple_consecutive_gaps_release_in_one_import_transaction(tmp_path):
    src, central = make_pair(tmp_path, "MG")
    src.record_event(physical("MG", 1, "S1", "collected", 8))
    first = package(src, "MG", 1)
    src.record_event(physical("MG", 2, "S1", "processed", 9))
    second = package(src, "MG", 1)
    src.record_event(physical("MG", 3, "S1", "aliquoted", 10))
    third = package(src, "MG", 1)
    assert central.import_package(third)["status"] == "quarantined"
    assert central.import_package(second)["status"] == "quarantined"
    result = central.import_package(first)
    assert result["status"] == "accepted"
    assert [item["end_seq"] for item in result["released"]] == [2, 3]
    assert central.list_sites()[0]["last_seq"] == 3


def test_hash_mismatch_stays_quarantined_and_cannot_contaminate_chain(tmp_path):
    src, central = make_pair(tmp_path, "CC")
    src.record_event(physical("CC", 1, "S1", "collected", 8))
    pkg = package(src, "CC")
    pkg["events"][0]["payload"]["location"] = "tampered"
    result = central.import_package(pkg)
    assert result["status"] == "quarantined"
    assert "event hash mismatch" in result["reason"]
    assert central.list_events() == []
    retry = central.retry_quarantine(result["batch_id"])
    assert retry["status"] == "quarantined"
    assert central.list_events() == []


def test_prev_hash_fork_and_event_id_collision_are_quarantined(tmp_path):
    src, central = make_pair(tmp_path, "DD")
    src.record_event(physical("DD", 1, "S1", "collected", 8))
    first = package(src, "DD")
    assert central.import_package(first)["status"] == "accepted"
    src.record_event(physical("DD", 2, "S1", "processed", 9))
    fork = package(src, "DD")
    fork["prev_hash"] = GENESIS_HASH
    result = central.import_package(fork)
    assert result["status"] == "quarantined"
    assert "previous hash fork" in result["reason"]
    collision = copy.deepcopy(fork)
    collision["prev_hash"] = first["event_hashes"][-1]
    collision["event_hashes"][0] = "f" * 64
    collision["signature"]["sig"] = "00" * 64
    result = central.import_package(collision)
    assert result["status"] == "quarantined"


def test_parallel_facts_require_explicit_reconciliation(tmp_path):
    left = Store(":memory:")
    right = Store(":memory:")
    central = Store(tmp_path / "central-parallel.db")
    li = left.create_site("LL", "LL")
    ri = right.create_site("RR", "RR")
    central.register_remote_site("LL", "LL", li["kid"], li["public_key"])
    central.register_remote_site("RR", "RR", ri["kid"], ri["public_key"])
    left.record_event(physical("LL", 1, "PX", "collected", 8, location="left"))
    right.record_event(physical("RR", 1, "PX", "collected", 9, location="right"))
    central.import_package(package(left, "LL"))
    central.import_package(package(right, "RR"))
    before = central.get_sample("PX")["state"]
    assert before["status"] == "parallel_facts"
    assert len(before["candidates"]) == 2
    decision = {
        "event_id": "CENTER-r1",
        "site_id": "LL",
        "sample_id": "PX",
        "type": "reconciliation",
        "payload": {
            "selected_event_ids": ["LL-e1"],
            "rejected_event_ids": ["RR-e1"],
            "reason": "left has custody labels",
        },
        "effective_at": t(10),
        "recorded_at": t(11),
    }
    central.record_event(decision)
    after = central.get_sample("PX")["state"]
    assert after["status"] == "collected"
    assert after["location"] == "left"
    assert after["resolution"]["reconciliation_event_id"] == "CENTER-r1"


def test_reconciliation_includes_winner_branch_head_at_decision_time(tmp_path):
    left = Store(":memory:")
    right = Store(":memory:")
    central = Store(tmp_path / "central-branch-head.db")
    li = left.create_site("WH", "WH")
    ri = right.create_site("WI", "WI")
    central.register_remote_site("WH", "WH", li["kid"], li["public_key"])
    central.register_remote_site("WI", "WI", ri["kid"], ri["public_key"])
    left.record_event(physical("WH", 1, "BH", "collected", 8))
    right.record_event(physical("WI", 1, "BH", "collected", 9))
    left.record_event(physical("WH", 2, "BH", "processed", 10))
    central.import_package(package(left, "WH", 1))
    central.import_package(package(right, "WI"))
    central.import_package(package(left, "WH"))
    central.record_event({
        "site_id": "WH",
        "sample_id": "BH",
        "type": "reconciliation",
        "payload": {"selected_event_ids": ["WH-e1"], "rejected_event_ids": ["WI-e1"], "reason": "chosen"},
        "effective_at": t(11),
        "recorded_at": t(11, 5),
    })
    state = central.get_sample("BH")["state"]
    assert state["status"] == "processed"
    assert state["last_event_id"] == "WH-e2"


def test_correction_is_append_only_and_changes_derived_payload(tmp_path):
    src, central = make_pair(tmp_path, "EE")
    src.record_event(physical("EE", 1, "S1", "collected", 8, location="old"))
    central.import_package(package(src, "EE"))
    original = central.list_events()[0]
    central.record_event({
        "event_id": "EE-e2",
        "site_id": "EE",
        "sample_id": "S1",
        "type": "correction",
        "payload": {"target_event_id": "EE-e1", "patch": {"location": "new bench"}},
        "effective_at": t(8),
        "recorded_at": t(12),
    })
    events = central.list_events()
    assert len(events) == 2
    assert events[0]["payload"]["location"] == "old"
    state = central.get_sample("S1")["state"]
    assert state["location"] == "new bench"
    assert state["last_event_id"] == "EE-e1"
    assert original["event_hash"] == events[0]["event_hash"]


def test_key_rotation_package_uses_old_signature_and_new_claim(tmp_path):
    src, central = make_pair(tmp_path, "FF")
    src.record_event(physical("FF", 1, "S1", "collected", 8))
    rotation = src.rotate_key("FF")
    package_with_claim = package(src, "FF")
    assert package_with_claim["signature"]["kid"] == "FF-k1"
    assert "private" not in canonical_json(package_with_claim).decode()
    assert package_with_claim["key"]["kid"] == rotation["new_kid"]
    assert central.import_package(package_with_claim)["status"] == "accepted"
    assert central.list_sites()[0]["current_kid"] == rotation["new_kid"]
    src.record_event(physical("FF", 2, "S1", "processed", 9))
    next_pkg = package(src, "FF")
    assert next_pkg["signature"]["kid"] == rotation["new_kid"]
    assert central.import_package(next_pkg)["status"] == "accepted"


def test_key_only_rotation_package_is_valid_and_idempotent(tmp_path):
    src, central = make_pair(tmp_path, "KR")
    rotation = src.rotate_key("KR")
    key_only = package(src, "KR")
    assert key_only["events"] == []
    assert key_only["key"]["kid"] == rotation["new_kid"]
    assert central.import_package(key_only)["status"] == "accepted"
    assert central.list_sites()[0]["current_kid"] == rotation["new_kid"]
    assert central.import_package(copy.deepcopy(key_only))["status"] == "accepted"


def test_concurrent_adjacent_packages_do_not_gap_or_duplicate_reconciliation(tmp_path):
    left_src = Store(":memory:")
    right_src = Store(":memory:")
    central = Store(tmp_path / "central-concurrent.db")
    for index, source in enumerate((left_src, right_src), start=1):
        site = f"G{index}"
        info = source.create_site(site, site)
        central.register_remote_site(site, site, info["kid"], info["public_key"])
        source.record_event(physical(site, 1, f"S{index}", "collected", 8))
        source.record_event(physical(site, 2, f"S{index}", "processed", 9))
    p1_left = package(left_src, "G1", 1)
    p2_left = package(left_src, "G1")
    p1_right = package(right_src, "G2", 1)
    p2_right = package(right_src, "G2")
    packages = [p2_left, p2_right, p1_left, p1_right]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(central.import_package, packages))
    assert {r["status"] for r in results[:2]} == {"quarantined"}
    assert {r["status"] for r in results[2:]} == {"accepted"}
    assert sorted((e["site_id"], e["seq"]) for e in central.list_events()) == [("G1", 1), ("G1", 2), ("G2", 1), ("G2", 2)]
    repeat = central.import_package(p2_left)
    assert repeat["repeated"] is True
    assert [e["type"] for e in central.list_events()].count("reconciliation") == 0


def test_point_in_time_uses_selected_basis_and_sort_is_explained(tmp_path):
    src, central = make_pair(tmp_path, "HH")
    src.record_event(physical("HH", 1, "S1", "collected", 8))
    src.record_event(physical("HH", 2, "S1", "processed", 9))
    central.import_package(package(src, "HH"))
    assert central.get_sample("S1", at=t(8, 30), basis="effective")["state"]["status"] == "collected"
    assert central.get_sample("S1", at=t(8), basis="recorded")["state"] == {"resolution": None}
    result = central.get_sample("S1")
    assert result["sorting_rule"] == "effective_at, recorded_at, site_id, seq, event_id"


def test_tests_do_not_access_network(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("network access is forbidden in tests")

    monkeypatch.setattr(socket, "socket", deny)
    src = Store(":memory:")
    info = src.create_site("II", "II")
    src.record_event(physical("II", 1, "S", "collected", 8))
    signed = package(src, "II")
    verify(bytes.fromhex(info["public_key"]), canonical_json({k: v for k, v in signed.items() if k != "signature"}), bytes.fromhex(signed["signature"]["sig"]))


def test_seeded_demo_contains_quarantine_then_completion_example():
    store = Store(":memory:")
    assert seed_demo(store) is True
    assert seed_demo(store) is False
    assert any(row["site_id"] == "GAMMA" and row["status"] == "accepted" and row["released_at"] for row in store.list_quarantine())
    assert any(row["status"] == "quarantined" for row in store.list_quarantine())
