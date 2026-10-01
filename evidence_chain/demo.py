from __future__ import annotations

import copy
from datetime import datetime, timezone

from .storage import Store
from .timeutils import utc_text


def t(hour: int, minute: int = 0, second: int = 0) -> str:
    return utc_text(datetime(2026, 9, 30, hour, minute, second, tzinfo=timezone.utc))


def seed(name: bytes) -> bytes:
    return (name * 32)[:32]


def _event(site: str, seq: int, sample: str, event_type: str, payload: dict, eff: str, rec: str) -> dict:
    return {
        "event_id": f"{site}-e{seq}",
        "site_id": site,
        "sample_id": sample,
        "type": event_type,
        "payload": payload,
        "effective_at": eff,
        "recorded_at": rec,
    }


def seed_demo(central: Store) -> bool:
    if central.list_sites():
        return False

    alpha_seed = seed(b"A")
    beta_seed = seed(b"B")
    gamma_seed = seed(b"G")
    delta_seed = seed(b"D")
    center_seed = seed(b"C")

    alpha_src = Store(":memory:")
    beta_src = Store(":memory:")
    gamma_src = Store(":memory:")
    delta_src = Store(":memory:")

    alpha_src.create_site("ALPHA", "一号采集站", seed=alpha_seed, kid="ALPHA-k1")
    beta_src.create_site("BETA", "二号移动站", seed=beta_seed, kid="BETA-k1")
    gamma_src.create_site("GAMMA", "隔离补齐站", seed=gamma_seed, kid="GAMMA-k1")
    delta_src.create_site("DELTA", "篡改示教站", seed=delta_seed, kid="DELTA-k1")
    central.register_remote_site("ALPHA", "一号采集站", "ALPHA-k1", alpha_src.list_sites()[0]["public_key"])
    central.register_remote_site("BETA", "二号移动站", "BETA-k1", beta_src.list_sites()[0]["public_key"])
    central.register_remote_site("GAMMA", "隔离补齐站", "GAMMA-k1", gamma_src.list_sites()[0]["public_key"])
    central.register_remote_site("DELTA", "篡改示教站", "DELTA-k1", delta_src.list_sites()[0]["public_key"])
    central.create_site("CENTER", "中心裁决站", seed=center_seed, kid="CENTER-k1")

    alpha_src.record_event(_event(
        "ALPHA", 1, "S-100", "collected",
        {"sample_type": "blood", "location": "Alpha Tent", "operator": "A. Lin"},
        t(8, 0), t(8, 5),
    ))
    alpha_p1 = alpha_src.export_next_package("ALPHA", max_events=1)

    alpha_src.record_event(_event(
        "ALPHA", 2, "S-100", "processed",
        {"process": "centrifuge", "location": "Alpha Tent", "operator": "A. Lin"},
        t(9, 0), t(9, 10),
    ))
    alpha_src.record_event(_event(
        "ALPHA", 3, "S-100", "correction",
        {"target_event_id": "ALPHA-e1", "patch": {"location": "Alpha Clean Bench"}, "note": "录入时位置过粗"},
        t(8, 0), t(10, 30),
    ))
    for seq, kind in enumerate((
        ("collected", {"sample_type": "swab", "location": "Alpha Storage", "operator": "M. Wu"}),
        ("processed", {"process": "lyophilize", "location": "Alpha Lab", "operator": "M. Wu"}),
        ("aliquoted", {"aliquot_id": "S-200-A1", "volume_ml": 1.5, "location": "Alpha Freezer", "operator": "M. Wu"}),
        ("destroyed", {"reason": "retention expired", "location": "Alpha Furnace", "operator": "M. Wu"}),
    ), start=4):
        event_type, payload = kind
        alpha_src.record_event(_event("ALPHA", seq, "S-200", event_type, payload, t(8 + seq), t(8 + seq, 5)))
    alpha_p2 = alpha_src.export_next_package("ALPHA")

    beta_src.record_event(_event(
        "BETA", 1, "S-100", "collected",
        {"sample_type": "blood", "location": "Beta Vehicle", "operator": "B. Xu"},
        t(8, 10), t(8, 12),
    ))
    beta_src.record_event(_event(
        "BETA", 2, "S-100", "processed",
        {"process": "manual spin", "location": "Beta Vehicle", "operator": "B. Xu"},
        t(9, 20), t(9, 25),
    ))
    beta_package = beta_src.export_next_package("BETA")

    gamma_src.record_event(_event(
        "GAMMA", 1, "S-300", "collected",
        {"sample_type": "water", "location": "Gamma Shore", "operator": "G. He"},
        t(7, 50), t(7, 55),
    ))
    gamma_first = gamma_src.export_next_package("GAMMA", max_events=1)
    gamma_src.record_event(_event(
        "GAMMA", 2, "S-300", "processed",
        {"process": "filter", "location": "Gamma Shore", "operator": "G. He"},
        t(8, 20), t(8, 24),
    ))
    gamma_second = gamma_src.export_next_package("GAMMA")

    delta_src.record_event(_event(
        "DELTA", 1, "S-400", "collected",
        {"sample_type": "soil", "location": "Delta Box", "operator": "D. Mo"},
        t(11), t(11, 2),
    ))
    tampered = copy.deepcopy(delta_src.export_next_package("DELTA"))
    tampered["events"][0]["payload"]["location"] = "Tampered Lab"

    central.import_package(alpha_p1)
    central.import_package(beta_package)
    central.import_package(alpha_p2)
    central.import_package(gamma_second)
    central.import_package(gamma_first)
    central.import_package(tampered)

    central.record_event({
        "event_id": "CENTER-e1",
        "site_id": "CENTER",
        "sample_id": "S-100",
        "type": "reconciliation",
        "payload": {
            "selected_event_ids": ["ALPHA-e2"],
            "rejected_event_ids": ["BETA-e2"],
            "reason": "Alpha 管带有完整离心温控记录，采用 Alpha 处理状态；Beta 事实保留。",
        },
        "effective_at": t(10, 15),
        "recorded_at": t(10, 45),
    })
    return True
