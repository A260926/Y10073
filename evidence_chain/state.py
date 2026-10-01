from __future__ import annotations

import copy
from typing import Any

from .canonical import canonical_json
from .timeutils import parse_utc

PHYSICAL_TYPES = {"collected", "processed", "aliquoted", "destroyed"}


def _at(value: dict[str, Any], basis: str) -> str:
    return value["recorded_at"] if basis == "recorded" else value["effective_at"]


def _sort_key(event: dict[str, Any]) -> tuple[str, str, str, int, str]:
    return (
        event["effective_at"],
        event["recorded_at"],
        event["site_id"],
        event["seq"],
        event["event_id"],
    )


def _same_state(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
    if left is None or right is None:
        return False
    comparable = ("status", "site_id", "payload")
    return canonical_json([left.get(key) for key in comparable]) == canonical_json(
        [right.get(key) for key in comparable]
    )


def _apply_event(state: dict[str, Any] | None, event: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(event["payload"])
    next_state: dict[str, Any] = {} if state is None else copy.deepcopy(state)
    next_state.update(payload)
    next_state["sample_id"] = event["sample_id"]
    next_state["status"] = event["type"]
    next_state["site_id"] = event["site_id"]
    next_state["last_event_id"] = event["event_id"]
    next_state["effective_at"] = event["effective_at"]
    next_state["recorded_at"] = event["recorded_at"]
    next_state["seq"] = event["seq"]
    return next_state


def _corrected_events(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_id = {event["event_id"]: copy.deepcopy(event) for event in events}
    corrections = [event for event in events if event["type"] == "correction"]
    corrections.sort(key=_sort_key)
    for correction in corrections:
        payload = correction["payload"]
        target_id = payload["target_event_id"]
        target = by_id.get(target_id)
        if target is None:
            continue
        target["payload"].update(copy.deepcopy(payload.get("patch", {})))
        target["corrected_by"] = [*target.get("corrected_by", []), correction["event_id"]]
    return by_id


def _included(event: dict[str, Any], at: str | None, basis: str) -> bool:
    if at is None:
        return True
    cutoff = parse_utc(at, "at")
    event_time = parse_utc(_at(event, basis), "event time")
    return event_time <= cutoff


def _site_state(events: list[dict[str, Any]], site_id: str, upto_seq: int | None = None) -> dict[str, Any] | None:
    state: dict[str, Any] | None = None
    for event in sorted(events, key=lambda item: (item["seq"], item["event_id"])):
        if event["site_id"] != site_id or event["type"] not in PHYSICAL_TYPES:
            continue
        if upto_seq is not None and event["seq"] > upto_seq:
            continue
        state = _apply_event(state, event)
    return state


def derive_sample_state(
    events: list[dict[str, Any]],
    *,
    at: str | None = None,
    basis: str = "effective",
) -> dict[str, Any]:
    if basis not in {"effective", "recorded"}:
        raise ValueError("basis must be 'effective' or 'recorded'")
    visible = [event for event in events if _included(event, at, basis)]
    corrected = _corrected_events(visible)
    physical = sorted(
        [corrected[event["event_id"]] for event in visible if event["type"] in PHYSICAL_TYPES],
        key=_sort_key,
    )
    reconciliations = sorted(
        [event for event in visible if event["type"] == "reconciliation"],
        key=_sort_key,
    )

    branches: dict[str, dict[str, Any]] = {}
    for event in physical:
        branches[event["site_id"]] = _apply_event(branches.get(event["site_id"]), event)

    latest_reconciliation = reconciliations[-1] if reconciliations else None
    if latest_reconciliation is not None:
        payload = latest_reconciliation["payload"]
        selected_ids = list(payload.get("selected_event_ids", []))
        rejected_ids = set(payload.get("rejected_event_ids", []))
        selected = corrected.get(selected_ids[0]) if selected_ids else None
        if selected is not None:
            recon_time = parse_utc(latest_reconciliation["effective_at"], "effective_at")
            upto_seq = max(
                event["seq"]
                for event in physical
                if event["site_id"] == selected["site_id"]
                and parse_utc(event["effective_at"], "effective_at") <= recon_time
            )
            state = _site_state(physical, selected["site_id"], upto_seq)
            for event in physical:
                if (
                    parse_utc(event["effective_at"], "effective_at")
                    > parse_utc(latest_reconciliation["effective_at"], "effective_at")
                    and event["event_id"] not in rejected_ids
                ):
                    state = _apply_event(state, event)
            result = copy.deepcopy(state or {})
            result["resolution"] = {
                "reconciliation_event_id": latest_reconciliation["event_id"],
                "selected_event_ids": selected_ids,
                "rejected_event_ids": sorted(rejected_ids),
                "reason": payload.get("reason"),
                "effective_at": latest_reconciliation["effective_at"],
                "recorded_at": latest_reconciliation["recorded_at"],
            }
            return result

    states = list(branches.values())
    distinct: list[dict[str, Any]] = []
    for state in states:
        if not any(_same_state(state, other) for other in distinct):
            distinct.append(state)
    if len(distinct) <= 1:
        result = copy.deepcopy(distinct[0] if distinct else {})
        result["resolution"] = None
        return result

    candidates = sorted(distinct, key=lambda item: (item["effective_at"], item["recorded_at"], item["site_id"], item["seq"], item["last_event_id"]))
    return {
        "sample_id": events[0]["sample_id"] if events else None,
        "status": "parallel_facts",
        "resolution": None,
        "candidates": candidates,
    }


def provenance(events: list[dict[str, Any]], *, at: str | None = None, basis: str = "effective") -> dict[str, Any]:
    visible = [event for event in events if _included(event, at, basis)]
    timeline = sorted(visible, key=_sort_key)
    by_site: dict[str, list[dict[str, Any]]] = {}
    for event in sorted(visible, key=lambda item: (item["site_id"], item["seq"], item["event_id"])):
        by_site.setdefault(event["site_id"], []).append(event)
    return {
        "sorting_rule": "effective_at, recorded_at, site_id, seq, event_id",
        "timeline": timeline,
        "site_chains": by_site,
        "state": derive_sample_state(visible, at=at, basis=basis),
    }
