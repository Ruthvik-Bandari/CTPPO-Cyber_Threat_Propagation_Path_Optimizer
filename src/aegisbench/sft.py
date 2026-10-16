"""Supervised fine-tuning examples for M1 (plan section 12, "Training examples").

Each example pairs the exact B2 prompt for an impaired case with its reference repair:

- the input is the B2 prompt. The diagnosis behind it comes from replaying the original rule on the
  case's development events, as the workflow does.
- the target is the repair that restores the healthy reference, recovered by diffing the impaired
  case against it:
  - a mapping patch;
  - a ``set_condition`` with the healthy condition;
  - a ``set_predicate`` with the healthy predicate.
- missing-telemetry and healthy cases target ``{"candidates": []}``, so abstention is learned too.

The function reads only the split it is given. M1 trains on ``train`` and uses ``development``
for evaluation loss; it never reads ``test``. Prompts hold no event values.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegissec.detect.diagnose import hypotheses
from aegissec.detect.engine import Elasticsearch
from aegissec.detect.fixtures import load_dataset, profile
from aegissec.detect.mapping import FieldMapping, parse_mapping
from aegissec.detect.replay import Replayer
from aegissec.detect.rule import Rule, parse_rule, render_condition

from .b2 import build_prompt
from .evaluate import load_case


def reference_repair(rule: Rule, mapping: FieldMapping, healthy: Rule, healthy_map: FieldMapping) -> dict[str, Any]:
    """The candidate list that turns the impaired case back into its healthy reference."""
    drifted = sorted(f for f in rule.fields if mapping.target(f) != healthy_map.target(f))
    if drifted:
        patch = [
            {
                "kind": "mapping",
                "sigma_field": f,
                "from_field": mapping.target(f),
                "to_field": healthy_map.target(f),
            }
            for f in drifted
        ]
        return {"candidates": [{"patch_kind": "mapping", "patch": patch}]}
    if rule.condition != healthy.condition:
        op = {"kind": "set_condition", "condition": render_condition(healthy.condition)}
        return {"candidates": [{"patch_kind": "rule", "patch": [op]}]}
    for name, sel in rule.selections.items():
        for p, q in zip(sel.predicates, healthy.selections[name].predicates, strict=True):
            if p != q:
                spec = {"field": q.field, "modifier": q.modifier, "values": list(q.values), "match_all": q.match_all}
                edit: dict[str, object] = {"kind": "set_predicate", "selection": name, "field": p.field}
                edit["predicate"] = spec
                return {"candidates": [{"patch_kind": "rule", "patch": [edit]}]}
    return {"candidates": []}


def example(case_dir: Path, es: Elasticsearch) -> dict[str, Any]:
    manifest, inputs = load_case(case_dir)
    rule, mapping = parse_rule(inputs.rule_text), parse_mapping(inputs.mapping_text)
    healthy = parse_rule(inputs.healthy_rule_text or inputs.rule_text)
    healthy_map = parse_mapping(inputs.healthy_mapping_text or inputs.mapping_text)
    dev = load_dataset(inputs.dev_path)
    with es.replay_index(dev.events) as index:
        original = Replayer(es, index, dev).run(rule, mapping)
    hyps = hypotheses(rule, mapping, profile(dev.events), dev, original)
    if manifest["expected"]["outcome"] == "repaired":
        target = reference_repair(rule, mapping, healthy, healthy_map)
    else:
        target = {"candidates": []}
    return {
        "case_id": manifest["case_id"],
        "root_id": manifest["root_id"],
        "kind": manifest["fault"]["kind"],
        "prompt": build_prompt(rule, mapping, dev, hyps, original.matched_ids),
        "completion": json.dumps(target, separators=(",", ":")),
    }


def build(cases_root: Path, split: str, es: Elasticsearch) -> list[dict[str, Any]]:
    if split == "test":
        raise ValueError("SFT never reads the locked test split")
    return [example(d, es) for d in sorted(p for p in (cases_root / split).glob("*") if (p / "case.yml").is_file())]
