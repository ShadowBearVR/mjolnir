# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Aggregates real-world pinned trials, blind review adjudications, and RQ1-RQ4 metrics into Markdown and LaTeX booktabs tables."""

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess

from evaluation.constants import ABLATION_TIERS, ORDERED_PIPELINE_PHASES
from evaluation.grader import (
    FindingPooler,
    _extract_duplicate_of_id,
    compute_inter_rater_stats,
    compute_phase_transitions,
    normalize_phase_id,
)
from evaluation.models import (
    BlindReviewFinding,
    InterRaterStats,
    TierEvaluationSummary,
    TrialRunRecord,
)
from utilities.logger import logger


class ScorecardGenerator:
    """Joins trial manifests with blind review labels to compute RQ1-RQ4 evaluation scorecards."""

    TOOL_CATEGORY_MAP: dict[str, str] = {
        "read_file": "file",
        "glob": "file",
        "grep_search": "search",
        "ctags_search": "search",
        "ast_search": "search",
        "search_cwe": "cwe",
        "ask_project_expert": "project_expert",
        "patch_worktree_file": "worktree",
        "write_worktree_file": "worktree",
        "get_worktree_diff": "worktree",
        "reset_worktree": "worktree",
        "run_harness_command": "harness",
    }
    TOOL_CATEGORIES: tuple[str, ...] = (
        "file",
        "search",
        "cwe",
        "project_expert",
        "worktree",
        "harness",
        "other",
    )
    SAFETY_REFUSAL_MARKERS: tuple[str, ...] = (
        "cannot fulfill your request",
        "cannot fulfill this request",
        "unable to fulfill",
        "cannot assist",
        "adhere to the strict refusal",
        "adhere to the strictest safety",
        "must refuse",
        "refusal justification",
        "prevent real-world harm",
        "i cannot provide",
        "sorry, i cannot",
        "safety policy",
        "prohibits generating",
        "unable to generate functional exploit",
    )

    def __init__(self) -> None:
        self._telemetry_cache: dict[str, dict] = {}

    MODEL_PRICING_SCHEDULES_USD_PER_1M: dict[str, dict[str, float | str]] = {
        "gemini-3.8-flash": {
            "uncached_input": 0.75,
            "cached_input": 0.075,
            "output_and_thoughts": 3.75,
            "as_of": "2026-10-19",
        },
        "gemini-4-argon": {
            "uncached_input": 2.00,
            "cached_input": 0.10,
            "output_and_thoughts": 10.00,
            "as_of": "2026-10-19",
        },
        "claude-sonnet-5-5": {
            "uncached_input": 2.00,
            "cached_input": 0.20,
            "output_and_thoughts": 10.00,
            "as_of": "2026-10-19",
        },
    }

    @staticmethod
    def _resolve_repo_root() -> Path:
        file_root = Path(__file__).resolve().parent.parent.parent
        return file_root if (file_root / ".git").exists() else Path.cwd()

    @classmethod
    def _get_mjolnir_commit(cls) -> str:
        try:
            repo_root = cls._resolve_repo_root()
            return (
                subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=repo_root, stderr=subprocess.DEVNULL
                )
                .decode("utf-8")
                .strip()
            )
        except Exception:
            return "unknown"

    @classmethod
    def _is_mjolnir_dirty(cls) -> bool:
        try:
            repo_root = cls._resolve_repo_root()
            out = (
                subprocess.check_output(
                    ["git", "status", "--porcelain"], cwd=repo_root, stderr=subprocess.DEVNULL
                )
                .decode("utf-8")
                .strip()
            )
            return bool(out)
        except Exception:
            return False

    @staticmethod
    def _load_trial_thoughts_and_output_tokens(
        eval_dir: Path, tier_key: str, trial: TrialRunRecord
    ) -> tuple[int, int]:
        """Reads separated (thoughts_tokens, pure_output_tokens) from trial token_usage.json."""
        base_tier = tier_key.split("@")[0]
        rep_dir = eval_dir / "trials" / base_tier / f"rep_{trial.repetition}"
        tu_files = (
            sorted(rep_dir.glob("run_*/token_usage.json"))
            or sorted(rep_dir.glob("token_usage.json"))
            if rep_dir.is_dir()
            else []
        )
        if tu_files:
            try:
                tu_data = json.loads(tu_files[-1].read_text(encoding="utf-8"))
                if "@" in tier_key:
                    ckpt = normalize_phase_id(tier_key.split("@", 1)[1])
                    by_phase = tu_data.get("by_phase") or {}
                    if isinstance(by_phase, dict) and ckpt in ORDERED_PIPELINE_PHASES:
                        idx = ORDERED_PIPELINE_PHASES.index(ckpt)
                        allowed = {"project_exploration", *ORDERED_PIPELINE_PHASES[: idx + 1]}
                        tho = sum(
                            int((by_phase.get(p) or {}).get("thoughts_tokens", 0) or 0)
                            for p in allowed
                        )
                        out = sum(
                            int((by_phase.get(p) or {}).get("output_tokens", 0) or 0)
                            for p in allowed
                        )
                        if tho + out > 0:
                            return tho, out
                tot = tu_data.get("total") or {}
                tho = int(tot.get("thoughts_tokens", 0) or 0)
                out = int(tot.get("output_tokens", 0) or 0)
                if tho + out > 0:
                    return tho, out
            except Exception:
                pass
        return 0, int(trial.output_tokens)

    @classmethod
    def _infer_phase_from_target_id(cls, target_id: str) -> str:
        tid = str(target_id or "")
        if tid == "project_exploration":
            return "project_exploration"
        if ".ProjectExpertAgent@" in tid:
            caller = tid.split(".ProjectExpertAgent@", 1)[0]
            return cls._infer_phase_from_target_id(caller)
        if tid.startswith("expert_query_"):
            return "discovery"
        if tid == "deduplication":
            return "deduplication"
        if tid.startswith("initial_review"):
            return "initial_review"
        if tid.startswith("poc_creation") or tid.startswith("poc_"):
            return "poc_creation"
        if tid.startswith("final_review"):
            return "final_review"
        return "discovery"

    @classmethod
    def _categorize_tool(cls, tool_name: str) -> str | None:
        if tool_name == "set_model_response":
            return None
        return cls.TOOL_CATEGORY_MAP.get(tool_name, "other")

    def _load_trial_telemetry(
        self,
        eval_dir: Path | None = None,
        base_tier: str = "",
        repetition: int = 1,
        trial_findings: list[dict] | None = None,
        rep_dir: Path | None = None,
    ) -> dict:
        """Loads or reconstructs LLM-call, tool-call, Project Expert, PoC-gate, and refusal telemetry for a trial."""
        if rep_dir is None:
            assert eval_dir is not None
            rep_dir = eval_dir / "trials" / base_tier / f"rep_{repetition}"
        cache_key = (
            str(rep_dir.resolve()) if rep_dir.exists() else f"{eval_dir}:{base_tier}:{repetition}"
        )
        if cache_key in self._telemetry_cache:
            return self._telemetry_cache[cache_key]

        empty_cats = {c: 0 for c in self.TOOL_CATEGORIES}
        phases_list = (
            "project_exploration",
            "discovery",
            "deduplication",
            "initial_review",
            "poc_creation",
            "final_review",
        )
        result: dict = {
            "has_telemetry": False,
            "llm_calls_total": 0,
            "llm_calls_by_agent": {},
            "llm_calls_by_phase": {p: 0 for p in phases_list},
            "tool_calls_total": 0,
            "tool_errors_total": 0,
            "tool_calls_by_category": dict(empty_cats),
            "tool_calls_by_agent": {},
            "tokens_by_agent": {},
            "tool_calls_by_phase": {p: 0 for p in phases_list},
            "tool_errors_by_phase": {p: 0 for p in phases_list},
            "tool_categories_by_phase": {p: dict(empty_cats) for p in phases_list},
            "expert_questions": 0,
            "expert_cache_hits": 0,
            "expert_zero_tool_subruns": 0,
            "expert_answered_from_history": 0,
            "poc_attempts": 0,
            "poc_harness_commands": 0,
            "poc_gate_failures": 0,
            "refusals": {
                "total_safety_refusals": 0,
                "hard_safety_refusals": 0,
                "soft_refusals": 0,
                "api_safety_blocks": 0,
                "schema_validation_drops": 0,
                "by_agent": {},
            },
        }
        if not rep_dir.is_dir():
            self._telemetry_cache[cache_key] = result
            return result

        run_dirs = sorted(p for p in rep_dir.glob("run_*") if p.is_dir())
        td = run_dirs[-1] if run_dirs else rep_dir
        tok_p = td / "token_usage.json"
        tool_p = td / "tool_usage.json"
        rlog_p = td / "reasoning_log.json"
        vulns_p = td / "vulnerabilities.json"
        if not vulns_p.exists() and (rep_dir / "vulnerabilities.json").exists():
            vulns_p = rep_dir / "vulnerabilities.json"

        tok = json.loads(tok_p.read_text(encoding="utf-8")) if tok_p.exists() else {}
        tool = json.loads(tool_p.read_text(encoding="utf-8")) if tool_p.exists() else {}
        rlog = json.loads(rlog_p.read_text(encoding="utf-8")) if rlog_p.exists() else {}
        vulns = (
            json.loads(vulns_p.read_text(encoding="utf-8"))
            if vulns_p.exists()
            else list(trial_findings or [])
        )
        if not (tok or tool or rlog):
            self._telemetry_cache[cache_key] = result
            return result
        result["has_telemetry"] = True

        # 1. Tool calls & errors from tool_usage.json (excluding ADK's synthetic set_model_response)
        by_tool = tool.get("by_tool") or {}
        for t_name, st in by_tool.items():
            calls = int(st.get("calls", 0) or 0)
            fails = int(st.get("failures", 0) or 0)
            cat = self._categorize_tool(t_name)
            if cat is not None:
                result["tool_calls_total"] += calls
                result["tool_errors_total"] += fails
                result["tool_calls_by_category"][cat] += calls

        result["expert_questions"] = int(
            (by_tool.get("ask_project_expert") or {}).get("calls", 0) or 0
        )
        result["poc_harness_commands"] = int(
            (by_tool.get("run_harness_command") or {}).get("calls", 0) or 0
        )

        # Per-agent tool calls (excluding synthetic set_model_response) & per-agent token breakdown
        for ag, a_vals in (tool.get("by_agent") or {}).items():
            if ag == "MjolnirComposableWorkflow" or not isinstance(a_vals, dict):
                continue
            tools_map = a_vals.get("tools", a_vals)
            if not isinstance(tools_map, dict):
                continue
            ag_calls = sum(
                int((st or {}).get("calls", 0) or 0)
                for t_name, st in tools_map.items()
                if isinstance(st, dict) and self._categorize_tool(t_name) is not None
            )
            if ag_calls > 0:
                result["tool_calls_by_agent"][ag] = ag_calls

        for ag, a_st in (tok.get("by_agent") or {}).items():
            if ag == "MjolnirComposableWorkflow" or not isinstance(a_st, dict):
                continue
            unc = float(a_st.get("uncached_tokens", 0) or 0)
            cac = float(a_st.get("cache_tokens", 0) or 0)
            inp = float(a_st.get("total_input_tokens", unc + cac) or (unc + cac))
            tho = float(a_st.get("thoughts_tokens", 0) or 0)
            out = float(a_st.get("output_tokens", 0) or 0)
            tot_out = float(a_st.get("total_output_tokens", tho + out) or (tho + out))
            if inp + tot_out > 0:
                result["tokens_by_agent"][ag] = {
                    "uncached_input": unc,
                    "cached_input": cac,
                    "total_input": inp,
                    "thoughts": tho,
                    "output": out,
                    "total_output": tot_out,
                }

        # Per-phase tool calls from tool_usage["by_phase"] when recorded directly
        by_phase_tools = tool.get("by_phase") or {}
        has_direct_phase_tools = bool(by_phase_tools)
        if has_direct_phase_tools:
            for pid, p_tools in by_phase_tools.items():
                if pid not in result["tool_calls_by_phase"] or not isinstance(p_tools, dict):
                    continue
                for t_name, st in p_tools.items():
                    cat = self._categorize_tool(t_name)
                    if cat is None:
                        continue
                    c = int(st.get("calls", 0) or 0)
                    f_cnt = int(st.get("failures", 0) or 0)
                    result["tool_calls_by_phase"][pid] += c
                    result["tool_errors_by_phase"][pid] += f_cnt
                    result["tool_categories_by_phase"][pid][cat] += c

        # 2. Direct LLM-call counts if recorded in token_usage.json
        tot_llm_direct = int((tok.get("total") or {}).get("llm_calls", 0) or 0)
        if tot_llm_direct > 0:
            result["llm_calls_total"] = tot_llm_direct
            for ag, a_st in (tok.get("by_agent") or {}).items():
                c_ag = int((a_st or {}).get("llm_calls", 0) or 0)
                if c_ag > 0 and ag != "MjolnirComposableWorkflow":
                    result["llm_calls_by_agent"][ag] = c_ag
            for pid, p_st in (tok.get("by_phase") or {}).items():
                if pid in result["llm_calls_by_phase"]:
                    result["llm_calls_by_phase"][pid] = int((p_st or {}).get("llm_calls", 0) or 0)

        # 3. Direct refusal counts if recorded in token_usage.json
        direct_ref = tok.get("refusals")
        has_direct_ref = isinstance(direct_ref, dict) and (
            "hard_safety_refusals" in direct_ref or "total_safety_refusals" in direct_ref
        )
        if has_direct_ref:
            for k in (
                "total_safety_refusals",
                "hard_safety_refusals",
                "soft_refusals",
                "api_safety_blocks",
                "schema_validation_drops",
            ):
                result["refusals"][k] = int(direct_ref.get(k, 0) or 0)
            for ag, ag_b in (direct_ref.get("by_agent") or {}).items():
                if isinstance(ag_b, dict):
                    result["refusals"]["by_agent"][ag] = {
                        k: int(ag_b.get(k, 0) or 0)
                        for k in (
                            "total_safety_refusals",
                            "hard_safety_refusals",
                            "soft_refusals",
                            "api_safety_blocks",
                            "schema_validation_drops",
                        )
                    }
        else:
            for err_k, cnt in (tok.get("errors_grouped") or {}).items():
                u_err = str(err_k).upper()
                if (
                    any(w in u_err for w in ("SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII"))
                    and "HARDSAFETYREFUSAL" not in u_err
                    and "SOFTREFUSAL" not in u_err
                ):
                    result["refusals"]["api_safety_blocks"] += int(cnt or 0)
                    result["refusals"]["total_safety_refusals"] += int(cnt or 0)

        # 4. Inspect reasoning_log.json for retroactive LLM turns, phase tools, expert Q&A, PoC claims, and refusals
        expert_subruns = 0
        expert_zero_tools = 0
        claimed_poc_verified_ids: set[str] = set()
        seen_soft_refusal_targets: set[str] = set()
        err_prefixes = ("Error:", "Error executing", "Error ")

        def _bump_agent_refusal(ag_name: str, r_kind: str) -> None:
            b = result["refusals"]["by_agent"].setdefault(
                ag_name,
                {
                    "total_safety_refusals": 0,
                    "hard_safety_refusals": 0,
                    "soft_refusals": 0,
                    "api_safety_blocks": 0,
                    "schema_validation_drops": 0,
                },
            )
            b[r_kind] += 1
            if r_kind != "schema_validation_drops":
                b["total_safety_refusals"] += 1

        for tid, entries in rlog.items():
            if not isinstance(entries, list) or not entries:
                continue
            pid = self._infer_phase_from_target_id(tid)
            in_turn = False
            for e in entries:
                etype = e.get("type")
                ag = str(e.get("agent") or "UnknownAgent")
                if etype in ("thought", "output", "tool_call", "refusal"):
                    if tot_llm_direct == 0 and not in_turn:
                        if ag != "MjolnirComposableWorkflow":
                            result["llm_calls_total"] += 1
                            result["llm_calls_by_agent"][ag] = (
                                result["llm_calls_by_agent"].get(ag, 0) + 1
                            )
                            if pid in result["llm_calls_by_phase"]:
                                result["llm_calls_by_phase"][pid] += 1
                        in_turn = True
                    if etype == "tool_call" and e.get("tool") == "set_model_response":
                        args_d = e.get("args") if isinstance(e.get("args"), dict) else {}
                        if tid.startswith("poc_creation_") and args_d.get("poc_verified") is True:
                            claimed_poc_verified_ids.add(tid[len("poc_creation_") :])
                        if not has_direct_ref and args_d.get("refusal_reason"):
                            seen_soft_refusal_targets.add(tid)
                            result["refusals"]["soft_refusals"] += 1
                            result["refusals"]["total_safety_refusals"] += 1
                            _bump_agent_refusal(ag, "soft_refusals")
                    elif etype == "output" and tid.startswith("poc_creation_"):
                        raw_out = str(e.get("content") or "").strip()
                        if raw_out.startswith("{"):
                            try:
                                out_obj = json.loads(raw_out)
                                if (
                                    isinstance(out_obj, dict)
                                    and out_obj.get("poc_verified") is True
                                ):
                                    claimed_poc_verified_ids.add(tid[len("poc_creation_") :])
                            except Exception:
                                pass
                elif etype == "tool_response":
                    in_turn = False
                    if not has_direct_phase_tools and pid in result["tool_calls_by_phase"]:
                        t_name = str(e.get("tool") or "unknown")
                        cat = self._categorize_tool(t_name)
                        if cat is not None:
                            result["tool_calls_by_phase"][pid] += 1
                            result["tool_categories_by_phase"][pid][cat] += 1
                            resp_s = str(e.get("response") or "").strip()
                            if resp_s.startswith(err_prefixes):
                                result["tool_errors_by_phase"][pid] += 1

            if "expert_query_" in tid:
                expert_subruns += 1
                repo_tools = [
                    e
                    for e in entries
                    if e.get("type") == "tool_call" and e.get("tool") != "set_model_response"
                ]
                if not repo_tools:
                    expert_zero_tools += 1

            # Retroactive hard safety refusal vs non-refusal schema drop detection
            if not has_direct_ref:
                last_e = entries[-1]
                last_ag = str(last_e.get("agent") or "")
                if last_ag in (
                    "AuditorAgent",
                    "DeduplicationAgent",
                    "AdversarialReviewerAgent",
                    "ExploitCreationAgent",
                ):
                    used_set_resp = any(
                        e.get("type") == "tool_call" and e.get("tool") == "set_model_response"
                        for e in entries
                    )
                    if not used_set_resp:
                        if last_e.get("type") in ("output", "thought"):
                            last_out = str(last_e.get("content") or "").strip()
                            is_json_out = last_out.startswith("{") or last_out.startswith("```")
                            if not is_json_out:
                                joined_low = " ".join(
                                    str(e.get("content") or "") for e in entries
                                ).lower()
                                if any(m in joined_low for m in self.SAFETY_REFUSAL_MARKERS):
                                    result["refusals"]["hard_safety_refusals"] += 1
                                    result["refusals"]["total_safety_refusals"] += 1
                                    _bump_agent_refusal(last_ag, "hard_safety_refusals")
                                else:
                                    result["refusals"]["schema_validation_drops"] += 1
                                    _bump_agent_refusal(last_ag, "schema_validation_drops")
                        elif last_e.get("type") == "tool_response" and not (
                            tok.get("errors_grouped") or {}
                        ):
                            result["refusals"]["schema_validation_drops"] += 1
                            _bump_agent_refusal(last_ag, "schema_validation_drops")

        result["expert_cache_hits"] = max(0, result["expert_questions"] - expert_subruns)
        result["expert_zero_tool_subruns"] = expert_zero_tools
        result["expert_answered_from_history"] = result["expert_cache_hits"] + expert_zero_tools

        # 5. PoC attempts & mechanical gate rejections from vulnerabilities.json
        poc_attempts = 0
        poc_gate_failures = 0
        for v in vulns:
            if not isinstance(v, dict):
                continue
            vid = str(v.get("id") or "")
            poc_bundle = str(v.get("poc") or "")
            for h in v.get("history") or []:
                if not isinstance(h, dict):
                    continue
                h_pid = normalize_phase_id(h.get("phase_id") or h.get("phase_name"))
                j_txt = str(
                    h.get("justification") or (h.get("finding") or {}).get("justification") or ""
                )
                if not has_direct_ref and "Model soft refusal:" in j_txt:
                    synth_tid = f"{h_pid}_{vid}"
                    if synth_tid not in seen_soft_refusal_targets:
                        seen_soft_refusal_targets.add(synth_tid)
                        ag_map = {
                            "poc_creation": "ExploitCreationAgent",
                            "initial_review": "AdversarialReviewerAgent",
                            "final_review": "AdversarialReviewerAgent",
                        }
                        ag_n = ag_map.get(h_pid, "UnknownAgent")
                        result["refusals"]["soft_refusals"] += 1
                        result["refusals"]["total_safety_refusals"] += 1
                        _bump_agent_refusal(ag_n, "soft_refusals")
                if h_pid == "poc_creation":
                    if not j_txt.startswith("Skipped:"):
                        poc_attempts += 1
                    actual_ver = bool(
                        h.get("poc_verified")
                        or (isinstance(h.get("finding"), dict) and h["finding"].get("poc_verified"))
                    )
                    h_poc = str(h.get("poc") or (h.get("finding") or {}).get("poc") or poc_bundle)
                    if "- **Mechanical Gate Rejected**: `True`" in h_poc:
                        poc_gate_failures += 1
                    elif vid and vid in claimed_poc_verified_ids and not actual_ver:
                        poc_gate_failures += 1

        if poc_attempts == 0 and rlog:
            poc_attempts = sum(1 for tid in rlog if str(tid).startswith("poc_creation_"))
        result["poc_attempts"] = poc_attempts
        result["poc_gate_failures"] = poc_gate_failures

        self._telemetry_cache[cache_key] = result
        return result

    def generate_scorecard(
        self, eval_path: Path, output_dir: Path | None = None
    ) -> list[TierEvaluationSummary]:
        eval_dir = eval_path if eval_path.is_dir() else eval_path.parent
        out_dir = output_dir or eval_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        manifest_path = (
            eval_path
            if eval_path.is_file() and eval_path.name == "trials_manifest.json"
            else eval_dir / "trials_manifest.json"
        )
        if not manifest_path.exists():
            raise FileNotFoundError(f"Trials manifest not found: {manifest_path}")

        raw_trials = json.loads(manifest_path.read_text(encoding="utf-8"))
        trials = [TrialRunRecord.model_validate(t) for t in raw_trials]

        pool_path = eval_dir / "blind_review_pool.json"
        need_build = not pool_path.exists()
        if not need_build:
            try:
                raw_pool = json.loads(pool_path.read_text(encoding="utf-8"))
                if raw_pool and isinstance(raw_pool[0], dict) and "review_id" not in raw_pool[0]:
                    need_build = True
            except Exception:
                need_build = True
        if need_build:
            FindingPooler().build_pool(trials=trials, output_dir=eval_dir)

        pool = [
            BlindReviewFinding.model_validate(c)
            for c in json.loads(pool_path.read_text(encoding="utf-8"))
        ]
        # Propagate human labels from sibling ../pinned/blind_review_pool.json (e.g. shared reps in stability/)
        sibling_pinned_pool = eval_dir.parent / "pinned" / "blind_review_pool.json"
        if eval_dir.name != "pinned" and sibling_pinned_pool.exists():
            try:
                pinned_by_key = {
                    (
                        c.get("ablation_tier", ""),
                        int(c.get("repetition", 1)),
                        c.get("finding_id", ""),
                    ): BlindReviewFinding.model_validate(c)
                    for c in json.loads(sibling_pinned_pool.read_text(encoding="utf-8"))
                    if isinstance(c, dict) and "review_id" in c and c.get("finding_id")
                }
                for bf in pool:
                    src = pinned_by_key.get((bf.ablation_tier, bf.repetition, bf.finding_id))
                    if src is not None:
                        if not bf.reviewer_1_label and src.reviewer_1_label:
                            bf.reviewer_1_label = src.reviewer_1_label
                        if not bf.reviewer_2_label and src.reviewer_2_label:
                            bf.reviewer_2_label = src.reviewer_2_label
                        if not bf.adjudicated_label and src.adjudicated_label:
                            bf.adjudicated_label = src.adjudicated_label
                        if not bf.maintainer_status and src.maintainer_status:
                            bf.maintainer_status = src.maintainer_status
                        if not bf.expert_severity and src.expert_severity:
                            bf.expert_severity = src.expert_severity
                        if not bf.poc_demonstrates and src.poc_demonstrates:
                            bf.poc_demonstrates = src.poc_demonstrates
                        if not bf.notes and src.notes:
                            bf.notes = src.notes
            except Exception as e:
                logger.warning(f"Could not sync labels from {sibling_pinned_pool}: {e}")

        inter_rater = compute_inter_rater_stats(pool)
        pool_by_run_fid: dict[tuple[str, int, str], BlindReviewFinding] = {
            (bf.ablation_tier, bf.repetition, bf.finding_id): bf for bf in pool if bf.finding_id
        }

        # Precompute intra-run duplicate_of chains so deduplicated TPs are not counted as false disproofs
        dup_parent_by_run: dict[tuple[str, int, str], str] = {}
        for t in trials:
            b_tier = t.ablation_tier.split("@")[0]
            for v in t.findings:
                fid = str(v.get("id") or "")
                dup_of = _extract_duplicate_of_id(v)
                if fid and dup_of and dup_of != fid:
                    dup_parent_by_run[(b_tier, t.repetition, fid)] = dup_of

        # Precompute discovery-stage TPs and FPs per (base_tier, repetition) for RQ2 funnel rates
        discovery_tps_by_run: dict[tuple[str, int], dict[str, float]] = defaultdict(dict)
        discovery_fps_by_run: dict[tuple[str, int], dict[str, float]] = defaultdict(dict)
        for t in trials:
            if t.ablation_tier.endswith("@discovery"):
                base_tier = t.ablation_tier.split("@")[0]
                for idx_v, v in enumerate(t.findings):
                    st_val = str(getattr(v.get("status"), "value", v.get("status", "Open")))
                    if st_val.split(".")[-1].lower() != "open":
                        continue
                    fid = str(v.get("id") or f"idx-{idx_v}")
                    bf = pool_by_run_fid.get((base_tier, t.repetition, fid))
                    if bf is None or not bf.in_blind_sample or bf.is_excluded:
                        continue
                    w = float(bf.sampling_weight)
                    if bf.resolved_label == "TP":
                        discovery_tps_by_run[(base_tier, t.repetition)][fid] = w
                    elif bf.resolved_label == "FP":
                        discovery_fps_by_run[(base_tier, t.repetition)][fid] = w

        by_tier: dict[str, list[TrialRunRecord]] = defaultdict(list)
        for t in trials:
            by_tier[t.ablation_tier].append(t)

        summaries: list[TierEvaluationSummary] = []
        for tier_key, tier_trials in by_tier.items():
            summaries.append(
                self._aggregate_tier(
                    eval_dir=eval_dir,
                    tier_key=tier_key,
                    tier_trials=tier_trials,
                    pool_by_run_fid=pool_by_run_fid,
                    dup_parent_by_run=dup_parent_by_run,
                    discovery_tps_by_run=discovery_tps_by_run,
                    discovery_fps_by_run=discovery_fps_by_run,
                )
            )

        refusal_summary = self._aggregate_refusal_summary(summaries)

        payload = {
            "inter_rater_stats": inter_rater.model_dump(),
            "refusal_summary": refusal_summary,
            "tiers": [s.model_dump() for s in summaries],
        }
        (out_dir / "scorecard.json").write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )
        (out_dir / "scorecard.md").write_text(
            self._render_markdown(summaries, inter_rater, refusal_summary),
            encoding="utf-8",
        )
        (out_dir / "scorecard_tables.tex").write_text(
            self._render_latex_booktabs(summaries, inter_rater),
            encoding="utf-8",
        )
        self._export_modular_paper_tables(
            out_dir=out_dir,
            trials=trials,
            summaries=summaries,
            inter_rater=inter_rater,
            refusal_summary=refusal_summary,
            manifest_path=manifest_path,
            pool_path=pool_path,
        )

        logger.success(
            f"Generated scorecard artifacts in {out_dir} (scorecard.json, scorecard.md, scorecard_tables.tex, paper_tables/)"
        )
        return summaries

    def _aggregate_tier(
        self,
        eval_dir: Path,
        tier_key: str,
        tier_trials: list[TrialRunRecord],
        pool_by_run_fid: dict[tuple[str, int, str], BlindReviewFinding],
        dup_parent_by_run: dict[tuple[str, int, str], str],
        discovery_tps_by_run: dict[tuple[str, int], dict[str, float]],
        discovery_fps_by_run: dict[tuple[str, int], dict[str, float]],
    ) -> TierEvaluationSummary:
        has_any_expert_severity = any(
            bf.normalized_expert_severity is not None
            for bf in pool_by_run_fid.values()
            if bf.in_blind_sample and bf.resolved_label == "TP"
        )
        base_tier = tier_key.split("@")[0]

        def _resolve_dup_root(b_tier: str, rep_num: int, fid: str) -> str:
            cur = fid
            visited: set[str] = {cur}
            while (b_tier, rep_num, cur) in dup_parent_by_run:
                nxt = dup_parent_by_run[(b_tier, rep_num, cur)]
                if not nxt or nxt in visited:
                    break
                visited.add(nxt)
                cur = nxt
            return cur

        open_counts: list[float] = []
        tp_counts: list[float] = []
        tp_med_plus_counts: list[float] = []
        fp_counts: list[float] = []
        unlabeled_counts: list[float] = []
        poc_counts: list[float] = []
        poc_tp_counts: list[float] = []
        poc_fp_counts: list[float] = []
        open_unverified_counts: list[float] = []
        unverified_tp_counts: list[float] = []
        unverified_fp_counts: list[float] = []
        harness_limitation_counts: list[float] = []
        disproved_by_harness_counts: list[float] = []
        precisions: list[float] = []
        poc_precisions: list[float] = []
        unverified_precisions: list[float] = []
        precisions_med_plus: list[float] = []
        false_disproofs: list[float] = []
        fp_eliminations: list[float] = []
        poc_pass_rates: list[float] = []

        run_tokens: list[int] = []
        run_cached_tokens: list[int] = []
        run_uncached_tokens: list[int] = []
        run_thoughts_tokens: list[int] = []
        run_pure_output_tokens: list[int] = []
        run_output_tokens: list[int] = []
        run_times: list[float] = []
        run_llm_calls: list[float] = []
        run_llm_by_agent: list[dict[str, int]] = []
        run_tool_calls: list[float] = []
        run_tool_errors: list[float] = []
        run_tool_by_cat: list[dict[str, int]] = []
        run_tool_by_agent: list[dict[str, int]] = []
        run_tokens_by_agent: list[dict[str, dict[str, float]]] = []
        run_expert_questions: list[float] = []
        run_expert_from_history: list[float] = []
        run_expert_cache_hits: list[float] = []
        run_poc_attempts: list[float] = []
        run_poc_harness_cmds: list[float] = []
        run_poc_harness_per_finding: list[float] = []
        run_poc_gate_failures: list[float] = []
        tier_refusals: dict[str, int | dict] = {
            "total_safety_refusals": 0,
            "hard_safety_refusals": 0,
            "soft_refusals": 0,
            "api_safety_blocks": 0,
            "schema_validation_drops": 0,
            "by_agent": {},
        }
        severity_totals: dict[str, int] = defaultdict(int)
        module_totals: dict[str, int] = defaultdict(int)

        for trial in sorted(tier_trials, key=lambda x: x.repetition):
            rep = trial.repetition
            open_fids: set[str] = set()
            w_tp = 0.0
            w_tp_med_plus = 0.0
            w_fp = 0.0
            w_poc_tp = 0.0
            w_poc_fp = 0.0
            w_unver_tp = 0.0
            w_unver_fp = 0.0
            n_unlabeled = 0

            open_findings: list[dict] = []
            for idx_v, v in enumerate(trial.findings):
                st_str = str(getattr(v.get("status"), "value", v.get("status", "Open")))
                if st_str.split(".")[-1].lower() != "open":
                    continue
                open_findings.append(v)
                fid = str(v.get("id") or f"idx-{idx_v}")
                open_fids.add(fid)
                poc_ver = bool(
                    v.get("poc_verified")
                    or (isinstance(v.get("poc"), dict) and v["poc"].get("verified"))
                )
                bf = pool_by_run_fid.get((base_tier, rep, fid))
                raw_sv = v.get("severity") or (bf.severity if bf else "Informational")
                sev = str(getattr(raw_sv, "value", raw_sv)).split(".")[-1].capitalize()
                severity_totals[sev] += 1
                fp_str = (
                    str(v.get("file") or v.get("file_path") or (bf.file if bf else "unknown"))
                    .replace("\\", "/")
                    .lstrip("./")
                )
                parts = [p for p in Path(fp_str).parts if p not in (".", "")]
                mod_key = (
                    "/".join(parts[:2]) if len(parts) >= 2 else (parts[0] if parts else "unknown")
                )
                module_totals[mod_key] += 1

                if bf is None:
                    n_unlabeled += 1
                    continue
                if not bf.in_blind_sample or bf.is_excluded:
                    continue

                w = float(bf.sampling_weight)
                label = bf.resolved_label
                if label == "TP":
                    w_tp += w
                    if bf.normalized_expert_severity in ("Critical", "High", "Medium"):
                        w_tp_med_plus += w
                    if poc_ver:
                        w_poc_tp += w
                    else:
                        w_unver_tp += w
                elif label == "FP":
                    w_fp += w
                    if poc_ver:
                        w_poc_fp += w
                    else:
                        w_unver_fp += w
                else:
                    n_unlabeled += 1

            w_labeled_open = w_tp + w_fp
            w_poc_labeled = w_poc_tp + w_poc_fp
            w_unver_labeled = w_unver_tp + w_unver_fp
            n_open = trial.open_findings_count or len(open_findings)
            n_poc = trial.poc_verified_count
            trial_pts = (
                compute_phase_transitions(trial.findings)
                if ("@" not in tier_key and trial.findings)
                else trial.phase_transitions
            )
            has_poc_stage = any(pt.phase_id == "poc_creation" for pt in trial_pts) or (
                "@" in tier_key and tier_key.split("@", 1)[1] in ("poc_creation", "final_review")
            )
            n_open_unverified = max(0, n_open - n_poc) if has_poc_stage else 0
            n_harness_limitation = (
                sum(
                    1
                    for v in open_findings
                    if not (
                        v.get("poc_verified")
                        or (isinstance(v.get("poc"), dict) and v["poc"].get("verified"))
                    )
                    and "[HARNESS_LIMITATION]" in json.dumps(v)
                )
                if has_poc_stage
                else 0
            )
            n_disproved_by_harness = (
                sum(1 for v in trial.findings if "[DISPROVED_BY_HARNESS]" in json.dumps(v))
                if has_poc_stage
                else 0
            )

            open_counts.append(float(n_open))
            tp_counts.append(w_tp)
            tp_med_plus_counts.append(w_tp_med_plus)
            fp_counts.append(w_fp)
            unlabeled_counts.append(float(n_unlabeled))
            poc_counts.append(float(n_poc))
            poc_tp_counts.append(w_poc_tp)
            poc_fp_counts.append(w_poc_fp)
            open_unverified_counts.append(float(n_open_unverified))
            unverified_tp_counts.append(w_unver_tp)
            unverified_fp_counts.append(w_unver_fp)
            harness_limitation_counts.append(float(n_harness_limitation))
            disproved_by_harness_counts.append(float(n_disproved_by_harness))

            if w_labeled_open > 0:
                precisions.append(w_tp / w_labeled_open)
                if has_any_expert_severity:
                    precisions_med_plus.append(w_tp_med_plus / w_labeled_open)
            if w_poc_labeled > 0:
                poc_precisions.append(w_poc_tp / w_poc_labeled)
            if w_unver_labeled > 0:
                unverified_precisions.append(w_unver_tp / w_unver_labeled)
            if n_open > 0:
                poc_pass_rates.append(n_poc / n_open)

            disc_tps_map = discovery_tps_by_run.get((base_tier, rep), {})
            if disc_tps_map:
                tot_disc_tp = sum(disc_tps_map.values())
                if tot_disc_tp > 0:
                    disproved_tp = sum(
                        w
                        for fid, w in disc_tps_map.items()
                        if fid not in open_fids
                        and _resolve_dup_root(base_tier, rep, fid) not in open_fids
                    )
                    false_disproofs.append(disproved_tp / tot_disc_tp)

            disc_fps_map = discovery_fps_by_run.get((base_tier, rep), {})
            if disc_fps_map:
                tot_disc_fp = sum(disc_fps_map.values())
                if tot_disc_fp > 0:
                    elim_fp = sum(w for fid, w in disc_fps_map.items() if fid not in open_fids)
                    fp_eliminations.append(elim_fp / tot_disc_fp)

            tho_tok, pure_out_tok = self._load_trial_thoughts_and_output_tokens(
                eval_dir=eval_dir, tier_key=tier_key, trial=trial
            )
            if "@" not in tier_key:
                rep_dir = eval_dir / "trials" / tier_key / f"rep_{rep}"
                telem = self._load_trial_telemetry(rep_dir=rep_dir, trial_findings=trial.findings)
                if telem.get("has_telemetry"):
                    run_llm_calls.append(float(telem["llm_calls_total"]))
                    run_llm_by_agent.append(dict(telem["llm_calls_by_agent"]))
                    run_tool_calls.append(float(telem["tool_calls_total"]))
                    run_tool_errors.append(float(telem["tool_errors_total"]))
                    run_tool_by_cat.append(dict(telem["tool_calls_by_category"]))
                    run_tool_by_agent.append(dict(telem["tool_calls_by_agent"]))
                    run_tokens_by_agent.append(dict(telem["tokens_by_agent"]))
                    run_expert_questions.append(float(telem["expert_questions"]))
                    run_expert_from_history.append(float(telem["expert_answered_from_history"]))
                    run_expert_cache_hits.append(float(telem["expert_cache_hits"]))
                    p_att = int(telem["poc_attempts"])
                    p_hcmds = int(telem["poc_harness_commands"])
                    run_poc_attempts.append(float(p_att))
                    run_poc_harness_cmds.append(float(p_hcmds))
                    if p_att > 0:
                        run_poc_harness_per_finding.append(p_hcmds / p_att)
                    run_poc_gate_failures.append(float(telem["poc_gate_failures"]))
                    t_ref = telem["refusals"]
                    for rk in (
                        "total_safety_refusals",
                        "hard_safety_refusals",
                        "soft_refusals",
                        "api_safety_blocks",
                        "schema_validation_drops",
                    ):
                        tier_refusals[rk] = int(tier_refusals.get(rk, 0)) + int(t_ref.get(rk, 0))
                    ag_dst = tier_refusals["by_agent"]
                    assert isinstance(ag_dst, dict)
                    for ag_name, ag_counts in (t_ref.get("by_agent") or {}).items():
                        b_ag = ag_dst.setdefault(
                            ag_name,
                            {
                                "total_safety_refusals": 0,
                                "hard_safety_refusals": 0,
                                "soft_refusals": 0,
                                "api_safety_blocks": 0,
                                "schema_validation_drops": 0,
                            },
                        )
                        for rk in b_ag:
                            b_ag[rk] += int(ag_counts.get(rk, 0))

            run_tokens.append(trial.total_tokens)
            run_cached_tokens.append(trial.cached_tokens)
            run_uncached_tokens.append(trial.uncached_input_tokens)
            run_thoughts_tokens.append(tho_tok)
            run_pure_output_tokens.append(pure_out_tok)
            run_output_tokens.append(trial.output_tokens)
            run_times.append(trial.wall_clock_seconds)

        funnel_acc: dict[str, dict[str, int]] = defaultdict(
            lambda: {
                "entering": 0,
                "surviving": 0,
                "closed": 0,
                "duplicate": 0,
                "poc_verified": 0,
                "upgraded": 0,
                "downgraded": 0,
                "unchanged": 0,
            }
        )
        base_tier_unqual = re.sub(r"\[.*\]$", "", base_tier)
        requires_full_pipeline = "@" not in tier_key and base_tier_unqual in (
            "full",
            "no_tm",
            "no_expert",
        )
        funnel_trial_pts: list[list] = []
        for trial in tier_trials:
            pts = (
                compute_phase_transitions(trial.findings)
                if ("@" not in tier_key and trial.findings)
                else trial.phase_transitions
            )
            if not pts:
                continue
            if (
                requires_full_pipeline
                and "final_review" not in {pt.phase_id for pt in pts}
                and pts[-1].surviving_open_count > 0
            ):
                continue
            funnel_trial_pts.append(pts)
        if not funnel_trial_pts:
            for trial in tier_trials:
                pts = (
                    compute_phase_transitions(trial.findings)
                    if ("@" not in tier_key and trial.findings)
                    else trial.phase_transitions
                )
                if pts:
                    funnel_trial_pts.append(pts)
        for pts in funnel_trial_pts:
            for pt in pts:
                bucket = funnel_acc[pt.phase_id]
                bucket["entering"] += pt.entering_count
                bucket["surviving"] += pt.surviving_open_count
                bucket["closed"] += pt.closed_count
                bucket["duplicate"] += pt.duplicate_count
                bucket["poc_verified"] += pt.poc_verified_count
                bucket["upgraded"] += pt.severity_upgraded_count
                bucket["downgraded"] += pt.severity_downgraded_count
                bucket["unchanged"] += pt.severity_unchanged_count

        n_reps = max(1, len(tier_trials))
        n_funnel_reps = max(1, len(funnel_trial_pts))
        phase_funnel_summary = {
            pid: {k: round(v / n_funnel_reps, 2) for k, v in counts.items()}
            for pid, counts in funnel_acc.items()
        }

        severity_distribution_mean = {
            sev: round(cnt / n_reps, 2) for sev, cnt in sorted(severity_totals.items())
        }
        module_distribution_mean = {
            mod: round(cnt / n_reps, 2)
            for mod, cnt in sorted(module_totals.items(), key=lambda x: (-x[1], x[0]))
        }

        mean_open = statistics.fmean(open_counts) if open_counts else 0.0
        mean_tp = statistics.fmean(tp_counts) if tp_counts else 0.0
        mean_tok = statistics.fmean(run_tokens) if run_tokens else 0.0
        tokens_per_tp = round(mean_tok / mean_tp, 1) if mean_tp > 0 else None

        lookup_base = re.sub(r"\[.*\]$", "", base_tier)
        fallback_name = str(ABLATION_TIERS.get(lookup_base, {}).get("name", tier_key))
        tier_name = (
            tier_trials[0].tier_name
            if tier_trials and tier_trials[0].tier_name
            else (
                f"{fallback_name} [{tier_key.split('@')[1]}]" if "@" in tier_key else fallback_name
            )
        )
        model_str = tier_trials[0].model if tier_trials else ""

        def _mean_std(vals: list[float], ndigits: int = 2) -> tuple[float, float]:
            if not vals:
                return 0.0, 0.0
            m_v = round(statistics.fmean(vals), ndigits)
            s_v = round(statistics.stdev(vals) if len(vals) > 1 else 0.0, ndigits)
            return m_v, s_v

        llm_mean, llm_std = _mean_std(run_llm_calls)
        tool_mean, tool_std = _mean_std(run_tool_calls)
        tool_err_mean, tool_err_std = _mean_std(run_tool_errors)
        exp_q_mean, exp_q_std = _mean_std(run_expert_questions)
        exp_hist_mean, exp_hist_std = _mean_std(run_expert_from_history)
        poc_att_mean, poc_att_std = _mean_std(run_poc_attempts)
        poc_cmd_mean, poc_cmd_std = _mean_std(run_poc_harness_cmds)
        poc_gate_mean, poc_gate_std = _mean_std(run_poc_gate_failures)

        llm_by_agent_summary: dict[str, dict[str, float]] = {}
        if run_llm_by_agent:
            seen_agents = sorted({ag for d in run_llm_by_agent for ag in d})
            for ag in seen_agents:
                ag_vals = [float(d.get(ag, 0)) for d in run_llm_by_agent]
                ag_m, ag_s = _mean_std(ag_vals)
                llm_by_agent_summary[ag] = {"mean": ag_m, "std": ag_s}

        tool_by_cat_summary: dict[str, dict[str, float]] = {}
        if run_tool_by_cat:
            for cat in self.TOOL_CATEGORIES:
                cat_vals = [float(d.get(cat, 0)) for d in run_tool_by_cat]
                c_m, c_s = _mean_std(cat_vals)
                tool_by_cat_summary[cat] = {"mean": c_m, "std": c_s}

        tool_by_agent_summary: dict[str, dict[str, float]] = {}
        if run_tool_by_agent:
            seen_tool_agents = sorted({ag for d in run_tool_by_agent for ag in d})
            for ag in seen_tool_agents:
                ag_vals = [float(d.get(ag, 0)) for d in run_tool_by_agent]
                ag_m, ag_s = _mean_std(ag_vals)
                tool_by_agent_summary[ag] = {"mean": ag_m, "std": ag_s}

        tokens_by_agent_summary: dict[str, dict[str, float | None]] = {}
        if run_tokens_by_agent:
            seen_tok_agents = sorted({ag for d in run_tokens_by_agent for ag in d})
            eff_model = model_str or "gemini-3.8-flash"
            for ag in seen_tok_agents:
                unc_vals = [
                    float((d.get(ag) or {}).get("uncached_input", 0.0)) for d in run_tokens_by_agent
                ]
                cac_vals = [
                    float((d.get(ag) or {}).get("cached_input", 0.0)) for d in run_tokens_by_agent
                ]
                inp_vals = [
                    float((d.get(ag) or {}).get("total_input", 0.0)) for d in run_tokens_by_agent
                ]
                tho_vals = [
                    float((d.get(ag) or {}).get("thoughts", 0.0)) for d in run_tokens_by_agent
                ]
                out_vals = [
                    float((d.get(ag) or {}).get("output", 0.0)) for d in run_tokens_by_agent
                ]
                tot_out_vals = [
                    float((d.get(ag) or {}).get("total_output", 0.0)) for d in run_tokens_by_agent
                ]
                unc_m, unc_s = _mean_std(unc_vals, ndigits=1)
                cac_m, cac_s = _mean_std(cac_vals, ndigits=1)
                inp_m, inp_s = _mean_std(inp_vals, ndigits=1)
                tho_m, tho_s = _mean_std(tho_vals, ndigits=1)
                out_m, out_s = _mean_std(out_vals, ndigits=1)
                tot_out_m, tot_out_s = _mean_std(tot_out_vals, ndigits=1)
                ag_cost = self._estimate_cost_usd(unc_m, cac_m, tot_out_m, model=eff_model)
                tokens_by_agent_summary[ag] = {
                    "uncached_mean": unc_m,
                    "uncached_std": unc_s,
                    "cached_mean": cac_m,
                    "cached_std": cac_s,
                    "input_mean": inp_m,
                    "input_std": inp_s,
                    "cache_hit_rate": round(cac_m / inp_m, 4) if inp_m > 0 else 0.0,
                    "thoughts_mean": tho_m,
                    "thoughts_std": tho_s,
                    "output_mean": out_m,
                    "output_std": out_s,
                    "output_total_mean": tot_out_m,
                    "output_total_std": tot_out_s,
                    "estimated_cost_usd": round(ag_cost, 4) if ag_cost is not None else None,
                }

        return TierEvaluationSummary(
            ablation_tier=tier_key,
            tier_name=tier_name,
            model=model_str,
            repetitions=len(tier_trials),
            mean_open_findings=round(mean_open, 2),
            std_open_findings=round(
                statistics.stdev(open_counts) if len(open_counts) > 1 else 0.0, 2
            ),
            min_open_findings=int(min(open_counts)) if open_counts else 0,
            max_open_findings=int(max(open_counts)) if open_counts else 0,
            mean_true_positives=round(mean_tp, 2),
            std_true_positives=round(statistics.stdev(tp_counts) if len(tp_counts) > 1 else 0.0, 2),
            mean_false_positives=round(statistics.fmean(fp_counts), 2) if fp_counts else 0.0,
            std_false_positives=round(
                statistics.stdev(fp_counts) if len(fp_counts) > 1 else 0.0, 2
            ),
            mean_unlabeled_open=round(statistics.fmean(unlabeled_counts), 2)
            if unlabeled_counts
            else 0.0,
            mean_poc_verified=round(statistics.fmean(poc_counts), 2) if poc_counts else 0.0,
            std_poc_verified=round(statistics.stdev(poc_counts) if len(poc_counts) > 1 else 0.0, 2),
            min_poc_verified=int(min(poc_counts)) if poc_counts else 0,
            max_poc_verified=int(max(poc_counts)) if poc_counts else 0,
            mean_poc_verified_tps=round(statistics.fmean(poc_tp_counts), 2)
            if poc_tp_counts
            else 0.0,
            mean_poc_verified_fps=round(statistics.fmean(poc_fp_counts), 2)
            if poc_fp_counts
            else 0.0,
            mean_open_unverified=round(statistics.fmean(open_unverified_counts), 2)
            if open_unverified_counts
            else 0.0,
            mean_open_unverified_tps=round(statistics.fmean(unverified_tp_counts), 2)
            if unverified_tp_counts
            else 0.0,
            mean_open_unverified_fps=round(statistics.fmean(unverified_fp_counts), 2)
            if unverified_fp_counts
            else 0.0,
            mean_harness_limitation=round(statistics.fmean(harness_limitation_counts), 2)
            if harness_limitation_counts
            else 0.0,
            mean_disproved_by_harness=round(statistics.fmean(disproved_by_harness_counts), 2)
            if disproved_by_harness_counts
            else 0.0,
            mean_true_positives_medium_plus=round(statistics.fmean(tp_med_plus_counts), 2)
            if tp_med_plus_counts
            else 0.0,
            precision_mean=round(statistics.fmean(precisions), 4) if precisions else None,
            precision_std=(
                round(statistics.stdev(precisions) if len(precisions) > 1 else 0.0, 4)
                if precisions
                else None
            ),
            poc_verified_precision_mean=(
                round(statistics.fmean(poc_precisions), 4) if poc_precisions else None
            ),
            poc_verified_precision_std=(
                round(statistics.stdev(poc_precisions) if len(poc_precisions) > 1 else 0.0, 4)
                if poc_precisions
                else None
            ),
            open_unverified_precision_mean=(
                round(statistics.fmean(unverified_precisions), 4) if unverified_precisions else None
            ),
            open_unverified_precision_std=(
                round(
                    statistics.stdev(unverified_precisions)
                    if len(unverified_precisions) > 1
                    else 0.0,
                    4,
                )
                if unverified_precisions
                else None
            ),
            precision_medium_plus_mean=(
                round(statistics.fmean(precisions_med_plus), 4) if precisions_med_plus else None
            ),
            false_disproof_rate_mean=(
                round(statistics.fmean(false_disproofs), 4) if false_disproofs else None
            ),
            fp_elimination_rate_mean=(
                round(statistics.fmean(fp_eliminations), 4) if fp_eliminations else None
            ),
            poc_pass_rate_mean=(
                round(statistics.fmean(poc_pass_rates), 4) if poc_pass_rates else None
            ),
            mean_tokens_per_run=round(mean_tok, 1),
            mean_cached_tokens_per_run=round(statistics.fmean(run_cached_tokens), 1)
            if run_cached_tokens
            else 0.0,
            mean_uncached_input_tokens_per_run=round(statistics.fmean(run_uncached_tokens), 1)
            if run_uncached_tokens
            else 0.0,
            mean_thoughts_tokens_per_run=round(statistics.fmean(run_thoughts_tokens), 1)
            if run_thoughts_tokens
            else 0.0,
            mean_pure_output_tokens_per_run=round(statistics.fmean(run_pure_output_tokens), 1)
            if run_pure_output_tokens
            else 0.0,
            mean_output_tokens_per_run=round(statistics.fmean(run_output_tokens), 1)
            if run_output_tokens
            else 0.0,
            tokens_per_tp=tokens_per_tp,
            mean_wall_clock_seconds=None
            if "@" in tier_key
            else (round(statistics.fmean(run_times), 2) if run_times else 0.0),
            mean_llm_calls_per_run=llm_mean,
            std_llm_calls_per_run=llm_std,
            llm_calls_by_agent=llm_by_agent_summary,
            mean_tool_calls_per_run=tool_mean,
            std_tool_calls_per_run=tool_std,
            mean_tool_errors_per_run=tool_err_mean,
            std_tool_errors_per_run=tool_err_std,
            tool_calls_by_category=tool_by_cat_summary,
            tool_calls_by_agent=tool_by_agent_summary,
            tokens_by_agent=tokens_by_agent_summary,
            mean_project_expert_questions=exp_q_mean,
            std_project_expert_questions=exp_q_std,
            mean_project_expert_answered_from_history=exp_hist_mean,
            std_project_expert_answered_from_history=exp_hist_std,
            mean_project_expert_cache_hits=(
                round(statistics.fmean(run_expert_cache_hits), 2) if run_expert_cache_hits else 0.0
            ),
            mean_poc_attempts=poc_att_mean,
            std_poc_attempts=poc_att_std,
            mean_poc_harness_commands=poc_cmd_mean,
            std_poc_harness_commands=poc_cmd_std,
            mean_poc_harness_commands_per_finding=(
                round(statistics.fmean(run_poc_harness_per_finding), 2)
                if run_poc_harness_per_finding
                else None
            ),
            std_poc_harness_commands_per_finding=(
                round(
                    statistics.stdev(run_poc_harness_per_finding)
                    if len(run_poc_harness_per_finding) > 1
                    else 0.0,
                    2,
                )
                if run_poc_harness_per_finding
                else None
            ),
            mean_poc_gate_failures=poc_gate_mean,
            std_poc_gate_failures=poc_gate_std,
            refusals_summary=tier_refusals if "@" not in tier_key else {},
            phase_funnel_summary=phase_funnel_summary,
            severity_distribution_mean=severity_distribution_mean,
            module_distribution_mean=module_distribution_mean,
        )

    @staticmethod
    def _aggregate_refusal_summary(summaries: list[TierEvaluationSummary]) -> dict:
        """Aggregates safety refusals and schema drops across all primary (non-checkpoint) tiers."""
        totals: dict[str, int | dict] = {
            "total_safety_refusals": 0,
            "hard_safety_refusals": 0,
            "soft_refusals": 0,
            "api_safety_blocks": 0,
            "schema_validation_drops": 0,
            "by_agent": {},
            "by_tier": {},
        }
        keys = (
            "total_safety_refusals",
            "hard_safety_refusals",
            "soft_refusals",
            "api_safety_blocks",
            "schema_validation_drops",
        )
        by_agent: dict[str, dict[str, int]] = {}
        by_tier: dict[str, dict[str, int]] = {}
        for s in summaries:
            if "@" in s.ablation_tier or not s.refusals_summary:
                continue
            rs = s.refusals_summary
            tier_entry = {k: int(rs.get(k, 0) or 0) for k in keys}
            for k in keys:
                totals[k] = int(totals[k]) + tier_entry[k]
            if any(v > 0 for v in tier_entry.values()):
                by_tier[s.ablation_tier] = tier_entry
            ag_map = rs.get("by_agent")
            if isinstance(ag_map, dict):
                for ag, ag_counts in ag_map.items():
                    if not isinstance(ag_counts, dict):
                        continue
                    b = by_agent.setdefault(ag, {k: 0 for k in keys})
                    for k in keys:
                        b[k] += int(ag_counts.get(k, 0) or 0)
        totals["by_agent"] = by_agent
        totals["by_tier"] = by_tier
        return totals

    def _render_markdown(
        self,
        summaries: list[TierEvaluationSummary],
        inter_rater: InterRaterStats,
        refusal_summary: dict | None = None,
    ) -> str:
        lines = [
            "# Mjolnir Real-World Evaluation Scorecard",
            "",
            "## 1. Blind Dual-Expert Review & Inter-Rater Reliability",
            "",
            f"- **Total Findings in Pool**: `{inter_rater.total_findings}` (In-Sample Deck: `{inter_rater.in_sample_findings}`)",
            f"- **Adjudicated Findings**: `{inter_rater.adjudicated_count}` "
            f"(Confirmed TPs: `{inter_rater.confirmed_tp_count}`, Medium+ TPs: `{inter_rater.confirmed_tp_medium_or_above_count}`, Confirmed FPs: `{inter_rater.confirmed_fp_count}`, Excluded: `{inter_rater.excluded_count}`, Unlabeled: `{inter_rater.unlabeled_count}`)",
            f"- **Double-Reviewed Findings**: `{inter_rater.double_reviewed_count}` (Single-Reviewed: `{inter_rater.single_reviewed_count}`) "
            f"| **Raw Agreement**: `{inter_rater.raw_agreement_rate:.1%}` | **Cohen's Kappa ($\\kappa$)**: `{inter_rater.cohens_kappa:.3f}`",
        ]
        if refusal_summary is not None:
            lines.append(
                f"- **Safety Refusals Across Primary Runs**: `{refusal_summary.get('total_safety_refusals', 0)}` "
                f"(Hard Plain-Text: `{refusal_summary.get('hard_safety_refusals', 0)}`, "
                f"Structured Soft: `{refusal_summary.get('soft_refusals', 0)}`, "
                f"API Safety Blocks: `{refusal_summary.get('api_safety_blocks', 0)}` "
                f"| Non-Refusal Schema Drops: `{refusal_summary.get('schema_validation_drops', 0)}`)"
            )
        lines.extend(
            [
                "",
                "## 2. RQ1, RQ2 & RQ4: Alert Precision, Verification & Token Cost Comparison",
                "",
                "| Tier | Mean Open | TPs | FPs | PoC Verified | Precision | False Disproof | FP Elim. | Tokens/Run | Tokens/TP | Time (s) |",
                "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
            ]
        )
        for s in summaries:
            tok_tp_str = f"{s.tokens_per_tp:,.0f}" if s.tokens_per_tp is not None else "N/A"
            time_str = (
                f"{s.mean_wall_clock_seconds:.1f}s"
                if s.mean_wall_clock_seconds is not None
                else "—"
            )
            prec_str = f"{s.precision_mean:.1%}" if s.precision_mean is not None else "N/A"
            fdisp_str = (
                f"{s.false_disproof_rate_mean:.1%}"
                if s.false_disproof_rate_mean is not None
                else "N/A"
            )
            fpelim_str = (
                f"{s.fp_elimination_rate_mean:.1%}"
                if s.fp_elimination_rate_mean is not None
                else "N/A"
            )
            lines.append(
                f"| **{s.tier_name}** | {s.mean_open_findings:.1f} | {s.mean_true_positives:.1f} "
                f"| {s.mean_false_positives:.1f} | {s.mean_poc_verified:.1f} "
                f"| {prec_str} | {fdisp_str} | {fpelim_str} "
                f"| {s.mean_tokens_per_run:,.0f} | {tok_tp_str} | {time_str} |"
            )

        primary_runs = [
            s for s in summaries if "@" not in s.ablation_tier and s.phase_funnel_summary
        ]
        if primary_runs:
            lines.extend(
                [
                    "",
                    "## 3. RQ2: Phase-Transition Verification Funnel & Severity Shifts",
                    "",
                    "| Run | Phase | Entering | Surviving Open | Closed | Duplicate | PoC Verified | Upgraded | Downgraded |",
                    "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
                ]
            )
            for s in primary_runs:
                for pid, counts in s.phase_funnel_summary.items():
                    lines.append(
                        f"| **{s.ablation_tier}** | `{pid}` | {counts['entering']:.1f} "
                        f"| {counts['surviving']:.1f} | {counts['closed']:.1f} "
                        f"| {counts['duplicate']:.1f} | {counts['poc_verified']:.1f} "
                        f"| {counts['upgraded']:.1f} | {counts['downgraded']:.1f} |"
                    )

        lines.extend(
            [
                "",
                "## 4. RQ3 & RQ4: Run-to-Run Stability, Token Caching & Computational Overhead",
                "",
                "| Tier | Reps | Mean Open (± SD) | Min–Max Open | Mean PoC (± SD) | Uncached Input Tokens | Cached Input Tokens | Thinking Tokens | Output Tokens | Total Tokens | Tokens/TP | Wall Clock (s) |",
                "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
            ]
        )
        for s in summaries:
            if "@" in s.ablation_tier:
                continue
            tok_tp_str = f"{s.tokens_per_tp:,.0f}" if s.tokens_per_tp is not None else "N/A"
            time_str = (
                f"{s.mean_wall_clock_seconds:.1f}s"
                if s.mean_wall_clock_seconds is not None
                else "—"
            )
            lines.append(
                f"| **{s.tier_name}** | {s.repetitions} "
                f"| {s.mean_open_findings:.1f} (\u00b1{s.std_open_findings:.1f}) "
                f"| {s.min_open_findings}\u2013{s.max_open_findings} "
                f"| {s.mean_poc_verified:.1f} (\u00b1{s.std_poc_verified:.1f}) "
                f"| {s.mean_uncached_input_tokens_per_run:,.0f} "
                f"| {s.mean_cached_tokens_per_run:,.0f} | {s.mean_thoughts_tokens_per_run:,.0f} | {s.mean_pure_output_tokens_per_run:,.0f} "
                f"| {s.mean_tokens_per_run:,.0f} "
                f"| {tok_tp_str} | {time_str} |"
            )

        return "\n".join(lines) + "\n"

    def _render_latex_booktabs(
        self,
        summaries: list[TierEvaluationSummary],
        inter_rater: InterRaterStats,
    ) -> str:
        lines = [
            "% Auto-generated by Mjolnir ScorecardGenerator",
            f"% Blind Review Pool: N={inter_rater.total_findings}, TP={inter_rater.confirmed_tp_count}, FP={inter_rater.confirmed_fp_count}, Cohen's kappa={inter_rater.cohens_kappa:.3f}",
            "\\begin{table*}[t]",
            "\\centering",
            "\\small",
            "\\begin{tabular}{lcccccccc}",
            "\\toprule",
            "\\textbf{Configuration} & \\textbf{Open} & \\textbf{PoC Ver.} & \\textbf{TP} & \\textbf{FP} & \\textbf{Precision} & \\textbf{Tokens (M)} & \\textbf{Tokens/TP} & \\textbf{Time (min)} \\\\",
            "\\midrule",
        ]
        for s in summaries:
            safe_name = self._paper_tier_label(s)
            tok_m_str = f"{s.mean_tokens_per_run / 1_000_000:.2f}M"
            tok_tp_str = f"{s.tokens_per_tp:,.0f}" if s.tokens_per_tp is not None else "---"
            time_str = (
                f"{s.mean_wall_clock_seconds / 60.0:.1f}m"
                if s.mean_wall_clock_seconds is not None
                else "\\textemdash{}"
            )
            prec_tex = (
                f"{s.precision_mean * 100:.1f}\\%"
                if s.precision_mean is not None
                else "\\textemdash{}"
            )
            lines.append(
                f"{safe_name} & {s.mean_open_findings:.1f} & {s.mean_poc_verified:.1f} & "
                f"{s.mean_true_positives:.1f} & {s.mean_false_positives:.1f} & {prec_tex} & "
                f"{tok_m_str} & {tok_tp_str} & {time_str} \\\\"
            )
        lines.extend(
            [
                "\\bottomrule",
                "\\end{tabular}",
                "\\caption{Evaluation across pinned Root-of-Trust targets: open findings, PoC-verified findings, confirmed true positives, alert precision, and token/time cost.}",
                "\\label{tab:mjolnir-evaluation}",
                "\\end{table*}",
            ]
        )
        return "\n".join(lines) + "\n"

    @classmethod
    def _get_model_pricing(cls, model: str = "gemini-3.8-flash") -> dict[str, float | str] | None:
        """Returns per-1M-token USD pricing schedule for a model from the pinned schedule."""
        norm_model = (model or "gemini-3.8-flash").strip().split("/")[-1].split("@")[0]
        return cls.MODEL_PRICING_SCHEDULES_USD_PER_1M.get(norm_model)

    @classmethod
    def _estimate_cost_usd(
        cls,
        uncached_in: float,
        cached_in: float,
        output_tok: float,
        model: str = "gemini-3.8-flash",
    ) -> float | None:
        """Computes list-price API dollar cost using the model's published schedule, or None if unavailable."""
        sched = cls._get_model_pricing(model)
        if sched is None:
            return None
        return (
            (uncached_in * float(sched["uncached_input"]) / 1_000_000.0)
            + (cached_in * float(sched["cached_input"]) / 1_000_000.0)
            + (output_tok * float(sched["output_and_thoughts"]) / 1_000_000.0)
        )

    @classmethod
    def _paper_tier_label(cls, s: TierEvaluationSummary) -> str:
        """Formats tier keys into concise LaTeX configuration labels."""
        tk = s.ablation_tier
        ckpt_suffix = ""
        if "@" in tk:
            base, ckpt = tk.split("@", 1)
            ckpt_suffix = f" (\\texttt{{@{cls._latex_escape(ckpt)}}})"
        else:
            base = tk
        model_suffix = ""
        if "[" in base and base.endswith("]"):
            b_core, m_slug = base[:-1].split("[", 1)
            base = b_core
            pretty_models = {
                "gemini-3.8-flash": "Gemini 3.8 Flash",
                "gemini-4-argon": "Gemini 4 Argon",
                "claude-sonnet-5-5": "Claude Sonnet 5.5",
            }
            model_suffix = f" ({pretty_models.get(m_slug, cls._latex_escape(m_slug))})"
        mapping = {
            "full": "\\texttt{Full}",
            "no_tm": "\\texttt{w/o Threat Model}",
            "no_expert": "\\texttt{w/o Project Expert}",
            "base": "\\texttt{Base (w/o TM, w/o Expert)}",
            "per_file": "Single-Agent (Per-File)",
            "per_file_no_tm": "Single-Agent (Per-File, w/o TM)",
            "holistic": "Single-Agent (Whole-Dir)",
            "holistic_no_tm": "Single-Agent (Whole-Dir, w/o TM)",
        }
        label = mapping.get(base, cls._latex_escape(s.tier_name))
        return f"{label}{model_suffix}{ckpt_suffix}"

    @staticmethod
    def _fmt_tokens_m(tokens: float) -> str:
        """Formats token counts in millions (M) for compact LaTeX tables."""
        m = tokens / 1_000_000.0
        if m >= 10.0:
            return f"{m:.1f}M"
        return f"{m:.2f}M"

    @staticmethod
    def _latex_escape(text: str) -> str:
        return (
            text.replace("&", "\\&")
            .replace("_", "\\_")
            .replace("@", "\\texttt{@}")
            .replace("%", "\\%")
        )

    def _export_modular_paper_tables(
        self,
        out_dir: Path,
        trials: list[TrialRunRecord],
        summaries: list[TierEvaluationSummary],
        inter_rater: InterRaterStats,
        refusal_summary: dict | None,
        manifest_path: Path,
        pool_path: Path,
    ) -> None:
        """Generates standalone LaTeX booktabs tables and vector figures with provenance metadata headers."""
        tables_dir = out_dir / "paper_tables"
        tables_dir.mkdir(parents=True, exist_ok=True)

        repo_name = trials[0].repo_name if trials else out_dir.parent.name
        project_name = trials[0].project_name if trials else repo_name
        pinned_rev = trials[0].pinned_rev if trials else "HEAD"
        target_dir = trials[0].target_dir if trials else "."
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        mjolnir_commit = self._get_mjolnir_commit()
        mjolnir_dirty = self._is_mjolnir_dirty()
        dirty_suffix = " (dirty)" if mjolnir_dirty else ""
        manifest_sha256 = (
            hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_path.exists() else ""
        )
        pool_sha256 = (
            hashlib.sha256(pool_path.read_bytes()).hexdigest() if pool_path.exists() else ""
        )

        meta_body_lines = [
            "=============================================================================",
            "AUTO-GENERATED BY MJOLNIR EVALUATION HARNESS — DO NOT EDIT MANUALLY",
            f"Target Repository : {project_name} ({repo_name}) @ {pinned_rev[:12]}",
            f"Target Scope      : {target_dir}",
            f"Mjolnir Commit    : {mjolnir_commit[:12]}{dirty_suffix}",
            f"Generated At (UTC): {generated_at}",
            f"Trials in Manifest: {len(trials)} (SHA-256: {manifest_sha256[:16]}...)",
            f"Blind Review Pool : N={inter_rater.total_findings} findings (In-sample={inter_rater.in_sample_findings}, TP={inter_rater.confirmed_tp_count}, FP={inter_rater.confirmed_fp_count}, Excluded={inter_rater.excluded_count}, Unlabeled={inter_rater.unlabeled_count}, kappa={inter_rater.cohens_kappa:.3f})",
            "Token Pricing     : Per-model list-price schedule ($/1M tokens as of 2026-10-19)",
            "=============================================================================",
        ]
        meta_header = "\n".join(f"% {line}" for line in meta_body_lines)
        svg_meta_header = "<!--\n" + "\n".join(f"  {line}" for line in meta_body_lines) + "\n-->"

        by_key = {s.ablation_tier: s for s in summaries}

        is_adjudicated = (inter_rater.confirmed_tp_count + inter_rater.confirmed_fp_count) > 0

        for stale_f in tables_dir.glob("*.tex"):
            stale_f.unlink()

        exported_table_names: list[str] = []

        if is_adjudicated:
            # 1. Table: RQ1 Quality & Domain-Context Ablation vs. Controlled Single-Agent Baselines
            rq1_order = [
                "per_file_no_tm",
                "per_file",
                "holistic_no_tm",
                "holistic",
                "no_tm@discovery",
                "no_expert@discovery",
                "full@discovery",
                "no_tm",
                "no_expert",
                "full",
            ]
            rq1_tiers = [by_key[k] for k in rq1_order if k in by_key] or summaries
            rq1_lines = [
                meta_header,
                "\\begin{tabular}{@{}lrrrrrrr@{}}",
                "\\toprule",
                "\\textbf{Configuration} & \\textbf{Open} & \\textbf{PoC Ver.} & \\textbf{TP} & \\textbf{FP} & \\textbf{Precision} & \\textbf{Tokens} & \\textbf{Time (min)} \\\\",
                "\\midrule",
            ]
            for s in rq1_tiers:
                safe_name = self._paper_tier_label(s)
                tok_m = self._fmt_tokens_m(s.mean_tokens_per_run)
                time_str = (
                    f"{s.mean_wall_clock_seconds / 60.0:.1f}m"
                    if s.mean_wall_clock_seconds is not None
                    else "\\textemdash{}"
                )
                prec_rq1 = (
                    f"{s.precision_mean * 100:.1f}\\%"
                    if s.precision_mean is not None
                    else "\\textemdash{}"
                )
                rq1_lines.append(
                    f"{safe_name} & {s.mean_open_findings:.1f} & {s.mean_poc_verified:.1f} & "
                    f"{s.mean_true_positives:.1f} & {s.mean_false_positives:.1f} & "
                    f"{prec_rq1} & {tok_m} & {time_str} \\\\"
                )
            rq1_lines.extend(
                [
                    "\\bottomrule",
                    "\\end{tabular}",
                    "",
                ]
            )
            (tables_dir / "tab_rq1_ablation_baseline.tex").write_text(
                "\n".join(rq1_lines), encoding="utf-8"
            )
            exported_table_names.append("tab_rq1_ablation_baseline.tex")

            # 2. Table: RQ2 5-Stage Verification Funnel
            funnel_order = [
                f"{base}@{stage}"
                for base in ("no_tm", "no_expert", "full")
                for stage in (
                    "discovery",
                    "deduplication",
                    "initial_review",
                    "poc_creation",
                    "final_review",
                )
            ]
            rq2_tiers = [by_key[k] for k in funnel_order if k in by_key]
            rq2_lines = [
                meta_header,
                "\\begin{tabular}{@{}lrrrrrr@{}}",
                "\\toprule",
                "\\textbf{Pipeline Stage Checkpoint} & \\textbf{Open} & \\textbf{PoC Ver.} & \\textbf{TP} & \\textbf{FP} & \\textbf{FP Elim.} & \\textbf{False Disproof} \\\\",
                "\\midrule",
            ]
            for s in rq2_tiers:
                safe_name = self._paper_tier_label(s)
                fpelim_tex = (
                    f"{s.fp_elimination_rate_mean * 100:.1f}\\%"
                    if s.fp_elimination_rate_mean is not None
                    else "\\textemdash{}"
                )
                fdisp_tex = (
                    f"{s.false_disproof_rate_mean * 100:.1f}\\%"
                    if s.false_disproof_rate_mean is not None
                    else "\\textemdash{}"
                )
                rq2_lines.append(
                    f"{safe_name} & {s.mean_open_findings:.1f} & {s.mean_poc_verified:.1f} & "
                    f"{s.mean_true_positives:.1f} & {s.mean_false_positives:.1f} & "
                    f"{fpelim_tex} & {fdisp_tex} \\\\"
                )
            rq2_lines.extend(
                [
                    "\\bottomrule",
                    "\\end{tabular}",
                    "",
                ]
            )
            (tables_dir / "tab_rq2_verification_funnel.tex").write_text(
                "\n".join(rq2_lines), encoding="utf-8"
            )
            exported_table_names.append("tab_rq2_verification_funnel.tex")

        # 3. Table: RQ3 Run-to-Run Stability (requires >= 2 repetitions)
        rq3_tiers = [s for s in summaries if "@" not in s.ablation_tier]
        multi_rep_rq3 = [s for s in rq3_tiers if s.repetitions >= 2]
        if multi_rep_rq3:
            rq3_lines = [
                meta_header,
                "\\begin{tabular}{@{}lccccc@{}}",
                "\\toprule",
                "\\textbf{Configuration} & \\textbf{Reps} & \\textbf{Mean Open ($\\pm$ SD)} & \\textbf{Min--Max Open} & \\textbf{Mean PoC ($\\pm$ SD)} & \\textbf{Min--Max PoC} \\\\",
                "\\midrule",
            ]
            for s in multi_rep_rq3:
                safe_name = self._paper_tier_label(s)
                has_poc = "poc_creation" in (s.phase_funnel_summary or {})
                poc_mean_sd = (
                    f"{s.mean_poc_verified:.1f} ($\\pm${s.std_poc_verified:.1f})"
                    if has_poc
                    else "\\textemdash{}"
                )
                poc_range = (
                    f"{s.min_poc_verified}--{s.max_poc_verified}" if has_poc else "\\textemdash{}"
                )
                rq3_lines.append(
                    f"{safe_name} & {s.repetitions} & {s.mean_open_findings:.1f} ($\\pm${s.std_open_findings:.1f}) & "
                    f"{s.min_open_findings}--{s.max_open_findings} & {poc_mean_sd} & {poc_range} \\\\"
                )
            rq3_lines.extend(
                [
                    "\\bottomrule",
                    "\\end{tabular}",
                    "",
                ]
            )
            (tables_dir / "tab_rq3_consistency_stability.tex").write_text(
                "\n".join(rq3_lines), encoding="utf-8"
            )
            exported_table_names.append("tab_rq3_consistency_stability.tex")

        # 4. Table: RQ4 Token, Caching, Thinking vs Output, Latency & API Dollar Cost Breakdown
        rq4_lines = [
            meta_header,
            "\\begin{tabular}{@{}lrrrrrrr@{}}",
            "\\toprule",
            "\\textbf{Configuration} & \\textbf{Uncached In} & \\textbf{Cached In} & \\textbf{Cache \\%} & \\textbf{Thinking} & \\textbf{Output} & \\textbf{API Cost (\\$)} & \\textbf{Time (min)} \\\\",
            "\\midrule",
        ]
        for s in rq3_tiers:
            safe_name = self._paper_tier_label(s)
            tot_in = s.mean_uncached_input_tokens_per_run + s.mean_cached_tokens_per_run
            cache_pct = (s.mean_cached_tokens_per_run / tot_in * 100.0) if tot_in > 0 else 0.0
            cost_usd = self._estimate_cost_usd(
                s.mean_uncached_input_tokens_per_run,
                s.mean_cached_tokens_per_run,
                s.mean_output_tokens_per_run,
                model=s.model,
            )
            cost_str = f"\\${cost_usd:.2f}" if cost_usd is not None else "\\textemdash{}"
            time_str = (
                f"{s.mean_wall_clock_seconds / 60.0:.1f}m"
                if s.mean_wall_clock_seconds is not None
                else "\\textemdash{}"
            )
            rq4_lines.append(
                f"{safe_name} & {self._fmt_tokens_m(s.mean_uncached_input_tokens_per_run)} & "
                f"{self._fmt_tokens_m(s.mean_cached_tokens_per_run)} & {cache_pct:.1f}\\% & "
                f"{self._fmt_tokens_m(s.mean_thoughts_tokens_per_run)} & "
                f"{self._fmt_tokens_m(s.mean_pure_output_tokens_per_run)} & "
                f"{cost_str} & {time_str} \\\\"
            )
        rq4_lines.extend(
            [
                "\\bottomrule",
                "\\end{tabular}",
                "",
            ]
        )
        (tables_dir / "tab_rq4_token_cost_breakdown.tex").write_text(
            "\n".join(rq4_lines), encoding="utf-8"
        )
        exported_table_names.append("tab_rq4_token_cost_breakdown.tex")

        used_models = {
            (s.model or "gemini-3.8-flash").strip().split("/")[-1].split("@")[0] for s in summaries
        }
        pricing_used = {
            m: sched
            for m, sched in self.MODEL_PRICING_SCHEDULES_USD_PER_1M.items()
            if m in used_models
        }
        phase_token_breakdown = self._collect_phase_token_stats(
            eval_dir=out_dir, by_key=by_key, include_ablations=True
        )

        # 5. JSON Metadata Companion
        metadata_payload = {
            "generated_at_utc": generated_at,
            "mjolnir_commit": mjolnir_commit,
            "mjolnir_dirty": mjolnir_dirty,
            "trial_mjolnir_commits": sorted({t.mjolnir_commit for t in trials if t.mjolnir_commit}),
            "trial_mjolnir_dirty": any(t.mjolnir_dirty for t in trials),
            "project_name": project_name,
            "repo_name": repo_name,
            "pinned_rev": pinned_rev,
            "target_dir": target_dir,
            "total_trial_records": len(trials),
            "manifest_sha256": manifest_sha256,
            "blind_review_pool_sha256": pool_sha256,
            "blind_review_pool_stats": inter_rater.model_dump(),
            "refusal_summary": refusal_summary,
            "pricing_schedules_usd_per_1m_tokens": pricing_used,
            "exported_tables": exported_table_names,
            "phase_token_breakdown": phase_token_breakdown,
            "tiers_summary": [
                {
                    "ablation_tier": s.ablation_tier,
                    "tier_name": s.tier_name,
                    "model": s.model or "gemini-3.8-flash",
                    "repetitions": s.repetitions,
                    "mean_open_findings": s.mean_open_findings,
                    "std_open_findings": s.std_open_findings,
                    "min_open_findings": s.min_open_findings,
                    "max_open_findings": s.max_open_findings,
                    "mean_poc_verified": s.mean_poc_verified,
                    "std_poc_verified": s.std_poc_verified,
                    "min_poc_verified": s.min_poc_verified,
                    "max_poc_verified": s.max_poc_verified,
                    "mean_poc_verified_tps": s.mean_poc_verified_tps,
                    "mean_poc_verified_fps": s.mean_poc_verified_fps,
                    "poc_verified_precision_mean": s.poc_verified_precision_mean,
                    "poc_verified_precision_std": s.poc_verified_precision_std,
                    "mean_open_unverified": s.mean_open_unverified,
                    "mean_open_unverified_tps": s.mean_open_unverified_tps,
                    "mean_open_unverified_fps": s.mean_open_unverified_fps,
                    "open_unverified_precision_mean": s.open_unverified_precision_mean,
                    "open_unverified_precision_std": s.open_unverified_precision_std,
                    "mean_harness_limitation": s.mean_harness_limitation,
                    "mean_disproved_by_harness": s.mean_disproved_by_harness,
                    "mean_true_positives": s.mean_true_positives,
                    "std_true_positives": s.std_true_positives,
                    "mean_true_positives_medium_plus": s.mean_true_positives_medium_plus,
                    "mean_false_positives": s.mean_false_positives,
                    "std_false_positives": s.std_false_positives,
                    "precision_mean": s.precision_mean,
                    "precision_std": s.precision_std,
                    "precision_medium_plus_mean": s.precision_medium_plus_mean,
                    "false_disproof_rate_mean": s.false_disproof_rate_mean,
                    "fp_elimination_rate_mean": s.fp_elimination_rate_mean,
                    "poc_pass_rate_mean": s.poc_pass_rate_mean,
                    "phase_funnel_summary": s.phase_funnel_summary,
                    "mean_llm_calls_per_run": s.mean_llm_calls_per_run,
                    "std_llm_calls_per_run": s.std_llm_calls_per_run,
                    "llm_calls_by_agent": s.llm_calls_by_agent,
                    "mean_tool_calls_per_run": s.mean_tool_calls_per_run,
                    "std_tool_calls_per_run": s.std_tool_calls_per_run,
                    "mean_tool_errors_per_run": s.mean_tool_errors_per_run,
                    "std_tool_errors_per_run": s.std_tool_errors_per_run,
                    "tool_calls_by_category": s.tool_calls_by_category,
                    "tool_calls_by_agent": s.tool_calls_by_agent,
                    "tokens_by_agent": s.tokens_by_agent,
                    "mean_project_expert_questions": s.mean_project_expert_questions,
                    "std_project_expert_questions": s.std_project_expert_questions,
                    "mean_project_expert_answered_from_history": s.mean_project_expert_answered_from_history,
                    "std_project_expert_answered_from_history": s.std_project_expert_answered_from_history,
                    "mean_project_expert_cache_hits": s.mean_project_expert_cache_hits,
                    "mean_poc_attempts": s.mean_poc_attempts,
                    "std_poc_attempts": s.std_poc_attempts,
                    "mean_poc_harness_commands": s.mean_poc_harness_commands,
                    "std_poc_harness_commands": s.std_poc_harness_commands,
                    "mean_poc_harness_commands_per_finding": s.mean_poc_harness_commands_per_finding,
                    "std_poc_harness_commands_per_finding": s.std_poc_harness_commands_per_finding,
                    "mean_poc_gate_failures": s.mean_poc_gate_failures,
                    "std_poc_gate_failures": s.std_poc_gate_failures,
                    "refusals_summary": s.refusals_summary,
                    "mean_uncached_input_tokens": s.mean_uncached_input_tokens_per_run,
                    "mean_cached_tokens": s.mean_cached_tokens_per_run,
                    "mean_thoughts_tokens": s.mean_thoughts_tokens_per_run,
                    "mean_pure_output_tokens": s.mean_pure_output_tokens_per_run,
                    "mean_output_tokens": s.mean_output_tokens_per_run,
                    "out_to_in_ratio": round(
                        s.mean_output_tokens_per_run
                        / (s.mean_uncached_input_tokens_per_run + s.mean_cached_tokens_per_run),
                        3,
                    )
                    if (s.mean_uncached_input_tokens_per_run + s.mean_cached_tokens_per_run) > 0
                    else 0.0,
                    "mean_total_tokens": s.mean_tokens_per_run,
                    "mean_estimated_cost_usd": (
                        round(c_val, 4)
                        if (
                            c_val := self._estimate_cost_usd(
                                s.mean_uncached_input_tokens_per_run,
                                s.mean_cached_tokens_per_run,
                                s.mean_output_tokens_per_run,
                                model=s.model,
                            )
                        )
                        is not None
                        else None
                    ),
                    "mean_wall_clock_seconds": s.mean_wall_clock_seconds,
                }
                for s in summaries
            ],
        }
        (tables_dir / "tables_metadata.json").write_text(
            json.dumps(metadata_payload, indent=2), encoding="utf-8"
        )

        # Also mirror into out_dir / "tables" for clean tables/ + plots/ layout
        clean_tables_dir = out_dir / "tables"
        clean_tables_dir.mkdir(parents=True, exist_ok=True)
        for stale_f in clean_tables_dir.iterdir():
            if stale_f.is_file():
                stale_f.unlink()
        for f in tables_dir.iterdir():
            if f.is_file():
                shutil.copy2(f, clean_tables_dir / f.name)

        # 6. Export standalone PGFPlots (.tex) and SVG (.svg) figures into out_dir / "plots"
        plots_dir = out_dir / "plots"
        plots_dir.mkdir(parents=True, exist_ok=True)
        for stale_f in plots_dir.iterdir():
            if stale_f.is_file():
                stale_f.unlink()
        self._export_modular_paper_plots(
            plots_dir=plots_dir,
            meta_header=meta_header,
            svg_meta_header=svg_meta_header,
            repo_name=repo_name,
            pinned_rev=pinned_rev,
            by_key=by_key,
            rq3_tiers=rq3_tiers,
            is_adjudicated=is_adjudicated,
        )

    def _export_modular_paper_plots(
        self,
        plots_dir: Path,
        meta_header: str,
        svg_meta_header: str,
        repo_name: str,
        pinned_rev: str,
        by_key: dict[str, TierEvaluationSummary],
        rq3_tiers: list[TierEvaluationSummary],
        is_adjudicated: bool = False,
    ) -> None:
        """Generates PGFPlots (.tex) and standalone vector (.svg) figures for paper-ready RQs."""
        # Plot 1: RQ2 5-Stage Verification Funnel (PGFPlots + SVG)
        stages = [
            ("discovery", "Discovery"),
            ("deduplication", "Dedup"),
            ("initial_review", "Init Review"),
            ("poc_creation", "PoC Creation"),
            ("final_review", "Final Review"),
        ]
        funnel_tex = [
            meta_header,
            "\\resizebox{\\columnwidth}{!}{%",
            "\\begin{tikzpicture}",
            "\\begin{axis}[",
            "    width=\\columnwidth,",
            "    height=5.2cm,",
            "    ylabel={Mean Open Findings},",
            "    symbolic x coords={Discovery,Dedup,Init Review,PoC Creation,Final Review},",
            "    xtick=data,",
            "    xticklabel style={rotate=20, anchor=east, font=\\footnotesize},",
            "    ymin=0,",
            "    ymajorgrids=true,",
            "    grid style=dashed,",
            "    legend pos=north east,",
            "    legend style={font=\\scriptsize},",
            "    mark size=2pt,",
            "    thick",
            "]",
        ]
        funnel_series = [
            ("no_tm", "\\texttt{w/o Threat Model}", "color=orange, mark=triangle*"),
            ("no_expert", "\\texttt{w/o Project Expert}", "color=teal, mark=square*"),
            ("full", "\\texttt{Full}", "color=blue, mark=*"),
        ]
        pretty_models = {
            "gemini-3.8-flash": "Gemini 3.8 Flash",
            "gemini-4-argon": "Gemini 4 Argon",
            "claude-sonnet-5-5": "Claude Sonnet 5.5",
        }
        alt_funnel_styles = [
            "color=violet, mark=diamond*, dashed",
            "color=magenta!80!black, mark=pentagon*, densely dotted",
            "color=brown!80!black, mark=star, dashdotted",
        ]
        alt_idx = 0
        for k in sorted(by_key.keys()):
            if k.startswith("full[") and "@" not in k:
                m_slug = k[len("full[") : -1]
                p_mod = pretty_models.get(m_slug, self._latex_escape(m_slug))
                style = alt_funnel_styles[alt_idx % len(alt_funnel_styles)]
                alt_idx += 1
                funnel_series.append((k, f"\\texttt{{Full}} ({p_mod})", style))
        for tier_prefix, label, style in funnel_series:
            coords = []
            for st_key, st_label in stages:
                rec = by_key.get(f"{tier_prefix}@{st_key}")
                if rec is not None:
                    coords.append(f"({st_label},{rec.mean_open_findings:.1f})")
            if coords:
                funnel_tex.append(f"\\addplot[{style}] coordinates {{ {' '.join(coords)} }};")
                funnel_tex.append(f"\\addlegendentry{{{label}}}")
        funnel_tex.extend(
            [
                "\\end{axis}",
                "\\end{tikzpicture}%",
                "}",
                "",
            ]
        )
        (plots_dir / "fig_rq2_verification_funnel.tex").write_text(
            "\n".join(funnel_tex), encoding="utf-8"
        )

        def _pgf_coord(tier_key: str) -> str:
            return tier_key.replace("_", "-").replace("[", "(").replace("]", ")")

        sym_coords = ",".join(_pgf_coord(s.ablation_tier) for s in rq3_tiers)

        # Plot 2 (Only when adjudicated): RQ1 Open vs. PoC-Verified vs. True Positives
        if is_adjudicated:
            open_coords = " ".join(
                f"({_pgf_coord(s.ablation_tier)},{s.mean_open_findings:.1f})" for s in rq3_tiers
            )
            poc_coords = " ".join(
                f"({_pgf_coord(s.ablation_tier)},{s.mean_poc_verified:.1f})" for s in rq3_tiers
            )
            tp_coords = " ".join(
                f"({_pgf_coord(s.ablation_tier)},{s.mean_true_positives:.1f})" for s in rq3_tiers
            )
            rq1_tex = [
                meta_header,
                "\\begin{tikzpicture}",
                "\\begin{axis}[",
                "    ybar,",
                "    bar width=5.5pt,",
                "    width=\\columnwidth,",
                "    height=5.4cm,",
                "    ylabel={Mean Findings / Run},",
                "    xtick=data,",
                f"    symbolic x coords={{{sym_coords}}},",
                "    xticklabel style={rotate=25, anchor=east, font=\\footnotesize},",
                "    ymin=0,",
                "    ymajorgrids=true,",
                "    grid style=dashed,",
                "    legend pos=north east,",
                "    legend style={font=\\scriptsize},",
                "    nodes near coords,",
                "    nodes near coords style={font=\\tiny}",
                "]",
                f"\\addplot[fill=blue!60!white, draw=black] coordinates {{ {open_coords} }};",
                "\\addlegendentry{Open Findings}",
                f"\\addplot[fill=green!55!black, draw=black] coordinates {{ {poc_coords} }};",
                "\\addlegendentry{PoC-Verified}",
                f"\\addplot[fill=orange!80!black, draw=black] coordinates {{ {tp_coords} }};",
                "\\addlegendentry{True Positives (TP)}",
                "\\end{axis}",
                "\\end{tikzpicture}",
                "",
            ]
            (plots_dir / "fig_rq1_ablation_comparison.tex").write_text(
                "\n".join(rq1_tex), encoding="utf-8"
            )
            self._render_rq1_comparison_svg(
                plots_dir / "fig_rq1_ablation_comparison.svg",
                rq3_tiers,
                repo_name=repo_name,
                svg_meta_header=svg_meta_header,
            )

        # Plot 3: RQ4 Token Cost Share Composition (100% Stacked PGFPlots .tex)
        priced_tiers = [s for s in rq3_tiers if self._get_model_pricing(s.model) is not None]
        if priced_tiers:
            priced_sym_coords = ",".join(_pgf_coord(s.ablation_tier) for s in priced_tiers)
            unc_coords, cac_coords, out_coords = [], [], []
            for s in priced_tiers:
                sched = self._get_model_pricing(s.model)
                assert sched is not None
                r_unc = float(sched["uncached_input"])
                r_cac = float(sched["cached_input"])
                r_out = float(sched["output_and_thoughts"])
                c_unc = s.mean_uncached_input_tokens_per_run * r_unc / 1_000_000.0
                c_cac = s.mean_cached_tokens_per_run * r_cac / 1_000_000.0
                c_out = s.mean_output_tokens_per_run * r_out / 1_000_000.0
                c_tot = max(1e-9, c_unc + c_cac + c_out)
                k = _pgf_coord(s.ablation_tier)
                unc_coords.append(f"({k},{c_unc / c_tot * 100.0:.1f})")
                cac_coords.append(f"({k},{c_cac / c_tot * 100.0:.1f})")
                out_coords.append(f"({k},{c_out / c_tot * 100.0:.1f})")

            rq4_tex = [
                meta_header,
                "\\begin{tikzpicture}",
                "\\begin{axis}[",
                "    ybar stacked,",
                "    bar width=11pt,",
                "    width=\\columnwidth,",
                "    height=5.2cm,",
                "    ylabel={Share of API Cost (\\%)},",
                "    xtick=data,",
                f"    symbolic x coords={{{priced_sym_coords}}},",
                "    xticklabel style={rotate=25, anchor=east, font=\\footnotesize},",
                "    ymin=0, ymax=100,",
                "    ymajorgrids=true,",
                "    grid style=dashed,",
                "    legend style={at={(0.5,1.05)}, anchor=south, legend columns=3, font=\\scriptsize}",
                "]",
                f"\\addplot[fill=blue!55!white, draw=black] coordinates {{ {' '.join(unc_coords)} }};",
                "\\addlegendentry{Uncached In}",
                f"\\addplot[fill=green!60!black, draw=black] coordinates {{ {' '.join(cac_coords)} }};",
                "\\addlegendentry{Cached In}",
                f"\\addplot[fill=red!70!black, draw=black] coordinates {{ {' '.join(out_coords)} }};",
                "\\addlegendentry{Thinking + Out}",
                "\\end{axis}",
                "\\end{tikzpicture}",
                "",
            ]
            (plots_dir / "fig_rq4_token_pathology.tex").write_text(
                "\n".join(rq4_tex), encoding="utf-8"
            )

        # Standalone SVG renders for instant preview
        self._render_funnel_svg(
            plots_dir / "fig_rq2_verification_funnel.svg",
            by_key,
            stages,
            repo_name=repo_name,
            svg_meta_header=svg_meta_header,
        )
        if priced_tiers:
            self._render_token_pathology_svg(
                plots_dir / "fig_rq4_token_pathology.svg",
                priced_tiers,
                repo_name=repo_name,
                svg_meta_header=svg_meta_header,
            )
        self._export_phase_token_breakdown_plot(
            plots_dir=plots_dir,
            eval_dir=plots_dir.parent,
            meta_header=meta_header,
            svg_meta_header=svg_meta_header,
            repo_name=repo_name,
            pinned_rev=pinned_rev,
            by_key=by_key,
        )

    @staticmethod
    def _render_funnel_svg(
        svg_path: Path,
        by_key: dict[str, TierEvaluationSummary],
        stages: list[tuple[str, str]],
        repo_name: str = "caliptra-sw",
        svg_meta_header: str = "",
    ) -> None:
        width, height = 720, 380
        pad_l, pad_r, pad_t, pad_b = 70, 45, 50, 65
        plot_w = width - pad_l - pad_r
        plot_h = height - pad_t - pad_b
        series_defs = [
            ("no_tm", "Mjolnir (No TM)", "#d95f02", 14),
            ("no_expert", "Mjolnir (No Expert)", "#1b9e77", -10),
            ("full", "Mjolnir (Full)", "#2b5c8f", -10),
        ]
        alt_svg_colors = [("#7570b3", 14), ("#e7298a", -12), ("#a6761d", 14)]
        alt_svg_idx = 0
        for k in sorted(by_key.keys()):
            if k.startswith("full[") and "@" not in k:
                m_slug = k[len("full[") : -1]
                c_hex, y_off = alt_svg_colors[alt_svg_idx % len(alt_svg_colors)]
                alt_svg_idx += 1
                series_defs.append((k, f"Mjolnir ({m_slug})", c_hex, y_off))
        all_vals = [
            by_key[f"{prefix}@{st_key}"].mean_open_findings
            for prefix, _, _, _ in series_defs
            for st_key, _ in stages
            if f"{prefix}@{st_key}" in by_key
        ]
        peak = max(all_vals) if all_vals else 35.0
        step = 5 if peak <= 45 else (10 if peak <= 100 else 25)
        max_y = float(((int(peak) // step) + 1) * step)
        y_ticks = list(range(0, int(max_y) + 1, step))

        svg = [
            *([svg_meta_header] if svg_meta_header else []),
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="sans-serif">',
            '<rect width="100%" height="100%" fill="#ffffff"/>',
            f'<text x="{width / 2}" y="26" text-anchor="middle" font-size="14" font-weight="bold" fill="#111">5-Stage Verification Funnel &amp; Adversarial Filtering ({repo_name})</text>',
            f'<text x="18" y="{pad_t + plot_h / 2}" text-anchor="middle" font-size="12" fill="#333" transform="rotate(-90, 18, {pad_t + plot_h / 2})">Mean Surviving Open Findings</text>',
        ]
        for y_val in y_ticks:
            y_px = pad_t + plot_h - (y_val / max_y) * plot_h
            svg.append(
                f'<line x1="{pad_l}" y1="{y_px:.1f}" x2="{width - pad_r}" y2="{y_px:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{pad_l - 10}" y="{y_px + 4:.1f}" text-anchor="end" font-size="11" fill="#555">{y_val}</text>'
            )
        for idx, (_, st_label) in enumerate(stages):
            x_px = pad_l + (idx / max(1, len(stages) - 1)) * plot_w
            svg.append(
                f'<line x1="{x_px:.1f}" y1="{pad_t}" x2="{x_px:.1f}" y2="{pad_t + plot_h}" stroke="#f2f2f2"/>'
            )
            svg.append(
                f'<text x="{x_px:.1f}" y="{height - pad_b + 24}" text-anchor="middle" font-size="11" font-weight="bold" fill="#222">{st_label}</text>'
            )
        plotted_idx = 0
        for s_idx, (prefix, label, color, y_off) in enumerate(series_defs):
            pts = []
            for idx, (st_key, _) in enumerate(stages):
                rec = by_key.get(f"{prefix}@{st_key}")
                if rec is not None:
                    x_px = pad_l + (idx / max(1, len(stages) - 1)) * plot_w
                    y_px = pad_t + plot_h - (min(rec.mean_open_findings, max_y) / max_y) * plot_h
                    pts.append((x_px, y_px, rec.mean_open_findings))
            if pts:
                poly = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts)
                svg.append(
                    f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="{poly}"/>'
                )
                for x, y, val in pts:
                    svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{color}"/>')
                    svg.append(
                        f'<text x="{x + (s_idx - 1) * 14:.1f}" y="{y + y_off:.1f}" text-anchor="middle" font-size="10" fill="{color}" font-weight="bold">{val:.1f}</text>'
                    )
                leg_x = width - pad_r - 160
                leg_y = pad_t + 16 + plotted_idx * 20
                svg.append(
                    f'<line x1="{leg_x}" y1="{leg_y}" x2="{leg_x + 20}" y2="{leg_y}" stroke="{color}" stroke-width="2.5"/>'
                )
                svg.append(f'<circle cx="{leg_x + 10}" cy="{leg_y}" r="3.5" fill="{color}"/>')
                svg.append(
                    f'<text x="{leg_x + 26}" y="{leg_y + 4}" font-size="11" fill="#222">{label}</text>'
                )
                plotted_idx += 1
        svg.append("</svg>\n")
        svg_path.write_text("\n".join(svg), encoding="utf-8")

    def _render_token_pathology_svg(
        self,
        svg_path: Path,
        rq3_tiers: list[TierEvaluationSummary],
        repo_name: str = "caliptra-sw",
        svg_meta_header: str = "",
    ) -> None:
        """Renders a 2-panel SVG: (Left) 100% Stacked Dollar Cost Share (Uncached In vs Cached In vs Thinking+Out), (Right) Thinking+Output Tokens per Run."""
        priced_tiers = [s for s in rq3_tiers if self._get_model_pricing(s.model) is not None]
        if not priced_tiers:
            return
        width, height = 780, 390
        pad_t, pad_b = 58, 85
        plot_h = height - pad_t - pad_b
        left_x0, left_w = 65, 305
        right_x0, right_w = 445, 305

        svg = [
            *([svg_meta_header] if svg_meta_header else []),
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="sans-serif">',
            '<rect width="100%" height="100%" fill="#ffffff"/>',
            f'<text x="{width / 2}" y="24" text-anchor="middle" font-size="14" font-weight="bold" fill="#111">Token Cost Composition &amp; Speculative Thinking Overhead ({repo_name})</text>',
            f'<text x="{left_x0 + left_w / 2}" y="44" text-anchor="middle" font-size="12" font-weight="bold" fill="#333">(a) Share of API Cost by Token Type (%)</text>',
            f'<text x="{right_x0 + right_w / 2}" y="44" text-anchor="middle" font-size="12" font-weight="bold" fill="#333">(b) Thinking + Output Tokens / Run (Millions)</text>',
        ]

        # Left Panel Y-axis (0% to 100%)
        for pct in (0, 25, 50, 75, 100):
            y_px = pad_t + plot_h - (pct / 100.0) * plot_h
            svg.append(
                f'<line x1="{left_x0}" y1="{y_px:.1f}" x2="{left_x0 + left_w}" y2="{y_px:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{left_x0 - 8}" y="{y_px + 4:.1f}" text-anchor="end" font-size="10" fill="#555">{pct}%</text>'
            )

        # Right Panel Y-axis (auto-scaled in Millions of output+thinking tokens)
        max_out_m = max(
            (s.mean_output_tokens_per_run / 1_000_000.0 for s in priced_tiers), default=1.0
        )
        max_y_m = float(int(max_out_m) + 1) if max_out_m >= 1.0 else 1.5
        for idx_tick in range(5):
            val_m = (idx_tick / 4.0) * max_y_m
            y_px = pad_t + plot_h - (val_m / max_y_m) * plot_h
            svg.append(
                f'<line x1="{right_x0}" y1="{y_px:.1f}" x2="{right_x0 + right_w}" y2="{y_px:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{right_x0 - 8}" y="{y_px + 4:.1f}" text-anchor="end" font-size="10" fill="#555">{val_m:.2f}M</text>'
            )

        n = max(1, len(priced_tiers))
        bar_w = min(40.0, left_w / n * 0.58)
        for idx, s in enumerate(priced_tiers):
            sched = self._get_model_pricing(s.model)
            assert sched is not None
            r_unc = float(sched["uncached_input"])
            r_cac = float(sched["cached_input"])
            r_out = float(sched["output_and_thoughts"])
            c_unc = s.mean_uncached_input_tokens_per_run * r_unc / 1_000_000.0
            c_cac = s.mean_cached_tokens_per_run * r_cac / 1_000_000.0
            c_out = s.mean_output_tokens_per_run * r_out / 1_000_000.0
            c_tot = max(1e-9, c_unc + c_cac + c_out)
            p_unc = c_unc / c_tot
            p_cac = c_cac / c_tot
            p_out = c_out / c_tot

            cx_l = left_x0 + (idx + 0.5) * (left_w / n)
            h_unc = p_unc * plot_h
            h_cac = p_cac * plot_h
            h_out = p_out * plot_h

            y_unc = pad_t + plot_h - h_unc
            y_cac = y_unc - h_cac
            y_out = y_cac - h_out

            svg.append(
                f'<rect x="{cx_l - bar_w / 2:.1f}" y="{y_unc:.1f}" width="{bar_w:.1f}" height="{h_unc:.1f}" fill="#3498db"/>'
            )
            svg.append(
                f'<rect x="{cx_l - bar_w / 2:.1f}" y="{y_cac:.1f}" width="{bar_w:.1f}" height="{h_cac:.1f}" fill="#2ecc71"/>'
            )
            svg.append(
                f'<rect x="{cx_l - bar_w / 2:.1f}" y="{y_out:.1f}" width="{bar_w:.1f}" height="{h_out:.1f}" fill="#e74c3c"/>'
            )
            svg.append(
                f'<text x="{cx_l:.1f}" y="{pad_t - 5}" text-anchor="middle" font-size="9.5" font-weight="bold" fill="#c0392b">{p_out * 100:.0f}% out</text>'
            )
            svg.append(
                f'<text x="{cx_l:.1f}" y="{height - pad_b + 16}" text-anchor="end" font-size="10" fill="#222" transform="rotate(-25, {cx_l:.1f}, {height - pad_b + 16})">{s.ablation_tier}</text>'
            )

            # Right panel bar: Thinking + Output Tokens (M)
            cx_r = right_x0 + (idx + 0.5) * (right_w / n)
            out_m = s.mean_output_tokens_per_run / 1_000_000.0
            bh_r = (min(out_m, max_y_m) / max_y_m) * plot_h
            by_r = pad_t + plot_h - bh_r
            tot_in = s.mean_uncached_input_tokens_per_run + s.mean_cached_tokens_per_run
            ratio = (s.mean_output_tokens_per_run / tot_in) if tot_in > 0 else 0.0
            r_color = "#e74c3c" if "per_file" in s.ablation_tier else "#2b5c8f"
            svg.append(
                f'<rect x="{cx_r - bar_w / 2:.1f}" y="{by_r:.1f}" width="{bar_w:.1f}" height="{bh_r:.1f}" fill="{r_color}" rx="2"/>'
            )
            svg.append(
                f'<text x="{cx_r:.1f}" y="{by_r - 6:.1f}" text-anchor="middle" font-size="9.5" font-weight="bold" fill="{r_color}">{out_m:.2f}M ({ratio:.2f}x)</text>'
            )
            svg.append(
                f'<text x="{cx_r:.1f}" y="{height - pad_b + 16}" text-anchor="end" font-size="10" fill="#222" transform="rotate(-25, {cx_r:.1f}, {height - pad_b + 16})">{s.ablation_tier}</text>'
            )

        # Legend at bottom
        leg_items = [
            ("#3498db", "Uncached In (Flash $0.75, Argon/Sonnet $2.00 / 1M)"),
            ("#2ecc71", "Cached In (Flash $0.075, Argon $0.10, Sonnet $0.20 / 1M)"),
            ("#e74c3c", "Thinking + Out (Flash $3.75, Argon/Sonnet $10.00 / 1M)"),
        ]
        for l_idx, (l_col, l_txt) in enumerate(leg_items):
            lx = 18 + l_idx * 254
            ly = height - 18
            svg.append(
                f'<rect x="{lx}" y="{ly - 10}" width="12" height="12" fill="{l_col}" rx="2"/>'
            )
            svg.append(f'<text x="{lx + 16}" y="{ly}" font-size="9.5" fill="#222">{l_txt}</text>')

        svg.append("</svg>\n")
        svg_path.write_text("\n".join(svg), encoding="utf-8")

    @staticmethod
    def _render_rq1_comparison_svg(
        svg_path: Path,
        rq3_tiers: list[TierEvaluationSummary],
        repo_name: str = "caliptra-sw",
        svg_meta_header: str = "",
    ) -> None:
        """Renders grouped bar chart of Open Findings, PoC-Verified Findings, and Confirmed True Positives across tiers."""
        width, height = 740, 390
        pad_l, pad_r, pad_t, pad_b = 70, 40, 50, 85
        plot_w = width - pad_l - pad_r
        plot_h = height - pad_t - pad_b
        peak = max((s.mean_open_findings for s in rq3_tiers), default=30.0)
        step = 5 if peak <= 45 else 10
        max_y = float(((int(peak) // step) + 1) * step)
        svg = [
            *([svg_meta_header] if svg_meta_header else []),
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="sans-serif">',
            '<rect width="100%" height="100%" fill="#ffffff"/>',
            f'<text x="{width / 2}" y="26" text-anchor="middle" font-size="14" font-weight="bold" fill="#111">Open Findings vs. PoC-Verified vs. Confirmed True Positives ({repo_name})</text>',
        ]
        for y_val in range(0, int(max_y) + 1, step):
            y_px = pad_t + plot_h - (y_val / max_y) * plot_h
            svg.append(
                f'<line x1="{pad_l}" y1="{y_px:.1f}" x2="{width - pad_r}" y2="{y_px:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{pad_l - 8}" y="{y_px + 4:.1f}" text-anchor="end" font-size="11" fill="#555">{y_val}</text>'
            )
        n = max(1, len(rq3_tiers))
        group_w = plot_w / n
        bw = min(18.0, group_w * 0.25)
        for idx, s in enumerate(rq3_tiers):
            cx = pad_l + (idx + 0.5) * group_w
            h_open = (min(s.mean_open_findings, max_y) / max_y) * plot_h
            h_poc = (min(s.mean_poc_verified, max_y) / max_y) * plot_h
            h_tp = (min(s.mean_true_positives, max_y) / max_y) * plot_h
            y_open = pad_t + plot_h - h_open
            y_poc = pad_t + plot_h - h_poc
            y_tp = pad_t + plot_h - h_tp
            svg.append(
                f'<rect x="{cx - 1.5 * bw - 2:.1f}" y="{y_open:.1f}" width="{bw:.1f}" height="{h_open:.1f}" fill="#5c7cfa" rx="2"/>'
            )
            svg.append(
                f'<text x="{cx - bw - 2:.1f}" y="{y_open - 4:.1f}" text-anchor="middle" font-size="9.5" font-weight="bold" fill="#364fc7">{s.mean_open_findings:.1f}</text>'
            )
            svg.append(
                f'<rect x="{cx - 0.5 * bw:.1f}" y="{y_poc:.1f}" width="{bw:.1f}" height="{h_poc:.1f}" fill="#2b8a3e" rx="2"/>'
            )
            svg.append(
                f'<text x="{cx:.1f}" y="{y_poc - 4:.1f}" text-anchor="middle" font-size="9.5" font-weight="bold" fill="#2b8a3e">{s.mean_poc_verified:.1f}</text>'
            )
            svg.append(
                f'<rect x="{cx + 0.5 * bw + 2:.1f}" y="{y_tp:.1f}" width="{bw:.1f}" height="{h_tp:.1f}" fill="#d9480f" rx="2"/>'
            )
            svg.append(
                f'<text x="{cx + bw + 2:.1f}" y="{y_tp - 4:.1f}" text-anchor="middle" font-size="9.5" font-weight="bold" fill="#d9480f">{s.mean_true_positives:.1f}</text>'
            )
            svg.append(
                f'<text x="{cx:.1f}" y="{height - pad_b + 18}" text-anchor="end" font-size="10" fill="#222" transform="rotate(-25, {cx:.1f}, {height - pad_b + 18})">{s.ablation_tier}</text>'
            )
        svg.append('<rect x="135" y="366" width="12" height="12" fill="#5c7cfa" rx="2"/>')
        svg.append('<text x="152" y="376" font-size="11" fill="#222">Open Findings</text>')
        svg.append('<rect x="305" y="366" width="12" height="12" fill="#2b8a3e" rx="2"/>')
        svg.append('<text x="322" y="376" font-size="11" fill="#222">PoC-Verified Findings</text>')
        svg.append('<rect x="495" y="366" width="12" height="12" fill="#d9480f" rx="2"/>')
        svg.append(
            '<text x="512" y="376" font-size="11" fill="#222">Confirmed True Positives (TP)</text>'
        )
        svg.append("</svg>\n")
        svg_path.write_text("\n".join(svg), encoding="utf-8")

    def _collect_phase_token_stats(
        self,
        eval_dir: Path,
        by_key: dict[str, TierEvaluationSummary],
        include_ablations: bool = False,
    ) -> list[dict]:
        """Collects per-phase mean and SD for uncached_input, cached_input, thoughts, and output tokens across full[<model>] (and optionally ablation) tiers."""
        phases = [
            ("project_exploration", "Project Expert"),
            ("discovery", "Discovery"),
            ("deduplication", "Dedup."),
            ("initial_review", "Init Review"),
            ("poc_creation", "PoC Creation"),
            ("final_review", "Final Review"),
        ]
        ablation_extras = ("no_tm", "no_expert") if include_ablations else ()
        candidate_tiers = [
            k
            for k in (
                "full",
                *ablation_extras,
                *[k for k in sorted(by_key.keys()) if k.startswith("full[") and "@" not in k],
            )
            if k in by_key
        ]
        if not candidate_tiers:
            return []

        model_series: list[dict] = []
        for tier_key in candidate_tiers:
            summary = by_key[tier_key]
            model_label = summary.model or tier_key
            trials_dir = eval_dir / "trials" / tier_key
            phase_samples: dict[str, dict[str, list[float]]] = {
                pid: {
                    "uncached": [],
                    "cached": [],
                    "input_total": [],
                    "thoughts": [],
                    "output": [],
                    "output_total": [],
                    "llm_calls": [],
                    "tool_calls": [],
                    "tool_errors": [],
                }
                for pid, _ in phases
            }
            phase_cat_samples: dict[str, dict[str, list[float]]] = {
                pid: {cat: [] for cat in self.TOOL_CATEGORIES} for pid, _ in phases
            }
            found_files = False
            if trials_dir.is_dir():
                for rep_dir in sorted(trials_dir.glob("rep_*")):
                    tu_files = sorted(rep_dir.glob("run_*/token_usage.json")) or sorted(
                        rep_dir.glob("token_usage.json")
                    )
                    if not tu_files:
                        continue
                    try:
                        tu_data = json.loads(tu_files[-1].read_text(encoding="utf-8"))
                        by_phase = tu_data.get("by_phase") or {}
                        if not isinstance(by_phase, dict) or not by_phase:
                            continue
                        telem = self._load_trial_telemetry(rep_dir=rep_dir)
                        found_files = True
                        for pid, _ in phases:
                            b = by_phase.get(pid) or {}
                            unc = float(b.get("uncached_tokens", 0) or 0)
                            cac = float(b.get("cache_tokens", 0) or 0)
                            inp = float(b.get("total_input_tokens", unc + cac) or (unc + cac))
                            tho = float(b.get("thoughts_tokens", 0) or 0)
                            out = float(b.get("output_tokens", 0) or 0)
                            tot_out = float(b.get("total_output_tokens", tho + out) or (tho + out))
                            if tho == 0.0 and out == 0.0 and tot_out > 0.0:
                                out = tot_out
                            phase_samples[pid]["uncached"].append(unc)
                            phase_samples[pid]["cached"].append(cac)
                            phase_samples[pid]["input_total"].append(inp)
                            phase_samples[pid]["thoughts"].append(tho)
                            phase_samples[pid]["output"].append(out)
                            phase_samples[pid]["output_total"].append(tot_out)
                            phase_samples[pid]["llm_calls"].append(
                                float((telem["llm_calls_by_phase"] or {}).get(pid, 0))
                            )
                            phase_samples[pid]["tool_calls"].append(
                                float((telem["tool_calls_by_phase"] or {}).get(pid, 0))
                            )
                            phase_samples[pid]["tool_errors"].append(
                                float((telem["tool_errors_by_phase"] or {}).get(pid, 0))
                            )
                            p_cats = (telem["tool_categories_by_phase"] or {}).get(pid) or {}
                            for cat in self.TOOL_CATEGORIES:
                                phase_cat_samples[pid][cat].append(float(p_cats.get(cat, 0)))
                    except Exception:
                        continue

            if not found_files:
                continue

            phase_stats: dict[str, dict] = {}
            n_reps = 0
            for pid, _ in phases:
                s_map = phase_samples[pid]
                n_reps = max(n_reps, len(s_map["input_total"]))
                unc_mean = statistics.fmean(s_map["uncached"]) if s_map["uncached"] else 0.0
                cac_mean = statistics.fmean(s_map["cached"]) if s_map["cached"] else 0.0
                inp_mean = statistics.fmean(s_map["input_total"]) if s_map["input_total"] else 0.0
                tho_mean = statistics.fmean(s_map["thoughts"]) if s_map["thoughts"] else 0.0
                out_mean = statistics.fmean(s_map["output"]) if s_map["output"] else 0.0
                tot_out_mean = (
                    statistics.fmean(s_map["output_total"]) if s_map["output_total"] else 0.0
                )
                llm_c_mean = statistics.fmean(s_map["llm_calls"]) if s_map["llm_calls"] else 0.0
                tool_c_mean = statistics.fmean(s_map["tool_calls"]) if s_map["tool_calls"] else 0.0
                tool_e_mean = (
                    statistics.fmean(s_map["tool_errors"]) if s_map["tool_errors"] else 0.0
                )
                est_cost = self._estimate_cost_usd(
                    unc_mean, cac_mean, tot_out_mean, model=model_label
                )
                cat_means = {
                    cat: round(statistics.fmean(vals), 2) if vals else 0.0
                    for cat, vals in phase_cat_samples[pid].items()
                }
                phase_stats[pid] = {
                    "uncached_mean": round(unc_mean, 1),
                    "uncached_std": round(
                        statistics.stdev(s_map["uncached"]) if len(s_map["uncached"]) >= 2 else 0.0,
                        1,
                    ),
                    "cached_mean": round(cac_mean, 1),
                    "cached_std": round(
                        statistics.stdev(s_map["cached"]) if len(s_map["cached"]) >= 2 else 0.0,
                        1,
                    ),
                    "input_mean": round(inp_mean, 1),
                    "input_std": round(
                        statistics.stdev(s_map["input_total"])
                        if len(s_map["input_total"]) >= 2
                        else 0.0,
                        1,
                    ),
                    "thoughts_mean": round(tho_mean, 1),
                    "thoughts_std": round(
                        statistics.stdev(s_map["thoughts"]) if len(s_map["thoughts"]) >= 2 else 0.0,
                        1,
                    ),
                    "output_mean": round(out_mean, 1),
                    "output_std": round(
                        statistics.stdev(s_map["output"]) if len(s_map["output"]) >= 2 else 0.0,
                        1,
                    ),
                    "output_total_mean": round(tot_out_mean, 1),
                    "output_total_std": round(
                        statistics.stdev(s_map["output_total"])
                        if len(s_map["output_total"]) >= 2
                        else 0.0,
                        1,
                    ),
                    "llm_calls_mean": round(llm_c_mean, 2),
                    "llm_calls_std": round(
                        statistics.stdev(s_map["llm_calls"])
                        if len(s_map["llm_calls"]) >= 2
                        else 0.0,
                        2,
                    ),
                    "tool_calls_mean": round(tool_c_mean, 2),
                    "tool_calls_std": round(
                        statistics.stdev(s_map["tool_calls"])
                        if len(s_map["tool_calls"]) >= 2
                        else 0.0,
                        2,
                    ),
                    "tool_errors_mean": round(tool_e_mean, 2),
                    "tool_errors_std": round(
                        statistics.stdev(s_map["tool_errors"])
                        if len(s_map["tool_errors"]) >= 2
                        else 0.0,
                        2,
                    ),
                    "tool_calls_by_category_mean": cat_means,
                    "estimated_cost_usd": round(est_cost, 4) if est_cost is not None else None,
                }
            model_series.append(
                {
                    "tier_key": tier_key,
                    "model": model_label,
                    "repetitions": n_reps,
                    "phases": phase_stats,
                }
            )
        return model_series

    def _export_phase_token_breakdown_plot(
        self,
        plots_dir: Path,
        eval_dir: Path,
        meta_header: str,
        svg_meta_header: str,
        repo_name: str,
        pinned_rev: str,
        by_key: dict[str, TierEvaluationSummary],
    ) -> None:
        """Exports 2-panel grouped bar chart (Uncached vs Cached Input and Thinking vs Output per agent role with +-1 SD error bars)."""
        phases = [
            ("ProjectExpertAgent", "Project Expert"),
            ("AuditorAgent", "Discovery"),
            ("DeduplicationAgent", "Dedup."),
            ("AdversarialReviewerAgent", "Review"),
            ("ExploitCreationAgent", "PoC Creation"),
        ]
        candidate_tiers = [
            k
            for k in sorted(
                by_key.keys(),
                key=lambda x: (0 if x == "full" else 1, x),
            )
            if (x_clean := k)
            and "@" not in x_clean
            and (x_clean == "full" or x_clean.startswith("full["))
        ]
        zero_bucket = {
            "uncached_mean": 0.0,
            "uncached_std": 0.0,
            "cached_mean": 0.0,
            "cached_std": 0.0,
            "input_mean": 0.0,
            "input_std": 0.0,
            "thoughts_mean": 0.0,
            "thoughts_std": 0.0,
            "output_mean": 0.0,
            "output_std": 0.0,
            "output_total_mean": 0.0,
            "output_total_std": 0.0,
        }
        model_series: list[dict] = []
        for tier_key in candidate_tiers:
            summary = by_key[tier_key]
            if not summary.tokens_by_agent:
                continue
            model_series.append(
                {
                    "tier_key": tier_key,
                    "model": summary.model or tier_key,
                    "repetitions": summary.repetitions,
                    "phases": {
                        ag_key: {**zero_bucket, **(summary.tokens_by_agent.get(ag_key) or {})}
                        for ag_key, _ in phases
                    },
                }
            )
        if not model_series:
            return

        sym_phases = ",".join(label for _, label in phases)

        # 1. Export PGFPlots (.tex) — disjoint grouped bars (no overlaid totals)
        n_mod = len(model_series)
        bw_pt = 2.6 if n_mod >= 3 else (3.6 if n_mod >= 2 else 6.0)
        pretty_models = {
            "gemini-3.8-flash": "Gemini 3.8 Flash",
            "gemini-4-argon": "Gemini 4 Argon",
            "claude-sonnet-5-5": "Claude Sonnet 5.5",
        }
        tex = [
            meta_header,
            "\\resizebox{\\textwidth}{!}{%",
            "\\begin{tikzpicture}",
            "\\begin{axis}[",
            "    name=leftplot,",
            "    ybar,",
            f"    bar width={bw_pt:.1f}pt,",
            "    width=0.48\\textwidth,",
            "    height=5.4cm,",
            "    ylabel={Input Tokens / Agent Role (Millions)},",
            f"    symbolic x coords={{{sym_phases}}},",
            "    xtick=data,",
            "    xticklabel style={rotate=22, anchor=east, font=\\footnotesize},",
            "    ymin=0,",
            "    ymajorgrids=true,",
            "    grid style=dashed,",
            "    title={\\footnotesize\\textbf{(a) Input Tokens per Agent Role (Uncached vs.\\ Cached)}},",
            "    legend style={at={(0.5,1.15)}, anchor=south, legend columns=2, font=\\scriptsize}",
            "]",
        ]
        palette_in = [
            ("blue!65!white", "green!60!black"),
            ("violet!65!white", "teal!70!black"),
            ("brown!75!black", "olive!75!black"),
        ]
        for idx, ms in enumerate(model_series):
            c_unc, c_cac = palette_in[idx % len(palette_in)]
            raw_m = str(ms["model"]).split("/")[-1].split("@")[0]
            m_name = pretty_models.get(raw_m, self._latex_escape(raw_m))
            if ms["repetitions"] >= 2:
                unc_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['uncached_mean'] or 0.0) / 1e6:.2f}) +- (0,{float(ms['phases'][pid]['uncached_std'] or 0.0) / 1e6:.2f})"
                    for pid, label in phases
                )
                cac_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['cached_mean'] or 0.0) / 1e6:.2f}) +- (0,{float(ms['phases'][pid]['cached_std'] or 0.0) / 1e6:.2f})"
                    for pid, label in phases
                )
                tex.append(
                    f"\\addplot[fill={c_unc}, draw=black, error bars/.cd, y dir=both, y explicit] coordinates {{ {unc_pts} }};"
                )
                tex.append(f"\\addlegendentry{{{m_name} Uncached In}}")
                tex.append(
                    f"\\addplot[fill={c_cac}, draw=black, error bars/.cd, y dir=both, y explicit] coordinates {{ {cac_pts} }};"
                )
                tex.append(f"\\addlegendentry{{{m_name} Cached In}}")
            else:
                unc_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['uncached_mean'] or 0.0) / 1e6:.2f})"
                    for pid, label in phases
                )
                cac_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['cached_mean'] or 0.0) / 1e6:.2f})"
                    for pid, label in phases
                )
                tex.append(f"\\addplot[fill={c_unc}, draw=black] coordinates {{ {unc_pts} }};")
                tex.append(f"\\addlegendentry{{{m_name} Uncached In}}")
                tex.append(f"\\addplot[fill={c_cac}, draw=black] coordinates {{ {cac_pts} }};")
                tex.append(f"\\addlegendentry{{{m_name} Cached In}}")
        tex.extend(
            [
                "\\end{axis}",
                "\\begin{axis}[",
                "    at={(leftplot.outer north east)},",
                "    anchor=outer north west,",
                "    xshift=0.8cm,",
                "    ybar,",
                f"    bar width={bw_pt:.1f}pt,",
                "    width=0.48\\textwidth,",
                "    height=5.4cm,",
                "    ylabel={Thinking / Output Tokens / Agent Role (Thousands)},",
                f"    symbolic x coords={{{sym_phases}}},",
                "    xtick=data,",
                "    xticklabel style={rotate=22, anchor=east, font=\\footnotesize},",
                "    ymin=0,",
                "    ymajorgrids=true,",
                "    grid style=dashed,",
                "    title={\\footnotesize\\textbf{(b) Thinking vs.\\ Output Tokens per Agent Role (K)}},",
                "    legend style={at={(0.5,1.15)}, anchor=south, legend columns=2, font=\\scriptsize}",
                "]",
            ]
        )
        palette_out = [
            ("red!70!black", "orange!85!white"),
            ("magenta!75!black", "cyan!75!black"),
            ("purple!80!black", "yellow!75!orange"),
        ]
        for idx, ms in enumerate(model_series):
            c_tho, c_out = palette_out[idx % len(palette_out)]
            raw_m = str(ms["model"]).split("/")[-1].split("@")[0]
            m_name = pretty_models.get(raw_m, self._latex_escape(raw_m))
            if ms["repetitions"] >= 2:
                tho_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['thoughts_mean'] or 0.0) / 1e3:.1f}) +- (0,{float(ms['phases'][pid]['thoughts_std'] or 0.0) / 1e3:.1f})"
                    for pid, label in phases
                )
                out_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['output_mean'] or 0.0) / 1e3:.1f}) +- (0,{float(ms['phases'][pid]['output_std'] or 0.0) / 1e3:.1f})"
                    for pid, label in phases
                )
                tex.append(
                    f"\\addplot[fill={c_tho}, draw=black, error bars/.cd, y dir=both, y explicit] coordinates {{ {tho_pts} }};"
                )
                tex.append(f"\\addlegendentry{{{m_name} Thinking}}")
                tex.append(
                    f"\\addplot[fill={c_out}, draw=black, error bars/.cd, y dir=both, y explicit] coordinates {{ {out_pts} }};"
                )
                tex.append(f"\\addlegendentry{{{m_name} Output}}")
            else:
                tho_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['thoughts_mean'] or 0.0) / 1e3:.1f})"
                    for pid, label in phases
                )
                out_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['output_mean'] or 0.0) / 1e3:.1f})"
                    for pid, label in phases
                )
                tex.append(f"\\addplot[fill={c_tho}, draw=black] coordinates {{ {tho_pts} }};")
                tex.append(f"\\addlegendentry{{{m_name} Thinking}}")
                tex.append(f"\\addplot[fill={c_out}, draw=black] coordinates {{ {out_pts} }};")
                tex.append(f"\\addlegendentry{{{m_name} Output}}")
        tex.extend(
            [
                "\\end{axis}",
                "\\end{tikzpicture}%",
                "}",
                "",
            ]
        )
        (plots_dir / "fig_rq4_phase_token_breakdown.tex").write_text(
            "\n".join(tex), encoding="utf-8"
        )

        # 2. Export standalone 2-panel SVG (.svg)
        width, height = 860, 440
        pad_t, pad_b = 64, 104
        plot_h = height - pad_t - pad_b
        left_x0, left_w = 68, 335
        right_x0, right_w = 485, 335

        max_in_m = max(
            (
                (
                    float(ms["phases"][pid]["input_mean"] or 0.0)
                    + float(ms["phases"][pid]["input_std"] or 0.0)
                )
                / 1e6
                for ms in model_series
                for pid, _ in phases
            ),
            default=10.0,
        )
        max_y_in = (
            float(((int(max_in_m) // 25) + 1) * 25)
            if max_in_m >= 25
            else max(5.0, math.ceil(max_in_m * 1.15))
        )

        max_out_k = max(
            (
                (
                    float(ms["phases"][pid]["output_total_mean"] or 0.0)
                    + float(ms["phases"][pid]["output_total_std"] or 0.0)
                )
                / 1e3
                for ms in model_series
                for pid, _ in phases
            ),
            default=100.0,
        )
        max_y_out = (
            float(((int(max_out_k) // 250) + 1) * 250)
            if max_out_k >= 250
            else max(50.0, math.ceil(max_out_k * 1.15))
        )

        svg = [
            *([svg_meta_header] if svg_meta_header else []),
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="sans-serif">',
            '<rect width="100%" height="100%" fill="#ffffff"/>',
            f'<text x="{width / 2}" y="24" text-anchor="middle" font-size="14" font-weight="bold" fill="#111">Per-Agent-Role Token Breakdown Across Models ({repo_name})</text>',
            f'<text x="{left_x0 + left_w / 2}" y="46" text-anchor="middle" font-size="12" font-weight="bold" fill="#333">(a) Input Tokens per Agent Role (Millions, ±1 SD)</text>',
            f'<text x="{right_x0 + right_w / 2}" y="46" text-anchor="middle" font-size="12" font-weight="bold" fill="#333">(b) Thinking vs. Output Tokens per Agent Role (Thousands, ±1 SD)</text>',
        ]

        for idx_tick in range(5):
            val_in = (idx_tick / 4.0) * max_y_in
            y_in = pad_t + plot_h - (val_in / max_y_in) * plot_h
            svg.append(
                f'<line x1="{left_x0}" y1="{y_in:.1f}" x2="{left_x0 + left_w}" y2="{y_in:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{left_x0 - 8}" y="{y_in + 4:.1f}" text-anchor="end" font-size="10" fill="#555">{val_in:.0f}M</text>'
            )

            val_out = (idx_tick / 4.0) * max_y_out
            y_out = pad_t + plot_h - (val_out / max_y_out) * plot_h
            svg.append(
                f'<line x1="{right_x0}" y1="{y_out:.1f}" x2="{right_x0 + right_w}" y2="{y_out:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{right_x0 - 8}" y="{y_out + 4:.1f}" text-anchor="end" font-size="10" fill="#555">{val_out:.0f}K</text>'
            )

        n_phases = len(phases)
        n_models = len(model_series)
        group_w_l = left_w / n_phases
        group_w_r = right_w / n_phases
        bar_w = min(22.0, (group_w_l * 0.76) / max(1, n_models))

        in_colors = [("#2b5c8f", "#2ecc71"), ("#7570b3", "#1b9e77"), ("#8c510a", "#66a61e")]
        out_colors = [("#c0392b", "#f39c12"), ("#8e44ad", "#16a085"), ("#6a3d9a", "#e6ab02")]

        for p_idx, (pid, p_label) in enumerate(phases):
            gx_l = left_x0 + (p_idx + 0.5) * group_w_l
            gx_r = right_x0 + (p_idx + 0.5) * group_w_r
            svg.append(
                f'<text x="{gx_l:.1f}" y="{height - pad_b + 18}" text-anchor="end" font-size="10" font-weight="bold" fill="#222" transform="rotate(-25, {gx_l:.1f}, {height - pad_b + 18})">{p_label}</text>'
            )
            svg.append(
                f'<text x="{gx_r:.1f}" y="{height - pad_b + 18}" text-anchor="end" font-size="10" font-weight="bold" fill="#222" transform="rotate(-25, {gx_r:.1f}, {height - pad_b + 18})">{p_label}</text>'
            )

            for m_idx, ms in enumerate(model_series):
                offset = (m_idx - (n_models - 1) / 2.0) * (bar_w + 3.0)
                st = ms["phases"][pid]

                # Panel (a): Input tokens (Uncached + Cached)
                cx_l = gx_l + offset
                unc_m = float(st["uncached_mean"] or 0.0) / 1e6
                cac_m = float(st["cached_mean"] or 0.0) / 1e6
                tot_in_m = float(st["input_mean"] or 0.0) / 1e6
                std_in_m = float(st["input_std"] or 0.0) / 1e6

                h_unc = (min(unc_m, max_y_in) / max_y_in) * plot_h
                h_cac = (min(cac_m, max(0.0, max_y_in - unc_m)) / max_y_in) * plot_h
                y_unc = pad_t + plot_h - h_unc
                y_cac = y_unc - h_cac
                col_unc, col_cac = in_colors[m_idx % len(in_colors)]

                svg.append(
                    f'<rect x="{cx_l - bar_w / 2:.1f}" y="{y_unc:.1f}" width="{bar_w:.1f}" height="{h_unc:.1f}" fill="{col_unc}"/>'
                )
                svg.append(
                    f'<rect x="{cx_l - bar_w / 2:.1f}" y="{y_cac:.1f}" width="{bar_w:.1f}" height="{h_cac:.1f}" fill="{col_cac}"/>'
                )
                if ms["repetitions"] >= 2 and std_in_m > 0:
                    err_top = (
                        pad_t + plot_h - (min(max_y_in, tot_in_m + std_in_m) / max_y_in) * plot_h
                    )
                    err_bot = pad_t + plot_h - (max(0.0, tot_in_m - std_in_m) / max_y_in) * plot_h
                    svg.append(
                        f'<line x1="{cx_l:.1f}" y1="{err_top:.1f}" x2="{cx_l:.1f}" y2="{err_bot:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )
                    svg.append(
                        f'<line x1="{cx_l - 3.5:.1f}" y1="{err_top:.1f}" x2="{cx_l + 3.5:.1f}" y2="{err_top:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )
                    svg.append(
                        f'<line x1="{cx_l - 3.5:.1f}" y1="{err_bot:.1f}" x2="{cx_l + 3.5:.1f}" y2="{err_bot:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )

                # Panel (b): Thinking + Output tokens (Thousands)
                cx_r = gx_r + offset
                tho_k = float(st["thoughts_mean"] or 0.0) / 1e3
                out_k = float(st["output_mean"] or 0.0) / 1e3
                tot_out_k = float(st["output_total_mean"] or 0.0) / 1e3
                std_out_k = float(st["output_total_std"] or 0.0) / 1e3

                h_tho = (min(tho_k, max_y_out) / max_y_out) * plot_h
                h_out = (min(out_k, max(0.0, max_y_out - tho_k)) / max_y_out) * plot_h
                y_tho = pad_t + plot_h - h_tho
                y_out = y_tho - h_out
                col_tho, col_out = out_colors[m_idx % len(out_colors)]

                svg.append(
                    f'<rect x="{cx_r - bar_w / 2:.1f}" y="{y_tho:.1f}" width="{bar_w:.1f}" height="{h_tho:.1f}" fill="{col_tho}"/>'
                )
                svg.append(
                    f'<rect x="{cx_r - bar_w / 2:.1f}" y="{y_out:.1f}" width="{bar_w:.1f}" height="{h_out:.1f}" fill="{col_out}"/>'
                )
                if ms["repetitions"] >= 2 and std_out_k > 0:
                    err_top_r = (
                        pad_t
                        + plot_h
                        - (min(max_y_out, tot_out_k + std_out_k) / max_y_out) * plot_h
                    )
                    err_bot_r = (
                        pad_t + plot_h - (max(0.0, tot_out_k - std_out_k) / max_y_out) * plot_h
                    )
                    svg.append(
                        f'<line x1="{cx_r:.1f}" y1="{err_top_r:.1f}" x2="{cx_r:.1f}" y2="{err_bot_r:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )
                    svg.append(
                        f'<line x1="{cx_r - 3.5:.1f}" y1="{err_top_r:.1f}" x2="{cx_r + 3.5:.1f}" y2="{err_top_r:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )
                    svg.append(
                        f'<line x1="{cx_r - 3.5:.1f}" y1="{err_bot_r:.1f}" x2="{cx_r + 3.5:.1f}" y2="{err_bot_r:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )

        # Bottom legend
        leg_entries = []
        for m_idx, ms in enumerate(model_series):
            c_unc, c_cac = in_colors[m_idx % len(in_colors)]
            c_tho, c_out = out_colors[m_idx % len(out_colors)]
            m_short = str(ms["model"]).replace("gemini-", "")
            leg_entries.extend(
                [
                    (c_unc, f"{m_short} Uncached In"),
                    (c_cac, f"{m_short} Cached In"),
                    (c_tho, f"{m_short} Thinking"),
                    (c_out, f"{m_short} Output"),
                ]
            )
        cols_per_row = 4
        for idx_l, (col_hex, text_l) in enumerate(leg_entries):
            row = idx_l // cols_per_row
            col = idx_l % cols_per_row
            lx = 55 + col * 195
            ly = height - 40 + row * 15
            svg.append(
                f'<rect x="{lx}" y="{ly - 9}" width="11" height="11" fill="{col_hex}" rx="2"/>'
            )
            svg.append(f'<text x="{lx + 15}" y="{ly}" font-size="10" fill="#222">{text_l}</text>')

        svg.append("</svg>\n")
        (plots_dir / "fig_rq4_phase_token_breakdown.svg").write_text(
            "\n".join(svg), encoding="utf-8"
        )
