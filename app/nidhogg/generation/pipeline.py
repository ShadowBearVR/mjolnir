# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Multi-agent ADK synthetic vulnerability generation pipeline (Planner -> Creator -> Adversarial Reviewer -> Oracle Gate)."""

import asyncio
import datetime
import json
from pathlib import Path
import uuid

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from agent_tools import format_tool_guidance
from agent_tools.ast_search import ast_search
from agent_tools.ctags_search import ctags_search
from agent_tools.glob import glob
from agent_tools.grep_search import grep_search
from agent_tools.read_file import read_file
from agent_tools.worktree import (
    get_worktree_diff,
    patch_worktree_file,
    reset_worktree,
    run_harness_command,
    write_worktree_file,
)
from executors.ctags import CtagsRunner
from nidhogg.constants import NCM_PROFILES
from nidhogg.data.models import (
    AdversarialReviewVerdict,
    CreatorSubmission,
    DatasetManifest,
    InjectionPlan,
    NcmCoordinate,
    SyntheticVulnManifest,
    VulnerableSpan,
)
from nidhogg.generation.realism_gate import WorktreeRealismGate
from nidhogg.sandbox.orphan_snapshot import OrphanSnapshotBuilder
from providers.adk.agents.isolated_agent import IsolatedAgent
from providers.adk.utilities.async_runner import extract_agent_output
from utilities.discovery import discover_source_files
from utilities.logger import logger
from utilities.worktree_sandbox import WorktreeSandbox, current_worktree_sandbox

ROT_CWES_PATH = Path(__file__).resolve().parent.parent / "data" / "rot_cwes.json"

PLANNER_TOOLS = [ctags_search, ast_search, grep_search, glob, read_file]
CREATOR_TOOLS = [
    ctags_search,
    ast_search,
    grep_search,
    glob,
    read_file,
    patch_worktree_file,
    write_worktree_file,
    run_harness_command,
    get_worktree_diff,
    reset_worktree,
]


async def execute_agent_task(
    agent: IsolatedAgent,
    prompt: str,
    state: dict,
    task_name: str,
):
    """Runs a standalone ADK IsolatedAgent task and extracts its structured output."""
    session_service = InMemorySessionService()
    runner = Runner(agent=agent, app_name="nidhogg", session_service=session_service)
    session = await session_service.create_session(
        app_name="nidhogg",
        user_id="nidhogg_user",
        state=state,
    )
    msg = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
    last_output = None
    try:
        for ev in runner.run(
            user_id="nidhogg_user",
            session_id=session.id,
            new_message=msg,
        ):
            if getattr(ev, "output", None) is not None:
                last_output = ev.output
            elif getattr(ev, "content", None) and getattr(ev.content, "parts", None):
                for part in ev.content.parts:
                    if getattr(part, "text", None):
                        last_output = part.text
    except Exception as e:
        logger.error(f"Nidhogg agent task '{task_name}' failed: {e}")
        return None

    return extract_agent_output(last_output, getattr(agent, "output_schema", None))


class GenerationPipeline:
    """Orchestrates NCM-stratified synthetic vulnerability injection and corpus packaging."""

    def __init__(
        self,
        spec: dict,
        corpus_root: Path,
        cache_root: Path,
        generator_model: str | None = None,
    ):
        self.spec = spec
        self.project = spec["project"]
        self.corpus_root = corpus_root.expanduser().resolve()
        self.snapshot_builder = OrphanSnapshotBuilder(cache_root=cache_root)
        self.realism_gate = WorktreeRealismGate()
        self.generator_model = (
            generator_model or self.project.get("generatorModel") or "claude-3-5-sonnet-latest"
        )
        with open(ROT_CWES_PATH, "r", encoding="utf-8") as f:
            self.rot_cwes = json.load(f)["tiers"]

    def generate_dataset(
        self,
        dataset_id: str,
        profile: str = "balanced",
        count: int = 3,
        scope_name: str | None = None,
        max_attempts_per_instance: int = 3,
    ) -> DatasetManifest:
        """Generates a stratified synthetic vulnerability dataset under benchmarks/corpus/<repo>/<dataset_id>/."""
        repo_name = self.project["repoName"]
        repo_url = self.project["repoUrl"]
        pinned_rev = self.project["pinnedRev"]

        baseline_dir = self.snapshot_builder.ensure_pinned_baseline(
            repo_name=repo_name,
            repo_url=repo_url,
            pinned_rev=pinned_rev,
            nix_source_path=self.project.get("nixSourcePath"),
        )
        CtagsRunner().ensure_tags(baseline_dir)

        dataset_dir = self.corpus_root / repo_name / dataset_id
        instances_dir = dataset_dir / "instances"
        instances_dir.mkdir(parents=True, exist_ok=True)

        ncm_cells = NCM_PROFILES.get(profile, NCM_PROFILES["balanced"])
        scopes = self.project.get("scopes", [{"name": "default", "srcDirs": ["."]}])
        if scope_name:
            scopes = [s for s in scopes if s["name"] == scope_name] or scopes

        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        dataset_manifest = DatasetManifest(
            dataset_id=dataset_id,
            project_name=repo_name,
            repo_url=repo_url,
            base_commit=pinned_rev,
            profile=profile,
            generator_model=self.generator_model,
            instance_ids=[],
            created_at=now_iso,
        )

        for idx in range(count):
            cell_dict = ncm_cells[idx % len(ncm_cells)]
            ncm = NcmCoordinate(**cell_dict)
            tier_cwes = self.rot_cwes.get(str(ncm.domain_subtlety), self.rot_cwes["1"])
            cwe_entry = tier_cwes[idx % len(tier_cwes)]
            scope = scopes[idx % len(scopes)]
            vuln_id = f"nidhogg-{idx + 1:03d}-{ncm.cell_id.lower()}-{cwe_entry['cwe_id'].lower()}"

            logger.header(
                f"Generating Instance [{idx + 1}/{count}]: {vuln_id} (Scope={scope['name']}, Model={self.generator_model})"
            )

            instance_manifest = self._generate_single_instance(
                vuln_id=vuln_id,
                dataset_id=dataset_id,
                baseline_dir=baseline_dir,
                scope=scope,
                ncm=ncm,
                cwe_entry=cwe_entry,
                instance_dir=instances_dir / vuln_id,
                max_attempts=max_attempts_per_instance,
            )
            if instance_manifest:
                dataset_manifest.instance_ids.append(vuln_id)

        manifest_path = dataset_dir / "dataset_manifest.json"
        manifest_path.write_text(
            json.dumps(dataset_manifest.model_dump(), indent=2), encoding="utf-8"
        )
        logger.success(
            f"Saved dataset manifest with {len(dataset_manifest.instance_ids)} validated instances to {manifest_path}"
        )
        return dataset_manifest

    def _generate_single_instance(
        self,
        vuln_id: str,
        dataset_id: str,
        baseline_dir: Path,
        scope: dict,
        ncm: NcmCoordinate,
        cwe_entry: dict,
        instance_dir: Path,
        max_attempts: int,
    ) -> SyntheticVulnManifest | None:
        instance_dir.mkdir(parents=True, exist_ok=True)
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        files = discover_source_files(
            code_dir=str(baseline_dir),
            src_dirs=scope.get("srcDirs", ["."]),
            extensions=set(self.project.get("extensions", ["rs", "c", "h"])),
            exclude_dirs=self.project.get("excludeDirs", []),
            exclude_patterns=self.project.get("excludePatterns", []),
        )
        probe_sandbox = WorktreeSandbox(baseline_dir, instance_dir, vuln_id)
        prod_candidates = [f for f in files if not probe_sandbox.is_test_or_harness_path(f)]
        if not prod_candidates:
            prod_candidates = files

        if self.generator_model == "mock":
            return self._generate_mock_instance(
                vuln_id=vuln_id,
                dataset_id=dataset_id,
                baseline_dir=baseline_dir,
                prod_candidates=prod_candidates,
                scope=scope,
                ncm=ncm,
                cwe_entry=cwe_entry,
                instance_dir=instance_dir,
                now_iso=now_iso,
            )

        return asyncio.run(
            self._generate_adk_instance_async(
                vuln_id=vuln_id,
                dataset_id=dataset_id,
                baseline_dir=baseline_dir,
                prod_candidates=prod_candidates,
                scope=scope,
                ncm=ncm,
                cwe_entry=cwe_entry,
                instance_dir=instance_dir,
                now_iso=now_iso,
                max_attempts=max_attempts,
            )
        )

    def _generate_mock_instance(
        self,
        vuln_id: str,
        dataset_id: str,
        baseline_dir: Path,
        prod_candidates: list[str],
        scope: dict,
        ncm: NcmCoordinate,
        cwe_entry: dict,
        instance_dir: Path,
        now_iso: str,
    ) -> SyntheticVulnManifest:
        """Synthesizes a deterministic, stealth-compliant mock injection for offline pipeline testing."""
        target_rel = prod_candidates[0]
        target_abs = baseline_dir / target_rel
        lines = target_abs.read_text(encoding="utf-8", errors="ignore").splitlines()
        insert_line = min(15, max(1, len(lines)))

        # Create a real unified diff via a temporary WorktreeSandbox
        sandbox = WorktreeSandbox(
            source_code_dir=baseline_dir,
            workspace_dir=instance_dir,
            vuln_id=f"mock_{uuid.uuid4().hex[:8]}",
        )
        sandbox.setup()
        try:
            wt_file = sandbox.worktree_dir / target_rel
            wt_lines = wt_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            mutation_line = "let _state_mask: u32 = 0xffff_fffe;"
            wt_lines.insert(insert_line - 1, mutation_line)
            wt_file.write_text("\n".join(wt_lines) + "\n", encoding="utf-8")
            vuln_patch = sandbox.get_diff()
        finally:
            sandbox.cleanup()

        oracle_poc_patch = (
            f"--- a/tests/oracle_{vuln_id}.rs\n"
            f"+++ b/tests/oracle_{vuln_id}.rs\n"
            "@@ -0,0 +1,4 @@\n"
            "+#[test]\n"
            "+fn test_state_transition_invariant() {\n"
            "+    assert_eq!(1, 1);\n"
            "+}\n"
        )

        manifest = SyntheticVulnManifest(
            vuln_id=vuln_id,
            dataset_id=dataset_id,
            project_name=self.project["repoName"],
            base_commit=self.project["pinnedRev"],
            scope=scope["name"],
            cwe_id=cwe_entry["cwe_id"],
            title=f"{cwe_entry['name']} in {Path(target_rel).name}",
            description=cwe_entry["rot_manifestation"],
            ncm=ncm,
            vulnerable_spans=[
                VulnerableSpan(
                    file_path=target_rel,
                    function_name="main",
                    start_line=insert_line,
                    end_line=insert_line + 2,
                )
            ],
            oracle_test_file=f"tests/oracle_{vuln_id}.rs",
            oracle_test_command="true",
            realism_gate_passed=True,
            oracle_verified=True,
            stealth_score=9,
            generator_model="mock",
            created_at=now_iso,
        )

        (instance_dir / "vuln_patch.diff").write_text(vuln_patch, encoding="utf-8")
        (instance_dir / "oracle_poc.diff").write_text(oracle_poc_patch, encoding="utf-8")
        (instance_dir / "ground_truth.json").write_text(
            json.dumps(manifest.model_dump(), indent=2), encoding="utf-8"
        )
        (instance_dir / "generation_trace.json").write_text(
            json.dumps(
                {
                    "canary": manifest.canary,
                    "vuln_id": vuln_id,
                    "mode": "mock",
                    "created_at": now_iso,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return manifest

    async def _generate_adk_instance_async(
        self,
        vuln_id: str,
        dataset_id: str,
        baseline_dir: Path,
        prod_candidates: list[str],
        scope: dict,
        ncm: NcmCoordinate,
        cwe_entry: dict,
        instance_dir: Path,
        now_iso: str,
        max_attempts: int,
    ) -> SyntheticVulnManifest | None:
        """Executes Planner -> Creator (in WorktreeSandbox) -> AdversarialReviewer -> WorktreeRealismGate."""
        planner = IsolatedAgent(
            name="VulnerabilityPlanner",
            model=self.generator_model,
            instruction=(
                "You are Nidhogg's VulnerabilityPlanner for Root-of-Trust firmware benchmarking.\n"
                f"{format_tool_guidance(PLANNER_TOOLS)}\n"
                "Select a realistic function in the candidate production files and design a subtle "
                "synthetic vulnerability (or benign unreachable decoy if is_distractor=True) that "
                "strictly matches the requested CWE and NCM 3D complexity coordinates. "
                "NEVER use comments, magic numbers (0xdeadbeef), or revealing variable names."
            ),
            output_schema=InjectionPlan,
            tools=PLANNER_TOOLS,
        )

        plan_prompt = json.dumps(
            {
                "project": self.project["repoName"],
                "scope": scope["name"],
                "candidate_files": prod_candidates[:40],
                "cwe": cwe_entry,
                "ncm": ncm.model_dump(),
                "test_cmd_hint": scope.get("testCmd") or self.project.get("testCmd"),
            },
            indent=2,
        )
        plan_dict = await execute_agent_task(
            agent=planner,
            prompt=plan_prompt,
            state={"code_dir": str(baseline_dir)},
            task_name=f"Plan_{vuln_id}",
        )
        if not plan_dict:
            logger.error(f"[{vuln_id}] VulnerabilityPlanner returned no plan.")
            return None
        plan = InjectionPlan.model_validate(plan_dict)

        feedback_history: list[str] = []
        trace_records: list[dict] = [{"stage": "plan", "output": plan.model_dump()}]

        for attempt in range(1, max_attempts + 1):
            async with WorktreeSandbox(
                source_code_dir=baseline_dir,
                workspace_dir=instance_dir,
                vuln_id=f"{vuln_id}_attempt_{attempt}",
            ) as sandbox:
                creator = IsolatedAgent(
                    name="VulnerabilityCreator",
                    model=self.generator_model,
                    instruction=(
                        "You are Nidhogg's VulnerabilityCreator operating inside an isolated WorktreeSandbox.\n"
                        f"{format_tool_guidance(CREATOR_TOOLS)}\n"
                        "1. Apply the planned subtle mutation to the production source file using patch_worktree_file. "
                        "NEVER add comments ('//', '/*') or revealing identifiers ('vuln', 'bug', 'cwe', 'exploit', 'deadbeef').\n"
                        "2. Add or update a unit test in a test file that FAILS when the vulnerability is present "
                        "(or PASSES if is_distractor=True) and PASSES on the unmutated baseline.\n"
                        "3. Run the test command via run_harness_command to verify compilation and behavior before submitting."
                    ),
                    output_schema=CreatorSubmission,
                    tools=CREATOR_TOOLS,
                )

                creator_prompt = json.dumps(
                    {
                        "attempt": attempt,
                        "injection_plan": plan.model_dump(),
                        "prior_rejection_feedback": feedback_history,
                        "lint_cmd": self.project.get("lintCmd"),
                        "default_test_cmd": scope.get("testCmd") or self.project.get("testCmd"),
                    },
                    indent=2,
                )
                sub_dict = await execute_agent_task(
                    agent=creator,
                    prompt=creator_prompt,
                    state={"code_dir": str(sandbox.worktree_dir)},
                    task_name=f"Create_{vuln_id}_try{attempt}",
                )
                if not sub_dict:
                    feedback_history.append("Creator failed to return structured submission.")
                    continue
                submission = CreatorSubmission.model_validate(sub_dict)
                prod_diff, test_diff, prod_files, test_files = (
                    self.realism_gate.split_prod_and_test_diffs(sandbox)
                )

            stealth_ok, stealth_issues = self.realism_gate.check_lexical_stealth(prod_diff)
            if not stealth_ok:
                msg = f"Lexical stealth gate rejected prod_diff: {stealth_issues}"
                logger.warning(f"[{vuln_id}] Attempt {attempt}: {msg}")
                feedback_history.append(msg)
                trace_records.append({"stage": f"stealth_gate_{attempt}", "issues": stealth_issues})
                continue

            reviewer = IsolatedAgent(
                name="AdversarialReviewer",
                model=self.generator_model,
                instruction=(
                    "You are Nidhogg's AdversarialReviewer. Inspect the production unified diff and "
                    "reject any patch that uses unnatural constructs, magic constants, obvious telltales, "
                    "or fails to match the target CWE and NCM coordinate."
                ),
                output_schema=AdversarialReviewVerdict,
                tools=[],
            )
            rev_dict = await execute_agent_task(
                agent=reviewer,
                prompt=json.dumps(
                    {
                        "plan": plan.model_dump(),
                        "prod_diff": prod_diff,
                        "test_diff": test_diff,
                    },
                    indent=2,
                ),
                state={"code_dir": str(baseline_dir)},
                task_name=f"Review_{vuln_id}_try{attempt}",
            )
            verdict = (
                AdversarialReviewVerdict.model_validate(rev_dict)
                if rev_dict
                else AdversarialReviewVerdict(
                    approved=False,
                    stealth_score=1,
                    realism_issues=["Reviewer returned empty verdict"],
                )
            )
            trace_records.append(
                {"stage": f"adversarial_review_{attempt}", "verdict": verdict.model_dump()}
            )
            if not verdict.approved:
                feedback_history.append(
                    f"AdversarialReviewer rejected (score={verdict.stealth_score}): {verdict.feedback or verdict.realism_issues}"
                )
                continue

            oracle_ok, oracle_detail = self.realism_gate.verify_two_sided_poc_oracle(
                baseline_dir=baseline_dir,
                vuln_patch=prod_diff,
                oracle_poc_patch=test_diff,
                oracle_test_cmd=submission.oracle_test_command,
                lint_cmd=self.project.get("lintCmd"),
                is_distractor=ncm.is_distractor,
            )
            trace_records.append(
                {
                    "stage": f"oracle_gate_{attempt}",
                    "passed": oracle_ok,
                    "detail": oracle_detail,
                }
            )
            if not oracle_ok:
                logger.warning(f"[{vuln_id}] Attempt {attempt} failed oracle gate: {oracle_detail}")
                feedback_history.append(f"Two-sided binary oracle failed: {oracle_detail}")
                continue

            manifest = SyntheticVulnManifest(
                vuln_id=vuln_id,
                dataset_id=dataset_id,
                project_name=self.project["repoName"],
                base_commit=self.project["pinnedRev"],
                scope=scope["name"],
                cwe_id=cwe_entry["cwe_id"],
                title=plan.title,
                description=submission.summary,
                ncm=ncm,
                vulnerable_spans=submission.vulnerable_spans,
                oracle_test_file=submission.oracle_test_file,
                oracle_test_command=submission.oracle_test_command,
                realism_gate_passed=True,
                oracle_verified=True,
                stealth_score=verdict.stealth_score,
                generator_model=self.generator_model,
                created_at=now_iso,
            )
            (instance_dir / "vuln_patch.diff").write_text(prod_diff, encoding="utf-8")
            (instance_dir / "oracle_poc.diff").write_text(test_diff, encoding="utf-8")
            (instance_dir / "ground_truth.json").write_text(
                json.dumps(manifest.model_dump(), indent=2), encoding="utf-8"
            )
            (instance_dir / "generation_trace.json").write_text(
                json.dumps(
                    {
                        "canary": manifest.canary,
                        "vuln_id": vuln_id,
                        "records": trace_records,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            logger.success(f"[{vuln_id}] Validated and saved to {instance_dir}")
            return manifest

        logger.error(f"[{vuln_id}] Exhausted {max_attempts} attempts without passing all gates.")
        return None
