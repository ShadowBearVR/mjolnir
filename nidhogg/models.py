# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import json

@dataclass
class NCMCoordinate:
    spatial_scope: str  # INTRA_PROCEDURAL, INTER_PROCEDURAL, CROSS_COMPONENT
    temporal_depth: str # STATELESS, SHALLOW_STATE, DEEP_STATE_RACE
    domain_subtlety: str # STANDARD_CWE, LOGIC_SPEC_MISMATCH, HW_FW_INTERFACE

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)

@dataclass
class VulnerabilitySpan:
    file: str
    start_line: int
    end_line: int

@dataclass
class VulnerabilitySpec:
    id: str
    cwe_id: str
    cwe_name: str
    title: str
    description: str
    ncm: NCMCoordinate
    target_files: List[str]
    patch_diff: str
    build_passed: bool
    build_command: str
    build_output: str
    vulnerable_spans: List[VulnerabilitySpan] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['ncm'] = self.ncm.to_dict()
        data['vulnerable_spans'] = [asdict(s) for s in self.vulnerable_spans]
        return data

@dataclass
class VulnerabilityItemStatus:
    id: str
    cwe_id: str
    cwe_name: str
    status: str  # "IN_PROGRESS", "SUCCESS", "FAILED"
    updated_at: str
    build_passed: bool = False
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class DatasetMetadata:
    dataset_id: str
    target_project: str
    profile: str
    status: str  # "IN_PROGRESS", "COMPLETED", "FAILED"
    started_at: str
    updated_at: str
    total_requested: int = 1
    completed_count: int = 0
    failed_count: int = 0
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class DatasetManifest:
    dataset_id: str
    target_project: str
    created_at: str
    vulnerabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
