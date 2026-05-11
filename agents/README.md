# Isolated Worker (Sub-agent) Model

This directory contains the definitions for custom agents used in the Mjolnir project.

## Overview

Mjolnir uses specialized, isolated workers (sub-agents) to perform specific security auditing tasks. This model ensures:

- **Isolation:** Agents have limited access to tools and context, reducing the risk of unintended actions or information leaks.
- **Specialization:** Each agent is tailored for a specific task (e.g., Rust auditing, C/C++ auditing) with a focused system prompt.
- **Multi-model Corroboration:** Different agents (potentially powered by different models) can be used to cross-check findings.

## Directory Structure

Each agent should have its own subdirectory containing a `manifest.yaml` file.

```text
agents/
├── README.md
├── manifest_schema.yaml
├── rust_auditor/
│   └── manifest.yaml
├── adversarial_reviewer/
│   └── manifest.yaml
└── c_cpp_auditor/
    └── manifest.yaml
```

## Agent Manifests

Agent manifests define the behavior and capabilities of an agent. They must adhere to the schema defined in `manifest_schema.yaml`.

Key fields:

- `name`: The name of the agent.
- `version`: The version of the manifest schema.
- `system_prompt`: The core instructions for the agent.
- `allowed_tools`: List of tools the agent can use.
- `supported_backends`: Validated LLM backends.
