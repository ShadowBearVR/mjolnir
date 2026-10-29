---
name: sv-audit-skill
description: Guidelines and check procedures for identifying security vulnerabilities in SystemVerilog and Verilog Root-of-Trust hardware RTL files.
---

# SystemVerilog / RTL Security Audit Guidelines

When analyzing SystemVerilog (`.sv`, `.svh`) or Verilog (`.v`, `.vh`) hardware RTL modules, pay special attention to the following RTL-specific vulnerability classes:

## 1. IEEE 1800-2017 Expression Bit-Width & Signedness Hazards

- **Self-Determined vs. Context-Determined Widths:** Scrutinize shifts (`a << b`), arithmetic (`a + b`), and ternary/concatenation expressions where an intermediate operand's width is narrower than the destination signal, causing silent high-bit truncation before assignment or address-range comparison.
- **Signed/Unsigned Promotion:** In SystemVerilog, mixing a single unsigned operand (including part-selects `sig[k:0]` or unsized literals) in an expression forces the entire operation unsigned, silently breaking negative/bounds comparisons.
- **Out-of-Range Indexing & Parameter Corner Cases:** Check dynamic bit-selects, word-index slices, and `$clog2(...)` sizing when buffer depths or counts hit boundary values (`0`, `1`, or non-powers-of-two).

## 2. Finite-State Machine (FSM) Integrity, Deadlocks & Fault Countermeasures

- **Protocol & Handshake Deadlocks:** Check ready/valid bus, FIFO, DMA, and cryptographic engine state machines for states that stall permanently when presented with aborted, zero-length, unaligned, or back-to-back malformed transactions.
- **Sparse FSM & Escalation Responsiveness (`SEC_CM`):** Verify that security-critical FSMs using sparse state encodings (e.g., `prim_sparse_fsm_flop`) transition deterministically to a terminal error/alert state on invalid states (`default:`), and check that lifecycle escalation / disable inputs (`lc_escalate_en_i`, `disable_i`, fatal alert triggers) are honored across **all** active states—not only `Idle`.

## 3. Hardware Access Control, Register Locks & Multi-Bit Decoding

- **Register Write-Enable & Lock Bypass (`REGWEN`):** Verify that security configuration, key, region-bound, and privilege registers cannot be modified once their corresponding lock or `regwen` signal is cleared, including via indirect shadow/FIFO/DMA paths.
- **Strict vs. Loose Multi-Bit Booleans (`MuBi` / Lifecycle Signals):** Check whether security-enabling signals (debug unlock, test/DFT access, key sideload enable, RMA transitions) use **strict** multi-bit truth checks (e.g., `mubi4_test_true_strict`) rather than loose inequality (`!= MuBi4False`), which permits single-bit faults or invalid encodings to enable privileged paths.

## 4. Clock-Domain Crossing (CDC), Reset Domains & Secret Zeroization

- **CDC & Reset-Domain Mismatches:** Look for multi-bit control, address, or lifecycle signals crossing clock domains without proper handshake/synchronizer primitives (e.g., `prim_flop_2sync`), or partial resets that clear access-control locks while leaving sensitive keys/digests intact in another reset domain.
- **Key & State Clearing on Escalation:** Ensure cryptographic key registers, sideload buses, intermediate state flops, and entropy buffers are wiped immediately upon zeroization commands, lifecycle transitions, or fault escalation.
