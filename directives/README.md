# Directives Layer

This directory represents the "Directive" layer (Layer 1) in the system's 4-layer architecture.

## Purpose

Directives are high-level goals, plans, and constraints written in natural language (Markdown). They guide the AI agent's decision-making process, ensuring its actions are aligned with the project's objectives.

A directive file should define:
- The overall goal of a task.
- The expected inputs and outputs.
- The tools required.
- Constraints and edge cases to consider.
- A history of learnings from past executions.

## Current Directives

*   `kernel_security_monitor.md`: This is the primary directive for the NeuroKernel Bridge, outlining the plan for monitoring the Linux kernel and responding to threats.
