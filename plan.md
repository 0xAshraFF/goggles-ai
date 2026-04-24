# goggles-ai Plan

## Product Strategy

### Open Source
- Core detectors for hidden prompt injection and content anomalies.
- Basic sanitizers and local scan API.
- CLI and developer SDK for local/offline testing.
- Evaluation harness with sample attacks and benchmarks.
- Minimal demo dashboard for single-user scanning and inspection.

### Private
- Hosted gateway with policy enforcement (`allow`, `sanitize`, `block`, `quarantine`, `review`).
- Team features: auth, tenants, audit logs, alerts, usage analytics.
- Enterprise integrations for browser agents, MCP gateways, and retrieval pipelines.
- Rendered-page pipeline, OCR pipeline, and advanced cloaking analysis as managed features.
- Detection tuning, proprietary rules, and incident intelligence.

### MVP Principle
- Open source enough to earn trust and adoption.
- Keep the system-of-record, enforcement layer, and team workflow private.
- Make the open-source repo useful on its own, but not the whole product.

## Phase 0: Today

### Goal
- Ship a polished demo and a credible story for LinkedIn and investor conversations.

### Deliverables
- Fix the critical product bugs already identified.
- Tighten positioning around "security gateway for agent inputs".
- Prepare one sharp demo flow: malicious page in, hidden attack found, policy action shown, clean output out.
- Update messaging so claims match the current product.
- Add a short announcement post draft and demo script.

### Must-Have By End Of Day
- URL scans do not report network failures as safe.
- URL scans return sanitized output when applicable.
- WebSocket flow returns a visible result in the dashboard, or the UI hides that mode for demo day.
- CLI works, or the broken entrypoint is removed before any public install instructions.
- Demo narrative is rehearsable in under 2 minutes.

## Phase 1: Fundraiseable MVP

### Goal
- Prove that goggles-ai protects agent workflows from hidden input attacks.

### Scope
- Scan API for URL, HTML, text, image, and uploaded file input.
- Policy engine with 4 actions: `allow`, `sanitize`, `block`, `quarantine`.
- Clean inspection UI showing:
  - original source
  - extracted machine-visible content
  - threats
  - enforcement result
  - sanitized output
- One strong integration target:
  - browser agent, or
  - MCP gateway

### Demo Story
1. User connects an agent workflow.
2. User sets a simple policy.
3. User scans a malicious page with hidden instructions.
4. goggles-ai highlights what the human missed.
5. goggles-ai blocks or sanitizes the content.
6. The agent proceeds with the clean version.

## Phase 2: Product Credibility

### Goal
- Move from impressive demo to something a team can pilot.

### Additions
- Playwright-rendered scanning path.
- Agent-visible content model:
  - raw HTML
  - rendered DOM text
  - hidden/accessibility text
  - OCR text
- Incident history with stored artifacts and reasons.
- Team policies and reusable policy templates.
- Better cloaking checks across JS on/off and bot/headless variants.

## Phase 3: Enterprise Motion

### Goal
- Make this buyable by security and platform teams.

### Additions
- Multi-tenant hosted dashboard.
- RBAC and SSO.
- Alerts and webhook integrations.
- Policy-as-code.
- Domain risk intelligence and reporting.
- Managed connectors for major agent stacks.

## Open Source Boundary Rules

### Keep Public
- Detection research and basic scanning primitives.
- Enough tooling for developers to test content locally.
- Example integrations and sample attacks.

### Keep Private
- Anything that becomes the control plane.
- Anything that stores customer incidents or policies.
- Anything that creates operational lock-in or recurring value.
- Premium datasets, tuned heuristics, and enterprise workflows.

## Demo Walkthrough

### Target User
- AI engineer or security lead evaluating protection for an agent that browses the web.

### Flow
1. Landing view: "Protect what your agent reads."
2. Select source: URL or file.
3. Show policy: "Block hidden instructions and quarantine suspicious images."
4. Run scan on a crafted malicious page.
5. Show findings side-by-side with sanitized output.
6. End with enforcement outcome and incident log.

### Success Criteria
- The audience understands the risk in less than 30 seconds.
- The hidden attack is visually obvious once revealed.
- The value of the product is clear before technical details are discussed.

## LinkedIn Announcement Draft

### Angle
- Announce goggles-ai as a new open-source security layer for AI agent inputs.

### Draft
Building agents that browse the web and read untrusted content is exciting, but it creates a new security problem: machines can see instructions humans never notice.

Today I’m sharing goggles-ai, an open-source security layer for AI agent inputs. It scans pages, text, and images for hidden prompt injections, cloaked content, and covert payloads before that content reaches an agent.

The goal is simple: give teams a way to inspect and sanitize untrusted content before an AI system acts on it.

Still early, but the direction is clear: input security for AI agents will become a real category.

If you’re building agentic systems, I’d love feedback.

## Immediate Task List

### Today
- Fix release-blocking and demo-breaking issues.
- Decide on one polished demo scenario.
- Trim README claims to match what works today.
- Prepare screenshots or a short screen recording.

### This Week
- Add rendered-page scanning.
- Introduce policy actions to the API and UI.
- Turn the dashboard into a product walkthrough instead of a dev console.
