# goggles-ai Launch Draft

Building agents that browse the web and ingest untrusted context is exciting, but it also creates a new security problem:

machines can read instructions humans never notice.

That is the idea behind `goggles-ai`.

goggles-ai is an open-source inspection layer for AI agent inputs. It scans pages, text, and images before they reach an agent, helping surface hidden prompt injections, cloaked content, and covert payloads that can quietly influence model behavior.

The core thesis is simple:

`AI agents need input security, not just output guardrails.`

Today the project can already inspect:
- hidden HTML and CSS payloads
- zero-width and Unicode-based text attacks
- suspicious metadata and image stego signals
- simple bot-vs-human cloaking patterns

Still early, but the direction feels important.

I think there is a real category forming around securing what agents read before they act.

If you are building agentic systems, browser agents, or retrieval-heavy AI workflows, I would love to hear how you are thinking about this layer.

Repo:
[https://github.com/0xAshraFF/goggles-ai](https://github.com/0xAshraFF/goggles-ai)

## Shorter Version

I’m open-sourcing `goggles-ai`, an inspection layer for AI agent inputs.

It scans untrusted pages, text, and images for hidden prompt injections and covert payloads before that content reaches an agent.

The bet: input security for AI agents is going to become its own category.

Would love feedback from anyone building browser agents, MCP tools, or retrieval-heavy AI products.
