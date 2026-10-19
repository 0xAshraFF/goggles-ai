# goggles-ai Launch Post

AI agents read things humans never see.

A page can look clean in a browser and still carry instructions for the model: text hidden with CSS, zero-width characters, lookalike letters from other alphabets, payloads in HTML comments, alt text, image metadata, or different content served only to bots.

I'm open-sourcing `goggles-ai` to deal with that layer. It's a deterministic hidden-channel and steganography sanitizer for MCP, browser, and LLM agents:

- finds content the model can read but a human can't see
- strips it and returns the visible content
- returns a policy decision: `allow`, `sanitize`, or `block`
- ships as a Python library, a CLI, and an MCP server, with Playwright and LangChain hooks

It's rule-based and statistical, with no model downloads.

Numbers, not vibes: I obfuscated all 263 injections in deepset/prompt-injections with zero-width splits and lookalike letters from Unicode's official confusables table. goggles stopped all of them. On 815 benign samples (text in 18 languages, emoji sequences, everyday HTML), it raised zero false flags. A popular injection classifier caught 30% of instructions hidden in CSS; goggles stripped 100%. Benchmark and code are in the repo.

What it doesn't do: detect plain-text prompt injection. If an attack is written in visible text, goggles-ai will let it through. Add a semantic classifier for that; the README has a short recipe. One surprise from the benchmark: obfuscation didn't blind the classifier, it made it more suspicious. So goggles isn't there to boost your classifier. It catches a different class of attack.

```bash
pip install goggles-ai
python -m goggles_ai.middleware.mcp_server
```

Repo: https://github.com/0xAshraFF/goggles-ai

If you're building browser agents or MCP tools, I'd like to hear which hidden-content tricks you've run into that it misses.

## Short Version

I'm open-sourcing `goggles-ai`: a deterministic sanitizer that strips hidden instructions (CSS-hidden text, zero-width characters, homoglyphs, comment and metadata payloads, image stego) from what your agent reads, then tells it to allow, sanitize, or block. Ships as a library, CLI, and MCP server. It doesn't catch visible prompt injection; pair it with a classifier for that.

https://github.com/0xAshraFF/goggles-ai
