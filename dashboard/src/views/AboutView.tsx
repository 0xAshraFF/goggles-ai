import { Shield, BookOpen } from 'lucide-react'

const DETECTORS = [
  { name: 'CSS Hidden Text', tier: 1, desc: 'Detects content invisible to humans but readable by AI agents: display:none, opacity:0, off-screen positioning, clip-rect, and color-matching techniques.' },
  { name: 'Unicode Steganography', tier: 1, desc: 'Finds zero-width characters, variation selectors, Cyrillic/Greek homoglyphs, and binary-encoded payloads hidden inside normal-looking text.' },
  { name: 'HTML Injection', tier: 1, desc: 'Scans HTML comments, aria-label/title/alt attributes, data-* attributes, noscript blocks, and meta tags for prompt injection payloads.' },
  { name: 'Image Triage', tier: 2, desc: 'Verifies magic bytes, scans EXIF/XMP metadata for high-entropy or instruction payloads, and runs chi-square, RS, and SPA statistical LSB tests.' },
  { name: 'Stego Deep (SRNet)', tier: 3, desc: 'Neural network (SRNet) and Aletheia CLI wrapper for deep steganography detection. Requires optional [deep] install.' },
  { name: 'Cloaking Detection', tier: 2, desc: 'Dual user-agent fetch comparing browser vs bot HTML responses via Jaccard DOM divergence scoring.' },
]

export function AboutView() {
  return (
    <div className="space-y-10 max-w-3xl">
      <div>
        <div className="flex items-center gap-3 mb-3">
          <Shield size={32} className="text-indigo-400" />
          <h1 className="text-2xl font-bold text-gray-100">goggles-ai</h1>
        </div>
        <p className="text-gray-400 leading-relaxed">
          Open-source inspection layer for AI agent inputs. goggles-ai scans pages, text, and images before
          they reach an agent, exposing hidden instructions and suspicious payloads that would otherwise slip
          into the model context.
        </p>
        <div className="flex gap-3 mt-4">
          <a
            href="https://github.com/goggles-ai/goggles-ai"
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm text-gray-300 transition-colors"
          >
            GitHub
          </a>
          <a
            href="/docs"
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm text-gray-300 transition-colors"
          >
            <BookOpen size={14} /> API Docs
          </a>
        </div>
      </div>

      {/* Architecture */}
      <section>
        <h2 className="text-lg font-semibold text-gray-200 mb-4">How The Demo Works</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { tier: '1', label: 'Inspect', latency: 'Source in', colour: 'indigo' },
            { tier: '2', label: 'Reveal', latency: 'Hidden risks', colour: 'purple' },
            { tier: '3', label: 'Respond', latency: 'Clean output', colour: 'pink' },
          ].map(t => (
            <div key={t.tier} className="rounded-lg border border-gray-700 bg-gray-800/50 p-4">
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold text-gray-100">{t.tier}</span>
                <span className="text-sm text-gray-400">{t.label}</span>
              </div>
              <div className="mt-1 text-xs text-gray-500 font-mono">{t.latency}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Detectors */}
      <section>
        <h2 className="text-lg font-semibold text-gray-200 mb-4">Detectors</h2>
        <div className="space-y-3">
          {DETECTORS.map(d => (
            <div key={d.name} className="rounded-lg border border-gray-700 bg-gray-800/40 p-4">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-semibold text-gray-200">{d.name}</span>
                <span className="text-xs text-gray-500 bg-gray-700 px-1.5 py-0.5 rounded font-mono">T{d.tier}</span>
              </div>
              <p className="text-sm text-gray-400">{d.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Integration */}
      <section>
        <h2 className="text-lg font-semibold text-gray-200 mb-4">Integrations</h2>
        <div className="space-y-4">
          <CodeBlock title="Python SDK" code={`from agentshield.scanner import scan, scan_url

result = scan_url("https://untrusted-site.com")
if not result.safe:
    for threat in result.threats:
        print(f"[{threat.severity}] {threat.plain_summary}")`} />
          <CodeBlock title="LangChain" code={`from agentshield.middleware.langchain import get_tools
from langchain.agents import initialize_agent, AgentType

tools = get_tools()
agent = initialize_agent(tools, llm, agent=AgentType.OPENAI_FUNCTIONS)
agent.run("Is https://example.com safe to read?")`} />
          <CodeBlock title="Playwright" code={`from playwright.sync_api import sync_playwright
from agentshield.middleware.playwright_hook import install_sync

with sync_playwright() as p:
    page = p.chromium.launch().new_page()
    hook = install_sync(page, on_threat=lambda e: print(e.threats))
    page.goto("https://untrusted-site.com")`} />
          <CodeBlock title="MCP Server" code={`# Start MCP server (stdio transport)
python -m agentshield.middleware.mcp_server

# HTTP transport
python -m agentshield.middleware.mcp_server --port 8765`} />
        </div>
      </section>
    </div>
  )
}

function CodeBlock({ title, code }: { title: string; code: string }) {
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900 overflow-hidden">
      <div className="px-4 py-2 bg-gray-800 border-b border-gray-700">
        <span className="text-xs font-semibold text-gray-400">{title}</span>
      </div>
      <pre className="p-4 text-xs text-gray-300 font-mono overflow-x-auto">{code}</pre>
    </div>
  )
}
