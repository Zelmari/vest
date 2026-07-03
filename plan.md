# VEST — Vulnerability Exploitation & Scanning Toolkit

## Philosophy

No limiters. No guardrails baked into the core. Safety is a runtime control the user dials up or down. If you want the agent to autonomously exploit a running game and submit the bounty to HackerOne without asking -- it should be able to. If you want interactive approval on every write, that should also work. Configuration, not code, sets boundaries.

Cross-platform (macOS, Windows, Linux). CLI-first. Rust. Pluggable LLM backend (cloud APIs + Ollama/local). General-purpose scanning -- the same harness should scan a Rust binary, a React web game, a Unity desktop game, a network service. The agent decides which tools to reach for.

---

## 1. Crate Layout

```
vest/
├── Cargo.toml                    # Workspace root
├── vest.toml                     # Default config template
├── vest-core/                    # Shared types, traits, errors (zero deps beyond serde)
│   └── src/
│       ├── lib.rs
│       ├── types/                # Finding, Severity, Target, ScanMode, etc.
│       ├── traits/               # Scanner, Provider, Agent, Reporter
│       ├── error.rs              # VestError enum wrapping all sub-crate errors
│       └── ids.rs                # UUID-based IDs for everything
├── vest-cli/                     # CLI entrypoint (clap)
│   └── src/
│       ├── main.rs               # Argument parsing, dispatch
│       ├── commands/             # scan, config, report, agent, provider
│       └── tui.rs                # Terminal UI for live scan progress (ratatui)
├── vest-config/                  # TOML config parsing, validation, defaults
│   └── src/
│       ├── lib.rs
│       ├── config.rs             # VestConfig struct
│       ├── provider.rs           # ProviderConfig per LLM backend
│       ├── scan.rs               # ScanConfig: modes, targets, rules
│       └── safety.rs             # SafetyConfig: boundaries, rate limits
├── vest-providers/               # LLM provider abstraction layer
│   └── src/
│       ├── lib.rs
│       ├── provider.rs           # LlmProvider trait definition
│       ├── registry.rs           # Provider registry (load from config)
│       ├── openai.rs             # OpenAI provider
│       ├── anthropic.rs          # Anthropic provider
│       ├── deepseek.rs           # DeepSeek provider
│       ├── google.rs             # Gemini provider
│       ├── ollama.rs             # Ollama/local provider
│       ├── groq.rs               # Groq provider
│       ├── openrouter.rs         # OpenRouter (catch-all for many providers)
│       └── builder.rs            # Provider builder pattern
├── vest-agent/                   # Agent orchestration engine
│   └── src/
│       ├── lib.rs
│       ├── agent.rs              # Agent trait + base Agent struct
│       ├── orchestrator.rs       # Top-level scan orchestrator
│       ├── patterns/
│       │   ├── mod.rs
│       │   ├── pipeline.rs       # Pipeline pattern (recon → analyze → exploit → report)
│       │   ├── swarm.rs          # Parallel swarm pattern
│       │   ├── tooluse.rs        # Single-agent tool-use loop
│       │   └── hierarchical.rs   # Parent/child agent spawning
│       ├── context.rs            # Agent context (messages, tools, memory)
│       ├── memory.rs             # Cross-session memory (vector store + FP tracking)
│       ├── planner.rs            # Task planning / decomposition
│       ├── validator.rs          # Skeptical validation gate (self-challenge)
│       └── safety.rs             # Runtime safety enforcement (approval gates, rate limits)
├── vest-scanner/                 # Scanner implementations
│   └── src/
│       ├── lib.rs
│       ├── scanner.rs            # Scanner trait definition
│       ├── registry.rs           # Scanner registry (tool definitions for LLM)
│       ├── memory/               # Process memory scanner
│       │   ├── mod.rs
│       │   ├── attach.rs         # Cross-platform process attachment
│       │   ├── read.rs           # Memory reading (read-process-memory + FFI)
│       │   ├── write.rs          # Memory writing (approval-gated)
│       │   ├── pattern.rs        # Pattern scanning (AOB scanning, SIMD-accelerated)
│       │   ├── hooks.rs          # Frida integration for runtime hooking
│       │   └── docs.md           # Memory scanning documentation
│       ├── binary/               # Binary vulnerability analysis
│       │   ├── mod.rs
│       │   ├── parse.rs          # Binary parsing (goblin, object)
│       │   ├── disasm.rs         # Disassembly (capstone, iced-x86)
│       │   ├── mitigations.rs    # Security mitigation checking (ASLR, NX, canaries, etc.)
│       │   ├── sinks.rs          # Sink catalog matching (unsafe function detection)
│       │   ├── rop.rs            # ROP gadget finding
│       │   ├── fuzz.rs           # Fuzzing integration (honggfuzz + arbitrary)
│       │   └── docs.md
│       ├── web/                  # Web/API vulnerability scanner
│       │   ├── mod.rs
│       │   ├── scanner.rs        # HTTP-based vulnerability scanning
│       │   ├── crawler.rs        # Web crawler (spider + link discovery)
│       │   ├── payloads.rs       # Vulnerability payloads (XSS, SQLi, SSTI, etc.)
│       │   ├── nuclei.rs         # Nuclei template integration
│       │   └── docs.md
│       ├── browser/              # Browser automation for web games / web apps
│       │   ├── mod.rs
│       │   ├── chrome.rs         # Chromium oxide / CDP control
│       │   ├── cdp.rs            # CDP domain wrappers (Network, Runtime, Debugger, Security)
│       │   ├── websocket.rs      # WebSocket interception and fuzzing
│       │   ├── wasm.rs           # WebAssembly inspection
│       │   ├── storage.rs        # LocalStorage/SessionStorage/IndexedDB manipulation
│       │   ├── canvas.rs         # Canvas/WebGL inspection
│       │   └── docs.md
│       ├── network/              # Network protocol analysis
│       │   ├── mod.rs
│       │   ├── capture.rs        # Packet capture (pcap)
│       │   ├── fuzz.rs           # Protocol fuzzing
│       │   ├── replay.rs         # Packet replay
│       │   └── docs.md
│       └── files/                # File/asset analysis
│           ├── mod.rs
│           ├── formats.rs        # Game save file format parsers
│           ├── fuzz.rs           # File format fuzzing
│           └── docs.md
├── vest-storage/                 # SQLite persistence layer
│   └── src/
│       ├── lib.rs
│       ├── connection.rs         # rusqlite connection pool
│       ├── schema.rs             # Table definitions + migrations
│       ├── targets.rs            # Target CRUD
│       ├── scans.rs              # Scan sessions
│       ├── findings.rs           # Vulnerability findings (JSON columns + indexed fields)
│       ├── artifacts.rs          # Scan artifacts (screenshots, dumps, payloads)
│       └── memory.rs             # FP memory / cross-scan patterns
├── vest-report/                  # Report generation
│   └── src/
│       ├── lib.rs
│       ├── json.rs               # JSON report output
│       ├── terminal.rs           # Rich terminal output (clap + ratatui)
│       ├── markdown.rs           # Markdown report for human reading
│       └── templates/            # Report templates
├── vest-tools/                   # External tool integrations
│   └── src/
│       ├── lib.rs
│       ├── frida.rs              # Frida dynamic instrumentation
│       ├── nuclei.rs             # Nuclei template scanner
│       ├── sqlmap.rs             # SQLMap integration
│       └── docker.rs             # Docker sandbox management
├── vest-payloads/                # Payload library
│   └── src/
│       ├── lib.rs
│       ├── web.rs                # XSS, SQLi, SSTI, XXE, etc.
│       ├── binary.rs             # Shellcode, ROP chains, format strings
│       ├── memory.rs             # Pattern payloads for memory scanning
│       └── network.rs            # Malformed packets, protocol attacks
└── docs/                         # Documentation
    ├── architecture.md
    ├── getting-started.md
    ├── providers.md
    ├── scanning/
    │   ├── memory.md
    │   ├── binary.md
    │   ├── web.md
    │   ├── browser.md
    │   └── network.md
    └── contributing.md
```

---

## 2. Dependency Map (Key Crates)

### Why each crate was chosen

| Crate | Used In | Purpose | Why Chosen |
|-------|---------|---------|------------|
| `rig-core` (1.4M downloads) | `vest-agent` | Agent orchestration, tool calling, streaming | Most mature Rust LLM agent framework. First-class agents, tools, RAG, embeddings. Actively maintained. |
| `genai` (250k downloads, most providers) | `vest-providers` | Multi-provider LLM client with widest provider coverage | Supports DeepSeek, Ollama, Bedrock, Vertex, and more out of the box. Used as fallback for providers rig-core doesn't cover. |
| `async-openai` | `vest-providers` | OpenAI-compatible API client | All local providers (Ollama, LM Studio) and most cloud providers use OpenAI-compatible endpoints. Configure base URL. |
| `goblin` (57M downloads) | `vest-scanner::binary` | ELF/PE/Mach-O parsing | Cross-platform binary parsing. Higher-level than `object`. Parses headers, sections, imports/exports. Finds RWX segments, checks mitigations. |
| `object` (519M downloads) | `vest-scanner::binary` | Low-level object file reading | De facto standard. Used when goblin's abstraction isn't enough. Symbol tables, relocation entries, debug info. |
| `capstone` (5M downloads) | `vest-scanner::binary` | Multi-architecture disassembly | Covers x86, ARM, MIPS, RISC-V, and 10+ more. Essential for finding gadgets and analyzing instruction patterns. |
| `iced-x86` (2.3M downloads) | `vest-scanner::binary` | Pure-Rust x86/x64 disassembly + assembler | No FFI overhead. Blazing fast for x86/x64 targets (most games). Full AVX-512 support. |
| `read-process-memory` (1.5M downloads) | `vest-scanner::memory` | Cross-platform memory reading | Proven by rbspy. Handles Windows (ReadProcessMemory), Linux (ptrace), macOS (mach_vm_read). |
| `chromiumoxide` (2.5M downloads) | `vest-scanner::browser` | Chrome DevTools Protocol control | Pure Rust CDP. Launch/connect, navigate, evaluate JS, intercept requests, capture screenshots. Most mature CDP crate. |
| `reqwest` (300M+ downloads) | Everywhere | HTTP client | The standard. Proxies, TLS, connection pooling, async. Used for API calls, web scanning, file downloads. |
| `pcap` (3M+ downloads) | `vest-scanner::network` | Packet capture | libpcap bindings. Live capture and offline analysis. |
| `rusqlite` | `vest-storage` | SQLite database | Battle-tested. With `serde_json` for JSON column handling. |
| `clap` | `vest-cli` | CLI argument parsing | Industry standard. Derive macros for type-safe CLI. |
| `ratatui` | `vest-cli` | Terminal UI for live scan progress | Actively maintained tui-rs fork. Rich terminal dashboards. |
| `serde` + `serde_json` | Everywhere | Serialization | Universal. TOML config parsing, JSON reports, message passing. |
| `tokio` | Everywhere | Async runtime | Standard Rust async runtime. Required by reqwest, chromiumoxide, rig-core. |
| `tracing` + `tracing-subscriber` | Everywhere | Structured logging | Replaces println debugging. Filter levels, span tracking. |
| `toml` | `vest-config` | TOML config parsing | For vest.toml. |
| `uuid` | `vest-core` | Unique IDs | UUIDv4 for every entity (scan IDs, finding IDs, target IDs). |
| `chrono` | `vest-core`, `vest-storage` | Timestamps | Scan times, finding discovery times. |
| `backon` | `vest-providers` | Retry/backoff | Exponential backoff for LLM API calls. |
| `qdrant-client` | `vest-agent` | Vector store for cross-session memory | Purpose-built vector DB. Semantic search across past findings. Runs locally. |
| `honggfuzz` + `arbitrary` | `vest-scanner::binary` | Fuzzing | Coverage-guided fuzzing for binary targets. |

### Crates we intentionally avoided

| Crate | Why Skipped |
|-------|-------------|
| `memflow` | Too complex for our needs. `read-process-memory` handles 95% of use cases. We'll add custom FFI for write operations. |
| `langchain-rust` | Dormant since Oct 2024. `rig-core` is more actively maintained. |
| `thirtyfour` | WebDriver/Selenium protocol -- useful for cross-browser, but CDP (chromiumoxide) gives us deeper access to DevTools. We can add thirtyfour later if Firefox support is needed. |
| `pelite` | PE-only. `goblin` handles PE + ELF + Mach-O in one API. Add pelite later if we need PE-specific features. |

---

## 3. LLM Provider Abstraction

### Design

A single `LlmProvider` trait that every backend implements. Configuration-driven -- you pick which provider to use in `vest.toml`.

```rust
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Send a chat completion request. Returns the model's response text.
    async fn chat(
        &self,
        messages: &[ChatMessage],
        tools: Option<&[ToolDefinition]>,
        config: &GenerationConfig,
    ) -> Result<ChatResponse, ProviderError>;

    /// Stream a chat completion. Returns a stream of response chunks.
    async fn chat_stream(
        &self,
        messages: &[ChatMessage],
        tools: Option<&[ToolDefinition]>,
        config: &GenerationConfig,
    ) -> Result<BoxStream<ChatChunk>, ProviderError>;

    /// List available models for this provider.
    async fn list_models(&self) -> Result<Vec<ModelInfo>, ProviderError>;

    /// Check if a specific model is available and ready.
    async fn check_model(&self, model: &str) -> Result<ModelStatus, ProviderError>;

    /// Generate embeddings for RAG/vector storage.
    async fn embed(&self, texts: Vec<String>, model: &str) -> Result<Vec<Vec<f32>>, ProviderError>;
}
```

### Provider implementations

| Provider | API Shape | Base URL | Notes |
|----------|-----------|----------|-------|
| OpenAI | OpenAI-native | `https://api.openai.com/v1` | GPT-4o, o4-mini, o3 |
| Anthropic | Anthropic-native | `https://api.anthropic.com/v1` | Claude 3.5/4 Sonnet/Opus. Different message format. |
| DeepSeek | OpenAI-compatible | `https://api.deepseek.com/v1` | DeepSeek V3, R1 |
| Google | Gemini-native | `https://generativelanguage.googleapis.com/v1beta` | Gemini 2.5 Pro/Flash |
| Ollama | OpenAI-compatible | `http://localhost:11434/v1` | Any model pulled into Ollama |
| Groq | OpenAI-compatible | `https://api.groq.com/openai/v1` | Fast inference for open models |
| OpenRouter | OpenAI-compatible | `https://openrouter.ai/api/v1` | Catch-all for 200+ models |

### Model selection logic

```rust
// From vest.toml:
// [providers.default]
// provider = "ollama"
// model = "glm-5.2"

// Override per scan:
// vest scan --provider deepseek --model deepseek-v3 target.exe

// Per-agent override (different models for different tasks):
// [agent.memory]
// provider = "openai"
// model = "gpt-4o"    # expensive model for complex memory analysis
//
// [agent.recon]
// provider = "groq"
// model = "llama-3.3-70b"  # fast/cheap for recon tasks
```

### Fallback chain

If the primary provider fails (rate limited, timeout, model not found), try the next one:

```toml
[providers.fallback]
chain = ["deepseek", "groq", "ollama"]  # try in order
strategy = "next_on_failure"             # or "next_on_rate_limit"
```

---

## 4. Agent Orchestration System

### Architecture

The orchestrator reads scan configuration and selects which agent pattern to use:

```
                    ┌──────────────────────────┐
                    │     Orchestrator          │
                    │  (reads vest.toml scan    │
                    │   config, selects pattern)│
                    └───────────┬──────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            │                   │                   │
    ┌───────▼──────┐   ┌───────▼──────┐   ┌───────▼──────┐
    │   Pipeline   │   │    Swarm     │   │  Tool-Use    │
    │   Pattern    │   │   Pattern    │   │   Pattern    │
    └──────────────┘   └──────────────┘   └──────────────┘
            │                   │                   │
            └───────────────────┼───────────────────┘
                                │
                    ┌───────────▼──────────┐
                    │   Agent Instance     │
                    │   (LLM + Tools +     │
                    │    Context + Memory) │
                    └──────────────────────┘
```

### Pattern 1: Pipeline (Sequential)

Used for structured, comprehensive scans. Each phase gates on the previous.

```
Phase 0: Reconnaissance
  └── Discover attack surface (open ports, loaded modules, API endpoints, file formats)
       ↓
Phase 1: Surface Analysis
  └── For each attack surface, identify potential vulnerability classes
       ↓
Phase 2: Vulnerability Hunting
  └── For each surface+vuln class pair, attempt detection with specialized tools
       ↓
Phase 3: Exploitation (optional, config-controlled)
  └── For each confirmed vulnerability, attempt PoC exploitation
       ↓
Phase 4: Validation
  └── Skeptical review of all findings. Second-pass agent challenges each one.
       ↓
Phase 5: Reporting
  └── Compile findings, rank by severity, generate output
```

**Config:**
```toml
[scan]
mode = "pipeline"
phases = ["recon", "analyze", "hunt", "validate", "report"]
# phases = ["recon", "analyze", "hunt", "exploit", "validate", "report"]  # with exploit
```

### Pattern 2: Swarm (Parallel)

Multiple independent agents run simultaneously against the same target, each focused on a different vulnerability class.

```
Target
├── Agent 1: Memory corruption hunter (buffer overflow, UAF, double free)
├── Agent 2: Web vulnerability hunter (XSS, SQLi, CSRF, SSRF, IDOR)
├── Agent 3: Binary vulnerability hunter (format string, ROP, ASLR bypass)
├── Agent 4: Network protocol hunter (packet fuzzing, replay, injection)
├── Agent 5: File format hunter (save file parsing, asset loading)
├── Agent 6: Browser game hunter (WebSocket manipulation, WebGL inspection)
└── Agent 7: Auth & logic hunter (auth bypass, race conditions, IDOR)

  ↓ (agents run in parallel)
  ↓

Merger: deduplicate findings, cross-validate, rank by severity
  ↓
Skeptical validator: second-pass agent reviews all findings
  ↓
Report
```

**Config:**
```toml
[scan]
mode = "swarm"
agents = ["memory", "web", "binary", "network", "files", "browser", "auth"]
parallelism = 7           # how many to run concurrently
diversity_seeds = 3        # Pass@K: run each agent K times with different prompts
merge_strategy = "voting"  # "voting" = finding confirmed if ≥2 agents find it
                           # "union"   = all findings kept, deduplicated
                           # "strict"  = only findings confirmed by ALL agents
```

### Pattern 3: Tool-Use (Single Agent Loop)

A single agent with access to all tools. The LLM decides what to do at each step. Best for quick scans and interactive use.

```
Loop:
  1. Agent receives observation (target state, previous tool results)
  2. Agent decides which tool to call (or reports completion)
  3. Tool executes (subject to safety gates)
  4. Result fed back to agent
  5. Repeat until agent reports completion or max iterations reached

Tools available:
  - read_memory(pid, address, size)
  - write_memory(pid, address, data)       [approval-gated]
  - search_memory_pattern(pid, pattern)
  - disassemble(pid, address, length)
  - http_request(url, method, headers, body)
  - navigate_browser(url)
  - evaluate_js(code)
  - intercept_websocket(url, filter)
  - fuzz_input(target, input_type, strategy)
  - execute_command(cmd)                   [approval-gated]
  - report_finding(title, severity, description, evidence)
```

**Config:**
```toml
[scan]
mode = "tool-use"
max_iterations = 200
max_tokens_per_iteration = 16000
```

### Pattern 4: Hierarchical (Parent/Child)

A parent agent plans the overall strategy and spawns child agents for subtasks.

```
Parent Agent (planner)
  │
  ├── Child 1: "Scan the login flow for auth bypass"
  ├── Child 2: "Analyze the game's protobuf protocol for injection points"
  ├── Child 3: "Memory scan the physics engine for integer overflow"
  └── Child 4: "Crawl the game's admin API, test for IDOR"
       │
       └── (each child runs its own tool-use loop)
            │
            └── Results bubble up to parent for aggregation
```

**Config:**
```toml
[scan]
mode = "hierarchical"
max_depth = 3         # how deep children can spawn grandchildren
max_children = 10     # max concurrent child agents
```

---

## 5. Scanner Modules

### 5.1 Memory Scanner (`vest-scanner::memory`)

**Purpose:** Attach to a running process, read/write memory, find patterns, hook functions.

**Platform support:**

| Platform | Read | Write | Hook | Notes |
|----------|------|-------|------|-------|
| Windows | ReadProcessMemory via `read-process-memory` | WriteProcessMemory via custom FFI | Frida, DLL injection, ETW | Requires SeDebugPrivilege (admin) |
| Linux | ptrace + /proc/pid/mem via `read-process-memory` | ptrace POKEDATA via custom FFI | Frida, LD_PRELOAD | Requires ptrace scope config |
| macOS | mach_vm_read via `read-process-memory` | mach_vm_write via custom FFI | Frida, DYLD_INSERT_LIBRARIES | Requires SIP disabled or task_for_pid entitlement |

**Key capabilities:**
- **Pattern scanning:** AOB (Array of Bytes) scanning with SIMD acceleration (SSE4.2/AVX2). Scan gigabytes/second for known vulnerability signatures.
- **Value scanning:** Exact value, unknown initial value, increased/decreased, changed/unchanged. Incremental scanning for game value finding.
- **Pointer scanning:** Find pointer chains to a given address. Critical for game hacking.
- **Structure dissection:** Data structure mapping. Find vtables, function pointers, critical structs.
- **Hook detection:** Detect inline hooks, IAT hooks, VMT hooks that might indicate anti-cheat or existing exploits.
- **Integrity checking:** Compare memory regions against known-good values (anti-tamper detection).

**LLM Integration:**
The LLM agent receives a summary of the memory layout and can request specific scans:
```
Agent: "Find all RWX memory regions in the target process"
Tool:  Returns list of RWX regions with sizes and module names
Agent: "Those are suspicious. Scan the largest RWX region for shellcode patterns"
Tool:  Returns matches with offsets
Agent: "Disassemble the code at offset 0x1400 in that region"
Tool:  Returns disassembly
Agent: "This looks like a code cave with network socket code. Report as finding."
```

### 5.2 Binary Scanner (`vest-scanner::binary`)

**Purpose:** Analyze binaries at rest. ELF, PE, Mach-O. Find vulnerabilities without running the target.

**Key capabilities:**
- **Sink catalog matching:** Deterministic grep-based scan for dangerous functions. Sink catalogs are plaintext files organized by language:
  ```
  sinks/c.txt:       strcpy, strcat, sprintf, gets, system, popen, alloca, memcpy(dynamic size)
  sinks/cpp.txt:     std::cin, reinterpret_cast, dynamic_cast, std::vector::operator[]
  sinks/rust.txt:    unsafe { }, std::mem::transmute, ptr::read, ptr::write, std::slice::from_raw_parts
  sinks/csharp.txt:  Marshal.Copy, unsafe { }, fixed statement, DllImport
  sinks/python.txt:  eval, exec, pickle.loads, yaml.load, subprocess.call(shell=True)
  sinks/js.txt:      eval(), Function(), innerHTML, document.write, vm.runInNewContext
  ```
- **Security mitigation checking:** Verify ASLR (PIE), NX/DEP, stack canaries, SafeSEH, CFG/RFG, CET. Each binary gets a "mitigation score."
- **ROP gadget finding:** Use capstone/iced-x86 to find gadgets ending in RET. Build gadget chains. Score exploitability.
- **Import/export analysis:** What dangerous functions are imported? What functions does the binary expose?
- **Version fingerprinting:** Identify known-vulnerable library versions embedded in the binary.
- **Fuzzing harness generation:** Given a binary with a known API surface, generate a honggfuzz harness to fuzz it.

### 5.3 Web Scanner (`vest-scanner::web`)

**Purpose:** Scan web applications and APIs for OWASP Top 10 vulnerabilities.

**Key capabilities:**
- **Active crawling:** Spider the target, discover endpoints, forms, API routes.
- **Passive crawling:** Analyze sitemap.xml, robots.txt, JS source maps, Swagger/OpenAPI specs.
- **Vulnerability detection:**
  - XSS (reflected, stored, DOM-based)
  - SQL injection (error-based, blind, time-based)
  - Command injection, SSTI, XXE
  - SSRF, path traversal, LFI/RFI
  - IDOR, auth bypass, JWT attacks
  - CORS misconfiguration, clickjacking
  - Cache poisoning, request smuggling
- **Nuclei integration:** Run Nuclei templates as a subprocess. Parse results. Feed found vulnerabilities to the LLM agent for deeper analysis.
- **API fuzzing:** Given an OpenAPI schema, fuzz all parameters with malicious values. Look for unexpected responses.

### 5.4 Browser Scanner (`vest-scanner::browser`)

**Purpose:** Control a real browser via CDP to test web games, WebSocket apps, and JavaScript-heavy targets.

**Key capabilities:**
- **CDP control:** Full access to Chrome DevTools Protocol domains:
  - `Network`: Intercept requests/responses. Modify headers. Capture WebSocket frames.
  - `Runtime`: Evaluate arbitrary JS. Inspect objects. Monitor console.
  - `Debugger`: Set breakpoints. Step through code. Inspect WASM.
  - `Security`: Check certificate chain, security state.
  - `DOM`: Query, modify, snapshot DOM.
  - `Storage`: Read/write LocalStorage, SessionStorage, IndexedDB, cookies.
  - `Performance`: Profile JS execution, find bottlenecks (for DoS vulns).
- **WebSocket interception:** Monitor and modify WebSocket messages in real-time. Fuzz game protocol messages.
- **WASM inspection:** Dump WASM modules. Disassemble to WAT. Find memory corruption patterns.
- **Canvas/WebGL inspection:** Screenshot canvas. Compare frames for rendering anomalies. Detect wallhack-like behaviors.
- **Auth flow testing:** Automate login, OAuth, multi-step auth. Test with different roles/privileges.
- **Client-side storage manipulation:** Modify save games in IndexedDB. Tamper with LocalStorage tokens. Test for client-side trust.

### 5.5 Network Scanner (`vest-scanner::network`)

**Purpose:** Capture and analyze network traffic. Fuzz custom protocols. Find network-layer vulnerabilities.

**Key capabilities:**
- **Packet capture:** Live capture on specified interface. Filter by target process/port.
- **Protocol reverse engineering:** Given a packet capture, use LLM to infer protocol structure (fields, types, length prefixes, checksums).
- **Protocol fuzzing:** Generate mutated packets. Replay against target. Monitor for crashes.
- **SSL/TLS inspection:** MITM proxy for HTTPS traffic. Certificate pinning bypass testing.

### 5.6 File Scanner (`vest-scanner::files`)

**Purpose:** Analyze static files for vulnerabilities. Game saves, config files, asset bundles.

**Key capabilities:**
- **Format detection:** Identify file format (zip, unity3d bundle, unreal pak, protobuf, leveldb, etc.)
- **Save file analysis:** Decompress. Parse structure. Find writable fields. Test for RCE via malformed saves.
- **Asset analysis:** Extract assets from game bundles. Check for hardcoded secrets, API keys, debug symbols.

---

## 6. Safety & Boundaries

### Philosophy

The harness itself has no hardcoded safety limits. Every boundary is configurable, and the user can disable any of them. The default configuration is conservative.

### Configurable Boundaries

```toml
[safety]
# What requires human approval
write_approval = true       # Approve memory writes, process injection, file modification
exploit_approval = true     # Approve before attempting exploitation
network_write_approval = true  # Approve before sending potentially destructive packets

# Rate limiting (protect targets from being DoSed)
rate_limit_enabled = true
rate_limit_requests_per_second = 10   # max HTTP requests/sec to a target
rate_limit_burst = 30                 # burst allowance
rate_limit_per_target = true          # per-target or global

# Scan scope
allowed_targets = []                  # empty = any target
blocked_targets = []                  # never scan these
allowed_networks = ["192.168.0.0/16", "10.0.0.0/8"]  # only scan private networks
# allowed_networks = []               # empty = any network (including internet)

# Execution
sandbox_enabled = true               # run exploits in Docker/VM
sandbox_image = "vest-sandbox:latest"
max_scan_duration_seconds = 3600     # kill scan after 1 hour (0 = unlimited)
max_concurrent_exploits = 1          # never run more than 1 exploit at a time
```

### Approval Workflow

When an action requires approval (e.g., memory write, exploit launch), the CLI:

```
╭─────────────────── APPROVAL REQUIRED ───────────────────╮
│ Action: Memory Write                                     │
│ Target: game.exe (PID 12345)                             │
│ Address: 0x7FF8A4B30000                                 │
│ Data: FF 00 A3 2C (4 bytes)                              │
│ Reason: Change player health value to test integrity     │
│ Risk: LOW — only modifies a game value, not code         │
│                                                          │
│ [A]pprove  [D]eny  [A]pprove All  [D]eny All  [I]nspect │
╰──────────────────────────────────────────────────────────╯
```

The user can also pre-approve via CLI flags:
```bash
vest scan --approve-writes --approve-exploits target.exe
```

### User-Controlled Rate Limiting

Variable rate limiting that the user controls:

```bash
# Aggressive: 50 req/s, no burst limit
vest scan --rate 50 --burst 0 target.com

# Stealth: 1 req/s, max 5 burst
vest scan --rate 1 --burst 5 target.com

# Unlimited: disable rate limiting entirely
vest scan --no-rate-limit target.com
```

Rate limiting applies to:
- HTTP requests (web scanner)
- Network packets (network scanner)
- CDP commands (browser scanner)
- Memory read/write operations (memory scanner)
- LLM API calls (across all providers)

---

## 7. Storage Schema

### SQLite with JSON Columns + Indexed Fields

```sql
-- Targets: what we're scanning
CREATE TABLE targets (
    id          TEXT PRIMARY KEY,        -- UUIDv4
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,           -- 'process', 'binary', 'web', 'network', 'browser', 'file'
    path        TEXT,                    -- file path for binaries/files
    url         TEXT,                    -- URL for web/browser targets
    pid         INTEGER,                -- PID for process targets
    host        TEXT,                    -- host:port for network targets
    metadata    TEXT NOT NULL DEFAULT '{}',  -- JSON: platform, architecture, notes, tags
    created_at  TEXT NOT NULL,           -- ISO 8601
    updated_at  TEXT NOT NULL
);

CREATE INDEX idx_targets_type ON targets(type);
CREATE INDEX idx_targets_name ON targets(name);

-- Scans: individual scan sessions
CREATE TABLE scans (
    id              TEXT PRIMARY KEY,
    target_id       TEXT NOT NULL REFERENCES targets(id),
    mode            TEXT NOT NULL,       -- 'pipeline', 'swarm', 'tool-use', 'hierarchical'
    config          TEXT NOT NULL,        -- JSON: full scan configuration snapshot
    status          TEXT NOT NULL,        -- 'pending', 'running', 'paused', 'completed', 'failed', 'cancelled'
    started_at      TEXT,
    completed_at    TEXT,
    duration_ms     INTEGER,
    agent_model     TEXT,                -- which LLM model was used
    total_findings  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    info_count      INTEGER DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}',  -- JSON
    created_at      TEXT NOT NULL
);

CREATE INDEX idx_scans_target ON scans(target_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at);

-- Findings: individual vulnerabilities found
CREATE TABLE findings (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    target_id       TEXT NOT NULL REFERENCES targets(id),
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,       -- full LLM-generated description
    vulnerability_class TEXT NOT NULL,   -- 'buffer_overflow', 'xss', 'sqli', 'uaf', etc.
    severity        TEXT NOT NULL,       -- 'critical', 'high', 'medium', 'low', 'info'
    confidence      REAL NOT NULL,       -- 0.0 to 1.0 (LLM confidence score)
    status          TEXT NOT NULL DEFAULT 'open',  -- 'open', 'confirmed', 'false_positive', 'fixed', 'wont_fix'
    cvss_score      REAL,                -- CVSS 3.1 score if applicable
    cve_id          TEXT,                -- CVE reference if known
    cwe_id          TEXT,                -- CWE reference (e.g., 'CWE-119')
    evidence        TEXT NOT NULL,       -- JSON: tool outputs, screenshots, memory dumps, requests
    poc             TEXT,                -- Proof of concept code/steps
    remediation     TEXT,                -- Suggested fix
    location        TEXT NOT NULL,       -- JSON: file/URL/address where vulnerability was found
    false_positive_history TEXT,         -- JSON: if previously marked FP, store context
    tags            TEXT NOT NULL DEFAULT '[]',  -- JSON array
    metadata        TEXT NOT NULL DEFAULT '{}',
    discovered_at   TEXT NOT NULL,
    updated_at      TEXT NOT NULL,

    -- Indexed JSON fields extracted for querying (extracted from evidence/location JSON)
    file_path       TEXT GENERATED ALWAYS AS (json_extract(location, '$.file')) VIRTUAL,
    url             TEXT GENERATED ALWAYS AS (json_extract(location, '$.url')) VIRTUAL,
    memory_address  TEXT GENERATED ALWAYS AS (json_extract(location, '$.address')) VIRTUAL
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_target ON findings(target_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_vuln_class ON findings(vulnerability_class);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_confidence ON findings(confidence);
CREATE INDEX idx_findings_cwe ON findings(cwe_id);

-- Artifacts: scan evidence files
CREATE TABLE artifacts (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    finding_id      TEXT REFERENCES findings(id),  -- nullable, may not be attached to finding yet
    type            TEXT NOT NULL,       -- 'screenshot', 'memory_dump', 'pcap', 'log', 'request', 'response', 'payload'
    mime_type       TEXT,
    filename        TEXT NOT NULL,
    size_bytes      INTEGER,
    content         BLOB,                -- actual file data (for small files)
    content_path    TEXT,                -- path to file on disk (for large files)
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL
);

CREATE INDEX idx_artifacts_scan ON artifacts(scan_id);
CREATE INDEX idx_artifacts_finding ON artifacts(finding_id);
CREATE INDEX idx_artifacts_type ON artifacts(type);

-- Cross-scan memory: persistent vulnerability patterns and false positive tracking
CREATE TABLE scan_memory (
    id              TEXT PRIMARY KEY,
    pattern_hash    TEXT NOT NULL,       -- hash of the vulnerability pattern
    pattern_type    TEXT NOT NULL,       -- 'false_positive', 'confirmed_vuln', 'useful_tool_sequence'
    target_hash     TEXT,                -- hash of target (for target-specific memory)
    description     TEXT NOT NULL,       -- what was learned
    evidence        TEXT NOT NULL,       -- JSON: what led to this conclusion
    confidence      REAL NOT NULL,       -- 0.0 to 1.0
    occurrences     INTEGER DEFAULT 1,   -- how many times this pattern was seen
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_memory_pattern ON scan_memory(pattern_hash, pattern_type, COALESCE(target_hash, ''));

-- Agent action log: full audit trail
CREATE TABLE agent_actions (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    sequence        INTEGER NOT NULL,    -- ordering within scan
    agent_role      TEXT NOT NULL,       -- which agent performed the action
    action_type     TEXT NOT NULL,       -- 'tool_call', 'llm_response', 'approval_request', 'approval_response', 'error'
    action_data     TEXT NOT NULL,       -- JSON: full action details
    timestamp       TEXT NOT NULL
);

CREATE INDEX idx_actions_scan ON agent_actions(scan_id);
CREATE INDEX idx_actions_sequence ON agent_actions(scan_id, sequence);
```

### Why Hybrid (JSON + Indexed Columns)

The `json_extract` virtual columns in SQLite let us:
1. Store complex nested data (evidence, location, metadata) as JSON -- flexible, no schema changes needed when we add new vulnerability types.
2. Index and query by important fields (severity, vulnerability class, status, CWE) -- fast filtering and aggregations.
3. Full-text search on `description` and `title` via FTS5 if needed later.
4. Port findings between installations by exporting the JSON.

---

## 8. Configuration Format

### `vest.toml` — Complete Configuration

```toml
# =========================================================================
# VEST Configuration
# =========================================================================

[general]
workspace_dir = "~/.vest"              # where databases, artifacts, configs live
auto_update_sinks = true               # pull latest sink catalogs from repo
log_level = "info"                     # trace, debug, info, warn, error

# =========================================================================
# LLM Providers
# =========================================================================

[providers.default]
provider = "openrouter"                # default provider for all agent work
model = "anthropic/claude-sonnet-4"

[providers.openai]
api_key_env = "OPENAI_API_KEY"         # reads from this env var
api_base = "https://api.openai.com/v1"
default_model = "gpt-4o"
organization_id = ""                   # optional
timeout_seconds = 120
max_retries = 3
retry_delay_ms = 1000

[providers.anthropic]
api_key_env = "ANTHROPIC_API_KEY"
default_model = "claude-sonnet-4-20250514"
max_tokens_default = 16384
thinking_enabled = true                # Claude extended thinking

[providers.deepseek]
api_key_env = "DEEPSEEK_API_KEY"
api_base = "https://api.deepseek.com/v1"
default_model = "deepseek-v3"

[providers.google]
api_key_env = "GOOGLE_API_KEY"
default_model = "gemini-2.5-pro"

[providers.ollama]
api_base = "http://localhost:11434/v1"
default_model = "glm-5.2"
# no api_key needed for local

[providers.groq]
api_key_env = "GROQ_API_KEY"
default_model = "llama-3.3-70b-versatile"

[providers.openrouter]
api_key_env = "OPENROUTER_API_KEY"
default_model = "openai/gpt-4o"

# =========================================================================
# Provider fallback chain
# =========================================================================

[providers.fallback]
enabled = true
chain = ["openrouter", "deepseek", "groq", "ollama"]
strategy = "next_on_failure"
# strategy options: "next_on_failure", "next_on_rate_limit", "try_all_parallel"

# =========================================================================
# Agent Configuration
# =========================================================================

[agent]
default_pattern = "pipeline"           # default scan pattern
max_concurrent_agents = 8              # for swarm/hierarchical modes
max_llm_iterations = 200               # max tool-use loop iterations
token_budget_per_scan = 1_000_000      # max tokens used across all agents in a scan
thinking_enabled = false               # extended thinking (Anthropic only)

# Per-agent role overrides (use different models for different tasks)
[agent.recon]
model = "groq"                         # cheap/fast model for recon
temperature = 0.1

[agent.hunter]
model = "openrouter"                   # smart model for vulnerability hunting
model_override = "anthropic/claude-sonnet-4"
temperature = 0.3

[agent.validator]
model = "deepseek"                     # different provider for validation
temperature = 0.0                      # deterministic for consistent validation

[agent.reporter]
model = "groq"                         # cheap model for report generation
temperature = 0.1

# =========================================================================
# Scanner Configuration
# =========================================================================

[scanner.memory]
enabled = true
max_memory_per_scan_mb = 4096          # max memory to scan per target
pattern_scan_acceleration = true        # use SIMD for pattern scanning
suspicious_regions = [                 # memory regions that are automatically flagged
    "RWX",                              # read-write-execute (suspicious)
    "PAGE_EXECUTE_READWRITE",           # Windows equivalent
]
hook_detection = true                  # detect inline/IAT/VMT hooks

[scanner.binary]
enabled = true
sink_catalogs = [                      # which sink catalogs to use
    "sinks/c.txt",
    "sinks/cpp.txt",
    "sinks/rust.txt",
]
disassembler = "capstone"              # or "iced-x86" for x86-only speed
check_mitigations = true               # verify ASLR, NX, canaries, etc.
find_rop_gadgets = false               # computationally expensive

[scanner.web]
enabled = true
crawl_depth = 10
crawl_max_urls = 10000
respect_robots_txt = true
user_agent = "VEST/0.1 Vulnerability Scanner"
nuclei_enabled = true
nuclei_severity = ["critical", "high", "medium"]  # which nuclei templates to run
nuclei_timeout = 300                   # max seconds for nuclei scan

[scanner.browser]
enabled = true
browser_path = ""                      # auto-detect Chrome/Chromium
headless = true
viewport_width = 1920
viewport_height = 1080
websocket_intercept = true
local_storage_inspect = true
indexeddb_inspect = true
wasm_inspect = true

[scanner.network]
enabled = true
interface = ""                         # auto-detect or specify
capture_filter = ""                    # pcap filter expression
packet_capture_max_mb = 500
protocol_analysis_llm = true           # use LLM to reverse-engineer protocols

[scanner.files]
enabled = true
max_file_size_mb = 500
extract_archives = true
fuzz_file_formats = false              # expensive

# =========================================================================
# Safety Boundaries
# =========================================================================

[safety]
write_approval = true
exploit_approval = true
network_write_approval = true
rate_limit_enabled = true
rate_limit_requests_per_second = 10
rate_limit_burst = 30
sandbox_enabled = true
sandbox_image = "vest-sandbox:latest"
max_scan_duration_seconds = 3600
max_concurrent_exploits = 1
allowed_targets = []
blocked_targets = []
allowed_networks = []

# =========================================================================
# Scan Profiles (reusable scan configurations)
# =========================================================================

[profiles.quick]
description = "Quick scan — 5 minute surface scan"
pattern = "tool-use"
max_llm_iterations = 20
token_budget_per_scan = 100_000
scanners = ["web", "binary"]

[profiles.deep]
description = "Deep scan — comprehensive multi-hour analysis"
pattern = "pipeline"
phases = ["recon", "analyze", "hunt", "validate", "report"]
token_budget_per_scan = 5_000_000
scanners = ["memory", "binary", "web", "network", "files", "browser"]

[profiles.game]
description = "Game-focused scan — memory + network + files"
pattern = "swarm"
agents = ["memory", "network", "files", "browser"]
token_budget_per_scan = 3_000_000

[profiles.bug_bounty]
description = "Bug bounty submission scan — full with PoC"
pattern = "pipeline"
phases = ["recon", "analyze", "hunt", "exploit", "validate", "report"]
token_budget_per_scan = 10_000_000
safety = { write_approval = false, exploit_approval = false }  # full auto!
scanners = ["web", "binary", "network"]
```

---

## 9. CLI Design

### Command Structure

```
vest
├── vest scan <target>              # Run a vulnerability scan
│   ├── --profile <name>           # Use a saved profile
│   ├── --mode <mode>              # Override scan mode
│   ├── --provider <provider>      # Override LLM provider
│   ├── --model <model>            # Override LLM model
│   ├── --scanner <scanner>        # Limit to specific scanners
│   ├── --output <path>            # Output report path
│   ├── --format <format>          # json, terminal, markdown
│   ├── --approve-writes           # Pre-approve all write operations
│   ├── --approve-exploits         # Pre-approve all exploit attempts
│   ├── --no-approval              # Completely disable approval gates
│   ├── --rate <n>                 # Override rate limit
│   ├── --no-rate-limit            # Disable rate limiting
│   ├── --timeout <seconds>        # Max scan duration
│   └── --dry-run                  # Plan the scan, don't execute
│
├── vest config                     # Configuration management
│   ├── vest config init            # Create vest.toml from template
│   ├── vest config show            # Display current configuration
│   ├── vest config validate        # Validate configuration
│   ├── vest config path            # Show config file path
│   └── vest config set <key> <value>  # Set a config value
│
├── vest providers                  # LLM provider management
│   ├── vest providers list         # List configured providers
│   ├── vest providers test         # Test all configured providers
│   ├── vest providers models       # List available models for a provider
│   ├── vest providers pull <model> # Pull a model into Ollama
│   └── vest providers status       # Check provider health
│
├── vest targets                    # Target management
│   ├── vest targets list           # List previously scanned targets
│   ├── vest targets show <id>      # Show target details
│   ├── vest targets add <target>   # Add a target to the database
│   └── vest targets remove <id>    # Remove a target
│
├── vest findings                   # Finding management
│   ├── vest findings list          # List findings (filterable)
│   ├── vest findings show <id>     # Show finding details with evidence
│   ├── vest findings validate <id> # Manually re-validate a finding
│   ├── vest findings export <id>   # Export finding as bug bounty submission
│   └── vest findings stats         # Statistics dashboard
│
├── vest report                     # Report generation
│   ├── vest report generate <scan> # Generate report for a scan
│   ├── vest report summary         # Summary of all scans
│   └── vest report compare <s1> <s2>  # Compare two scans
│
├── vest tools                      # External tool management
│   ├── vest tools install <tool>   # Install external tool (nuclei, frida, etc.)
│   ├── vest tools update           # Update all external tools
│   └── vest tools list             # List installed tools and versions
│
├── vest sandbox                    # Docker sandbox management
│   ├── vest sandbox build          # Build sandbox Docker image
│   ├── vest sandbox start          # Start sandbox container
│   └── vest sandbox clean          # Clean up sandbox containers
│
└── vest completions <shell>        # Generate shell completions
```

### Example Usage

```bash
# Initialize
vest config init

# Pull a local model
vest providers pull glm-5.2

# Quick scan of a web app
vest scan https://game.example.com --profile quick

# Deep game scan (memory + network + files)
vest scan --pid 12345 --profile game --output game_scan.json

# Fully autonomous bug bounty run
vest scan target.com --profile bug_bounty --no-approval

# Binary analysis without running
vest scan ./target.exe --scanner binary --format terminal

# Resume a previous scan
vest scan --resume scan_abc123

# Dry run to see what would happen
vest scan target.com --dry-run
```

---

## 10. Reporting

### JSON Report Format

```json
{
  "report": {
    "version": "0.1.0",
    "generated_at": "2026-07-03T12:00:00Z",
    "scan_id": "uuid",
    "target": {
      "id": "uuid",
      "name": "game.exe",
      "type": "process",
      "platform": "windows",
      "metadata": {}
    },
    "scan_config": {
      "mode": "pipeline",
      "duration_ms": 3600000,
      "phases_completed": ["recon", "analyze", "hunt", "exploit", "validate", "report"],
      "token_usage": 450000,
      "cost_estimate_usd": 2.35
    },
    "summary": {
      "total": 15,
      "critical": 2,
      "high": 5,
      "medium": 6,
      "low": 1,
      "info": 1,
      "false_positives": 3
    },
    "findings": [
      {
        "id": "uuid",
        "title": "Buffer Overflow in Network Packet Handler",
        "description": "The game's UDP packet handler at 0x1400A4B00 does not validate...",
        "vulnerability_class": "buffer_overflow",
        "severity": "critical",
        "confidence": 0.92,
        "cvss_score": 9.8,
        "cwe": "CWE-120",
        "location": {
          "module": "game.exe",
          "address": "0x1400A4B00",
          "function": "ProcessIncomingPacket"
        },
        "evidence": {
          "memory_dump": "artifacts/dump_001.bin",
          "disassembly": "...",
          "crash_reproduction": "..."
        },
        "poc": "Send 4096 bytes to port 27015 when game is in lobby. EIP overwritten at offset 1024.",
        "remediation": "Add bounds checking before the memcpy call at 0x1400A4B12. Validate packet length against buffer size."
      }
    ]
  }
}
```

### Terminal Output

```
╭─────────────────────────────────────────────────────────────╮
│                     VEST Scan Report                         │
│  Target: game.exe (PID 12345)                               │
│  Duration: 45m 12s | Mode: pipeline | Model: claude-sonnet-4│
├─────────────────────────────────────────────────────────────┤
│  SUMMARY                                                     │
│  ───────                                                     │
│  Critical:  2   ████████████                                │
│  High:      5   ████████████████████████████████             │
│  Medium:    6   ██████████████████████                       │
│  Low:       1   ██████                                       │
│  Info:      1   ██████                                       │
│                                                              │
│  False Positives Filtered: 3                                 │
│  Total Token Cost: ~$2.35                                    │
├─────────────────────────────────────────────────────────────┤
│  TOP FINDINGS                                                │
│  ────────────                                                │
│  [CRITICAL] CVSS 9.8 | Buffer Overflow (W)                   │
│    Network Packet Handler — game.exe+0xA4B00                 │
│    Remotely exploitable via UDP port 27015                   │
│                                                              │
│  [CRITICAL] CVSS 8.6 | Auth Bypass (W)                       │
│    Login endpoint — /api/auth/login                          │
│    JWT algorithm confusion: 'none' accepted                  │
│                                                              │
│  [HIGH] CVSS 7.5 | Use-After-Free (M)                        │
│    Physics engine object lifecycle — physics.dll+0x2300      │
│    Triggered by rapid entity spawn/despawn                   │
│                                                              │
│  [HIGH] CVSS 7.2 | XSS (W)                                   │
│    Chat message rendering — /api/chat/send                   │
│    Stored XSS in player name field                           │
╰─────────────────────────────────────────────────────────────╯
```

---

## 11. Cross-Session Memory

### How It Works

Every scan contributes to a shared knowledge base. The vector store (Qdrant) stores embeddings of:
- Vulnerability patterns found (so we can detect similar patterns faster next time)
- False positive patterns (so we don't re-discover the same FPs)
- Successful tool sequences (so the agent learns which tool combos work)

### False Positive Memory

When a finding is marked as FP, we store:
```json
{
  "pattern_hash": "sha256 of the vulnerability signature",
  "target_hash": "sha256 of target binary first 64KB",
  "reason": "Function is behind an auth guard we didn't detect on first pass",
  "context": "The API endpoint /admin/debug appears unprotected but actually requires internal JWT signed by a key only accessible server-side"
}
```

Next time a scan hits the same pattern on the same target, the agent skips it (or flags it with much lower priority).

### Pattern Library

As VEST scans more targets, it accumulates a library of:
- Vulnerability signatures (byte patterns, API patterns, code patterns)
- Exploitation techniques (which payloads work against which targets)
- False positive heuristics (patterns that LOOK vulnerable but aren't)

This makes each subsequent scan faster and more accurate.

---

## 12. Implementation Phases

### Phase 0: Scaffolding (Week 1-2)
- Set up workspace with all crates
- Core types and traits (`vest-core`)
- Configuration system (`vest-config`)
- SQLite schema and migrations (`vest-storage`)
- CLI skeleton with clap (`vest-cli`)
- No actual scanning yet -- just the framework

### Phase 1: LLM Integration (Week 3-4)
- `LlmProvider` trait and all implementations (`vest-providers`)
- Ollama integration (test with local models)
- OpenAI, Anthropic, DeepSeek, Google, Groq
- Provider fallback chain
- Provider list/models/test CLI commands

### Phase 2: Agent Engine (Week 5-8)
- Agent base struct with context management (`vest-agent`)
- Tool-use loop pattern
- Tool definition registry (connect scanner tools to LLM tool definitions)
- Pipeline pattern
- Swarm pattern
- Hierarchical pattern
- Safety enforcement (approval gates, rate limiting)
- Cross-session memory (vector store integration)

### Phase 3: Binary Scanner (Week 9-10)
- Binary parsing (goblin/object)
- Sink catalog matching
- Security mitigation checking
- Disassembly (capstone/iced-x86)
- ROP gadget finding
- CLI integration

### Phase 4: Web Scanner (Week 11-12)
- HTTP client with proxy support
- Web crawler
- Vulnerability detection (XSS, SQLi, SSTI, SSRF, etc.)
- Nuclei integration
- Payload library

### Phase 5: Browser Scanner (Week 13-14)
- Chrome CDP integration (chromiumoxide)
- WebSocket interception
- WASM inspection
- Storage manipulation
- Web game-specific scanning

### Phase 6: Memory Scanner (Week 15-17)
- Cross-platform process attachment
- Memory reading (read-process-memory)
- Memory writing (custom FFI)
- Pattern scanning (SIMD-accelerated)
- Frida integration for runtime hooking
- Game-specific memory analysis

### Phase 7: Network + File Scanners (Week 18-19)
- Packet capture and analysis
- Protocol reverse engineering (LLM-assisted)
- Protocol fuzzing
- File format analysis
- Save file fuzzing

### Phase 8: Validation & Reporting (Week 20-21)
- Skeptical validation gate
- Report generation (JSON, terminal, markdown)
- Finding management CLI
- Statistics and dashboards

### Phase 9: Polish & Hardening (Week 22-24)
- Integration tests
- Documentation
- Performance optimization
- Platform-specific edge cases
- Bug bounty submission templates

---

## 13. Questions to Resolve

As we build, we'll need to answer:

1. **Memory write FFI:** How much of the Windows/macOS/Linux write primitives do we expose? Just raw bytes, or higher-level operations (modify health value, toggle noclip flag)?

2. **Browser detection:** How does the agent KNOW it's looking at a game? Does it inspect the DOM for game engines (Unity WebGL, Godot HTML5, Phaser, PixiJS)? Does the user have to tell it?

3. **Protocol fuzzing strategy:** For custom game network protocols -- do we use generic fuzzing (bitflip, byte mutation) or do we invest in LLM-assisted protocol reverse engineering?

4. **Docker sandbox:** Should the sandbox be a pre-built image, or should we generate sandboxes dynamically based on target? How do we handle Windows targets if we're sandboxing via Docker?

5. **Plugin system:** Do we want a plugin system for community-built scanners? WASM plugins? Python scripting? This would be post-Phase 9.

6. **Agent prompt engineering:** How do we structure the system prompts for each agent role? What's the format for tool definitions that works across providers with different tool-calling schemas?

7. **Rate limiting architecture:** Token-bucket per target? What happens when rate limit is hit mid-scan -- pause or skip?

8. **Concurrency model:** Within a swarm scan, do agents run as tokio tasks? Separate threads? Separate processes? How do we handle crashes in child agents without killing the parent?

---

## 14. Non-Goals (for now)

- GUI / web dashboard (CLI only for v1)
- Real-time collaboration (single user)
- Mobile game scanning (Android/iOS -- too platform-specific for v1)
- Cloud deployment (local-first)
- Machine learning model training (we USE LLMs, we don't train them)
- Integration with CI/CD pipelines (focused on interactive use)
- Automated bug bounty submission (generate the report, user submits manually)
