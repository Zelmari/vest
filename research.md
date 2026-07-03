# State of the Art: AI-Powered Vulnerability Scanning & Agentic Security
## Comprehensive Research Report for VEST Architecture

---

# 1. AI Agent Frameworks for Security

## 1.1 Tier 1: Major Open-Source Platforms (15k+ stars)

### Shannon by Keygraph (45.4k stars)
- **Type**: Autonomous white-box AI pentester for web apps/APIs
- **Architecture**: Multi-agent workflow — Pre-Reconnaissance (source scan) → Reconnaissance (attack surface) → parallel Vulnerability Analysis agents (Injection, XSS, SSRF, Auth) → Exploitation (PoC validation) → Reporting
- **Key Pattern**: Only reports vulnerabilities with **working proof-of-concept**. Agents run in ephemeral Docker containers. Uses Claude models. TypeScript monorepo.
- **Vuln Coverage**: Injection, XSS, SSRF, Broken Authentication, Broken Authorization, IDOR
- **License**: AGPL-3.0 (community) / Commercial (enterprise)

### Strix (34.4k stars)
- **Type**: Open-source AI pentesting agents with CLI + SaaS platform
- **Architecture**: Multi-agent orchestration — specialized AI agents for recon, exploitation, and post-exploitation. Uses Caido (HTTP interception proxy), Playwright (browser), custom Python sandbox.
- **Key Pattern**: "Graph of Agents" — distributed pentesting with parallel execution across multiple targets. Dynamic coordination where agents share discoveries and chain vulnerabilities.
- **Tool Suite**: Full pentesting toolkit (HTTP proxy, browser exploitation, shell/command execution, custom exploit runtime, recon/OSINT, SAST+DAST)
- **Vuln Coverage**: OWASP Top 10 + NoSQL injection, SSTI, XXE, insecure deserialization, prototype pollution, race conditions, JWT attacks, mass assignment, rate limiting bypass
- **License**: Apache 2.0

### Anthropic Cybersecurity Skills (24.2k stars)
- **Type**: 817 structured cybersecurity skills for AI agents — mapped to MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, D3FEND, NIST AI RMF, MITRE F3
- **Pattern**: Skills are structured knowledge bases loaded by AI agents (Claude Code, Copilot, Codex CLI, Cursor, Gemini CLI) — not an agent itself but the knowledge layer agents use
- **Domains**: 29 security domains covered

### PentAGI (18.1k stars)
- **Type**: Fully autonomous AI multi-agent pen-testing system
- **Architecture**: Orchestrator → Researcher → Developer → Executor with vector store + knowledge graph (Neo4j/Graphiti) + memory systems (long-term, working, episodic)
- **Key Innovation**: Agent supervision system — **Execution Monitoring** (mentor agent auto-invoked when patterns indicate issues) + **Intelligent Task Planning** (planner generates 3-7 actionable steps). Own LLM summarizer for context management.
- **Stack**: Go backend + React frontend + PostgreSQL/pgvector + Neo4j + Grafana/Prometheus + Langfuse
- **Tools**: 20+ professional pentesting tools (nmap, metasploit, sqlmap, etc.), Docker-sandboxed execution
- **License**: MIT

### Nuclei by ProjectDiscovery (29.5k stars)
- **Type**: Template-based vulnerability scanner (YAML DSL), NOT AI-native but foundational
- **Pattern**: ~10000+ community templates for vulnerability detection. Fast, customizable scan engine.
- **Relevance**: The de-facto standard for template-based vuln scanning. Any AI agent should integrate with Nuclei.

## 1.2 Tier 2: Agentic Security-Specific (100–4k stars)

### Claude Bug Bounty / BugHunter (3.8k stars)
- **Type**: AI-powered bug bounty hunting toolkit — terminal-based, works with or without Claude subscription
- **Architecture**: Recon → Hunt → Validate (7-Question Gate) → Report. 9 specialized AI agents (recon-agent, report-writer, validator, web3-auditor, chain-builder, autopilot, recon-ranker, token-auditor, credential-hunter)
- **Key Pattern**: **7-Question Gate** — strict validation kills weak findings before submission. Cross-session hunt memory persists across targets. Autonomous /autopilot full-loop mode.
- **Vuln Coverage**: 20 web2 classes + 10 web3/smart contract classes
- **Free AI Support**: Ollama (local, free), Groq (free tier), DeepSeek (cheap) — no subscription needed
- **License**: MIT

### PentestAgent (2.7k stars)
- **Type**: AI agent framework for black-box security testing
- **Architecture**: Three modes — Assist (single-shot), Agent (autonomous), Crew (multi-agent with Orchestrator spawning specialized workers). Agent self-spawning (spawn_mcp_agent for hierarchical multi-agent).
- **Key Innovation**: **Agent Self-Spawning** — agents can spawn child copies as MCP servers for parallel recon. Conversation history with rewind/fork. Prebuilt attack playbooks.
- **MCP**: Both consumes external MCP servers AND exposes itself as MCP server
- **License**: MIT

### Tachi (79 stars)
- **Type**: Threat modeling + AI-reasoning vulnerability detection harness for Claude Code — STRIDE + AI + MAESTRO
- **Architecture**: 14 detection agents (6 STRIDE + 5 LLM + 3 Agentic) + 7 utility agents. Dispatches agents per component type. 5-phase pipeline: scope → determine threats → countermeasures → assess → report.
- **Key Innovation**: Full OWASP coverage across 5 frameworks (50/50 items). MAESTRO 7-layer taxonomy for agentic AI. Cross-layer attack chain correlation. SARIF output for GitHub Code Scanning. Baseline delta tracking.
- **Output**: threats.md, SARIF, narrative report, attack trees, risk scores, compensating controls, infographics, PDF security report
- **License**: Apache 2.0

### Mythos Research Edition (31 stars)
- **Type**: Outside-in replication of Anthropic's Mythos Preview / Project Glasswing — agentic vulnerability-discovery scaffold
- **Architecture**: 8-phase sink-guided pipeline: Language detection → Sink-guided slicing (ripgrep-based sink catalogs) → File ranking → Build sandbox → Agentic hunt (parallel Claude-Code subagents) → Adversarial self-challenge → Skeptical validation → Aggregate + FP-memory writeback
- **Key Innovation**: **Sink-guided approach** — language-specific sink catalogs (`sinks/python.txt`, `sinks/c-cpp.txt`) identify high-risk code patterns. **Pass@K diversity seeding** (K=2..3) increases bug-discovery breadth. **Cross-session FP memory** prevents re-discovery of false positives.
- **Cost**: $0.30–$1.50 per run (vs $20–$50 for Anthropic's Glasswing)
- **License**: Apache 2.0

### DeepAudit (6.5k stars)
- **Type**: Multi-agent code security audit platform — China's first open-source multi-agent vulnerability discovery system
- **Architecture**: Orchestrator → Recon Agent → Analysis Agent → Verification Agent (sandbox PoC). RAG knowledge base + AST analysis. Docker sandbox for PoC verification with self-correction.
- **Key Pattern**: "Pursue false positives to zero" — if PoC fails, agent self-corrects and retries. RAG-enhanced code understanding. Supports Ollama for data sovereignty.
- **Vuln Coverage**: SQL injection, XSS, command injection, path traversal, SSRF, XXE, insecure deserialization, hardcoded secrets, weak crypto, auth bypass, authz bypass, IDOR
- **Record**: 49 CVE + 6 GHSA discovered across 17 OSS projects
- **License**: AGPL-3.0

### Different by Trail of Bits (6 stars)
- **Type**: Variant-analysis agentic tool (DeepAgents-based)
- **Pattern**: Extracts bug fixes from "inspiration" repo → checks "target" repo for same issues. Uses LLM to call git tools in a loop to inspect commits, diffs, PRs.
- **Relevance**: Cross-codebase variant analysis pattern — critical for game engine/framework vulnerability scanning

## 1.3 Tier 3: Runtime Security & EDR for AI Agents

### Adrian by Secure Agentics (369 stars)
- **Type**: Runtime AI agent security monitoring (AARM-aligned)
- **Pattern**: Analyzes both activity logs AND reasoning traces to detect malicious behavior. Classifiers judge actions against the agent's defined remit. Catches: prompt injection, tool poisoning, data exfiltration, privilege escalation, out-of-remit actions.
- **Architecture**: SDK → Backend → Classifier Model (local Gemma) → Verdict → Control Plane (Alert/Block)

### Clawdstrike by Backbay Labs (283 stars)
- **Type**: AI EDR for developer workstations and autonomous agent fleets
- **Pattern**: Unified policy engine for AI agent tool_calls alongside OS-level events (file_access, process_exec, network_flow). Ed25519-signed causal graph. Fail-closed defaults.
- **Guards**: ForbiddenPathGuard, PathAllowlistGuard, EgressAllowlistGuard, SecretLeakGuard, PatchIntegrityGuard, ShellCommandGuard, McpToolGuard, PromptInjectionGuard, JailbreakGuard

### Cynative (7 stars)
- **Type**: Deep research agent for cloud, code, and runtime — read-only by default
- **Pattern**: Reasons through GitHub, GitLab, AWS, GCP, Azure, Kubernetes as one system. Writes sandboxed JS to fan out calls concurrently. Action-gate authorizes every call against read-only policy.

---

# 2. Game/Memory Vulnerability Tools

## 2.1 Memory Scanners & Debuggers

### Open-Source Cheat Engine Alternatives
- **ReClass.NET** (2.2k stars): .NET memory analysis tool — structure rebuild, remote memory viewer, scanner. C#.
- **PyMemoryEditor** (202 stars): Pure-Python process memory inspector/modifier — works on Windows/macOS/Linux. Search, read, write process memory.
- **mem** (158 stars): C++11 headers for reverse engineering — Boyer-Moore AOB scanner, RTTI, pointer utilities.
- **LightningScanner** (45 stars C++, 28 stars Rust): Lightning-fast memory pattern scanner using SIMD (AVX2, SSE4.2), capable of scanning gigabytes/second.
- **Pattern16** (52 stars): Fastest x86-64 signature matching library.
- **PatternScanner** (20 stars): Compile-time pattern scanning for x86_64 AND arm64.

### Process Debuggers & Instrumentation
- **Frida**: Dynamic instrumentation toolkit — inject scripts into black-box processes, hook functions, trace crypto, monitor APIs. JavaScript-based scripting. The gold standard for runtime analysis.
- **DynamoRIO**: Dynamic binary instrumentation framework — runtime code manipulation, instruction-level tracing, memory tracing.
- **Intel PIN**: Dynamic binary instrumentation for IA-32/x86-64 — instruction-level analysis, memory access tracing, control flow tracking.
- **GDB/LLDB**: Standard debuggers with Python scripting for automated analysis.

### Game-Specific Tools
- **GH Entity List Finder** (96 stars): Scans game processes for entity list addresses — key for game hacking.
- **MemRE** (63 stars): Memory editor with Unreal Engine support.
- **Hakutaku** (249 stars): Android memory editor/scanner (MemoryTools) — for mobile game hacking.

### Defensive Memory Scanners
- **StackSentry** (37 stars): Windows memory scanner for call stack spoofing detection, unbacked shellcode, injected DLLs, in-memory C2 implants.
- **ETWProcessMon2** (320 stars): ETW-based process/thread/memory/image load/TCP monitoring + remote thread injection payload detection.

## 2.2 Key Libraries for Memory Analysis

| Library | Language | Capability |
|---------|----------|------------|
| Frida | JS/Python | Dynamic instrumentation, hooking, tracing |
| DynamoRIO | C/C++ | Runtime code manipulation, instruction tracing |
| PIN | C/C++ | Instruction-level analysis |
| Capstone | C/Python | Disassembly framework (x86, ARM, MIPS, etc.) |
| Unicorn | C/Python | CPU emulator (based on QEMU) |
| LIEF | C++/Python | Parse/modify ELF, PE, Mach-O formats |
| Ghidra | Java | NSA's reverse engineering framework |
| Binary Ninja | C++ | Commercial RE platform with Python API |

---

# 3. Browser Automation for Security Testing

## 3.1 Core Automation Frameworks

### Playwright (Microsoft)
- **Security Features**: Full browser control, network interception, request/response modification, cookie/session manipulation, JS injection, screenshot/recording.
- **Relevance**: Used by Strix as its browser exploitation engine. Can automate complex auth flows, XSS testing, CSRF testing, auth bypass testing.
- **Extensibility**: Python, JS/TS, Java, .NET bindings.

### Puppeteer (Google)
- **Security Features**: Chrome DevTools Protocol access, performance tracing, coverage collection, JS/DOM manipulation, request interception.
- **Relevance**: Foundation for many security tools. Lighter than Playwright for simple automation.

### Chrome DevTools Protocol (CDP)
- **Low-Level Access**: Network monitoring, DOM inspection, JS runtime access, security panel, audits, coverage, performance.
- **Security-Specific CDP Features**: `Security` domain (certificate info, security state), `Audits` domain (Lighthouse), `Network` domain (request/response interception).

## 3.2 Security-Specific Browser Tools

### Crawlergo (3k stars)
- **Type**: Powerful browser crawler for web vulnerability scanners
- **Stack**: Chrome DevTools Protocol, headless Chrome, chromedp (Go)
- **Relevance**: Key component for web vuln scanners — crawls dynamic JS-heavy apps

### Playwright-Based Security Extensions
- **Request interception**: Modify headers, inject payloads, test auth bypass
- **Multi-context testing**: Test with different auth states, roles, sessions
- **Network monitoring**: Track all requests/responses for vulnerability signatures
- **Screenshot comparison**: Detect visual regressions that might indicate vulnerabilities

### Caido (used by Strix)
- **Type**: HTTP interception proxy (Burp Suite alternative)
- **Relevance**: Essential for web pentesting — request/response manipulation, replay, fuzzing
- **Integration**: Strix integrates Caido as an agentic tool for HTTP traffic analysis

## 3.3 Key Patterns for Web Game Security Testing

1. **WebSocket interception**: Games using WebSocket for real-time communication can be tested via Playwright's route interception
2. **WebGL/Canvas analysis**: Screenshot comparison, pixel analysis for visual Cheat/hack detection
3. **WebAssembly inspection**: Browser DevTools for WASM debugging, memory inspection
4. **Local Storage/Session Storage manipulation**: Test for client-side state manipulation vulnerabilities
5. **IndexedDB inspection**: Game save data often stored in IndexedDB
6. **Service Worker interception**: PWA games with service workers can have their network layer intercepted

---

# 4. Bug Bounty Automation

## 4.1 Reconnaissance Automation

### ProjectDiscovery Ecosystem
- **Nuclei** (29.5k stars): Template-based scanning
- **Subfinder**: Subdomain discovery
- **Httpx**: HTTP probing
- **Katana**: Crawling
- **Naabu**: Port scanning

### Other Recon Tools
- **Amass**: Network mapping of attack surface, DNS enumeration
- **Shuffledns**: DNS enumeration with massdns
- **Dnsx**: DNS toolkit
- **Gau/Gauplus**: Get all URLs (Wayback Machine, AlienVault, CommonCrawl)

## 4.2 Automated Submission & Workflow

### Report Generation
- **BugHunter's /report**: Generates HackerOne/Bugcrowd/Intigriti/Immunefi submissions in 60s
- **Shannon's Reporting Agent**: Compiles validated findings, evidence, remediation guidance
- **Tachi's /security-report**: Professional PDF assessment booklet

### Workflow Automation Tools
- **BugHunter's /autopilot**: Full autonomous loop — scope → recon → hunt → validate → report
- **BugHunter's /pickup**: Resume from last session, untested endpoints first
- **BugHunter's /chain**: Bug A found → finds bugs B and C that chain with it

### Vulnerability Management Platforms
- **DefectDojo** (4.8k stars): Open-source unified vulnerability management, DevSecOps & ASPM
- **Faraday** (6.6k stars): Open-source vulnerability management platform with collaboration
- **Dependency-Track** (4k stars): Component analysis platform for software supply chain

## 4.3 Key Bug Bounty Automation Patterns

1. **Continuous recon**: Subdomain monitoring, cert transparency logs, new asset discovery
2. **Automated triage**: Filter findings by severity, exploitability, program scope
3. **Duplicate detection**: Hash-based finding deduplication across runs
4. **Submission templating**: Per-platform (H1, Bugcrowd, etc.) format generation
5. **Chain detection**: Automatically find related vulnerabilities (e.g., XSS → CSRF → Account Takeover)
6. **Memory/pattern DB**: Cross-target pattern learning for faster discovery

---

# 5. Architecture Patterns for Multi-Agent Security Systems

## 5.1 Orchestration Patterns Observed

### Pattern A: Pipeline (Sequential)
**Used by**: Tachi, Mythos, Shannon (partially)
```
Phase 0 → Phase 1 → Phase 2 → ... → Phase N
```
- Each phase gates on previous phase completion
- Clean output → input contracts between phases
- Good for: Auditing, threat modeling, source-code analysis

### Pattern B: Central Orchestrator + Specialized Workers
**Used by**: DeepAudit, PentAGI, Claude Bug Bounty
```
Orchestrator
  ├── Recon Agent (attack surface mapping)
  ├── Analysis Agent(s) (vulnerability discovery)
  ├── Verification Agent (PoC validation)
  └── Report Agent (finding compilation)
```
- Orchestrator plans strategy, dispatches agents, aggregates results
- Specialized agents are stateless tools with specific roles
- Good for: Penetration testing, autonomous vulnerability discovery

### Pattern C: Parallel Agent Swarm
**Used by**: Strix ("Graph of Agents"), Mythos (Pass@K)
```
Source/Target
  ├── Agent 1 (Injection, pass 1)
  ├── Agent 1 (Injection, pass 2, different seed)  ← diversity seeding
  ├── Agent 2 (XSS)
  ├── Agent 3 (Auth)
  └── Agent 4 (SSRF)
```
- Multiple independent agents run in parallel on same target
- Diversity seeding: same agent, different prompts/seeds
- Merging: deduplication, cross-validation of findings
- Good for: High-throughput scanning, broad coverage

### Pattern D: Hierarchical Agent Spawning
**Used by**: PentestAgent (spawn_mcp_agent)
```
Parent Agent
  ├── Child Agent 1 (recon subnet A)
  ├── Child Agent 2 (recon subnet B)
  └── Child Agent 3 (target specific host)
```
- Agents spawn sub-agents as MCP servers
- Parent aggregates child results
- Fully isolated child processes with own LLM client
- Good for: Distributed recon, parallel target enumeration

### Pattern E: Sink-Guided Agentic Hunt
**Used by**: Mythos Research Edition
```
Source Code
  → Phase 0: Language Detection
  → Phase 1: Sink-Guided Slicing (ripgrep sink catalogs → NDJSON hits)
  → Phase 2: File Ranking (by sink density, severity)
  → Phase 3: Agentic Hunt (parallel agents per top-ranked files)
  → Phase 3.5: Adversarial Self-Challenge (fresh agent argues against each finding)
  → Phase 4: Skeptical Validation (second-pass agent = CONFIRMED/FALSE_POSITIVE/DOWNGRADED)
  → Phase 7: Cross-Session FP Memory Writeback
```
- Combines deterministic static analysis (sink catalogs) with LLM-based reasoning
- Pass@K diversity seeding increases breadth
- Adversarial validation reduces false positives
- Good for: Source-code vulnerability discovery at scale, low cost

## 5.2 Tool-Use Patterns in Security Contexts

### Deterministic Tools (Always Used)
1. **Network scanning**: nmap, masscan, naabu
2. **Web scanning**: nuclei, sqlmap, ffuf/dirbuster
3. **Subdomain enumeration**: subfinder, amass, dnsx
4. **HTTP probing**: httpx, curl, wget
5. **Source analysis**: grep/ripgrep, semgrep, CodeQL patterns

### LLM-Mediated Tools (AI Decides When/How)
1. **Shell execution**: The LLM decides which commands to run based on context
2. **Browser automation**: The LLM decides which pages to visit, forms to fill, requests to intercept
3. **Code generation**: The LLM writes exploit scripts, PoC validators, custom fuzzers
4. **Memory analysis**: The LLM chooses memory regions to inspect, values to search for
5. **Protocol fuzzing**: The LLM generates valid-but-malformed protocol messages

### Validation Gates (Critical Pattern)
- **BugHunter's 7-Question Gate**: Each finding must pass 7 strict questions before submission
- **Mythos's Skeptical Validation**: Second-pass agent explicitly framed as "skeptical reviewer"
- **Mythos's Self-Challenge**: Fresh agent asked for strongest counter-argument against finding
- **Shannon's Proof-by-Exploitation**: Only findings with working PoC are reported
- **DeepAudit's Sandbox PoC**: Docker-sandboxed PoC execution with self-correction

## 5.3 Planning vs Reactive Approaches

### Planning-First (Proactive)
- **Tachi**: 5-phase deterministic pipeline with explicit scope → threat → countermeasure → assess → report
- **PentAGI Intelligent Task Planning**: Planner generates 3-7 actionable steps BEFORE execution
- **DeepAudit Orchestrator**: Receives task → analyzes project type → creates audit plan → dispatches agents
- **Advantage**: Comprehensive coverage, predictable output
- **Disadvantage**: Slower, higher token cost

### Reactive (Exploratory)
- **BugHunter Hunt Mode**: Agent explores target, tests what it finds, branches based on results
- **Mythos Agentic Hunt**: Agent receives sink hits + build sandbox → explores hypotheses live
- **PentestAgent Assist Mode**: Single-shot, tool execution based on LLM reasoning
- **Advantage**: Fast, adaptive, can discover unexpected vulnerabilities
- **Disadvantage**: May miss systematic issues, less reproducible

### Hybrid (Most Common)
- **Shannon**: Pre-Recon (planning) → Recon (exploration) → parallel specialized agents (both)
- **Strix**: Architecture description (planning) → dynamic exploration (reactive) → exploit validation (deterministic)
- **PentAGI**: Execution Monitoring (reactive mentor intervention) + Task Planning (proactive step generation)

## 5.4 Memory & Context Management

### Approaches to Long-Running Security Tasks
1. **Chain Summarization** (PentAGI): Selectively summarize older messages to prevent token limit overflow. ChainAST structured representation. Different thresholds for global vs assistant contexts.
2. **Vector Store Memory** (PentAGI, DeepAudit): Semantic search across past findings, stored as embeddings in pgvector
3. **Knowledge Graphs** (PentAGI, PentestAgent): Neo4j/Graphiti for relationship tracking between entities, actions, outcomes
4. **Cross-Session FP Memory** (Mythos): Dismissals JSON keyed by target SHA-256 — same FP not re-discovered
5. **Conversation History Fork/Rewind** (PentestAgent): Interactive branching of agent conversation paths
6. **Notes System** (BugHunter, PentestAgent): Agents save categorized findings (credential, vulnerability, artifact) that persist across sessions

---

# 6. Key Vulnerability Categories for VEST

## 6.1 Memory Vulnerabilities

| Category | Description | Detection Approach |
|----------|-------------|-------------------|
| **Buffer Overflow** | Stack/heap overflow, off-by-one | Pattern scanning for unsafe functions (strcpy, gets, sprintf), fuzzing, ASan integration |
| **Use-After-Free** | Dangling pointer usage | Dynamic analysis (Frida/PIN/DynamoRIO), pattern matching for free+use patterns |
| **Double Free** | Freeing memory twice | Memory allocator hooking, canary detection |
| **Integer Overflow** | Arithmetic overflow leading to undersized allocation | Static analysis for unchecked arithmetic, symbolic execution |
| **Format String** | User-controlled format strings | Pattern matching for printf-like functions with user input |
| **Race Conditions** | TOCTOU, multi-thread race | Thread sanitizer (TSan), systematic interleaving exploration |
| **Stack Canary Bypass** | Information leak + overwrite | Leak detection, canary value analysis |
| **ROP Chain Detection** | Return-oriented programming gadgets | ROPgadget integration, gadget chain analysis |
| **Heap Spray** | Memory layout manipulation | Memory pattern detection, allocation monitoring |

### Tools for Memory Analysis
- **ASan (AddressSanitizer)**: Compile-time instrumentation for memory errors
- **MSan (MemorySanitizer)**: Uninitialized reads detection
- **TSan (ThreadSanitizer)**: Data races
- **UBSan (UndefinedBehaviorSanitizer)**: Undefined behavior
- **Valgrind**: Memory leak, race condition, cache profiling
- **Frida**: Dynamic hooking for runtime memory inspection
- **LIEF**: PE/ELF/Mach-O parsing for binary analysis

## 6.2 Web Vulnerabilities

| Category | Description | Detection Approach |
|----------|-------------|-------------------|
| **XSS** | Stored, Reflected, DOM-based | Payload injection + DOM monitoring via Playwright, response analysis |
| **CSRF** | Cross-Site Request Forgery | Token absence detection, same-site cookie analysis |
| **SQL Injection** | Error-based, blind, time-based, UNION | sqlmap integration, error pattern detection, timing analysis |
| **NoSQL Injection** | MongoDB, Redis, etc. | Operator injection payloads, error analysis |
| **Command Injection** | OS command execution | Command separator enumeration, time-based detection |
| **SSTI** | Server-Side Template Injection | Template syntax injection, expression evaluation |
| **XXE** | XML External Entity | XML parsing with external entity declarations |
| **SSRF** | Server-Side Request Forgery | URL injection, callback detection (Burp Collaborator, interactsh) |
| **Insecure Deserialization** | Pickle, Java serialization, PHP unserialize | Magic method detection, gadget chain analysis |
| **Path Traversal** | Directory traversal, LFI/RFI | Path traversal payloads, response content analysis |
| **IDOR/BOLA** | Insecure Direct Object Reference | Sequential ID enumeration, role-based access testing |
| **Auth Bypass** | Authentication bypass | Header manipulation, JWT attacks, session fixation |
| **Mass Assignment** | API parameter binding | Extra parameter injection, API schema analysis |
| **JWT Attacks** | Algorithm confusion, key confusion | JWT header manipulation, key type switching |
| **CORS Misconfiguration** | Cross-Origin Resource Sharing | Origin header testing, null origin, subdomain matching |
| **Open Redirect** | URL redirection | Redirect parameter testing, protocol whitelisting |
| **Clickjacking** | UI redressing | Frame-ancestors / X-Frame-Options testing |
| **Cache Poisoning** | Web cache deception/poisoning | Cache key identification, header-based poisoning |
| **Request Smuggling** | HTTP request smuggling | Transfer-Encoding/Content-Length confusion, HTTP/2 downgrade |

## 6.3 Game-Specific Vulnerabilities

| Category | Description | Detection Approach |
|----------|-------------|-------------------|
| **Speed Hacks** | Game speed manipulation | Memory value monitoring for time/tick counters, rate detection |
| **Wall Hacks / ESP** | Rendering manipulation, transparency | Render state hooking, depth buffer analysis |
| **Aimbot** | Automated targeting | Mouse input monitoring, aim pattern detection |
| **No-Clip** | Collision bypass | Memory flag detection (noclip flags), position validation |
| **Infinite Resources** | Health, ammo, currency modification | Memory value freezing detection, sanity checks on resource deltas |
| **RCE via Save Files** | Malformed save file parsing | Fuzzing save parsers, format-specific vulnerability patterns |
| **Network Protocol Exploits** | Packet manipulation, replay, injection | Protocol reverse engineering, packet fuzzing, replay detection, encryption bypass |
| **DLL Injection** | Code injection via DLL loading | Loaded module monitoring, signature verification |
| **Code Caves** | Hidden code in executable | PE section analysis, entropy scanning |
| **Anti-Debug/Anti-Tamper** | Debugger detection, integrity checks | Anti-anti-debug techniques, hooking detection bypass |
| **WebSocket Manipulation** (web games) | Real-time protocol tampering | WebSocket message interception via Playwright CDP |
| **Client-Side Prediction Exploits** | Lag compensation abuse | Network latency manipulation, state prediction reversal |
| **Asset Theft** | Model/texture extraction | Memory dumping of GPU buffers, render target capture |
| **DRM Bypass** | Copy protection circumvention | Binary patching, license check bypass, emulation layer detection |
| **Unity/Unreal Engine Exploits** | Engine-specific vulnerabilities | IL2CPP analysis for Unity, Blueprint analysis for Unreal |

### Game Engine-Specific Analysis Tools
- **IL2CPP Inspector**: Unity IL2CPP metadata analysis
- **UE4SS/UE5SS**: Unreal Engine scripting system for runtime inspection
- **BepInEx**: Unity modding framework (also useful for vulnerability research)
- **Mono Injection**: Inject C# code into Unity Mono games
- **RenderDoc**: Graphics debugger — useful for wallhack detection research
- **Intel GPA / NVIDIA Nsight**: Graphics performance tools — frame analysis

## 6.4 Binary Vulnerabilities

| Category | Description | Detection Approach |
|----------|-------------|-------------------|
| **Format String** | Printf-family vulnerabilities | Static analysis of format string arguments, dynamic fmt string detection |
| **Stack Canary Bypass** | Stack protector bypass via leak | Information leak detection preceding buffer overflow |
| **ROP/JOP/COP** | Return/Jump/Call-oriented programming | ROPgadget analysis, control flow integrity validation |
| **ASLR Bypass** | Address space layout randomization bypass | Information disclosure leading to address leaks |
| **DEP/NX Bypass** | Data execution prevention bypass | mprotect/VirtualProtect detection, JIT spraying |
| **SEH Overwrite** | Structured exception handler corruption | SEH chain validation, SafeSEH verification |
| **Import Table Hooking** | IAT/EAT manipulation | Import/export table integrity verification |
| **TLS Callback Abuse** | Thread-local storage callbacks for anti-debug | TLS directory analysis |
| **PE Injection** | Code injection via PE manipulation | Section analysis, entropy detection, digital signature verification |

---

# Summary: Key Architectural Insights for VEST

## What's Been Proven to Work

1. **Multi-Agent Orchestration is the standard**: Every major tool uses multiple specialized agents with an orchestrator. Single-agent approaches are insufficient for comprehensive security testing.

2. **Proof-by-Exploitation is the gold standard**: Shannon, Strix, DeepAudit, and BugHunter all gate findings on validated PoCs. The industry has moved past "scanner says there's a vulnerability" to "we proved it's exploitable."

3. **Skeptical Validation Gates are essential**: Mythos's self-challenge + skeptical validator, BugHunter's 7-Question Gate, and 3 out of the top 5 tools have explicit validation phases to kill false positives.

4. **Sink-Guided + AI is the best source-code approach**: Mythos's approach of deterministic sink catalogs (ripgrep) to identify high-risk code, then LLM agents to reason about exploitability, combines the best of both worlds.

5. **Cross-Session Memory is critical**: Successful tools persist findings, patterns, and false-positive markers across sessions. PentAGI uses pgvector, Mythos uses JSON FP memory, BugHunter uses hunt memory.

6. **Docker Sandboxing is universal**: Every agentic tool that executes code uses Docker for isolation — Shannon, DeepAudit, PentAGI, PentestAgent all sandbox agent actions.

7. **Tool Integration > Tool Building**: The most successful tools integrate existing security tools (nuclei, sqlmap, nmap, subfinder, Playwright) rather than rebuilding them. The AI agent is the orchestrator, not the scanner.

## Gaps in the Current Landscape

1. **No unified game + web + binary vulnerability scanner**: Existing tools focus on either web (Shannon, Strix, BugHunter), source code (DeepAudit, Mythos), or infrastructure (PentAGI). No tool covers game-specific vulnerabilities (memory manipulation, speed hacks, network protocol exploits) alongside web and binary.

2. **No browser-automation-first game security tool**: While Playwright is used for web testing, no existing tool uses browser automation specifically for in-browser game security testing (WebGL manipulation, Canvas inspection, WebSocket protocol fuzzing for games).

3. **No MCP-native security agent framework**: While PentestAgent supports MCP, no tool is built from the ground up as an MCP-based security agent that can be plugged into any LLM agent framework.

4. **Memory analysis is still largely manual**: Cheat Engine, ReClass, Frida require significant human expertise. No tool combines memory scanning with LLM reasoning for automated game exploit discovery.

5. **Game network protocol fuzzing is underserved**: Tools for reverse-engineering and fuzzing custom game network protocols are scarce and fragmented.

## Recommended Architecture for VEST

Based on this research, VEST should adopt:

1. **Mythos-style sink-guided pipeline** for source-code analysis (deterministic sink catalogs + LLM reasoning)
2. **Shannon-style multi-agent orchestration** with specialized agents per vulnerability category
3. **Frida-based runtime instrumentation** for memory analysis and game-specific vulnerability detection
4. **Playwright-based browser automation** for web game security testing and web vulnerability scanning
5. **Cross-session memory with vector store** (pgvector) for persistent pattern learning
6. **Skeptical validation gates** (self-challenge + secondary validator) for false-positive reduction
7. **Docker sandbox** for all PoC execution
8. **MCP-native architecture** for maximum interoperability with existing agent frameworks
9. **Game-specific tooling**: Memory scanning + network protocol analysis + save file fuzzing + engine-specific hooks
