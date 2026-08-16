# Agent Loop development tooling

`voku/anti-xss` supports PHP 7.1+, while `voku/agent-loop` requires PHP 8.3+.
Keeping the agent tooling in this isolated Composer project prevents the library's
normal development dependency graph and legacy PHP CI matrix from being raised to
PHP 8.3.

Install the repository-local agent tooling with PHP 8.3+:

```bash
composer install --working-dir=tools/agent-loop
composer check-platform-reqs --working-dir=tools/agent-loop
```

Run `agent-loop` from the repository root so its project root remains the
`anti-xss` checkout while workflow state stays below `.agent-loop/`:

```bash
tools/agent-loop/vendor/bin/agent-loop init paths
tools/agent-loop/vendor/bin/agent-loop verify
```

The first tracked board task is `ANTIXSS-1`; this imported tooling state does
not claim a completed governed Run.
