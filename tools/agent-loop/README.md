# Agent Loop development tooling

`voku/anti-xss` supports PHP 7.1+, while `voku/agent-loop` requires PHP 8.3+.
Keeping the agent tooling in this isolated Composer project prevents the library's
normal development dependency graph and legacy PHP CI matrix from being raised to
PHP 8.3.

Install the repository-local agent tooling with PHP 8.3+:

```bash
composer install --working-dir=tools/agent-loop
```

Run `agent-loop` from the repository root so its workflow paths are rooted in the
`anti-xss` checkout:

```bash
tools/agent-loop/vendor/bin/agent-loop verify
```

The first real task is `ANTIXSS-1`.
