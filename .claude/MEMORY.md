# waypoint — project memory

## Purpose
waypoint answers the questions people get stuck on when they've forgotten their server's ecosystem:
0. **What runs on this machine and how?** Every app, how it is started, which sites lead to it.
1. **Where does this request actually go?** Reads nginx config, draws the route map
   (domain → nginx → upstream → process/container/systemd) and checks every hop against reality.
2. **Why is this broken?** Collects evidence for a target, finds the root cause, shows the
   evidence chain and suggests a fix. Suggestions are printed, never executed.

## Principles
- Target: the user's dev machine or server, when nginx or an app is broken/crashed.
- Open source; goal is GitHub stars, so the first run must be impressive.
- Very few code comments; only where behavior is non-obvious.
- Nothing unnecessary. Every feature must answer a real developer need.
- Deterministic diagnosis: evidence → rules → finding. AI is never the source of a diagnosis.
- Config ≠ reality: always compare what is configured with what is actually running.
- Dead simple: zero config, forgiving input, readable output, works without sudo
  (degrade gracefully and say what is missing).
- Never suggest destructive commands (prune, rm volumes, ...).

## Decisions
- Repo https://github.com/Sirius-Star42/waypoint, module `github.com/Sirius-Star42/waypoint`, Go 1.24, CLI with cobra.
- Platforms: Linux + macOS (amd64, arm64) only.
- Commands: `waypoint` (SITES + APPS + PROBLEMS overview), `waypoint <target>` (trace one request), `waypoint map --mermaid` (diagram incl. apps).
- APPS inventory: every listener grouped by how it runs (systemd / compose / container / process) with command, folder, unit file, routes; fully stopped compose projects are "stopped", not broken.
- nginx config source: `nginx -T` first, fall back to parsing files + includes.
- Docker via the `docker` CLI (works with Docker Desktop, Colima, OrbStack, dockerd).
- Install: Homebrew tap (primary), `go install`, release binaries (goreleaser). No curl|sh script.

## Workflow
- At the end of every change, give the user a short commit message (don't commit it).

## Roadmap (later phases)
- Caddy / Traefik / HAProxy support.
- `fix` that runs a suggestion only after explicit confirmation.
- Optional LLM explanation over a sanitized diagnosis (explanation only, never diagnosis).
