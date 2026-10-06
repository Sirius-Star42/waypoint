# waypoint

**One command that shows what runs on your server, where every request goes, and why it's broken.**

nginx, Docker, compose, systemd and hand-started processes, mapped and checked in a few seconds.
No config, no agent, no account. A single binary that only reads.

## Install

```sh
brew install sirius-star42/tap/waypoint
```

or `go install github.com/Sirius-Star42/waypoint/cmd/waypoint@latest`, or grab a binary for
Linux / macOS (amd64, arm64) from [releases](https://github.com/Sirius-Star42/waypoint/releases).

## Use

```sh
waypoint                    # every site, every app, and what's broken
waypoint 8080               # why isn't localhost:8080 working?
waypoint api.example.com    # follow a domain through nginx to the app behind it
waypoint map --open         # the whole picture as a diagram in your browser
```

On a server, run it with `sudo` so it can see every user's processes.

---

<p align="center">
  <img src="docs/map.png" alt="waypoint map: clients, nginx sites, compose services, databases and the problems between them" width="100%">
</p>

## Why

You set up a server a year ago: nginx in front, a few apps behind it, some as systemd services,
some in Docker, one you started by hand. Now a site returns 502 and you no longer remember which
config file handles it, which port it proxies to, or how that app is even started.

The usual answer is ten commands and twenty minutes:

| Question | Without waypoint | With waypoint |
|---|---|---|
| Which server block and location handle this URL? | `nginx -T \| less`, reason through match order | `waypoint <url>` |
| What listens on port 9000, and how was it started? | `ss -ltnp`, `ps`, `systemctl status`, `docker ps` | shown on every route |
| Why does the container keep restarting? | `docker inspect`, `docker logs`, read the env | root cause + last log lines |
| Is anything exposed that shouldn't be? | check every bind address by hand | public ports and databases flagged |
| What's eating the memory? | `docker stats`, `top` | CPU and memory on every app |

## What you get

**One overview of the whole machine.** Sites from nginx, the apps behind them and how each one
runs, apps nothing routes to, and every problem ranked by importance.

```
$ sudo waypoint
SITES  served by nginx · nginx -T · 4 config files

shop.example.com  :443 ssl  ✓ certificate: R11, 61 days left  ✓ TLS 1.2, 1.3
├─ /         → http://127.0.0.1:3000  ✓ web · compose shop
└─ /static/  → /srv/shop/public       ✓ directory exists

admin.example.com  :80
└─ /  → http://127.0.0.1:9000  ✗ systemd: admin.service · failed, exit-code 3

APPS  3 apps on this machine · 2 with problems

✗ shop  docker compose · 1 of 4 containers down
    file      /srv/shop/compose.yaml
    usage     cpu 0.9% · mem 290 MiB
      SERVICE    PORT    ACCESS   STATUS                     CPU    MEM       ROUTES
    ✗ api                         crashing (restarted 7×)
    ✓ postgres                    running for 3 days         0.2%   96 MiB
    ✓ redis                       running for 3 days         0.3%   12 MiB
    ✓ web        :3000   local    running for 3 days         0.4%   182 MiB   shop.example.com/
    manage    cd /srv/shop && docker compose ps

✓ old-api  process · running for 41 days
    command   python3 main.py
    folder    /home/deploy/old-api
    usage     cpu 0.1% · mem 64 MiB
    port      :9101 all interfaces
    ! started by hand, not by systemd or Docker: it won't come back after a reboot or crash
    ! no nginx route points here

PROBLEMS  3 problems, most important first

✗ admin.example.com / → admin.service is failed, exit-code 3
  The systemd service that serves this port is not running.

  Last logs journalctl -u admin.service
    │ admin: missing SECRET_KEY
    │ admin.service: Failed with result 'exit-code'.

  Fix
    Restart after fixing the cause
      $ sudo systemctl restart admin.service
...
```

**The root cause, not just the symptom.** Trace one request hop by hop. When several things fail,
waypoint follows the chain (nginx → app → database) and names the deepest real failure.

```
$ waypoint localhost:8088/api/
✗ api connects to localhost:5432, but inside a container localhost is the container itself

  ✓ nginx (docker: nginx) listening on :8088
  ✗   HTTP http://localhost:8088/api/         timed out after 3s
  ✓ server localhost                          exact name  conf.d/default.conf:1
  ✓   location /api/                          conf.d/default.conf:9
  ✗     proxy_pass http://api:8080/
  ✗       api:8080 (from nginx)               docker: api · restarting (7 restarts)
  ✗         localhost:5432 (from api)         localhost here is the api container itself · via DATABASE_URL
  ✓         redis:6379                        docker: redis · via REDIS_URL
  ✓         postgres:5432                     docker: postgres

  Fix
    In compose.yaml, use the service name instead of localhost (password hidden)
      $ DATABASE_URL=postgres://app:***@postgres:5432/app
    Then recreate the container
      $ cd ~/shop && docker compose up -d api
```

**A map you can share.** `waypoint map --open` opens the diagram above in your browser.
`waypoint map --mermaid` prints it as Mermaid for your README or wiki, with a link to view it.

**Security basics, checked for free.** Deprecated TLS 1.0/1.1, expiring or mismatched
certificates, databases published on all interfaces (Docker bypasses ufw and firewalld), and
processes that won't survive a reboot.

## Try it in a minute

The repo ships a small broken stack: nginx → API → Postgres and Redis, with one classic bug.

```sh
git clone https://github.com/Sirius-Star42/waypoint && cd waypoint/examples/broken-compose
docker compose up -d
waypoint                    # see the problem
waypoint localhost:8088/api/
docker compose down         # clean up
```

## Options

| Flag | |
|---|---|
| `-v` | evidence and full logs for every problem, hidden system processes |
| `--timeout 3s` | timeout for each network check |
| `--nginx path` | use this nginx.conf instead of auto-detecting |
| `map --open` | open the map as a diagram in your browser (prints the link over SSH) |
| `map --mermaid` | print the map as Mermaid |

Exit code: `0` all good, `1` problems found, `2` waypoint itself failed, so it works in scripts
and CI: `waypoint https://example.com/health || alert`.

<details>
<summary><b>Everything it checks</b></summary>

**nginx**
- which `server` and `location` a URL really hits, using nginx's own matching order (exact,
  longest prefix, `^~`, regex in order, wildcard and regex `server_name`, `default_server`)
- upstreams with nothing listening, dead `upstream {}` members, missing `root`/`alias` directories
- a `server_name` defined twice on a port (nginx silently ignores the second one)
- a config that fails `nginx -t`, meaning nginx won't come back after a reload or reboot
- expired, soon-to-expire or wrong-name TLS certificates
- the TLS versions each site really accepts, with the `ssl_protocols` line to change
- nginx in Docker pointing at `localhost`, or at a container on another network

**every app on the machine**
- how it runs: systemd unit, compose project, container and image, or a bare process with its
  command, folder and user, plus the command to restart it or follow its logs
- CPU and memory of every app and container
- which sites lead to it, and apps no nginx route points to (often a forgotten or moved app)
- ports published on all interfaces, and databases other machines can reach
- processes started by hand that won't survive a reboot
- crashed systemd services, even ones that don't hold a port
- stopped compose projects and old containers, and which of them used a port you ask about

**apps behind nginx**
- the owner of each upstream port: process, systemd unit or container
- crashed or failed systemd services, with their last journal lines
- stopped, crash-looping and unhealthy containers, with the last log lines and what the exit code means
- a port mapped to the wrong container port, or a running container where nothing answers on it
- a port taken by another process that your compose service expects
- `DATABASE_URL`-style settings pointing at `localhost` inside a container

</details>

## How it works

```
nginx config ──► routes ──► probes ──► evidence ──► rules ──► root cause + fix
 (nginx -T,        (server,    (TCP, HTTP,   (process, container,
  files, or         location,   TLS, DNS)     systemd unit, compose
  a container)      upstream)                 dependencies, logs)
```

- **Read-only.** It never restarts, edits or kills anything. Fixes are printed for you to run.
- **Deterministic.** Every conclusion comes from a rule over collected evidence, and the evidence
  is printed so you can check it. No AI guesses.
- **Zero setup.** No config file, no daemon, no root required. When it can't see something, it says
  so and tells you to use `sudo`.
- **Private.** waypoint sends nothing anywhere. The `map --open` diagram travels inside the link's
  `#` fragment, which browsers never send to a server.
- **Works where you are.** Linux and macOS, on your laptop or over SSH. Docker Desktop, Colima,
  OrbStack and plain dockerd all work. Without nginx it still maps and checks every app.

## Contributing

Bug reports with a (sanitized) nginx config that waypoint gets wrong are the most useful
contribution. Add the config to `internal/nginx/testdata` together with a test case.

```sh
go test ./...
```

## License

MIT
