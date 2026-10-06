# waypoint

**What runs on this server, where does each site go, and why is it broken?**

You set up a server a year ago: nginx in front, a few apps behind it, some as systemd services,
some in Docker, one you started by hand. Now a site returns 502 and you no longer remember which
config file handles it, which port it proxies to, or how that app is even started.

Run `waypoint` on the server. It reads your nginx config, finds every app on the machine, works out
how each one runs (systemd, Docker, compose or a bare process) and which sites lead to it. It checks
every hop against what is actually running, and when something is broken it shows the root cause,
the evidence, the last log lines and the command to fix it.

```
$ sudo waypoint
SITES  served by nginx · nginx -T · 4 config files

admin.example.com  :80
└─ /  → http://127.0.0.1:9000  ✗ systemd: admin.service · failed, exit-code 3

api.example.com  :80
└─ /  → http://127.0.0.1:8080  ✓ my-api · systemd

shop.example.com  :80 + www.shop.example.com
├─ /         → http://127.0.0.1:9100  ✗ nothing listening
└─ /static/  → /srv/shop/public       ✓ directory exists

APPS  4 apps on this machine · 2 with problems

✗ admin         systemd service · failed, exit-code 3
    command   /usr/bin/python3 -c import sys; print('admin: missing SECRET_KEY', file=sys.stderr); sys.exit(3)
    folder    /opt/my-api
    unit file /etc/systemd/system/admin.service
    port      :9000 not listening  ← admin.example.com/
    manage    journalctl -u admin -n 50  ·  sudo systemctl restart admin

✗ worker        systemd service · failed, exit-code 1
    command   /usr/bin/python3 /opt/worker/worker.py
    folder    /opt/worker
    unit file /etc/systemd/system/worker.service
    manage    journalctl -u worker -n 50  ·  sudo systemctl restart worker

✓ my-api        systemd service · running for 2 minutes
    command   /usr/bin/python3 /opt/my-api/server.py
    folder    /opt/my-api
    unit file /etc/systemd/system/my-api.service
    user      www-data
    port      :8080 local only  ← api.example.com/
    manage    sudo systemctl restart my-api  ·  journalctl -u my-api -f

✓ old-api       process · running for a few seconds
    command   python3 main.py
    program   /usr/bin/python3.12
    folder    /home/deploy/old-api
    user      root
    pid       275
    port      :9101 all interfaces
    ! started by hand, not by systemd or Docker: it won't come back after a reboot or crash
    ! no nginx route points here

  · 1 system process hidden (-v to show)

PROBLEMS  3 problems, most important first

✗ admin.example.com / → admin.service is failed, exit-code 3
  The systemd service that serves this port is not running.

  Evidence
    ✗ nothing listening on 127.0.0.1:9000
    ✗ admin.service mentions port 9000 and is failed since Mon 2026-10-05 17:57:39 UTC

  Last logs journalctl -u admin.service
    │ Started admin.service.
    │ admin: missing SECRET_KEY
    │ admin.service: Main process exited, code=exited, status=3/NOTIMPLEMENTED
    │ admin.service: Failed with result 'exit-code'.

  Fix
    Full logs
      $ journalctl -u admin.service -n 100 --no-pager
    Restart after fixing the cause
      $ sudo systemctl restart admin.service

✗ worker.service has crashed (failed, exit-code 1)
  $ journalctl -u worker.service -n 100 --no-pager

✗ shop.example.com / → nothing is listening on 127.0.0.1:9100
  $ ss -ltnp 'sport = :9100'

waypoint <url or port> traces one request · -v shows evidence and logs for every problem
```

`waypoint map --open` opens the same picture as a diagram in your browser (over SSH it prints the
link instead). The diagram travels in the link's `#` fragment, which is never sent to a server.
`waypoint map --mermaid` prints it as Mermaid that renders on GitHub, ready to paste into your
server's README or wiki:

```mermaid
flowchart LR
  clients((clients))
  subgraph nginx["nginx"]
    n0["admin.example.com<br/>:80"]
    n1["api.example.com<br/>:80"]
    n2["shop.example.com<br/>:80"]
  end
  n5["127.0.0.1:9100<br/>nothing running"]
  n6["files /srv/shop/public"]
  n3["admin :9000<br/>systemd service<br/>/opt/my-api<br/>failed, exit-code 3"]
  n4["my-api :8080<br/>systemd service<br/>/opt/my-api<br/>running for 2 minutes"]
  subgraph unrouted["not behind nginx"]
    n7["worker<br/>systemd service<br/>/opt/worker<br/>failed, exit-code 1"]
    n8["old-api :9101<br/>process<br/>/home/deploy/old-api<br/>running for a few seconds"]
  end
  clients --> n0
  clients --> n1
  clients --> n2
  n0 -- "/" --> n3
  n1 -- "/" --> n4
  n2 -- "/" --> n5
  n2 -- "/static/" --> n6
  class n0 ok
  class n1 ok
  class n2 ok
  class n3 bad
  class n4 ok
  class n5 bad
  class n6 ok
  class n7 bad
  class n8 ok
  classDef ok stroke:#2da44e,stroke-width:2px
  classDef bad stroke:#cf222e,stroke-width:2px,color:#cf222e
  classDef warn stroke:#bf8700,stroke-width:2px
  classDef info stroke:#8c959f
```

Trace a single request, here through a dockerized nginx into a crash-looping compose service:

```
$ waypoint localhost:8088/api/
✗ api connects to localhost:5432, but inside a container localhost is the container itself

  ✓ nginx (docker: nginx) listening on :8088
  ✗   HTTP http://localhost:8088/api/         timed out after 3s
  ✓ server localhost                          exact name  conf.d/default.conf:1
  ✓   location /api/                          conf.d/default.conf:9
  ✗     proxy_pass http://api:8080/
  ✗       api:8080 (from nginx)               docker: api · restarting (7 restarts) · nc: bad address 'api'
  ✗         localhost:5432 (from api)         localhost here is the api container itself · via DATABASE_URL
  ✓         redis:6379                        docker: redis · via REDIS_URL
  ✓         postgres:5432                     docker: postgres

  DATABASE_URL=postgres://app:***@localhost:5432/app is resolved inside the api container, where nothing listens on 5432.

  Evidence
    ✗ DATABASE_URL=postgres://app:***@localhost:5432/app
    ✗ shop-api-1: restarting (7 restarts)
    ✓ shop-postgres-1 exposes 5432 and is reachable as postgres:5432

  Last logs docker logs shop-api-1
    │ FATAL: could not connect to database at localhost:5432: [Errno 111] Connection refused  (×7)

  Fix
    In compose.yaml, use the service name instead of localhost (password hidden)
      $ DATABASE_URL=postgres://app:***@postgres:5432/app
    Then recreate the container
      $ cd ~/shop && docker compose up -d api
```

You can reproduce this with [examples/broken-compose](examples/broken-compose).

## Install

```sh
brew install sirius-star42/tap/waypoint        # macOS and Linux
go install github.com/Sirius-Star42/waypoint/cmd/waypoint@latest
```

Prebuilt binaries for Linux and macOS (amd64, arm64) are on the
[releases page](https://github.com/Sirius-Star42/waypoint/releases). It's a single static binary
with no dependencies.

## Usage

```sh
waypoint                        # sites, the apps behind them, how each runs, and what's broken
waypoint 8080                   # why isn't localhost:8080 working?
waypoint api.example.com        # follow a domain through nginx to the app
waypoint https://x.dev/api/v1   # trace one URL, including which location block matches
waypoint map --open             # the same as a diagram in your browser
waypoint map --mermaid          # the same as Mermaid, to paste into a README
```

| Flag | |
|---|---|
| `-v` | show evidence and full logs for every problem |
| `--timeout 3s` | timeout for each network check |
| `--nginx path` | use this nginx.conf instead of auto-detecting |

Exit code: `0` all good, `1` problems found, `2` waypoint itself failed. Works in scripts and CI.

There is no config file. Run it on your laptop or over SSH on a server; use `sudo` on servers so it
can see processes of every user. Without nginx, `waypoint` still lists and checks every app on the machine.

## What it finds

**nginx**
- which `server` and `location` a URL really hits, using nginx's own matching order (exact,
  longest prefix, `^~`, regex in order, wildcard and regex `server_name`, `default_server`)
- upstreams with nothing listening, dead `upstream {}` members, missing `root`/`alias` directories
- a `server_name` defined twice on a port (nginx silently ignores the second one)
- a config that fails `nginx -t`, meaning nginx won't come back after a reload or reboot
- expired, soon-to-expire or wrong-name TLS certificates
- TLS versions each site really accepts, flagging deprecated TLS 1.0/1.1 (RFC 8996) with the `ssl_protocols` line to change
- nginx in Docker pointing at `localhost`, or at a container on another network

**every app on the machine**
- how it runs: systemd unit and unit file, compose project and file, container and image, or a
  bare process with its command, folder and user, plus the command to restart it or follow its logs
- which sites lead to it, and apps no nginx route points to (often a forgotten or moved app)
- processes started by hand that won't survive a reboot, and databases listening on all interfaces
- crashed systemd services, even ones that don't hold a port
- stopped compose projects and old containers, with when they stopped

**apps behind nginx**
- the owner of each upstream port: process, systemd unit or container
- crashed or failed systemd services, with their last journal lines
- stopped, crash-looping and unhealthy containers, with the last log lines and what the exit code means
- a port mapped to the wrong container port, or a running container where nothing answers on it
- a port taken by another process that your compose service expects
- `DATABASE_URL`-style settings pointing at `localhost` inside a container

When several things fail, waypoint follows the chain (nginx → app → database) and reports the
deepest real failure as the root cause and the others as side effects.

## How it works

```
nginx config ──► routes ──► probes ──► evidence ──► rules ──► root cause + fix
 (nginx -T,        (server,    (TCP, HTTP,   (process, container,
  files, or         location,   TLS, DNS)     systemd unit, compose
  a container)      upstream)                 dependencies, logs)
```

- The config comes from `nginx -T` when possible, which prints exactly what nginx runs. Otherwise
  waypoint parses the files and their `include`s, or reads them from a running nginx container.
- Diagnosis is deterministic. Every conclusion comes from a rule over collected evidence, and the
  evidence is printed so you can check it. No AI guesses.
- waypoint only reads. It never restarts, edits or kills anything. Fixes are printed for you to run.
- It doesn't need root. When it can't see something (another user's process, the journal), it says
  so and tells you to run it with `sudo`.

Supported platforms: Linux and macOS. On Linux, port owners and systemd units come from `/proc`.
On macOS they come from `lsof`. Docker is used through the `docker` CLI, so Docker Desktop, Colima,
OrbStack and plain dockerd all work.

## Contributing

Bug reports with a (sanitized) nginx config that waypoint gets wrong are the most useful
contribution. Add the config to `internal/nginx/testdata` together with a test case.

```sh
go test ./...
```

## License

MIT
