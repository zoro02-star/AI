---
name: caido
description: Caido proxy control from the terminal — headless caido-cli instance management, GraphQL API (history search with HTTPQL, replay, automate, findings, scope, intercept), proxying tools through Caido, token auth setup. Use for ANY task involving Caido, HTTP history review, replaying requests through the proxy, reading proxied traffic programmatically, or when the user mentions Caido/caido-cli/proxy history. Replaces Burp Suite workflows.
---

# CAIDO CLI CONTROL

Drive a headless Caido instance entirely from the terminal: start/stop it, query its GraphQL API (history, replay, findings, scope, intercept), and route any tool's traffic through its proxy.

Verified against local install: `caido-cli` at /usr/local/bin, schema introspected 2026-08. Desktop app (`/usr/bin/caido`) is NEVER used — headless only.

> **Shared layer (bb-common):** Caido is a *proxy/evidence* tool — it doesn't
> itself decide scope. Before sending any request through it, validate the target
> with `bb-common/safe_scope.py` and confirm tool availability with
> `bb-common/capabilities.py` (`~/.config/opencode/skills/bb-common/scripts/`).

---

## 1. INSTANCE MANAGEMENT

### Start (standard command — user's preferred flags)

```bash
# Headless instance: proxy on 0.0.0.0:8081, UI/API on 127.0.0.1:8080
nohup caido-cli --proxy-listen 0.0.0.0:8081 --ui-listen 127.0.0.1:8080 \
  > /tmp/caido.log 2>&1 & echo "PID: $!"
```

### Useful extra flags

| Flag | Purpose |
|---|---|
| `--invisible` | Hide listeners from targets (anti-detection) |
| `--no-sync` | Disable cloud sync |
| `--allow-guests` | Allow guest login |
| `--data-path <DIR>` | Custom data directory |
| `CAIDO_REGISTRATION_KEY=ckey_...` | Env var to auto-register to workspace |

### Health checks

```bash
pgrep -f caido-cli                          # running?
curl -s http://127.0.0.1:8080/graphql -X POST -H 'Content-Type: application/json' \
  -d '{"query":"{__typename}"}'             # -> {"data":{"__typename":"QueryRoot"}}
curl -sx http://127.0.0.1:8081 http://example.com -o /dev/null -w "%{http_code}\n"  # proxy alive -> 200
```

- UI: http://127.0.0.1:8080
- Proxy: `127.0.0.1:8081` (bound 0.0.0.0 → reachable from LAN/VMs)
- Data dir: `~/.local/share/caido/` (config.db, projects.db, secrets.db, plugins.db)
- Stop: `pkill -f 'caido-cli'`

---

## 2. AUTHENTICATION (one-time + refresh)

The GraphQL API requires `Authorization: Bearer <accessToken>`. Cloud PATs (`caido_...`) DO NOT work — you need the session access token.

**One-time setup** (token expires ~7 days, redo when it does):

1. Open http://127.0.0.1:8080 in browser, log in.
2. DevTools console (`Ctrl+Shift+I`) → run:
   ```js
   JSON.parse(localStorage.CAIDO_AUTHENTICATION).accessToken
   ```
3. Save it:
   ```bash
   mkdir -p ~/.config/caido && echo -n '<TOKEN>' > ~/.config/caido/token && chmod 600 ~/.config/caido/token
   ```

Expired-token signature in API responses:
```json
{"errors":[{"extensions":{"CAIDO":{"reason":"INVALID_TOKEN","code":"AUTHORIZATION"}}}]}
```
→ tell the user to re-grab the token (step 2).

Schema introspection works WITHOUT auth — only data queries need the token.

---

## 3. GQL HELPER (use this for every API call)

Companion script at `~/.config/opencode/skills/caido/caidoq.sh`:

```bash
G=~/.config/opencode/skills/caido/caidoq.sh
$G '{ __typename }'                                  # simple query
echo '<query>' | $G                                  # via stdin
$G 'query($n:Int!){requestsByOffset(limit:$n){edges{node{id host method path}}}}' '{"n":5}'
```

Reads token from `~/.config/caido/token` or `$CAIDO_TOKEN`; endpoint override via `$CAIDO_URL`.

**Key schema facts (verified by introspection):**
- Root types are `QueryRoot` / `MutationRoot` (introspect those names, not `Query`)
- `Blob` scalar = **base64-encoded string** — decode with `base64 -d`
- History filter arg is `filter: HTTPQLInput` = `{code: "<HTTPQL string>"}`

---

## 4. CORE RECIPES

### Search HTTP history (HTTPQL filter)

```bash
G=~/.config/opencode/skills/caido/caidoq.sh
# Latest 10 requests containing "admin" anywhere:
$G 'query($q:String!,$l:Int!){
  requestsByOffset(limit:$l, filter:{code:$q}, order:{by:CREATED_AT, ordering:DESC}){
    edges{node{id host method path isTls port createdAt response{id statusCode}}}
  }}' '{"q":"req.raw.cont:\"admin\"","l":10}' | jq .
# order: {by: CREATED_AT|HOST|METHOD|PATH|RESP_STATUS_CODE|RESP_LENGTH|..., ordering: ASC|DESC} (both required)
```

Response fields available: `id statusCode length roundtripTime raw(Blob)`.
Request fields: `id host method path query length port isTls sni fileExtension source alteration edited createdAt raw(Blob) response metadata`.

### Read full raw request/response of one item

```bash
$G '{ request(id:"<REQ_ID>"){ raw response { statusCode raw roundtripTime } } }' \
  | jq -r '.data.request.raw' | base64 -d          # request bytes
# same for .data.request.response.raw
```

### Send an arbitrary raw request through Caido

```bash
RAW=$(printf 'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n' | base64 -w0)
$G 'mutation($in:CreateRequestInput!){ createRequest(input:$in){ id } }' \
  "{\"in\":{\"host\":\"example.com\",\"method\":\"GET\",\"path\":\"/\",\"port\":80,
     \"isTls\":false,\"query\":\"\",\"source\":\"SAMPLE\",\"raw\":\"$RAW\"}}"
```
(`Source` enum: AUTOMATE INTERCEPT REPLAY WORKFLOW SAMPLE PLUGIN IMPORT. The created Request appears in history; fetch its `response{raw}` after.)

### Replay (like Burp Repeater)

```bash
# 1. Create session from an existing history request:
$G 'mutation($id:ID!){ createReplaySession(input:{requestSource:{id:$id}, kind:HTTP}){
       session{ ...on ReplaySessionHttp{ id activeEntry{ id } } } }}' '{"id":"<REQ_ID>"}'
# 2. Fire it:
$G 'mutation{ startReplayTask(sessionId:"<SESSION_ID>"){ task{ id sessionKind
       replayEntry{ id } } } }'
# 3. Poll result (entry's request/response land as normal Request objects):
$G '{ replayEntry(id:"<ENTRY_ID>", sessionKind:HTTP){ ...on ReplayEntryHttp{
       request{ id response{ statusCode raw } } } } }'
```
Kinds: `HTTP`, `HTTP_ONE_PIPELINE`, `WS`. Edit before send via `updateReplayEntryDraft(id, input)` then re-run step 2.

### Findings (notes attached to requests)

```bash
$G '{ findings(first:20){ edges{node{id title description host path reporter request{id}}}}}'
$G 'mutation($rid:ID!){ createFinding(requestId:$rid, input:{
       title:"SQLi in q", description:"UNION-based confirmed", reporter:"manual"}){ finding{ id } }}' \
  '{"rid":"<REQ_ID>"}'
```

### Scope

```bash
$G '{ scopes{ id name allowlist denylist indexed } }'
```
Update/delete via `updateScope(id,input)` / `deleteScope(id)` / `createScope(input)`. Requests outside scope still get logged but flagged — filtering by scope: add `scopeId:` arg to `requests`.

### Intercept control

```bash
$G '{ interceptStatus }'          # -> PAUSED | RUNNING
$G 'mutation{ pauseIntercept{ status } }'
$G 'mutation{ resumeIntercept{ status } }'
```

### Projects & environments

```bash
$G '{ projects{ id name } currentProject{ project{ id name } readOnly } }'
$G 'mutation{ selectProject(id:"<PROJECT_ID>"){ currentProject{ project{id name} } } }'
```

### Run a workflow on a request

```bash
$G '{ workflows { id name kind enabled } }'
$G 'mutation($w:ID!,$r:ID!){ runActiveWorkflow(id:$w, input:{requestId:$r}){ task{ id } } }' \
  '{"w":"<WF_ID>","r":"<REQ_ID>"}'
```

### Automate (like Burp Intruder)

Sessions/fuzzing live under `automateSessions`, `createAutomateSession`, `startAutomateTask`, `pause/resume/cancelAutomateTask`. Fetch results: `automateEntry(id){ requests(...) }` ordered by RESP_STATUS_CODE / RESP_LENGTH etc.

---

## 5. HTTPQL CHEAT SHEET (the filter language)

Syntax: `<namespace>.<field>.<operator>:<value>` combined with `AND`/`OR` (AND binds tighter; parens allowed).

Namespaces & fields:

| NS | Fields |
|---|---|
| `req` | `created_at ext host len method path port query raw tls` |
| `resp` | `code len raw roundtrip` |
| `row` | `id` |
| `preset` | filter preset alias/name directly |

Operators: `eq ne gt gte lt lte cont ncont like nlike regex nregex`
(`cont/ncont` case-insensitive; `regex` = Rust flavor, no lookahead; `eq/ne` on `ext` needs leading dot: `req.ext.eq:".js"`)

Ready-made queries:

```text
req.host.eq:"api.target.com"                       # one host
req.method.eq:"POST" AND resp.code.eq:"403"        # POSTs that got 403
resp.code.regex:"^30[12]" AND req.path.cont:"redirect"
req.ext.ncont:".js" AND req.ext.ncont:".css" AND req.ext.ncont:".png"   # no static
req.tls.eq:false                                    # plaintext traffic
resp.roundtrip.gt:1000                              # slow endpoints
(req.raw.cont:"token" OR resp.raw.cont:"jwt") AND req.method.ne:"OPTIONS"
row.id.gte:100 AND row.id.lte:200                   # row range
```

A bare string `"value"` expands to `(req.raw.cont:"value" OR resp.raw.cont:"value")`.

---

## 6. ROUTING TOOL TRAFFIC THROUGH CAIDO

Proxy listens on `127.0.0.1:8081` (and LAN via 0.0.0.0). CA cert: export from UI (Proxy → Intercept → CA Certificate) and trust it in the tool/OS for HTTPS interception.

```bash
export http_proxy=http://127.0.0.1:8081 https_proxy=http://127.0.0.1:8081
curl -x http://127.0.0.1:8081 https://target.com ...
~/go/bin/httpx -l subs.txt -http-proxy http://127.0.0.1:8081
ffuf -x http://127.0.0.1:8081 ...
nuclei -l urls.txt -proxy http://127.0.0.1:8081
katana -proxy http://127.0.0.1:8081 ...
sqlmap --proxy=http://127.0.0.1:8081 ...
```

Everything routed shows up in history → search/replay/findings via recipes above.

---

## 7. SCHEMA DISCOVERY (when you need more)

Introspection is open (no token):

```bash
$G '{__schema{types{name kind}}}'                    # all type names
$G '{__type(name:"ReplaySessionHttp"){fields{name type{name}}}}'
```

Full docs: https://docs.caido.io (Reference → HTTPQL/StreamQL), developer.caido.io (SDK).
75 root queries / 157 mutations exist — introspect before hand-writing anything exotic.

---

## 8. TROUBLESHOOTING

| Symptom | Fix |
|---|---|
| `INVALID_TOKEN` / `AUTHORIZATION` errors | Token expired (~7d). User re-grabs from UI localStorage → overwrite `~/.config/caido/token` |
| Connection refused on 8080/8081 | Instance not running → section 1 start command; check `/tmp/caido.log` |
| `Unknown field` errors | Wrong root/type name — roots are `QueryRoot`/`MutationRoot`; introspect first (section 7) |
| Raw looks like gibberish | Blob is base64 → `\| jq -r '.data...' \| base64 -d` |
| Proxy returns 200 for everything but no TLS detail | Install Caido CA cert in the client/browser |
| Port already in use | Another instance or desktop app running → `pkill -f caido`; desktop (`/usr/bin/caido`) must stay closed |

---

## 9. HUNT INTEGRATION (bug bounty glue)

Typical chain while hunting:

1. Route recon/exploit tools through proxy (section 6) so every request lands in history.
2. Mine history with HTTPQL for anomalies: `resp.code.eq:"500"`, unusual params `req.path.cont:"id="`, auth headers `req.raw.cont:"authorization"`.
3. Pull interesting pairs raw (section 4), analyze bodies offline.
4. Mutate & resend via Replay recipe; compare `statusCode`/`roundtripTime`/length.
5. Fuzz parameter sets via Automate; rank by `RESP_STATUS_CODE`/`RESP_LENGTH` outliers.
6. Pin confirmed issues with `createFinding` so they survive project switches.
