# source — telemetry acquisition

Two `EventSource` implementations behind one interface (`source.go`):

- **`replay.go`** — reads a `.jsonl` trace, streams `NormalizedEvent`s. Cross-platform;
  drives every automated test. This is the "record ETW once, replay forever" fixture path.
- **`etw_windows.go`** (`//go:build windows`) — real userland ETW consumer via
  [`0xrawsec/golang-etw`](https://github.com/0xrawsec/golang-etw). No kernel driver.
  `etw_stub.go` provides a non-Windows `NewETWSource` that returns an error.

## Why 0xrawsec/golang-etw

Chosen over `bi-zone/etw` because it ships a real-time consumer with a parsed-event
callback (`Consumer.EventCallback(*etw.Event)`) that exposes `EventData` as a decoded
property map — we don't have to hand-roll TDH property parsing. Pure-Go, cgo-free
(keeps the single-static-exe promise), maintained, MIT.

## Manual Windows-VM smoke test (not in CI — ETW can't run on WSL2/Linux)

ETW requires Windows and an **elevated** process (`EnableProvider` fails otherwise).

1. On a Windows 10/11 VM, build the agent:
   ```
   set CGO_ENABLED=0
   go build -o nitewatch.exe ./cmd/nitewatch
   ```
2. Run elevated (Admin prompt), serving the dashboard:
   ```
   nitewatch.exe --serve
   ```
3. Open a browser to a couple of sites, then visit `http://127.0.0.1:8973`.
4. **Expected:** the "Who's talking?" table fills with rows attributed to
   `browser.exe` (or `chrome.exe`/`msedge.exe`), each with a resolved domain joined
   from the DNS-Client provider — not just a bare IP.
5. **Provider-name caveat:** `EventData` field names vary by Windows build
   (e.g. Kernel-Network uses `daddr`/`dport`; some builds differ). If domains or
   IPs come through empty, dump one raw `*etw.Event` in `normalize` and adjust the
   `str/u16` keys. This is the first thing to check on a new Windows version.
