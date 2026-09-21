# Volga relay authentication recovery

Follow-up to p1neappleXpress/OpenFlux#79, covering the HTTP relay 401 path
reported in #64. This does not establish a production fix without a real run
beyond the original approximately four-hour expiry window.

## Refresh contract

The relay and WebSocket share one credential state. Every HTTP attempt/socket
captures an immutable credential generation and a completed-refresh ticket.
One refresh may run at a time; network I/O occurs outside the state mutex.
Concurrent callers share the attempt's completion/result, including failure.
Requests captured before a failed attempt do not start sequential reauthorizations.
A new request captured after failure can try again. There is no permanent failed
state, cooldown scheduler, or additional singleflight dependency.

Only an explicit HTTP 401 causes relay refresh and at most **one retry** of the
same encoded logical packet batch. The request is rebuilt with fresh token,
request path, referer, cookies and payload user ID. Another 401 ends that send;
403, 429, 5xx and ambiguous network errors are not retried. Public `Send` remains
asynchronous. Packet/logical-batch counters count recovered delivery once.

A successful refresh also invalidates a live WebSocket. Its existing run loop
reconnects using the shared new generation; an old socket's failure cannot
refresh an already replaced generation again. Stop/context cancellation ends
waiters and socket I/O; authorization has a shared lifecycle context and a
30-second overall deadline, independent of an individual waiter's cancellation.

## Cookie/client concurrency audit

PR #79 replaced shared `http.Client.Jar` while workers could be in `Do`.
The auth mutex did not protect the HTTP client's reads of that field.

Shared client configuration is now fixed. Each HTTP attempt makes a local client
copy and binds the jar from its credential snapshot. The transport/connection
pool is still shared. This preserves both explicit auth cookies and automatic
`Set-Cookie` handling, whose removal is not justified by the available protocol
contract. The production `cookiejar.Jar` supports concurrent access. Old requests
can finish updating their old jar without contaminating a new generation's jar.
Credential/cookie values are copied on publication; the per-generation jar's
internal cookie updates are intentionally separate from these immutable values.

Each response body is closed, including 401 and retry responses. Discarding an
unneeded body is limited to 64 KiB and bounded by the request timeout/context;
small drained responses can reuse the underlying connection.

## Session state audit

The following choices follow the current request construction and receive path,
not an unverified assertion of a published Volga protocol contract:

| State | Decision | Reason |
| --- | --- | --- |
| `frontier` | Preserve | The receive path records document operation IDs from incoming bundles, including other users. Refreshing credentials for the same document does not erase its causal history. |
| `bundleID` | Preserve, monotonically increasing | Client-generated bundle identity, not supplied by authorization. Reset could collide with still-in-flight or previously accepted bundles. |
| `seq` | Preserve, monotonically increasing | Operation IDs combine the current user ID and this counter. Rebuild the user-ID component on retry; do not reuse IDs if authorization returns the same user ID. |
| `localID` | Preserve, monotonically increasing | Local operation identity is not returned by authorization. Reset would reuse identifiers while old-generation requests may still complete. |

Retries allocate new operation/bundle IDs because the previous request was
explicitly rejected. Their encoded packet batch is unchanged. Tests cover the
preserved frontier/counters and new user ID across a refresh. No reset or wire
protocol extension is introduced; these choices still need long-run validation.

`PROACTIVE_REFRESH = NotImplementedBecauseTTLContractNotProven`.
The existing TTL value is still forwarded during authorization; no timer or
assumption about its units or expiry reference is added.

## Tests and remaining acceptance

Tests use synthetic credentials, fake HTTP transports and loopback HTTP/WS
servers only. They cover normal 200/204, 401 recovery/error/repeated rejection,
non-auth statuses, ambiguous network errors, 100 concurrent callers on both
successful and failed refresh, later recovery after failure, WS/HTTP coalescing,
live WS invalidation, coherent fresh credentials, cookie-jar concurrency,
cancellation/Stop, bounded body disposal, statistics and auth log sanitization.

After review, run a disposable Volga setup for more than four hours: observe real
expiry, continued relay and WS traffic without manual restart, repeated 401 or
reconnect storms, significant packet outage or unbounded memory growth.
Integration with #85/#87 on a real iPhone is a separate validation phase.
Cups.online and other transports are unchanged by this follow-up.
