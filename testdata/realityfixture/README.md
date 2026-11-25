# Local recovery fixture

This separate module builds a maintained REALITY server for the core's
`reliability_protocol` tests. Its dependency graph does not enter the shipped
Mihomo module. The server, TLS cover destination and HY2 fault tests use only
loopback sockets. The helper emits a public key and listening address; its
private key is ephemeral and never printed. Stdin EOF terminates the process,
with an additional four-minute hard limit. The test owner also bounds and waits
for the helper process.

Build with the repository's qualified Go toolchain, then supply the binary:

```sh
go build -C testdata/realityfixture -mod=readonly -o /tmp/reality-fixture .
YUELINK_REALITY_FIXTURE=/tmp/reality-fixture go test -race -tags reliability_protocol ./adapter/outboundgroup
```

The REALITY configuration follows Xray's `GetREALITYConfig`, including disabled
server session tickets. The independent cover server is not a public trusted
website. Discovery readiness is explicitly bounded before test admission. This
fixture proves the local protocol and recovery boundary, not real carrier
quality or the behavior of public probe destinations.

Thirty alternating control/candidate pairs per automatic group hold the primary
node's past-health state constant while its actual TCP port refuses connections.
The secondary node has a successful real strict-204 measurement. The recorded
primary/alternate counts are proxy-level `DialContext` calls, not SYN counts.
The native dialer can use multiple DNS addresses or dual-stack sockets. Each
candidate success includes an application echo; an already-open REALITY stream
is checked after every pair. The fixture provider's background health callback
is counted without launching a new campaign, so this experiment isolates new
dials and does not measure health-check scheduling.

The HY2 server API and certificate digest pin follow YueLink's existing
`TestSubscriptionHysteria2ObfsRoundTrip`. Existing healthy obfuscation evidence
is reused. These tests add a distinct UDP blackhole endpoint, ordinary automatic
selection of a healthy TCP/REALITY member, target-only UDP failure, and survival
of an existing HY2 TCP stream. HY2 does not advertise optional retry support.

The production extension remains disabled by default. Both group
`advisory-retry: true` and a valid lease with `retry: true` are required. The
extension allows at most one alternate within the caller's remaining deadline
and six seconds. Only native TCP VLESS connect errors explicitly proven to
precede application data qualify. TLS/REALITY handshake errors, transport
wrappers, custom dialers, UDP and first-write failures do not qualify. No
application payload is replayed. These local results alone do not authorize
shipping enabled defaults or claiming customer latency improvement.
