# bare-network-connect

**Models:** A package that phones home during install — a telemetry ping,
a version check — with no credential access and no child process
involved.

**Behavior:** One `connect(2)` to `203.0.113.7:443` (TEST-NET-3, RFC 5737,
reserved/unroutable). The connection fails inside the sandbox's network
namespace; the syscall is still captured. Nothing else.

**Exercises:** Rule 2 (network egress) in isolation — proves a standalone
connection is reported as **MEDIUM** and is *not* escalated to HIGH when
there is no credential-read finding to correlate it with. This is the
minimal counterpart to `faux-node-gyp`, which combines a connection with
subprocess launches; here neither the subprocess nor the credential
dimension is present, so only the plain MEDIUM finding should appear.

**Expected report:** Exactly one finding, `[MEDIUM] Network connection`,
naming `203.0.113.7:443`. No HIGH finding. OBSERVED shows 1 connection,
0 process launches.
