# Timeline — Sentinel Lab 08

## Investigation Timeline

| Time UTC | Activity | Result |
|---|---|---|
| 10:00 | Authentication from `198.51.100.25` | user1 failed |
| 10:01 | Authentication from `198.51.100.25` | user2 failed |
| 10:02 | Authentication from `198.51.100.25` | user3 failed |
| 10:03 | Authentication from `198.51.100.25` | user4 failed |
| 10:04 | Authentication from `198.51.100.25` | user1 succeeded |
| 10:05 | IP activity window reviewed | 5 events across 4 users |
| 10:06 | IP used as endpoint investigation pivot | Related endpoint activity identified |
| 10:07 | Endpoint activity observed | winword.exe → powershell.exe |
| 10:08 | Command line reviewed | Bypass + EncodedCommand identified |
| 10:10 | Identity and endpoint events correlated | 3-minute gap identified |
| 10:15 | Evidence assessment performed | Suspicious IP sequence identified |
| 10:20 | False-positive considerations reviewed | Legitimate infrastructure considered |
| 10:25 | Evidence gaps documented | Additional telemetry required |
| 10:30 | Final verdict assigned | Suspicious — IP Associated With Authentication Anomalies and Endpoint Activity |

---

## Key Event Sequence

    10:00
    198.51.100.25 → user1
    Authentication failed

    ↓

    10:01
    198.51.100.25 → user2
    Authentication failed

    ↓

    10:02
    198.51.100.25 → user3
    Authentication failed

    ↓

    10:03
    198.51.100.25 → user4
    Authentication failed

    ↓

    10:04
    198.51.100.25 → user1
    Authentication succeeded
    New York

    ↓ 3 minutes

    10:07
    198.51.100.25
    user1
    DESKTOP-LAB01
    winword.exe → powershell.exe
    -ExecutionPolicy Bypass
    -EncodedCommand

---

## IP Activity Window

**First Seen:** 10:00 UTC

**Last Seen:** 10:04 UTC

**Duration:** 4 minutes

**Total Authentication Events:** 5

**Targeted Users:** 4

**Failed Attempts:** 4

**Successful Attempts:** 1

---

## Investigation Milestones

### Initial IP Review

The source `198.51.100.25` was identified as the primary investigation pivot.

### User Analysis

Four different accounts were associated with the source.

### Authentication Analysis

Four failures were followed by one successful authentication for `user1`.

### Location Analysis

The successful authentication was associated with New York.

### Endpoint Pivot

The same source IP was associated with endpoint activity on `DESKTOP-LAB01`.

### Process Analysis

The endpoint event showed:

    winword.exe → powershell.exe

### Command-Line Analysis

PowerShell was executed with:

    -ExecutionPolicy Bypass
    -EncodedCommand

### Cross-Source Correlation

The endpoint event occurred three minutes after the successful authentication.

### Evidence Assessment

The sequence was classified as suspicious, but malicious intent and compromise remained unconfirmed.

---

## Evidence Summary

| Evidence | Status |
|---|---|
| Five authentication events from the IP | Confirmed |
| Four failed authentication attempts | Confirmed |
| Four targeted users | Confirmed |
| One successful authentication | Confirmed |
| user1 succeeded after a failed attempt | Confirmed |
| New York associated with successful authentication | Confirmed |
| Same IP associated with endpoint activity | Confirmed |
| PowerShell execution | Confirmed |
| winword.exe parent process | Confirmed |
| `-ExecutionPolicy Bypass` | Confirmed |
| `-EncodedCommand` | Confirmed |
| Three-minute authentication-to-endpoint interval | Confirmed |
| IP is malicious | Unknown |
| Authentication was unauthorized | Unknown |
| PowerShell activity was malicious | Unknown |
| Account compromise | Unknown |
| Endpoint impact | Unknown |

---

## Final Assessment

**Verdict:** Suspicious — IP Associated With Authentication Anomalies and Endpoint Activity

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Primary Evidence Chain:**

    198.51.100.25
    →
    Four authentication failures
    →
    Four users targeted
    →
    user1 successful authentication
    →
    3 minutes
    →
    winword.exe → powershell.exe
    →
    Bypass + EncodedCommand

**Evidence Gap:**

No threat-intelligence, VPN or proxy context, MFA, Conditional Access, sign-in risk, PowerShell Script Block, network, file, child-process, or endpoint-security telemetry was available.

**Final SOC Principle:**

> **Pivot on the indicator, correlate the evidence, and avoid treating the indicator itself as the verdict.**
