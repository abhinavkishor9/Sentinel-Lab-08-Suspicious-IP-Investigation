# Investigation Notes 

## Evidence Reviewed

The investigation reviewed:

- Authentication timestamps.
- User accounts.
- Source IP.
- Authentication results.
- Authentication locations.
- First and last observed activity.
- Endpoint source IP.
- Parent process.
- PowerShell process.
- Command-line parameters.

---

## IP Activity Summary

The source `198.51.100.25` generated:

| Metric | Result |
|---|---:|
| Total events | 5 |
| Failed authentication attempts | 4 |
| Successful authentication attempts | 1 |
| Targeted users | 4 |
| First Seen | 10:00 UTC |
| Last Seen | 10:04 UTC |
| Activity Duration | 4 minutes |

The activity was highly concentrated in a short time window.

---

## User Analysis

The IP was associated with four accounts:

| User | Attempts | Failed | Successful |
|---|---:|---:|---:|
| `user1@sentinellab.local` | 2 | 1 | 1 |
| `user2@sentinellab.local` | 1 | 1 | 0 |
| `user3@sentinellab.local` | 1 | 1 | 0 |
| `user4@sentinellab.local` | 1 | 1 | 0 |

The source therefore interacted with multiple accounts.

---

## Authentication Sequence

Observed activity:

    10:00
    user1 — Failed

    10:01
    user2 — Failed

    10:02
    user3 — Failed

    10:03
    user4 — Failed

    10:04
    user1 — Success

The successful event occurred immediately after four failed attempts against different users.

---

## Failure-to-Success Analysis

The source produced:

    4 failed authentications
    +
    1 successful authentication

The successful authentication belonged to:

`user1@sentinellab.local`

This pattern is suspicious, but the available evidence does not identify the actor or establish malicious intent.

---

## Location Analysis

The source was associated with:

    Unknown
    New York

The successful authentication for `user1` was associated with New York.

Location was treated as supporting context rather than proof of malicious activity.

---

## Endpoint Analysis

The IP was then used as a pivot into endpoint activity.

The relevant event was:

| Field | Value |
|---|---|
| Time | 10:07 UTC |
| Computer | `DESKTOP-LAB01` |
| User | `user1` |
| Source IP | `198.51.100.25` |
| Parent Process | `winword.exe` |
| Process | `powershell.exe` |

Observed command line:

    powershell.exe -ExecutionPolicy Bypass -EncodedCommand ...

---

## Command-Line Assessment

The endpoint event contained:

    -ExecutionPolicy Bypass

and:

    -EncodedCommand

These are suspicious characteristics that justify additional investigation.

They were not treated as independent proof of malicious execution.

---

## Authentication-to-Endpoint Correlation

Successful authentication:

    10:04 UTC

Endpoint activity:

    10:07 UTC

Time difference:

**3 minutes**

The events share:

    user1
    DESKTOP-LAB01
    198.51.100.25

This creates the strongest cross-source relationship in the investigation.

---

## Complete Investigation Sequence

    10:00–10:03
    Four failed authentication attempts
    Four different users
    198.51.100.25

              ↓

    10:04
    Successful authentication
    user1
    198.51.100.25
    New York

              ↓ 3 minutes

    10:07
    user1
    DESKTOP-LAB01
    198.51.100.25
    winword.exe → powershell.exe
    Bypass + EncodedCommand

---

## Evidence Classification

### Confirmed

- `198.51.100.25` generated five authentication events.
- Four authentication attempts failed.
- Four different users were targeted.
- `user1` later authenticated successfully from the same source.
- The successful authentication was associated with New York.
- The same source IP appeared in endpoint activity.
- Endpoint activity was associated with `user1`.
- The endpoint was `DESKTOP-LAB01`.
- `winword.exe` launched PowerShell.
- `-ExecutionPolicy Bypass` was present.
- `-EncodedCommand` was present.
- Endpoint activity occurred three minutes after successful authentication.

### Plausible

- The authentication and endpoint activity may be related.
- The source may represent suspicious authentication activity.
- The sequence may be consistent with unauthorized activity.

### Unknown

- Whether the IP is attacker-controlled.
- Whether the successful authentication was unauthorized.
- Whether the account was compromised.
- Whether the PowerShell command was malicious.
- Whether a payload executed.
- Whether additional hosts or accounts were affected.
- Whether data was accessed or exfiltrated.

---

## Investigation Verdict

**Suspicious — IP Associated With Authentication Anomalies and Endpoint Activity**

The evidence supports further investigation but does not establish confirmed compromise.

---

