# Sentinel Lab 08 — Suspicious IP Investigation

## Overview

This lab investigates a source IP address associated with multiple authentication events and subsequent endpoint activity.

The investigation focuses on `198.51.100.25` and examines how the IP interacts with different user accounts, authentication results, locations, and endpoints. The goal is to determine whether the observed behavior represents a meaningful security concern rather than treating the IP address itself as proof of malicious activity.

> **Investigation principle:** An IP address is an investigation pivot, not a verdict.

---

## Investigation Scenario

The source IP `198.51.100.25` appears in several authentication events over a short period. Four different users experience failed authentication attempts from the source, followed by a successful authentication for `user1@sentinellab.local`.

Shortly afterward, the same source IP is associated with suspicious PowerShell activity on `DESKTOP-LAB01`. The PowerShell process is launched by `winword.exe` and includes `-ExecutionPolicy Bypass` and `-EncodedCommand`.

The investigation therefore examines the IP across both identity and endpoint activity to determine whether the events form a meaningful security sequence.

---

## Lab Objectives

- Investigate an IP address across multiple security events.
- Measure authentication activity associated with the source.
- Identify affected users and endpoints.
- Analyze failed and successful authentication attempts.
- Examine the failure-to-success pattern.
- Review the time window in which the IP was active.
- Correlate the IP with endpoint activity.
- Evaluate the significance of suspicious PowerShell execution.
- Consider legitimate explanations for shared or unusual IP activity.
- Determine an evidence-based investigation verdict.

---

## Environment

| Component | Details |
|---|---|
| Platform | Microsoft Sentinel |
| Workspace | `Microsoft-Sentinel-Workspace` |
| Query Language | KQL |
| Data Type | Synthetic telemetry |
| Primary IP | `198.51.100.25` |
| Primary User | `user1@sentinellab.local` |
| Primary Host | `DESKTOP-LAB01` |
| Investigation Date | 2026-09-18 |

---

## Data Source

Persistent identity and endpoint telemetry was not available for this investigation.

Synthetic authentication and endpoint data was therefore created using KQL `datatable()`.

The datasets are temporary and exist only within the queries where they are defined. They are used for investigation and learning purposes and do not represent production telemetry.

---

## Investigation Workflow

The investigation followed these stages:

1. Review the authentication dataset.
2. Pivot on the suspicious IP.
3. Determine the IP's first and last observed activity.
4. Count failed and successful authentication attempts.
5. Identify the users targeted by the IP.
6. Review the failure-to-success sequence.
7. Examine locations associated with the IP.
8. Pivot from the IP into endpoint activity.
9. Correlate identity and endpoint events.
10. Assess the complete evidence chain and limitations.

---

## Step 1 — Review Authentication Activity

The initial authentication review identified activity involving the source IP `198.51.100.25`.

The IP was associated with:

- Four failed authentication attempts.
- One successful authentication.
- Four distinct user accounts.
- Two observed locations: `Unknown` and `New York`.

---

## Step 2 — Determine the IP Activity Window

The following values were observed for `198.51.100.25`:

| Field | Result |
|---|---|
| First Seen | 2026-09-18 10:00 UTC |
| Last Seen | 2026-09-18 10:04 UTC |
| Event Count | 5 |
| Activity Duration | 4 minutes |

The activity was therefore concentrated within a short four-minute interval.

---

## Step 3 — Identify Users Associated With the IP

The source interacted with four accounts:

| User | Attempts | Failed | Successful |
|---|---:|---:|---:|
| `user1@sentinellab.local` | 2 | 1 | 1 |
| `user2@sentinellab.local` | 1 | 1 | 0 |
| `user3@sentinellab.local` | 1 | 1 | 0 |
| `user4@sentinellab.local` | 1 | 1 | 0 |

This shows that the IP interacted with multiple user accounts rather than only one.

---

## Step 4 — Review the Authentication Sequence

The activity from the IP occurred in the following order:

| Time UTC | User | Result |
|---|---|---|
| 10:00 | `user1@sentinellab.local` | Failed |
| 10:01 | `user2@sentinellab.local` | Failed |
| 10:02 | `user3@sentinellab.local` | Failed |
| 10:03 | `user4@sentinellab.local` | Failed |
| 10:04 | `user1@sentinellab.local` | Success |

The sequence shows four failed authentications against different accounts followed by a successful authentication for `user1`.

This pattern is suspicious, but the synthetic dataset alone does not establish the intent of the source.

---

## Step 5 — Review Users by Result

The result-based analysis showed:

| ResultType | User Count | Users |
|---|---:|---|
| `50126` | 4 | user1, user2, user3, user4 |
| `0` | 1 | user1 |

This confirms that:

- Four users experienced failed authentication.
- Only `user1` later authenticated successfully from the source.

Because the failures involve multiple users, the activity is more consistent with a multi-account authentication pattern than the single-user pattern observed in earlier labs.

---

## Step 6 — Review Location Context

The IP was associated with:

    Unknown
    New York

The successful authentication for `user1` was associated with:

    New York

The location information provides additional context but should not be treated as proof that the source is malicious.

---

## Step 7 — Pivot From the IP to Endpoint Activity

The same source IP was searched in the endpoint dataset.

The relevant endpoint event was:

| Field | Value |
|---|---|
| Time | 2026-09-18 10:07 UTC |
| Computer | `DESKTOP-LAB01` |
| User | `user1` |
| Source IP | `198.51.100.25` |
| Parent Process | `winword.exe` |
| Process | `powershell.exe` |

Command line:

    powershell.exe -ExecutionPolicy Bypass -EncodedCommand ...

This event links the suspicious IP to endpoint activity associated with `user1`.

---

## Step 8 — Correlate Authentication and Endpoint Activity

The successful authentication occurred at:

**10:04 UTC**

The endpoint event occurred at:

**10:07 UTC**

Observed difference:

**3 minutes**

Both events involve:

- `user1`
- `DESKTOP-LAB01`
- `198.51.100.25`

The resulting sequence is:

    10:00–10:03
    Four failed authentication attempts
    Multiple users
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
    winword.exe → powershell.exe
    ExecutionPolicy Bypass + EncodedCommand

This is the strongest correlation in the investigation.

---

## Primary Finding

The source IP `198.51.100.25` was observed interacting with four user accounts within a four-minute window.

The activity included:

- Four failed authentication attempts.
- One successful authentication.
- Four targeted users.
- A successful authentication for `user1`.
- Subsequent endpoint activity for `user1`.
- A three-minute gap between successful authentication and endpoint activity.
- Suspicious PowerShell execution from `winword.exe`.

The combined sequence warrants further investigation.

---

## Investigation Verdict

**Verdict: Suspicious — IP Associated With Authentication Anomalies and Endpoint Activity**

The IP demonstrates a suspicious authentication pattern and is subsequently associated with suspicious endpoint execution.

However, the IP itself should not be classified as malicious solely from this dataset.

---

## Evidence Assessment

| Evidence | Assessment |
|---|---|
| IP generated five authentication events | Confirmed |
| Four failed authentication attempts | Confirmed |
| Four different users targeted | Confirmed |
| One successful authentication | Confirmed |
| `user1` succeeded after a failed attempt | Confirmed |
| IP associated with New York for successful login | Confirmed |
| Same IP associated with endpoint activity | Confirmed |
| `winword.exe` launched PowerShell | Confirmed |
| `-ExecutionPolicy Bypass` present | Confirmed |
| `-EncodedCommand` present | Confirmed |
| Three-minute auth-to-endpoint interval | Confirmed |
| IP is attacker-controlled | Unknown |
| Successful authentication was unauthorized | Unknown |
| PowerShell activity was malicious | Unknown |
| Account compromise | Unknown |
| Additional system impact | Unknown |

---

## False-Positive Considerations

Potential legitimate explanations include:

- VPN gateways.
- Proxy infrastructure.
- Corporate NAT.
- Shared internet connections.
- Security scanners.
- Automated applications.
- Administrative activity.
- Incorrect IP geolocation.

The IP should therefore be investigated using ownership, reputation, network context, and additional security telemetry.

---

## Evidence Gaps

The investigation did not contain:

- Threat intelligence reputation.
- IP ownership or WHOIS information.
- VPN or proxy identification.
- MFA results.
- Conditional Access results.
- Authentication method.
- Sign-in risk.
- Device identity.
- PowerShell Script Block Logging.
- Child-process activity.
- Network connections.
- File activity.
- Endpoint detection alerts.
- Decoded PowerShell command content.

---

## MITRE ATT&CK

**T1059.001 — Command and Scripting Interpreter: PowerShell**

The endpoint activity involves PowerShell execution.

The technique mapping describes the observed execution mechanism and does not independently prove malicious activity.

---

## Key SOC Lesson

An IP address becomes more useful as an investigation pivot when its activity is correlated across different telemetry sources.

In this lab:

**IP → multiple users → authentication anomalies → successful authentication → endpoint activity**

This provides more investigative context than simply labeling an IP as suspicious.

---

## Lab Outcome

This investigation demonstrated how to:

- Pivot on a source IP.
- Measure the IP's activity window.
- Identify affected users.
- Analyze authentication results.
- Detect a failure-to-success sequence.
- Correlate the IP with endpoint activity.
- Build an evidence-based investigation timeline.
- Document uncertainty and evidence gaps.

---

## Conclusion

The investigation identified `198.51.100.25` as a source associated with four failed authentication attempts against four users, followed by successful authentication for `user1`. Three minutes later, the same IP was associated with PowerShell execution on `DESKTOP-LAB01`, where `winword.exe` launched PowerShell with `-ExecutionPolicy Bypass` and `-EncodedCommand`.

The combined activity is suspicious and warrants further investigation, but the available synthetic telemetry does not establish that the IP is malicious, that the authentication was unauthorized, or that the endpoint was compromised.
