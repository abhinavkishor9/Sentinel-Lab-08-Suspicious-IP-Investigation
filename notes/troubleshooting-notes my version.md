# Troubleshooting Notes 

## Issue 1 — Persistent Authentication Telemetry Was Unavailable

### Problem

The Sentinel workspace did not contain the persistent authentication telemetry required for this investigation.

### Resolution

Synthetic authentication data was created using KQL `datatable()`.

This allowed the IP investigation to proceed without presenting simulated events as production telemetry.

---

## Issue 2 — Persistent Endpoint Telemetry Was Unavailable

### Problem

Endpoint telemetry required for correlating the source IP with process activity was not available in the workspace.

### Resolution

A synthetic endpoint dataset was created containing:

- Time.
- Computer.
- User.
- Source IP.
- Parent process.
- Process.
- Command line.

---

## Issue 3 — Synthetic Data Is Temporary

### Problem

The KQL `datatable()` exists only within the query where it is defined.

It does not create a permanent Sentinel table.

### Resolution

The relevant synthetic dataset must be defined again when running another independent query.

This keeps the investigation reproducible and makes the telemetry limitation explicit.

---

## Issue 4 — IP Activity Was Limited to a Four-Minute Window

### Observation

The source was first seen at:

    10:00 UTC

and last seen at:

    10:04 UTC

### Resolution

The activity window was documented as four minutes.

The short duration was treated as a contextual indicator rather than proof of malicious behavior.

---

## Issue 5 — Multiple Users Were Targeted

### Observation

The IP interacted with four different accounts:

    user1
    user2
    user3
    user4

### Resolution

This was treated as an important authentication pattern.

However, the investigation did not infer attacker intent solely from the number of targeted users.

---

## Issue 6 — Failed Authentication Followed by Success

### Observation

The sequence was:

    Failed
    Failed
    Failed
    Failed
    Success

The successful authentication belonged to `user1`.

### Resolution

The sequence was classified as suspicious authentication behavior.

It was not treated as confirmed account compromise.

---

## Issue 7 — Do Not Label the IP as Malicious Without Supporting Evidence

### Problem

The source displayed multiple suspicious characteristics.

It would be easy to classify the IP as malicious solely from its behavior.

### Resolution

The IP was treated as a suspicious investigation pivot.

Additional evidence such as threat intelligence, ownership information, VPN or proxy identification, and broader telemetry would be required before making a stronger determination.

---

## Issue 8 — Endpoint Correlation Strengthened the Investigation

### Observation

The same IP was associated with:

    user1
    DESKTOP-LAB01
    winword.exe → powershell.exe

The endpoint event occurred three minutes after successful authentication.

### Resolution

The authentication and endpoint events were correlated using:

- User.
- Source IP.
- Computer.
- Timestamp.

This produced a stronger investigation sequence than analyzing the IP only at the identity layer.

---

## Issue 9 — Suspicious PowerShell Parameters Are Not Proof

### Observation

The endpoint command contained:

    -ExecutionPolicy Bypass
    -EncodedCommand

### Resolution

These were treated as suspicious characteristics.

They were not considered definitive evidence of malicious execution without additional PowerShell and endpoint telemetry.

---

## Issue 10 — IP Geolocation Requires Context

### Observation

The successful authentication from the suspicious IP was associated with:

    New York

### Resolution

The location was treated as supporting context.

Possible explanations such as VPNs, proxies, shared infrastructure, and geolocation inaccuracies remain possible.

---

## Issue 11 — No Evidence of Endpoint Impact

### Problem

The synthetic endpoint data does not contain:

- Network connections.
- File creation.
- Child processes.
- Script Block Logging.
- Endpoint detection alerts.
- Persistence.
- Data access.

### Resolution

These were documented as evidence gaps.

No additional activity was assumed or fabricated.

---
