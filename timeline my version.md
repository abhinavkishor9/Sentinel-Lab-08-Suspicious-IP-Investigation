# Timeline 

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

