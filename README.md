Security Monitoring and Incident Response with Splunk

📌 Overview This project simulated the role of a SOC (Security Operations Center) analyst using Splunk as a SIEM tool. The focus was on monitoring security events, detecting suspicious activities, classifying alerts by severity, and practicing incident response documentation.

⚡ Activities Performed

Splunk Setup & Exploration: Configured Splunk to ingest logs, run SPL queries, and create dashboards.

Suspicious Event Detection: Used SPL queries to identify failed logins, malware infections, and abnormal host behavior.

Alert Actions: Simulated SOC workflows by classifying and prioritizing suspicious events.

Incident Documentation: Recorded each incident with timeline, severity, impact, and remediation recommendations.

Escalation Recommendation: Noted high-priority alerts for escalation to a Tier 2 SOC team for further investigation.

🛡️ Findings

1️⃣ Multiple Failed Login Attempts

Description: Several failed login attempts detected from multiple external IP addresses.

Risk: Possible brute-force or credential-stuffing attack.

Response: Classified as High Priority and flagged as a potential compromise attempt.

Recommendation: Enforce MFA, set account lockout policies, and block suspicious IPs.

2️⃣ Malware Activity Detection

Description: SPL queries revealed malware activity including Trojans, ransomware, worms, and spyware.

Risk: Potential compromise with risk of persistence and data exfiltration.

Response: Classified as High Priority and recorded for immediate attention.

Recommendation: Isolate infected hosts, run malware scans, and update endpoint protection.

3️⃣ Suspicious Host Activity (IP: 203.0.113.77)

Description: Host activity showed a pattern of successful login, file access, and later a Trojan detection.

Risk: Strong evidence of host compromise and possible data theft.

Response: Classified as High Priority and documented for escalation.

Recommendation: Quarantine the host, reset credentials, and conduct forensic analysis.

4️⃣ Unauthorized Internal Connection Attempt (IP: 10.0.0.5)

Description: User charlie attempted to connect to an internal/private host shortly after suspicious login and malware events.

Risk: Indicates possible lateral movement attempts by an attacker.

Response: Classified as High Priority due to the risk of attacker exploration inside the network.

Recommendation: Review network segmentation, audit access logs, and monitor user activity closely.

📤 Incident Reporting All findings were documented in an incident response report with severity levels, impact analysis, and recommended remediation. Some incidents were highlighted as requiring escalation to a Tier 2 SOC team for deeper investigation.
