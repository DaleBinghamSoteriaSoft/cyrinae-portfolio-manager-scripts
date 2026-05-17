Under the official CMMC rule (**32 CFR § 170.24**) and the **NIST SP 800-171 DoD Assessment Methodology**, the 110 controls are strictly grouped into **5-point**, **3-point**, and **1-point** deduction values.

If you are pulling this through your OpenRMF API, you can map the control IDs to the exact point values below to calculate your true SPRS score and flag critical compliance blockers.

---

## 5-Point Controls (44 Practices)

These are basic and derived requirements that, if missing, directly allow for network exploitation or data exfiltration. **None of these are allowed on a POA&M** (except for narrow FIPS validation loopholes). If any of these are marked "Open," you cannot pass a CMMC audit.

### Access Control (AC)

* **3.1.1** Limit system access to authorized users.
* **3.1.2** Limit system access to types of transactions/functions authorized users can execute.
* **3.1.12** Monitor and control remote access sessions.
* **3.1.13** Control remote access via authorized access control points.
* **3.1.16** Authorize wireless access prior to allowing connection.
* **3.1.17** Protect wireless access using authentication and encryption.
* **3.1.18** Control connection of mobile devices.

### Awareness and Training (AT)

* *None. All AT controls are 1 point.*

### Audit and Accountability (AU)

* **3.3.1** Create and retain system audit logs and records.
* **3.3.2** Ensure actions of individual system users can be uniquely traced to those users.

### Configuration Management (CM)

* **3.4.1** Establish and maintain baseline configurations.
* **3.4.2** Enforce security configuration settings for organizational IT products.
* **3.4.6** Monitor and control changes to organizational systems.
* **3.4.7** Restrict, disable, or prevent the use of unauthorized programs/functions.
* **3.4.8** Apply deny-by-exception (blacklisting) or allow-by-exception (whitelisting) policies.

### Identification and Authentication (IA)

* **3.5.1** Identify system users, processes-acting-on-behalf-of-users, and devices.
* **3.5.2** Authenticate (verify) the identities of users, processes, and devices prior to access.
* **3.5.3** Use multi-factor authentication (MFA) for local/network access to privileged accounts and remote network access. *(Note: Missing entirely = -5 points; Partially missing for standard local users = -3 points).*

### Incident Response (IR)

* **3.6.1** Establish an operational incident-handling capability.
* **3.6.2** Track, document, and report incidents to designated officials.

### Maintenance (MA)

* **3.7.2** Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.

### Media Protection (MP)

* **3.8.1** Protect (i.e., physically control and securely store) system media containing CUI.
* **3.8.2** Limit access to CUI on system media to authorized users.
* **3.8.3** Sanitize or destroy system media containing CUI before disposal or reuse.

### Personnel Security (PS)

* *None. All PS controls are 1 point.*

### Physical Protection (PE)

* **3.10.1** Limit physical access to organizational systems, equipment, and the respective operating environments.
* **3.10.3** Escort visitors and monitor visitor activity.
* **3.10.4** Maintain physical access logs.
* **3.10.5** Secure physical keys, combinations, and other physical access devices.

### Risk Assessment (RA)

* **3.11.1** Periodically assess the risk to organizational operations resulting from system operation.

### Security Assessment (CA)

* **3.12.1** Periodically assess the security controls in organizational systems.
* **3.12.2** Develop and implement plans of action designed to correct deficiencies.
* **3.12.3** Monitor system security controls on an ongoing basis.
* **3.12.4** Develop, document, and periodically update a **System Security Plan (SSP)**. *(Critical Gatekeeper: Missing this instantly results in a "No Score" automatic failure).*

### System and Communications Protection (SC)

* **3.13.1** Monitor, control, and protect organizational communications at external/internal boundaries.
* **3.13.2** Employ architectural designs, software development techniques, and systems engineering principles that promote effective security.
* **3.13.5** Deny network communications traffic by default and allow network communications traffic by exception.
* **3.13.6** Prevent unauthenticated phone transmissions (e.g., split tunneling).
* **3.13.15** Protect the confidentiality of CUI at rest.

### System and Information Integrity (SI)

* **3.14.1** Flawlessly identify, report, and correct system flaws in a timely manner.
* **3.14.2** Provide protection from malicious code at appropriate locations within organizational systems.
* **3.14.4** Update malicious code protection mechanisms when new releases are available.
* **3.14.5** Monitor system security alerts and advisories and take appropriate actions.

---

## 3-Point Controls (14 Practices)

These are primary or derived requirements that have a specific but more localized security impact. **These are allowed on a POA&M** (except for 3.11.2 Vulnerability Scanning, which must be implemented).

* **3.1.5** Employ the principle of least privilege.
* **3.1.19** Encrypt CUI on mobile devices and mobile computing platforms.
* **3.4.3** Track, review, approve, and audit changes to organizational systems.
* **3.5.10** Store and transmit only encrypted representation of passwords.
* **3.8.4** Mark media with necessary CUI markings.
* **3.8.5** Explain accountability for CUI media to users.
* **3.11.2** **Scan for vulnerabilities** in the organizational system and applications. *(Must be MET; cannot go on a POA&M).*
* **3.13.11** **Employ FIPS-validated cryptography** to protect the confidentiality of CUI. *(Note: If encryption exists but isn't FIPS-validated, deduct 3 points. If no encryption exists at all, deduct 5 points via SC.3.13.15).*
* **3.13.16** Protect the confidentiality of CUI in transit.
* **3.14.3** Monitor organizational systems, including inbound/outbound communications traffic, to detect attacks.
* **3.14.6** Monitor organizational systems to detect unauthorized use.
* **3.14.7** Restrict unauthorized access to internal system administrative accounts.

---

## 1-Point Controls (52 Practices)

These are administrative, operational, or secondary safeguards. If these are "Open" in your OpenRMF system, **they are fully allowed on a POA&M** as long as your overall calculated score is 88 or higher.

### Access Control (AC)

* **3.1.3** Control the flow of CUI.
* **3.1.4** Separate the duties of individuals.
* **3.1.6** Use non-privileged accounts for general functions.
* **3.1.7** Limit unsuccessful logon attempts.
* **3.1.8** Display system use notifications before granting access.
* **3.1.9** Terminate session automatically after conditions are met.
* **3.1.10** Review session connectivity limits.
* **3.1.11** Control session termination.
* **3.1.14** Encrypt/route remote sessions securely.
* **3.1.15** Authorize execution of remote commands.
* **3.1.20** Verify use of shared/group accounts.
* **3.1.21** Limit CUI storage on non-organizational systems.
* **3.1.22** Control public posting of CUI.

### Awareness and Training (AT)

* **3.2.1** Ensure managers, administrators, and users are trained on security risks.
* **3.2.2** Ensure personnel are trained to carry out their security duties.
* **3.2.3** Provide role-specific security training.

### Audit and Accountability (AU)

* **3.3.3** Review and update logged events.
* **3.3.4** Alert in the event of an audit logging process failure.
* **3.3.5** Correlate audit review, analysis, and reporting processes.
* **3.3.6** Provide system clock synchronization.
* **3.3.7** Protect audit information and logging tools.
* **3.3.8** Limit management of audit logging functions.
* **3.3.9** Archive audit logs.

### Configuration Management (CM)

* **3.4.4** Analyze security impact of changes.
* **3.4.5** Define access restrictions for changes.
* **3.4.9** Control user-installed software.

### Identification and Authentication (IA)

* **3.5.4** Employ identifiers (uniqueness).
* **3.5.5** Prevent reuse of identifiers.
* **3.5.6** Disable identifiers after period of inactivity.
* **3.5.7** Enforce minimum password complexity rules.
* **3.5.8** Prohibit password reuse.
* **3.5.9** Allow temporary password overrides.
* **3.5.11** Terminate session identifiers upon logout.

### Incident Response (IR)

* **3.6.3** Test organizational incident response capability.

### Maintenance (MA)

* **3.7.1** Perform periodic maintenance.
* **3.7.3** Ensure non-local maintenance is logged/vetted.
* **3.7.4** Check personnel clearances for maintenance activities.
* **3.7.5** Require multifactor authentication for remote maintenance.
* **3.7.6** Supervise maintenance activities.

### Media Protection (MP)

* **3.8.6** Prohibit use of unauthorized media on assets.
* **3.8.7** Control access to media handling areas.
* **3.8.8** Prevent transport of CUI media outside boundaries.
* **3.8.9** Protect CUI backup data.

### Personnel Security (PS)

* **3.9.1** Screen individuals prior to authorizing CUI access.
* **3.9.2** Protect CUI during personnel transfers or terminations.

### Physical Protection (PE)

* **3.10.2** Protect physical power/cabling infrastructure.
* **3.10.6** Control delivery and removal of assets.

### Risk Assessment (RA)

* **3.11.3** Remediate vulnerabilities based on risk priority.

### System and Communications Protection (SC)

* **3.13.3** Separate security functions from non-security functions.
* **3.13.4** Prevent unauthorized information transfer (shared resources).
* **3.13.7** Establish trusted sessions (cryptography/tokens).
* **3.13.8** Route public data streams away from CUI.
* **3.13.9** Terminate network connections upon session end.
* **3.13.10** Establish operational configurations for internal controls.
* **3.13.12** Prohibit collaborative device remote activations.
* **3.13.13** Control mobile code execution.
* **3.13.14** Control Voice over IP (VoIP) use.

### System and Information Integrity (SI)

* **3.14.8** Block malicious software execution.
* **3.14.9** Analyze incoming/outgoing communications traffic for anomalies.
* **3.14.10** Track and verify system integrity.


# Level 3 scoring

The scoring architecture changes dramatically when moving from Level 2 to Level 3. Understanding how the point calculations work, the specific 24 controls pulled from NIST SP 800-172, and the exact scoring values is necessary for organizing this data via your OpenRMF API.

---

## 1. The Core Level 3 Scoring Mechanism

The Department of Defense uses a completely separate scoring rubric for Level 3 under **32 CFR § 170.24**.

* **The Baseline:** You start with a perfect score of **24** (representing the 24 advanced practices).
* **The Deductive System:** Like Level 2, Level 3 uses a negative deductive point system. However, the point weights are different. Controls are weighted as either **1 point** or **5 points**.
* **The Maximum Penalty Math:** There are **19 five-point controls** and **5 one-point controls**. If you were to fail every single one of them, your score would drop by 100 points ($19 \times 5 + 5 \times 1 = 100$). Therefore, the absolute lowest score you can receive on a Level 3 assessment is **-76** ($24 - 100 = -76$).

### Passing Thresholds for Level 3

* **Final Level 3 Status:** A perfect score of **24** with zero open controls.
* **Conditional Level 3 Status:** You must achieve a minimum score of **8** (out of 24), and **no 5-point controls** can be open. Any open 1-point controls must be placed on a POA&M and closed within **180 days**.

---

## 2. The 24 Level 3 Controls & Point Breakdown

The 24 Level 3 practices are designed specifically to counter **Advanced Persistent Threats (APTs)**. They are layered directly on top of your existing 110 Level 2 controls. When pulling from your API, map these exact control IDs to the following 5-point and 1-point values:

### 5-Point Advanced Controls (19 Practices)

These are critical architectural and tactical requirements. **None of these are allowed on a POA&M.** If even one is "Open," you fail the Level 3 assessment.

* **AC.L3-3.1.3e** Securely store and isolate information components across distinct security domains (Enhanced Sandboxing/Segmentation).
* **CM.L3-3.4.1e** Establish and maintain authoritative baseline configurations for high-value assets.
* **CM.L3-3.4.2e** Automate the verification and enforcement of baseline configurations to detect unauthorized modifications.
* **IA.L3-3.5.1e** Dual-authorize critical administrative actions (e.g., changing firewalls or deleting backups requires two independent admins to log in).
* **IA.L3-3.5.2e** Limit the use of administrative privileges to designated, hardened organizational assets.
* **IR.L3-3.6.1e** Establish and maintain a cyber incident response team capable of continuous coverage.
* **RA.L3-3.11.1e** Conduct **Threat-Informed Risk Assessments** using cyber threat intelligence regarding APT tactics.
* **RA.L3-3.11.2e** **Threat Hunting:** Proactively hunt for indicators of compromise (IoCs) and anomalous activity across the network.
* **RA.L3-3.11.4e** Assess and mitigate risk stemming from supply chain vulnerabilities and single points of failure.
* **RA.L3-3.11.5e** Assess the effectiveness of security controls against specific, sophisticated adversary TTPs (Tactics, Techniques, and Procedures).
* **SC.L3-3.13.1e** Employ dynamic isolation techniques (e.g., micro-segmentation) to contain compromised network components.
* **SC.L3-3.13.2e** Actively disrupt adversary command and control (C2) infrastructure using deceptive network practices.
* **SC.L3-3.13.3e** Limit the blast radius of a breach by logically separating organizational systems.
* **SC.L3-3.13.4e** Implement physical or logical isolation of critical system components (Air-gapping or advanced enclaves).
* **SC.L3-3.13.11e** Utilize cryptographic mechanisms to protect information at rest in high-availability, high-risk repositories.
* **SI.L3-3.14.1e** Establish a comprehensive system monitoring capability across all incoming and outgoing network perimeters.
* **SI.L3-3.14.3e** Continuously monitor internal systems and endpoints to detect unauthorized modifications and advanced persistent threats.
* **SI.L3-3.14.6e** Automatically analyze system logs and security alerts for indications of advanced adversary behavior.
* **SI.L3-3.14.7e** Ensure rapid remediation and recovery capabilities are engineered into infrastructure configurations following a cyber event.

### 1-Point Advanced Controls (5 Practices)

These are operational enhancements. They **are allowed on a POA&M** for up to 180 days, provided your overall Level 3 score remains 8 or higher.

* **AC.L3-3.1.2e** Restrict access to specific system commands and functions based on advanced contextual factors (e.g., time of day, location).
* **AT.L3-3.2.1e** Provide advanced, threat-specific security awareness training regarding APT social engineering and watering-hole attacks.
* **SI.L3-3.14.2e** Automate the distribution and installation of security patches and malware definitions across high-value assets.
* **SI.L3-3.14.4e** Verify the integrity and authenticity of software and firmware updates prior to installation.
* **SI.L3-3.14.5e** Constrain and closely monitor the execution of high-risk mobile code (e.g., scripts, macros) within the environment.

---

## 3. How to Structure Your OpenRMF Reporting Logic

To translate your raw OpenRMF API payloads into an executive-ready Level 3 gap analysis, apply the following logic rules to your query results:

1. **The Level 2 Gatekeeper Check:** Scan all 110 Level 2 controls. If your API returns even a single Level 2 control as `Open`, flag the environment as **Ineligible for Level 3 Assessment**.
2. **The "Automatic Fail" Scan:** Query the 19 Level 3 controls listed in the 5-point section above. If any of those rows return a status of `Open`, the report should instantly output **Status: Failed (Critical 5-Point Blocker)**.
3. **The Score Multiplier Logic:** For your scoring engine, apply this formula:

$$\text{L3 Score} = 24 - [(\text{Open 5-Pt Controls} \times 5) + (\text{Open 1-Pt Controls} \times 1)]$$


4. **The POA&M Eligibility Validation:** If the calculated score is $\geq 8$ and the only open items are from the 1-point list, programmatically flag those specific controls as **"Eligible for 180-day POA&M remediation."** All other gaps must be treated as absolute project blockers.