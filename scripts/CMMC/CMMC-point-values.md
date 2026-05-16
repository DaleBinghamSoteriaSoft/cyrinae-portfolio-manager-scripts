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