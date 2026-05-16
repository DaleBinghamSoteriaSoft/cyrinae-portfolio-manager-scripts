To understand how the CMMC Level 2 scoring system operates under the hood, you have to look at the **NIST SP 800-171 DoD Assessment Methodology**. It uses a "negative deductive system," meaning you start at a perfect **110** and subtract points for gaps.

There are specific point breakdowns, partial credit rules, and details on how a score can bottom out at **-203**.

---

## 1. The Point Breakdown (110 Total Controls)

The 110 practices are broken down into three penalty tiers based on how critical they are to preventing a massive data breach or network compromise.

* **5-Point Controls (44 practices):** These are foundational security elements. Failing any of these can lead to immediate exploit. Examples include Access Control boundaries, Encryption, Firewalls, System Security Plans (SSP), and Audit Logging capabilities.
* **3-Point Controls (14 practices):** These have a high impact but are more localized in nature. Examples include employing the principle of least privilege, unique user accountability, and encrypting CUI specifically on mobile devices.
* **1-Point Controls (52 practices):** These are typically operational or administrative rules that support the larger controls. Examples include session locks, limiting logon attempts, or training policies.

---

## 2. Math Behind the "-203" Bottom Score

It sounds bizarre that a test with 110 questions can net you a **-203**, but the math is straightforward when you calculate the total weighted penalties:

$$\text{Total 5-Point Deductions: } 44 \times 5 = 220 \text{ points}$$

$$\text{Total 3-Point Deductions: } 14 \times 3 = 42 \text{ points}$$

$$\text{Total 1-Point Deductions: } 52 \times 1 = 52 \text{ points}$$

$$\text{Total Maximum Deductions} = 220 + 42 + 52 = 314 \text{ points}$$

If you have a completely blank environment with zero security implemented, your starting score is 110, and you subtract all 314 possible penalty points:

$$110 - 314 = -203$$

---

## 3. The Partial Points / Mitigation Rules

In standard compliance frameworks, a control is usually binary (Met or Not Met). In the DoD methodology, there are explicit rules regarding **partial points** or **conditional non-subtractions**:

### The "Do Not Deduct If Not Permitted" Rule

If your organization formally outlaws a certain capability in its System Security Plan (SSP), you do not lose points for not securing it.

* *Example:* If **Remote Access** or **Wireless** are strictly disabled and physically/logically blocked across your entire CUI environment, you do not lose the 5 points for failing to secure them. They are effectively treated as "Not Applicable" (which counts as MET).

### The Mobile Device Exception (3 Points vs 5 Points)

* **Control 3.1.19** specifies encrypting CUI on mobile devices and carries a **3-point deduction** if missing, because the risk exposure is limited only to what is physically on that asset.
* This contrasts with **Control 3.1.18** (controlling connection of mobile devices to the network), which carries a **5-point deduction** if missing because a rogue unmanaged mobile device can compromise the entire infrastructure.

### The Myth of Partial Credit for MFA (Control 3.1.5.3 / IA.L2-3.5.3)

> **IA.L2-3.5.3 (Multi-Factor Authentication):** While it is a critical blocker, it actually **allows for a split point deduction rather than an instant automated failure**.

The DoD methodology outlines specific partial implementation criteria for MFA:

* **Deduct 5 points** if MFA is not implemented at all.
* **Deduct 3 points** if MFA is implemented for remote and privileged users, but *not* implemented for local access by non-privileged users.

*Note: While you don't "instantly fail" the math, losing 5 points on MFA prevents you from getting a perfect 110, and because it is a 5-point control, it **cannot be put on a POA&M**. Therefore, you cannot achieve a Conditional Pass either.*

---

## 4. What Can (and Cannot) Be Pushed to a POA&M?

To pass an assessment with a **Conditional Score** (minimum score of **88**), your OpenRMF gaps must look like this:

### Strictly Forbidden on a POA&M (Automatic Failure if "Open")

* **Any 5-point control** (with very narrow exceptions for FIPS validation or standard operational updates). If your 5-point controls are open, you cannot pass.
* **Control 3.12.4 (The System Security Plan):** If this is marked "Not Met," the assessor will halt the audit. You receive a "No Score" and an automatic failure.

### Allowed on a POA&M (Must be closed within 180 Days)

* **Any 1-point control.**
* **Any 3-point control** (except for *Control 3.11.2 - Vulnerability Scanning*, which the DoD treats as a critical operational blocker).

### How to configure this logic for your OpenRMF API data:

When pulling your data, map the CMMC control IDs to their respective DoD point values (1, 3, or 5). Look specifically for any rows where `Status == "Open"` and `PointValue == 5`. Those are your "red flags" that will sink an audit instantly, regardless of what the overall percentage-complete metric looks like.