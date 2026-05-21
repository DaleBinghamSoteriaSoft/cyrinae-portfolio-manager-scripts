Under the official CMMC rule (**32 CFR § 170.24**), the rulesets for "passing" vary completely by level. You cannot rely on a basic "percentage complete" metric to determine compliance because the Department of Defense (DoD) weights specific controls differently, uses a negative deduction system for Level 2, and enforces strict rules on what can or cannot be pushed to a Plan of Action and Milestones (POA&M).

The exact scoring mechanism, threshold rules, and passing criteria across all three levels outline how your OpenRMF API data aligns with these requirements:

---

## CMMC Level 1: The "All-or-Nothing" Pass/Fail

Level 1 covers **17 basic safeguarding practices** for Federal Contract Information (FCI).

* **Scoring Mechanism:** There is **no numerical score**. Controls are strictly evaluated as **MET** or **NOT MET**.
* **Passing Threshold:** You must achieve **100% MET**.
* **POA&M Allowed?** **No.** If even a single control is "Open" or "Not Met," the entire assessment fails.
* **How to map your data:** Filter your API data for Level 1 controls. If any control status equals "Open," your status is failing.

---

## CMMC Level 2: The Weighted Deductive Score (SPRS)

Level 2 covers **110 practices** derived directly from **NIST SP 800-171 Rev 2** for protecting Controlled Unclassified Information (CUI). This is where your gap sheets get complex.

* **Scoring Mechanism:** You start with a perfect score of **110**. For every control that is "Open" (Not Met), points are subtracted from 110 based on the control's risk weight. The lowest possible score is **-203**.
* **Deduction Tiers:**
* **5 Points:** Critical controls (e.g., Access Control, System Security Plan). Missing these means massive exposure.
* **3 Points:** Moderate impact controls.
* **1 Point:** Low/indirect impact controls.
* *Note: Multi-Factor Authentication (IA.L2-3.5.3) allows partial credit (3 points deducted if implemented for remote/privileged users but missing for general users; 5 points deducted if entirely missing).*



### Passing Thresholds for Level 2

To "Pass" and achieve contract eligibility, you can achieve one of two statuses:

1. **Final CMMC Status:** A perfect score of **110** with zero open controls.
2. **Conditional CMMC Status:** You can achieve a passing conditional status if you meet **all** of the following criteria:
* Your overall calculated score is **at least 88** (out of 110).
* **None** of the open controls are "5-point" controls (with very minor exceptions like FIPS validation on encryption).
* The missing controls are allowed on a POA&amp;M and must be fully remediated and closed within **180 days**.

> ⚠️ **Critical Gatekeeper Control:** If control **CA.L2-3.12.4 (System Security Plan)** is "NOT MET" or "Open", you automatically receive **"No Score"** and fail the assessment entirely, regardless of how many other controls are passing.

---

## CMMC Level 3: Advanced & Strategic Security

Level 3 builds directly on top of Level 2, adding **24 advanced practices** from **NIST SP 800-172** to defend against Advanced Persistent Threats (APTs).

* **Scoring Mechanism:** Level 3 utilizes its own point system on top of your baseline.
* **Prerequisite to Pass:** You **cannot** even attempt a Level 3 assessment unless you have already achieved a **Final CMMC Level 2 Status** (a perfect 110 score with no remaining open POA&amp;Ms).
* **Passing Threshold:** Like Level 1, Level 3 expects total implementation of its advanced rules.
* **POA&M Allowed?** **No.** Open gaps or placeholders are not allowed during the final DIBCAC (Defense Contract Management Agency) government-led audit. Everything must be "MET" to receive the certification.

---

## Summary Matrix for Your Reporting

| CMMC Level | Total Controls | Scoring Method | Min. Score to Pass | POA&Ms Allowed? |
| --- | --- | --- | --- | --- |
| **Level 1** | 17 | Pass / Fail (Met/Not Met) | 17 / 17 Met | **No** |
| **Level 2** | 110 | Start at 110; Deduct 1, 3, or 5 | **110** (Final)<br>

<br>**88** (Conditional) | **Yes** (Max 180 days; no 5-pt controls) |
| **Level 3** | 110 + 24 | Advanced Review | 100% Met | **No** |

### How to use your OpenRMF API Data:

To properly demonstrate your gaps, do not just count your "Open" vs "Not Applicable" percentages. You should write a script or build a dashboard using your API data that map to the rules above:

1. Assign the official DoD point values (1, 3, 5) to each CMMC Level 2 control ID.
2. For every control returned as "Open," subtract that point value from 110.
3. Flag any "Open" control that carries a 5-point value as a **Critical Blocker** that will instantly disqualify you from a Conditional pass.