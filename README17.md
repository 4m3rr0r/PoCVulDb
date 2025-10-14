# [Broken Access Control] in [Hospital Management System] leading to Admin Privilege Escalation

---

### 👨‍💻 **BUG Author:**

### 4m3rr0r


---

### 📦 **Product Information:**

* **Vendor Homepage:** [https://www.bdtask.com](https://www.bdtask.com)
* **Software Link:** [https://codecanyon.net/item/hospital-hospital-management-system-with-website/18955750](https://codecanyon.net/item/hospital-hospital-management-system-with-website/18955750)
* **Demo URL:** [https://hospital.bdtask-demo.com/](https://hospital.bdtask-demo.com/)
* **Affected Version:** Last Update 9 March 2025 
* **BUG Author:** 4m3rr0r

---

### 🛠 **Vulnerability Details**

* **Type:** Broken Access Control / Insecure Session Management
* **Affected URL:** All authenticated endpoints (e.g., `/dashboard_patient/home/profile`)
* **Vulnerable Parameter:** `Cookie: ci_session`
* **Vulnerable Component:** The application's core session management and authorization mechanism.

---

### 🧨 **Vulnerability Type**

* **Broken Access Control**
* **CWE ID:** CWE-285: Improper Authorization
* **Severity Level:** CRITICAL
* **CVSS Score:** 9.8 (Critical)

---

### 🧬 **Root Cause**

The application fails to securely manage user sessions on the server-side. It exclusively trusts the client-provided `ci_session` cookie to determine a user's identity and permission level. The application does not validate that the session belongs to the current user against a secure, server-side record on every request. This allows an attacker to substitute a low-privilege user's session cookie (e.g., a patient) with that of a high-privilege user (e.g., an administrator) to gain complete control.

---

### ⚠️ **Impact**

* **Complete System Compromise:** An attacker can become an administrator by hijacking a valid admin session cookie.
* **Massive Sensitive Data Breach:** This allows unauthorized access to all sensitive data within the hospital management system, including **patient medical records, personal identifiable information (PII), appointments, billing, and staff details**.
* **Loss of Data Integrity and Patient Safety:** An attacker can create, modify, or delete any records, including patient diagnoses, prescriptions, and appointments, posing a direct risk to patient safety.
* **Full Account Takeover:** The attacker can take over any user account in the system, from patients to doctors to administrators.

---

### 🔬 **Proof of Concept (PoC)**


A video demonstrating this vulnerability has been recorded and can be viewed here:

[![Watch the video](https://img.youtube.com/vi/sC9r9X8lMAY/0.jpg)](https://youtu.be/sC9r9X8lMAY)


The vulnerability is demonstrated by intercepting a request with Burp Suite and replaying it with a modified session cookie to escalate privileges from a patient to an administrator.


**PoC Steps using Burp Suite Repeater:**

1.  **Configure Proxy:** Set up your browser to proxy traffic through Burp Suite.

2.  **Capture Patient Request:** Log in to the application as a patient (e.g., `patient@example.com`). In Burp Suite's **Proxy > HTTP history** tab, find a request to an authenticated page, such as `GET /dashboard_patient/home/profile`.

3.  **Send to Repeater:** Right-click on that request and select **"Send to Repeater"**.

4.  **Establish Baseline:** Go to the **Repeater** tab. Send the original, unmodified request to confirm the response is the limited dashboard for the patient.

5.  **Modify the Cookie:** In the Repeater request panel, locate the `Cookie` header. Replace the existing `ci_session` value with the session cookie of a known administrator.

    * **Original Cookie (Patient):**
        `Cookie: ci_session=pglp1eu11v60td0scnelhjoj3hmorrri`

    * **Modified Cookie (Admin):**
        `Cookie: ci_session=mdiclf3lbvnt2bu8gj88vqb0cm7g8ghp`

6.  **Send the Modified Request:** Click the "Send" button again.

7.  **Analyze the Result:** Examine the response from the server. The response will now contain the full administrator dashboard, including access to all hospital management functions. This confirms a complete privilege escalation.

---

### 🛡 **Suggested Remediation**

* **Implement Strict Server-Side Session Management:** User roles and permissions must be stored securely on the server, linked to a cryptographically random session identifier. **Never trust client-side data for authorization.**
* **Validate Permissions on Every Request:** For every request to a protected endpoint, the application must use the session ID from the cookie to look up the user's role in its server-side session store and verify they are authorized for the requested action.
* **Regenerate Session ID on Login:** Upon successful login, invalidate the old session ID and generate a new, secure one to prevent session fixation attacks.
* **Secure Cookie Attributes:** Ensure cookies are sent with `HttpOnly`, `Secure`, and `SameSite=Strict` attributes to mitigate theft via XSS and CSRF.

---

### 📚 **References**

* [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/252.html)

---
