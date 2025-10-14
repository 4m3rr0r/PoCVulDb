# [Broken Access Control] in [Pharmacy Management System] leading to Admin Privilege Escalation [v9.4]

---

### 👨‍💻 **BUG Author:**

### 4m3rr0r

---

### 📦 **Product Information:**

* **Vendor Homepage:** [https://www.bdtask.com](https://www.bdtask.com)
* **Software Link:** [https://www.bdtask.com/pharmacy-management-system.php](https://www.bdtask.com/pharmacy-management-system.php)
* **Demo URL:** [https://pharmacysoft.bdtask-demo.com/](https://pharmacysoft.bdtask-demo.com/)
* **Affected Version:** v9.4
* **BUG Author:** 4m3rr0r

---

### 🛠 **Vulnerability Details**

* **Type:** Broken Access Control / Insecure Session Management
* **Affected URL:** All authenticated endpoints (e.g., `/dashboard/my_profile`)
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

The application fails to securely manage user sessions on the server-side. It exclusively trusts the client-provided `ci_session` cookie to determine the user's identity and permission level. The application does not validate that the session belongs to the current user against a secure, server-side record on every request. This allows an attacker to substitute a low-privilege user's session cookie with that of an administrator to gain full control.

---

### ⚠️ **Impact**

* **Complete System Compromise:** An attacker can become an administrator by hijacking a valid admin session cookie.
* **Total Data Breach:** This allows unauthorized access to all sensitive data, including patient information, prescription records, inventory, and financial data.
* **Loss of Data Integrity:** An attacker can create, modify, or delete any records, including prescriptions and user accounts, compromising patient safety and business operations.
* **Full Account Takeover:** The attacker can take over any user account in the system.

---

### 📋 **Description**

1.  **Vulnerability Details:**
    * The application uses a CodeIgniter session cookie (`ci_session`) to manage user authentication and state.
    * The server does not perform adequate back-end validation to ensure the user making a request is the legitimate owner of the permissions associated with their session cookie.

2.  **Attack Vectors:**
    * An attacker logs in with a low-privilege account (e.g., "Account Head User").
    * The attacker obtains a valid `ci_session` cookie from an administrator's session.
    * The attacker uses a proxy tool like Burp Suite to replace their own cookie with the administrator's cookie in a new request.
    * The server grants the attacker's session full administrative access.

---

### 🔬 **Proof of Concept (PoC)**

A video demonstrating this vulnerability has been recorded and can be viewed here:

[![Watch the video](https://img.youtube.com/vi/RtKBnudLgkU/0.jpg)](https://youtu.be/RtKBnudLgkU)


**PoC Steps using Burp Suite Repeater:**

1.  **Configure Proxy:** Set up your browser to proxy traffic through Burp Suite.

2.  **Capture a Valid Request:** Log in to the application as a normal, low-privilege user (e.g., "Account Head User"). In Burp Suite's **Proxy > HTTP history** tab, find a request to an authenticated page, such as `GET /dashboard/my_profile`.

3.  **Send to Repeater:** Right-click on that request and select **"Send to Repeater"**.

4.  **Establish Baseline:** Go to the **Repeater** tab. Send the original, unmodified request to confirm that the response is the limited dashboard for the "Account Head User".

5.  **Modify the Cookie:** In the Repeater request panel, locate the `Cookie` header. Replace the existing `ci_session` value with the session cookie of a known administrator.

    * **Original Cookie:**
        `Cookie: ci_session=4b045a8b30c1efc382bcadf2ee00ca2760a480ea`

    * **Modified Cookie (Admin):**
        `Cookie: ci_session=620fc163ae053b09204ca226bdda6e39bcb63b0f`

6.  **Send the Modified Request:** Click the "Send" button again.

7.  **Analyze the Result:** Examine the response from the server. The HTML in the response body will now contain the full administrator dashboard, including admin-only menu items and data. This confirms a complete privilege escalation.

---

### 🛡 **Suggested Remediation**

* **Implement Strict Server-Side Session Management:** User permissions and identity must be stored securely on the server, linked to a cryptographically random session identifier. **Never trust client-side data for authorization.**
* **Validate Permissions on Every Request:** For every request to a protected endpoint, the application must use the session ID from the cookie to look up the user's permissions in its server-side session store and verify they are authorized for the requested action.
* **Regenerate Session ID on Login:** Upon successful login, invalidate the old session ID and generate a new, secure one to prevent session fixation attacks.
* **Secure Cookie Attributes:** Ensure cookies are sent with `HttpOnly`, `Secure`, and `SameSite=Strict` attributes.

---

### 📚 **References**

* [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

---
