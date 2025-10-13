# [Broken Access Control] in [Sales ERP Software] leading to Admin Privilege Escalation

---

### 👨‍💻 **BUG Author:**

## 4m3rr0r

---

### 📦 **Product Information:**

* **Vendor Homepage:** [https://www.bdtask.com](https://www.bdtask.com)
* **Software Link / Demo URL:** [https://codecanyon.net/item/erp-business-erp-solution-product-shop-company-management/19314578?irgwc=1&clickid=VpTxVqWs6xycUy62I-yUlUTDUkpyQiQdq1uV2k0&iradid=275988&irpid=1356783&iradtype=ONLINE_TRACKING_LINK&irmptype=mediapartner&mp_value1=&utm_campaign=af_impact_radius_1356783&utm_medium=affiliate&utm_source=impact_radius](https://codecanyon.net/item/erp-business-erp-solution-product-shop-company-management/19314578?irgwc=1&clickid=VpTxVqWs6xycUy62I-yUlUTDUkpyQiQdq1uV2k0&iradid=275988&irpid=1356783&iradtype=ONLINE_TRACKING_LINK&irmptype=mediapartner&mp_value1=&utm_campaign=af_impact_radius_1356783&utm_medium=affiliate&utm_source=impact_radius)
* **Affected Version:** Latest version as of 2025-10-13
* **BUG Author:** 4m3rr0r
---

### 🛠 **Vulnerability Details**

* **Type:** Broken Access Control / Insecure Session Management
* **Affected URL:** All authenticated endpoints, including `/home`
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

The application fails to properly manage user sessions on the server-side. It trusts the client-provided `ci_session` cookie to determine the user's identity and privilege level without validating that the session belongs to the current user on every request. This allows an attacker to substitute the session cookie of a low-privileged user with that of a high-privileged user (e.g., an administrator) and gain all of that user's permissions.

---

### ⚠️ **Impact**

* **Complete Account Takeover:** Any user can become an administrator by hijacking a valid admin session cookie.
* **Full System Compromise:** An attacker with admin privileges can access all data, modify system settings, delete records, and manage all users.
* **Total Data Breach:** All sensitive information, including sales data, customer lists, product information, and financial records, can be exfiltrated.
* **Loss of Integrity and Availability:** The attacker can alter or destroy data, disrupting business operations entirely.

---

### 📋 **Description**

1.  **Vulnerability Details:**
    * The application uses a CodeIgniter session cookie (`ci_session`) to manage user state.
    * The server does not sufficiently validate the session on the back-end to ensure the user making the request is the legitimate owner of the permissions associated with the session.

2.  **Attack Vectors:**
    * An attacker logs in with a low-privilege account.
    * The attacker obtains a valid `ci_session` cookie from an administrator's session (e.g., through another exploit like XSS, or by having prior access).
    * The attacker replaces their own browser cookie with the administrator's cookie.
    * Upon refreshing the page, the server grants the attacker full administrative access.

---

### 🔬 **Proof of Concept (PoC)**

The vulnerability is demonstrated by swapping the session cookie of a regular user with that of an administrator.


##### watch the video

[![Watch the video](https://img.youtube.com/vi/euBhYEXaJVA/0.jpg)](https://youtu.be/euBhYEXaJVA)



1.  **Log in as a normal user ("Jason Salesman"):**
    The browser receives a user-level cookie.
    `Cookie: ci_session=kkpigpao7np924mmnqhfqqae9ao1gpfc`
    The server responds with a limited dashboard.

2.  **Replace the cookie with an admin's cookie:**
    Using browser developer tools, the user cookie is replaced with a known admin cookie.
    `Cookie: ci_session=gh0irdp4g7p3ag32i272cttuipnragri`

3.  **Refresh the page:**
    A new request is sent to `/home` with the admin cookie.

4.  **Result:**
    The server responds with the full administrator dashboard for "Admin User", granting access to sensitive modules like "Human Resource", "Bank", "Accounts", and full "Settings" control. This confirms a complete privilege escalation.

---

### 🛡 **Suggested Remediation**

* **Implement Strict Server-Side Session Management:** User permissions and identity must be stored securely on the server, linked to a cryptographically random session identifier. **Never trust client-side data for authorization.**
* **Validate Permissions on Every Request:** For every request to a protected endpoint, the application must use the session ID from the cookie to look up the user's permissions in the server-side session store and verify they are authorized for the requested action.
* **Regenerate Session ID on Login:** Upon successful login, invalidate the old session ID and generate a new, secure one to prevent session fixation attacks.
* **Secure Cookie Attributes:** Ensure cookies are sent with `HttpOnly`, `Secure`, and `SameSite=Strict` attributes to mitigate theft via XSS and CSRF.

### 🔐 **Security Recommendations**

* Implement IP address and user-agent binding to sessions to make session hijacking more difficult.
* Implement short session timeout periods for high-privilege accounts.
* Provide a secure "log out everywhere" feature for users.
* Conduct regular security audits on the authentication and authorization logic.

---

### 📚 **References**

* [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

---
