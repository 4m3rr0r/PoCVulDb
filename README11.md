# [Unrestricted File Upload] in [Bdtask Flight Booking Software B2B Portal] [v3.1]

---

### 👨‍💻 **BUG Author:**

##  4m3rr0r



### 📦 **Product Information:**

* **Vendor Homepage:** [https://www.bdtask.com](https://www.bdtask.com)
* **Software Link:** [https://www.bdtask.com/flight-booking-software.php](https://www.bdtask.com/flight-booking-software.php)
* **Affected Version:** v3.1
* **BUG Author:** 4m3rr0r
---

### 🛠 **Vulnerability Details**

* **Type:** Unrestricted File Upload leading to Remote Code Execution (RCE)
* **Affected URL:** `https://subah.bdtask-demo.com/subah_v3.1/admin/transaction/deposit`
* **Vulnerable Parameter:** `Document` (File Upload)
* **Vulnerable Component:** The "Record new transaction" feature in the B2B admin panel.

---

### 🧨 **Vulnerability Type**

* **Unrestricted Upload of File with Dangerous Type**
* **CWE ID:** CWE-434
* **Severity Level:** CRITICAL
* **CVSS Score:** 9.8 (Critical)

---

### 🧬 **Root Cause**

The application's file upload functionality within the B2B portal's transaction deposit module fails to properly validate the extension or MIME type of user-submitted files. It does not enforce a strict whitelist of safe file types, allowing authenticated users to upload executable scripts (e.g., PHP web shells) disguised as documents. The server then stores these files in a web-accessible directory, enabling attackers to execute them by navigating to the corresponding URL.

---

### ⚠️ **Impact**

* **Full Server Compromise:** Attackers can execute arbitrary commands on the server, leading to a complete system takeover.
* **Data Breach:** Unauthorized access to the entire application database, including customer information, booking details, and payment records.
* **Website Defacement:** The attacker can modify or delete website files.
* **Internal Network Pivot:** The compromised server can be used as a staging point to attack other internal systems.

---

### 📋 **Description**

1.  **Vulnerability Details:**
    * An authenticated user in the B2B portal can access the "Deposit" feature under "Transaction".
    * The form includes a "Document" file upload field that lacks server-side validation.
    * This allows a malicious file, such as a PHP web shell, to be uploaded to the server.

2.  **Attack Vectors:**
    * The attacker uploads a PHP script via the document upload form.
    * The application confirms the upload and makes the file accessible through the "Pending Transactions" page.
    * The attacker accesses the direct URL of the uploaded script to achieve Remote Code Execution.

3.  **Attack Payload Example:**
    * Create a file named `shell.php` with the following content:
        ```php
        <?php system($_GET['cmd']); ?>
        ```
    * Upload this file through the vulnerable form.




---

### 🔬 **Proof of Concept (PoC)**

A video PoC has been recorded demonstrating the following steps and is available at: 

[![Watch the video](https://img.youtube.com/vi/AelgRlSQEqQ/0.jpg)](https://youtu.be/AelgRlSQEqQ)


1.  Log in to the B2B portal.
2.  Navigate to **Transaction -> Deposit**.
3.  Fill in the transaction form fields.
4.  For the **Document** field, upload the malicious `shell.php` file.
5.  Submit the form.
6.  Navigate to **Transaction -> Pending Transactions**.
7.  Locate the new transaction and click the link to "view" the uploaded document.
8.  The browser will be redirected to the web shell. Execute a command by appending a query parameter to the URL: `/storage/cash_payment_attachment/1760182871_web.php`
9.  The server responds with the output of the command (e.g., `www-data`), confirming RCE.

---

### 🛡 **Suggested Remediation**

* Use a **strict whitelist** to allow only specific safe file extensions (e.g., `pdf`, `jpg`, `png`). Deny all other extensions.
* **Validate MIME type** on the server-side to ensure the file content matches its extension.
* **Store uploaded files outside the webroot**. Access them via a secure script that serves the files to the user, preventing direct execution.
* **Rename uploaded files** to a random, non-executable name upon storage.




### 📚 **References**

* [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
* [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

---
