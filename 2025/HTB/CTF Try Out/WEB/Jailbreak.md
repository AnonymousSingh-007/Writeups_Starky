![platform](https://img.shields.io/badge/platform-HTB-2ea44f) ![category](https://img.shields.io/badge/category-Web-ff69b4) ![difficulty](https://img.shields.io/badge/difficulty-Very%20Easy-brightgreen) ![status](https://img.shields.io/badge/status-Solved-blue)

# Jailbreak — HTB CTF — Writeup

> Short summary  
I solved the *Jailbreak* web challenge on HTB by inspecting the application's firmware update flow and abusing an XML External Entity (XXE) in the submitted XML payload to read the `flag.txt` file. This writeup documents reconnaissance, the vulnerable vector, exploitation steps, the payload used, and remediation notes.

---

# Table of Contents
- [Target & Scope](#target--scope)  
- [Recon / Surface discovery](#recon--surface-discovery)  
- [Static analysis / Useful finds](#static-analysis--useful-finds)  
- [Attack hypothesis](#attack-hypothesis)  
- [Exploitation — step by step](#exploitation---step-by-step)  
- [Payload](#payload)  
- [Result / Flag](#result--flag)  
- [Root cause](#root-cause)  
- [Mitigations](#mitigations)  
- [Lessons learned](#lessons-learned)  
- [Appendix: Burp / requests / notes](#appendix-burp--requests--notes)

---

# Target & Scope
- **Platform:** Hack The Box (HTB)  
- **Challenge:** *Jailbreak* (web)  
- **Category:** Web Application / XML Processing (XXE)  
- **Difficulty:** Very Easy  
- **Goal:** Retrieve the flag from the target (local file read)

---

# Recon / Surface discovery
- Loaded the supplied Docker image and interacted with the UI.
- Explored the tabs/buttons: `MAP`, `STAT`, `ROM`, `RADIO`, etc.
- `ROM` tab contained firmware update instructions and example XML describing firmware components and a SHA-256 integrity check.
- `RADIO` had recordings — not useful for flag retrieval but noted during exploration.

Key observation: the **Firmware Update** functionality accepted XML input (an upload/submit flow). This suggested XML parsing on the server side — a common place for XXE or similar XML-related vulnerabilities.

---

# Static analysis / Useful finds
- Firmware metadata in the `ROM` tab (or linked code) referenced:
  - **current version:** `1.33.7`
  - **components:** navigation, communication, biometric_security
  - **integrity check:** SHA-256
- The update flow accepted XML and performed server-side XML parsing without apparent safeguards (based on errors and response behavior observed during testing).

---

# Attack hypothesis
Because the server accepts XML input, and the parsing produced errors (including Unicode/string handling issues) while experimenting, the application likely parses the submitted XML with an XML parser that might have external entity processing enabled. That makes it a candidate for an **XML External Entity (XXE)** vulnerability which can be used to read local files (e.g., `/flag.txt`) if the parser resolves external entities.

Plan:
1. Capture the firmware update submission request with Burp.
2. Replace the submitted XML with a crafted XML containing a `DOCTYPE` and an `ENTITY` declaration referencing `file:///flag.txt`.
3. Submit and see whether the server includes the file content in the response (or otherwise leaks it).

---

# Exploitation — step-by-step

> Note: These steps describe what I did during the CTF. They are written to be reproducible for educational / defensive purposes.

1. **Start the app / Docker image** and interact with the web UI locally.  
2. **Open Burp Suite** and set the browser to use the Burp proxy.  
3. **Navigate** to the `ROM` / Firmware Update page and trigger the "Submit" button while Burp is intercepting the request.  
4. **Inspect the intercepted request** — identify the request method, URL and the XML body being submitted.  
5. **Modify the request body** to include a DOCTYPE with an external entity referencing the local file (here: `file:///flag.txt`).  
6. **Forward the modified request** to the server.  
7. **Observe the response** — the application returned the contents of `/flag.txt` (the flag).

Example (conceptual) Burp request sequence:
- Intercept → Replace body with crafted XML → Forward → Review response for the flag.

---

# Payload

Below is the minimal XXE-style XML payload used (this is the vulnerable **demo** payload that was crafted for the CTF). Replace `...` with any required wrapper/content fields the application expects (or use the application's example XML and inject the DOCTYPE):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<firmwareUpdate>
  <version>1.33.7</version>
  <notes>&xxe;</notes>
  <!-- other expected fields here -->
</firmwareUpdate>
