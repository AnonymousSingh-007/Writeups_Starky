# HTB TimeKORP – *Web* –  Writeup  
**Points**: 50 | **Difficulty**: Easy  

![Web](https://img.shields.io/badge/category-web-1DA1F2?style=flat-square)  
![Difficulty](https://img.shields.io/badge/difficulty-easy-success?style=flat-square)  
![HTB](https://img.shields.io/badge/platform-HTB-00D26A?style=flat-square&logo=hackthebox)  
![Command Injection](https://img.shields.io/badge/vuln-Command_Injection-FF2D55?style=flat-square)  

---

## Description
> A time-display web app with a mysterious `?format` parameter. Something smells like PHP injection…

---

## Solution

### 1. **Recon: Docker + Dev Tools**
- Launched the provided Docker instance.
- Opened **DevTools → Sources** to inspect frontend files.
- Discovered `index.js` — but the real action was in the backend behavior.

### 2. **Parameter Discovery**
- Noticed the URL supports `?format=` to customize time output.
- Tested basic input: ?format=hello → "hello"

→ Confirmed **direct string injection** into output.

### 3. **PHP + URL Encoding Crash Course**
- Realized the backend uses PHP’s `date()` with user input.
- Researched: `date()` stops at first null byte or invalid format → perfect for **command injection via semicolon `;`**.
- But direct `;ls` didn’t work → needed to **break out of string context**.

### 4. **Breaking Out with Single Quotes**
- PHP string: `date('$format')` → We control `$format`.
- Tried: ?format=';ls'

→ Became: `date('';ls')` → **Command injection confirmed!**

### 5. **Directory Traversal + Flag Hunt**
- `ls` revealed no `flag.txt` in current dir.
- Tried common paths: ?format=';ls ../' ,, ?format=';cat ../flag.txt'

→ Failed (no such file).

- ## Final winning payload: ?format=';cat%20../flag%20/'

→ URL-decoded: `';cat ../flag '`

**Why it worked**:
- `../flag` is the actual flag file (not `flag.txt`).
- Space in filename → must be `%20`.
- Closing `'` terminates the PHP string early.

---

## Exploit URL
```url
http://83.136.255.106:35477/?format=%27;cat%20../flag%20/%27

Lesson,Detail
PHP date() is dangerous,Never pass raw user input to date() — classic CTF injection vector.
String termination = RCE,'; closes the string → ; starts a new command.
Spaces in filenames,Always URL-encode (%20) when injecting.
Think outside flag.txt,Real challenges hide flags in weird paths like ../flag.
DevTools = Goldmine,"Even if JS is useless, it confirms parameter existence."
