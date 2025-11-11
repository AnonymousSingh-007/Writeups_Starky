```markdown
![platform](https://img.shields.io/badge/platform-HTB-2ea44f) ![category](https://img.shields.io/badge/category-Networking%2F%20Pwn-ff8c00) ![difficulty](https://img.shields.io/badge/difficulty-Very%20Easy-brightgreen) ![points](https://img.shields.io/badge/points-975-orange) ![status](https://img.shields.io/badge/status-Solved-blue)

# Stop, Drop and Roll — HTB CTF — Writeup

> One-line summary  
Automated a simple networked reaction game using **pwntools** to read the prompts, translate moves to actions, and send responses until the flag is returned.

---

## Table of Contents
- [Target & Scope](#target--scope)  
- [What I did (raw notes)](#what-i-did-raw-notes)  
- [Recon / Observations](#recon--observations)  
- [Approach](#approach)  
- [Exploit script (ready-to-run)](#exploit-script-ready-to-run)  
- [How to run](#how-to-run)  
- [Result / Flag](#result--flag)  
- [Notes & hardening](#notes--hardening)  
- [Final notes](#final-notes)

---

## Target & Scope
- **Challenge name:** Stop, Drop and Roll  
- **Platform:** Hack The Box (HTB)  
- **Category:** Networking / Automation  
- **Difficulty:** Very Easy  
- **Points:** 975  
- **Goal:** Automate the protocol to respond correctly and retrieve the flag.

---

## What I did (raw notes)
1. Spawned the Docker for the challenge.  
2. Opened the IP+port in a browser and read the instructions.  
3. Tried uselessly to put that same IP in a terminal browser.  
4. Website instructions said:
   - If I tell you there's a **GORGE**, you send back **STOP**  
   - If I tell you there's a **PHREAK**, you send back **DROP**  
   - If I tell you there's a **FIRE**, you send back **ROLL**  
5. Tried passing `stop`/`drop`/`roll` in the URL — static, no progress.  
6. Connected with `nc <IP> <PORT>` (example: `nc 83.136.254.84 40261`) to interact properly.  
7. Played a few manual rounds to observe server prompts and behaviour.  
8. Tried arbitrary commands (`ls`, `cd`) — nothing.  
9. Decided to automate using Python + **pwntools**.  
10. Wrote a script to parse the prompt, map moves → actions, and loop until the flag.  
11. Ran and debugged until stable.  
12. Script completed and returned the flag:

```

HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_w4Y_oUt!}

```

> **If you plan to upload this to a public repo:** replace the flag above with a redaction or follow HTB disclosure rules.

---

## Recon / Observations
- The server speaks a short protocol: it prints a question containing one or more moves (comma-separated in the game observed) and then prompts:
```

What do you do?

````
- Responses are simple uppercase words joined with hyphens (e.g. `STOP-DROP-ROLL`) depending on moves order.
- After a number of correct rounds the server returns the flag and closes/ends the session (EOF), or sometimes the flag appears then the server closes — script should handle EOF and print remaining output.

---

## Approach
1. Use `pwntools` `remote()` to connect to the target IP + PORT.  
2. Wait for initial handshake prompt and send acceptance (`y`) if asked.  
3. Loop: receive until `"What do you do? "`; parse the previous line to extract the moves; map each move to the corresponding action (`GORGE → STOP`, `PHREAK → DROP`, `FIRE → ROLL`); join with `-` and send back.  
4. Repeat until the server drops the connection (EOF) or sends the flag.  
5. Print any received output (including flag) and exit.

---

## Exploit script (ready-to-run)

> Save this file as `solve_stop_drop_roll.py`. It uses **pwntools** (install with `pip install pwntools`).

```python
#!/usr/bin/env python3
# solve_stop_drop_roll.py
# Usage: python3 solve_stop_drop_roll.py <HOST> <PORT>
# Example: python3 solve_stop_drop_roll.py 83.136.254.84 40261

import sys
import re
from pwn import remote, context

context.log_level = 'info'

ACTIONS = {
  "GORGE": "STOP",
  "PHREAK": "DROP",
  "FIRE": "ROLL"
}

def parse_moves(line):
  """
  Try to extract move tokens from a server line.
  The server may send lines like:
    "GORGE, PHREAK, FIRE"
  or a natural-language sentence that includes those words.
  We'll find all known tokens (case-insensitive).
  """
  tokens = []
  # Normalize and find known words
  for key in ACTIONS.keys():
      if re.search(r'\b' + re.escape(key) + r'\b', line, flags=re.IGNORECASE):
          tokens.append(key)
  # If no tokens found by word search, try splitting by commas
  if not tokens:
      parts = [p.strip() for p in re.split(r'[,\n\r]+', line) if p.strip()]
      for p in parts:
          up = p.upper()
          if up in ACTIONS:
              tokens.append(up)
  return tokens

def solve(host, port, rounds_to_try=10000):
  p = remote(host, port, timeout=10)
  try:
      # Optional: wait for an initial prompt like "Are you ready? (y/n)" and answer.
      try:
          intro = p.recvuntil(b'?', timeout=2).decode(errors='ignore')
          if 'ready' in intro.lower() and 'y/n' in intro.lower():
              p.sendline(b'y')
      except Exception:
          # no handshake, continue
          pass

      for i in range(rounds_to_try):
          # Read until the prompt asking for the action
          data = p.recvuntil(b'What do you do? ', timeout=10)
          text = data.decode(errors='ignore')
          # Heuristically find the line with moves:
          lines = text.splitlines()
          # pick the last non-empty line before the prompt
          question_line = None
          for ln in reversed(lines):
              if ln.strip() and 'What do you do' not in ln:
                  question_line = ln.strip()
                  break
          if not question_line:
              # fallback to whole text
              question_line = text.strip()

          # Parse moves
          moves = parse_moves(question_line)
          if not moves:
              # As extra fallback, try to extract capital words
              caps = re.findall(r'\b[A-Z]{2,}\b', question_line)
              for c in caps:
                  if c.upper() in ACTIONS and c.upper() not in moves:
                      moves.append(c.upper())

          # Map moves to actions and send answer
          answers = [ACTIONS[m] for m in moves if m in ACTIONS]
          answer_str = "-".join(answers) if answers else ""
          if answer_str:
              print(f"[+] Round {i+1}: Question-> {question_line!r} | Answer-> {answer_str}")
              p.sendline(answer_str.encode())
          else:
              # if we can't parse, try sending an empty newline to observe server behavior
              print(f"[-] Round {i+1}: Could not parse moves from: {question_line!r} -- sending blank line")
              p.sendline(b"")

          # Small recv to show server feedback (not strictly necessary)
          try:
              peek = p.recv(timeout=1)
              if peek:
                  s = peek.decode(errors='ignore')
                  # If flag-like content visible, print and exit
                  if "HTB{" in s or "}" in s:
                      print("[+] Received:", s)
                      break
                  # otherwise print small server response
                  print(s.strip())
          except Exception:
              pass

  except EOFError:
      # Server closed connection; try to read remaining data
      try:
          rest = p.recvall(timeout=2).decode(errors='ignore')
          if rest:
              print("[+] Connection closed; remaining output:\n", rest)
      except Exception:
          pass
  except KeyboardInterrupt:
      print("[*] Interrupted by user.")
  finally:
      # drop to interactive in case the flag is still there or just close
      try:
          p.interactive()
      except Exception:
          p.close()

if __name__ == "__main__":
  if len(sys.argv) < 3:
      print("Usage: python3 solve_stop_drop_roll.py <HOST> <PORT>")
      sys.exit(1)
  host = sys.argv[1]
  port = int(sys.argv[2])
  solve(host, port)
````

---

## How to run

1. Install pwntools (use a venv if you prefer):

   ```bash
   pip install pwntools
   ```
2. Run the script against the target:

   ```bash
   python3 solve_stop_drop_roll.py 83.136.254.84 40261
   ```
3. The script prints each round's question and answer. When the flag appears it will be printed; the script then drops to interactive mode so you can copy it if needed.

---

## Result / Flag

When the script completed, the server returned the flag:

```
HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_w4Y_oUt!}
```

> **Reminder:** If you plan to push this file to a public GitHub repo, **do not** include raw HTB flags. Replace the flag with a redaction or a note that the flag was captured.

---

## Notes & hardening

* This challenge is designed to be solved by reading the prompt and sending deterministic responses — automation is straightforward.
* If you plan to harden a similar service, consider:

  * Rate-limiting connections.
  * Introducing proof-of-work or captchas for automated clients (not typical for CTFs).
  * Randomizing prompts or using a non-deterministic protocol to complicate simple parsers (again, bad for gameplay).
* For CTF-solve scripts, include robust parsing and EOF handling because some servers either close after flag or before it prints.

---
