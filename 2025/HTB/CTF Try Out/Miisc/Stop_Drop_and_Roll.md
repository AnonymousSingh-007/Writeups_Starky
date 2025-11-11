
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
- [Result / Flag](#result--flag)  
- [Notes & hardening](#notes--hardening)  


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
from pwn import *
import sys

# --- Configuration ---
actions = {"GORGE": "STOP", "PHREAK": "DROP", "FIRE": "ROLL"}
HOST = '****'
PORT = *****
ROUNDS = 10000 

def repeat_test(p):
    """Handles the repetitive 'What do you do?' question and answer."""
    try:
        # 1. Receive data up to the prompt.
        data = p.recvuntil(b'What do you do? ', timeout=1) 

        # 2. Robust Question Extraction
        lines = data.split(b'\n')
        
        # We need at least two lines to safely grab the line before the prompt.
        if len(lines) < 2:
            # Raising a standard ValueError to move to the non-fatal exception block.
            raise ValueError("Incomplete data received for question parsing.") 
            
        question_line_bytes = lines[-2].strip(b'\r')
        question = question_line_bytes.decode('ascii', errors='ignore')
        
        moves = question.split(',')
        
        answer = []
        for move in moves:
            action_key = move.strip().upper()  # Ensure key is clean and uppercase
            if action_key in actions:
                answer.append(actions[action_key])
            else:
                warning(f"Unknown move received: {action_key}. Skipping.")
                
        # 3. Format and Send Answer
        answer_str = "-".join(answer)
        info(f"Question is: {question}")
        info(f"Answered with: {answer_str}")
        
        p.sendline(answer_str.encode('ascii'))

    except EOFError:
        # This is the expected successful exit condition.
        success("Server closed connection. Attempting to retrieve flag...")
        try:
            rcv = p.recvall().decode(errors='ignore')
            if rcv.strip():
                success("FLAG/Final Output:\n%s", rcv)
            else:
                error("Connection closed, but no final output received.")
        except Exception as e:
            error(f"Error retrieving final output: {e}")
        sys.exit(0) # Exit successfully after flag attempt
        
    except Exception as e:
        # CATCHES VALUE ERROR / TIMEOUT / etc.
        # This is the non-fatal block. Using warning() instead of error() 
        # prevents pwnlib from raising a PwnlibException and crashing the script.
        warning(f"Non-fatal error encountered (will continue): {e}")
        # The script returns from the function, and the 'for' loop continues.


# --- Main Execution ---
# context.log_level = 'info' 

p = remote(HOST, PORT)

# 1. Initial Handshake
print(p.recvuntil(b'Are you ready? (y/n)').decode())
p.sendline(b"y") 

# 2. Automation loop
print(f"Entering loop for {ROUNDS} rounds until flag is reached...")
for i in range(ROUNDS):
    repeat_test(p)

# 3. Fallback Interactive session (unlikely to be reached)
warning("Loop finished without EOF. Dropping to interactive mode.")
p.interactive()
````

---

## Result / Flag

When the script completed, the server returned the flag:

```
HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_w4Y_oUt!}
```

---

## Notes & hardening

* This challenge is designed to be solved by reading the prompt and sending deterministic responses — automation is straightforward.
* If you plan to harden a similar service, consider:

  * Rate-limiting connections.
  * Introducing proof-of-work or captchas for automated clients (not typical for CTFs).
  * Randomizing prompts or using a non-deterministic protocol to complicate simple parsers (again, bad for gameplay).
* For CTF-solve scripts, include robust parsing and EOF handling because some servers either close after flag or before it prints.

---
