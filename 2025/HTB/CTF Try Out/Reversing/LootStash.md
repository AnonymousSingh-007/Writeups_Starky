![platform](https://img.shields.io/badge/platform-HTB-2ea44f) ![category](https://img.shields.io/badge/category-Binary%2FReverse-8a2be2) ![difficulty](https://img.shields.io/badge/difficulty-Very%20Easy-brightgreen) ![points](https://img.shields.io/badge/points-750-orange) ![status](https://img.shields.io/badge/status-Solved-blue)

# LootStash — HTB CTF — Writeup

> Short summary  
Solved the **LootStash** (HTB) binary by inspecting the distributed executable, running it to see runtime output, and extracting printable strings from the ELF to find the flag. This writeup documents reconnaissance, analysis, exploitation steps, the exact commands used, and mitigation notes.

---

## Table of Contents
- [Target & Scope](#target--scope)  
- [Recon / Initial inspection](#recon--initial-inspection)  
- [Dynamic check / Running the binary](#dynamic-check--running-the-binary)  
- [Static analysis / `strings` discovery](#static-analysis--strings-discovery)  
- [Result / Flag](#result--flag)  
- [Root cause](#root-cause)  
- [Mitigations](#mitigations)  
- [Lessons learned](#lessons-learned)  
- [Appendix: Commands / Notes](#appendix-commands--notes)

---

## Target & Scope
- **Challenge name:** LootStash  
- **Platform:** Hack The Box (HTB)  
- **Category:** Binary / Reverse Engineering  
- **Difficulty:** Very Easy  
- **Points:** 750  
- **Goal:** Retrieve the flag from the provided binary

---

## Recon / Initial inspection
- Received a single executable named `stash` (or `Stash` in reports).
- Opened the file with a terminal editor (`nano stash`) — saw non-printable/garbage bytes (expected for a compiled binary) and one helpful human-readable message:

*You got: '%s'. Now run, before anyone tries to steal it!*

(This indicated the binary prints some saved string when executed.)

- Checked file type:
file stash
## Output : stash: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV)

### Dynamic check / Running the binary

- Ran the program to observe behavior:

"./stash" 


- xample output observed:

Diving into the stash - let's see what we can find.
.....
You got: 'Brilliance, Idol of the Forgotten'. Now run, before anyone tries to steal it!


- The runtime output showed a human-readable string but did not explicitly show the HTB flag format.

## Static analysis — strings discovery

"strings stash "
- Because this is a compiled ELF, quick static checks often reveal secrets or helpful constants
- Pair it with grep sp:
"strngs stash | grep "HTB" "

### Got the FLAG!

## Root Cause
The binary contains the flag as a literal string (string constant) embedded in the executable. The build/distribution process left this data in an accessible section of the ELF; strings can extract such literals even if the binary is PIE or partially stripped. Common reasons for leakage:

-- Developer left a test/debug string in the code.

-- The binary was not stripped or sensitive data was hard-coded.