# HTB Dynastic – *Crypto* – Writeup  
**Points**: 950 | **Difficulty**: Very Easy  

![Crypto](https://img.shields.io/badge/category-crypto-FFD43B?style=flat-square)   
![HTB](https://img.shields.io/badge/platform-HTB-00D26A?style=flat-square&logo=hackthebox)  
![Python](https://img.shields.io/badge/tool-Python-3776AB?style=flat-square&logo=python)  
![Difficulty](https://img.shields.io/badge/difficulty-very_easy-success?style=flat-square)  

---

## Description
> *“A message from a Roman emperor, drawn in blood…”*  
> Given:  
> ```text
> DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL
> ```  
> + A Python script (`source.py`)  
> → Classic crypto, Roman theme → **Caesar? Vigenère? Something custom?**

---

## Solution

### 1. **Initial Recon**
- Downloaded challenge files: `source.py` + ciphertext.
- Hint: **“Roman emperor drawn in blood”** → **Julius Caesar** → Caesar cipher?
- Tried **standard ROT-3**:  
  `DJF → AGC`, `CTA → ZQX` → **gibberish**  
  → Not classic Caesar.

### 2. **Analyze the Python Script**
Used AI (ChatGPT) to break down the logic:

## Encryption Rule:

- -For character at position i (0-indexed):
- -→ cipher_char = (plain_pos + i) % 26

- -Decryption Rule:

- -plain_char = (cipher_pos - i) % 26

Pos,Cipher,Cipher Pos,Shift = i,Plain Pos = (C - i) % 26,Plain Char
D,3,0,(3 - 0) % 26 = 3,D
J,9,1,(9 - 1) % 26 = 8,I
blank line for underscore
C,2,4,(2 - 4) % 26 = 24,Y
T,19,5,(19 - 5) % 26 = 14,O
A,0,6,(0 - 6) % 26 = 20,U

- and so on...

Lesson,Detail
Read the code!,encrypt.py gave the exact algorithm.
Not all Caesar is ROT-N,This was positional shift (+i).
AI = Force multiplier,ChatGPT explained the loop in 10 seconds.
Manual verify first,Decrypt first 5 chars → confirm logic.
Preserve non-letters,"_, !, ? stay unchanged."