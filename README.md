# StegoVault – Steganography Web Application

## Overview

StegoVault is a web application that hides an arbitrary secret file **M** inside a carrier file **P** using bit-replacement steganography with user-supplied parameters **S** (starting bit), **L** (bit interval / periodicity), and **C** (mode). Authenticated users create posts; anyone may browse and download posted stego files.

---

## Features

- User authentication (register / login / logout)
- Embed a **secret message** as typed text (UTF-8) **or** an uploaded file (any format) into a **carrier file** (any format); if both are given, the **upload** wins
- Extract hidden payloads when **S**, **L**, and **C** match embedding
- Modes **C**: `fixed`, `alternate`, `increasing` (period **L** can vary step-by-step per mode)
- Public gallery with image preview when the stego output is a common image type
- Download stego files from the gallery; download extracted payloads from the extract page
- Per-user “My posts” with delete

---

## How embedding works (matches assignment spec)

The carrier **P** is treated as a linear bit stream (each byte expanded MSB-first, consistent end-to-end). Let **N** be the total number of bits in **P**.

- **S**: Embedding begins at bit index **S** (bits `0 … S−1` are left unchanged).
- **L** and **C**: Successive bits of the wrapped payload are written at bit indices **S**, **S + Δ₀**, **S + Δ₀ + Δ₁**, … where each **Δᵢ** is produced by the mode **C** from the base interval **L** (same sequence as in `interval_generator` in `stego.py`).
- Each selected bit is **replaced** by the next bit of the payload (not LSB-only masking), so the scheme matches “every **L**-th bit” stepping in **bits** after **S**, with variable step sizes when **C** changes the effective period.

The payload on disk is a small header (magic, lengths, original filename) followed by the raw bytes of **M**, so extraction can restore both the original name and content reversibly.

---

## Answer to discussion question (given only **L**)

Knowing **L** alone is not enough to recover **M** or the original **P**.

- **S** is unknown: an attacker does not know which bit positions were used without **S** (and without **C**, the gap sequence **Δᵢ** is also unknown).
- **C** changes the step pattern: unless the mode is guessed, the sequence of indices is wrong even if **S** were brute-forced.
- Even with guessed **S** and **C**, **M** is wrapped in a header; random-looking **M** or encrypted **M** does not stand out without other side information.

An attacker who knows **L** might try many **S** values and extraction paths and look for structured output (e.g. known file signatures), which shrinks the search only if other parameters are weak or the payload is redundant. Embedding pre-encrypted **M** and choosing unpredictable **S** and **C** reduces practical risk.

---

## References (course materials and external)

Course / assignment pointers:

- Stanford bit tricks collection (bit-level thinking): [Sean Eron Anderson, *Bit Twiddling Hacks*](http://graphics.stanford.edu/~seander/bithacks.html)
- Python bit-oriented tooling (not required for this project but cited in the assignment): [bitstring](https://github.com/scott-griffiths/bitstring)

Background reading (steganography context):

- Wired, “Steganography,” *Hacker Lexicon*: https://www.wired.com/story/steganography-hacker-lexicon/
- WonderHowTo / Null Byte introductions to steganography (linked from the assignment PDF).

---

## Technologies

- Python 3, Flask, Flask-Login, Flask-SQLAlchemy, SQLite
- HTML/CSS (Bootstrap-style templates in repo)

---

## Configuration

Optional: install `python-dotenv` and copy `.env.example` to `.env`, then set `SECRET_KEY` to a long random string for deployment. If `SECRET_KEY` is unset, a development default is used (change before production).

---

## How to run

### 1. Install dependencies

```
pip install -r requirements.txt
```

### 2. Run the application

```
python app.py
```

### 3. Open in browser

http://127.0.0.1:5000

### 4. Also i have already hosted it so can be accessed using
```
https://stego-site-mpha.onrender.com/
```

---

## Project structure

```
stego-site/
├── app.py
├── stego.py
├── requirements.txt
├── README.md
├── static/
│   ├── css/
│   ├── uploads/
│   └── outputs/
└── templates/
    ├── base.html
    ├── dashboard.html
    ├── create_post.html
    ├── gallery.html
    ├── my_posts.html
    ├── extract.html
    ├── profile.html
    ├── login.html
    └── register.html
```

---

## Notes

- Skipping **S** bits at the start of **P** avoids disturbing critical headers when **S** is chosen appropriately; aggressive **S** values can still corrupt format-specific data.
- Correct **S**, **L**, and **C** are required for extraction.
- This is an educational baseline; stronger deployments would use encryption for **M**, HTTPS, secrets management, and hardened hosting.
