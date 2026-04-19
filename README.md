# StegoVault – Steganography Web Application

## Overview

StegoVault is a web-based application that allows users to securely hide secret messages inside files using steganography. T
he system supports embedding and extracting hidden data using customizable parameters and provides a user-friendly interface with 
authentication and file management.

---

## Features

- User authentication (Register / Login / Logout)
- Embed secret messages into carrier files
- Extract hidden messages from stego files
- Support for parameters:
  - **S** – Starting bit
  - **L** – Periodicity / interval
  - **C** – Mode of operation
- Multiple embedding modes:
  - Fixed
  - Alternate
  - Increasing
- Public gallery of stego files
- Download generated stego files
- User dashboard
- My Posts page for managing uploads
- Delete functionality for user posts
- Profile page to update user details
- Image preview in gallery

---

## Answer to Discussion Question

If an attacker knows only the periodicity parameter **L**, recovering the hidden message is not straightforward but
 becomes partially feasible through analysis.The attacker could attempt to extract bits at every **L-th position** for
different starting offsets **S**. By trying multiple values of **S**, the attacker may eventually reconstruct a bit 
sequence that resembles structured data. Known file signatures (such as JPEG or PNG headers) can help identify correct extraction.
Additionally, statistical analysis of modified bits may reveal anomalies in the carrier file. If the attacker also knows or
guesses the embedding mode **C**, the search space becomes smaller.However, without knowledge of both **S** and **C**, extraction 
remains difficult. The security of the method improves when:

- The starting bit **S** is unknown  
- The mode **C** varies dynamically  
- The payload is encrypted before embedding  

Thus, knowing only **L** provides limited advantage but does not guarantee successful recovery of the hidden message.

---

## Technologies Used

- Python (Flask)
- Flask-Login (Authentication)
- Flask-SQLAlchemy (Database)
- SQLite (Database)
- HTML, CSS, Bootstrap (Frontend)

---

## How It Works

### Embedding Process

1. The user uploads a carrier file (**P**).
2. The user enters a secret message (**M**).
3. The user specifies parameters:
   - Starting bit (**S**)
   - Interval (**L**)
   - Mode (**C**)
4. The system converts both carrier and message into bit streams.
5. Starting after **S bits**, every **L-th bit** is replaced with message bits.
6. A new modified file (stego file) is generated and stored.

---

### Extraction Process

1. The user uploads a stego file.
2. The user enters the same parameters (**S, L, C**).
3. The system reads the embedded bits.
4. The original hidden message is reconstructed and displayed.

---

## How to Run the Project

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

---

## Project Structure

stego-site/  
├── app.py  
├── stego.py  
├── requirements.txt  
├── README.md  
├── static/  
│   ├── css/  
│   ├── uploads/  
│   └── outputs/  
├── templates/  
│   ├── base.html  
│   ├── dashboard.html  
│   ├── create_post.html  
│   ├── gallery.html  
│   ├── my_posts.html  
│   ├── extract.html  
│   ├── profile.html  
│   ├── login.html  
│   └── register.html  

---

## Notes

- The first **S bits** are skipped to avoid corrupting file headers.  
- Correct parameters (**S, L, C**) must be used during extraction.  
- The application uses basic steganography and is not fully resistant to advanced attacks.  
- Optional encryption can be added for improved security.
