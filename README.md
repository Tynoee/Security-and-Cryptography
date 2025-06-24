# 🔐 Cryptographic Application

This is a Python-based cryptographic application that supports encryption, decryption, and hashing using both **classic** and **modern** algorithms. It provides two interfaces for interaction:
- A **RESTful API built with Flask and FastAPI**, documented using **Swagger UI**
- A **Streamlit frontend** for a more visual, user-friendly experience

It also supports file-based cryptographic operations, such as hashing and digital signatures.


---

## 🚀 Features

### 🏛️ Classic Ciphers
- **Caesar Cipher** – supports custom shift keys and optional custom alphabets
- **Vigenère Cipher** – supports customizable keyword input

### 🔐 Modern Cryptography
- **SHA-256 hashing**
- **RSA encryption/decryption**
- **RSA key pair generation**
- **Digital signing and signature verification**

### 🖥️ Interfaces
- **REST API** (via Flask + FastAPI)
  - Accessible and interactive via **Swagger UI**
  - Easy testing through Postman or `curl`
- **Streamlit Frontend**
  - Clean UI for selecting algorithms, entering inputs, and viewing results
  - Choose cipher or algorithm
  - Input message, key, and view result

- **Testing**
  - Unit tests for all ciphers using various inputs

---

## ⚙️ Installation

1. **Clone the repository**

```bash
git clone https://github.com/Tynoee/Security-and-Cryptography.git
cd Security-and-Cryptography
````

2. **Install dependencies**

```bash
pip install -r requirements.txt
```
---

## 🧪 Running the Application

### Launch the REST API (FastAPI via Uvicorn)

```bash
uvicorn main:app --reload
```

- Swagger documentation: http://127.0.0.1:8000/docs
- ReDoc (optional): http://127.0.0.1:8000/redoc

## Launch the Streamlit UI
```bash
streamlit run streamlit_app.py
```
- Opens at: http://localhost:8501

### ✅ Run Tests
python -m unittest discover -s tests

### 📦 Dependencies
cryptography>=42.0
pycryptodome>=3.20
fastapi>=0.110.0
uvicorn[standard]>=0.27.0
streamlit>=1.30.0
python-multipart




