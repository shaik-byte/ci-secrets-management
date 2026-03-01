# 🔐 CI-Vault

CI-Vault is a Django-based web application designed to manage audit logs, IP tracking, location detection, scheduling tasks, and cryptographic security operations.

---

## 🚀 Features

- User Authentication
- Audit Logging
- IP Address Tracking
- Location Detection from IP
- Background Scheduling (APScheduler)
- Cryptographic Security Handling
- Secure HTTP Requests using Requests Library

---

## 🛠 Tech Stack

- Python 3.10+
- Django
- SQLite (Default Database)
- APScheduler
- Requests
- Cryptography
- tzlocal
- sqlparse
- cffi

---

## 📂 Project Structure

CI-Vault/
│
├── vault/              # Main Django app
├── manage.py
├── requirements.txt
├── README.md
└── venv/

---

## ⚙️ Installation & Setup Guide

### 1️⃣ Clone the Repository

```bash
git clone <your-repository-url>
cd CI-Vault
```

---

### 2️⃣ Create Virtual Environment

```bash
python -m venv venv
```

Activate the environment:

**Windows**
```bash
venv\Scripts\activate
```

**Mac/Linux**
```bash
source venv/bin/activate
```

---

### 3️⃣ Upgrade pip

```bash
python -m pip install --upgrade pip setuptools wheel
```

---

### 4️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 5️⃣ Run Migrations

```bash
python manage.py migrate
```

---

### 6️⃣ Run Development Server

```bash
python manage.py runserver localhost:8000 
```

Server will run at:

http://127.0.0.1:8000/ or localhost:8000 

---

## 📦 Requirements File

Make sure your `requirements.txt` contains:

```
Django>=4.2
requests>=2.31.0
APScheduler>=3.10.4
tzlocal>=5.2
cryptography>=42.0.0
cffi>=1.16.0
sqlparse>=0.4.4
pytz>=2024.1
```

---

## 🔒 Security Notes

- Never commit `venv/` to Git
- Do not expose SECRET_KEY publicly
- Use environment variables in production
- Set `DEBUG = False` in production
- Use PostgreSQL for production deployment

---

## 📌 Best Practices

- Always use virtual environments
- Install dependencies using requirements.txt
- Keep dependencies updated
- Use `.gitignore` for sensitive files

Recommended `.gitignore`:

```
venv/
__pycache__/
*.pyc
db.sqlite3
.env
```

---

## 🚀 Future Enhancements

- JWT Authentication
- Role-Based Access Control
- REST API Support

---

## 👨‍💻 Author

Shaik Mahammad Gouse

---

