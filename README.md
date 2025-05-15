# 🔐 Password Manager

A simple GUI-based password manager built with **Python** and **Tkinter**, using **Fernet encryption** from the `cryptography` library for secure password storage.

## 📦 Features

- Register and encrypt passwords for different websites.
- Retrieve saved passwords securely.
- Update existing account credentials.
- Remove stored account data.
- View all stored account usernames/websites (with a master password).
- Reset the application to start fresh.

## 🛠️ Technologies Used

- Python 3
- Tkinter (for GUI)
- cryptography (for encryption)
- pickle (for secure object serialization)

## 🔒 How It Works

- A symmetric encryption key is generated and stored in `secret.key`.
- Passwords are encrypted and saved to `passwords.dat` using `Fernet`.
- Users must enter a master password to view the list of stored accounts.

## 🚀 Getting Started

### Prerequisites

Make sure you have Python 3 installed. Then install the required module:

```bash
pip install cryptography
```

## 🖥️ Create Standalone Application

Install `PyInstaller` using the command:

```bash
pip install pyinstaller
```

After installing `PyInstaller`. Run the command:

```bash
pyinstaller --noconsole --onefile file_name.py
