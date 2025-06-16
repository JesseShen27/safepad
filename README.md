# SafePad

SafePad is a secure, AI-assisted password manager built with Python and Tkinter. It allows users to store, view, and retrieve encrypted login credentials entirely offline — with optional natural language help from a local AI model (Ollama).

---

## Features

- Strong encryption using Fernet (AES + HMAC) with a master password
- AI assistant (via Ollama) helps you find credentials using natural language
- Modern desktop UI built with Tkinter
- Add, edit, and delete login entries with labels, notes, and aliases
- Data persistence with autosave and file-based vault storage
- Fully offline — no cloud, no third-party data sharing

---

## Getting Started

### Requirements

- Python 3.8+
- `cryptography` library
- (Optional) Ollama for local AI

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install cryptography requests
```

### Running Ollama (AI)

Start Ollama on your machine and pull a model:

```bash
ollama run llama3
```

SafePad connects to http://localhost:11434 to use this model.

---

## Running the App

```bash
python3 main.py
```

### First-Time Setup

- You’ll be asked to create a master password.
- This password will be used to encrypt and decrypt your vault.

---

## Asking the AI

You can type things like:

```
what's my github login?
school email?
login for wizard101 alt?
```

The AI will respond with the most relevant entry based on your saved keys, notes, and aliases.

> Note: SafePad only sends key names, notes, and aliases to the AI — never passwords.

---

## How Data Is Kept Safe

| Security Layer     | Details |
|--------------------|---------|
| Encryption         | Fernet (AES with HMAC), key derived from your master password |
| File storage       | Vault is saved in ~/.safepad/data.json.enc, encrypted at rest |
| AI usage           | AI sees only labels and notes; real credentials are stored and displayed locally |
| Connectivity       | Fully offline by default; Ollama runs locally |

---

## File Structure

```plaintext
safepad/
├── main.py             # Main Tkinter app
├── encryption.py       # Handles Fernet encryption
├── ollama_ai.py        # Talks to local AI model
├── icon.icns           # App icon (optional)
├── data.json.enc       # Encrypted vault (ignored by Git)
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Important Notes

- Don't forget your master password — if lost, there's no way to recover your vault.
- This project is not yet code-signed or notarized — macOS may warn users when opening it.
- Consider setting permissions on your vault:

```bash
chmod 600 ~/.safepad/data.json.enc
```

---

## License

MIT License — use it, fork it, improve it.

---

## Future Plans

- Web app version
- Chrome extension
- Mobile support (eventually)
