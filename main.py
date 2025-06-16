import tkinter as tk
from tkinter import scrolledtext
import os
import sys
from encryption import encrypt_data, decrypt_data
from ollama_ai import ask_ollama
import json

if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

APP_DATA_DIR = os.path.expanduser("~/.safepad")
os.makedirs(APP_DATA_DIR, exist_ok=True)
VAULT_FILE = os.path.join(APP_DATA_DIR, "data.json.enc")


class SafePadApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SafePad")
        self.master_password = None
        self.data = {}
        self.placeholders = {}
        self.selected_key = None
        self.selected_tag = None
        self.dirty = False
        self.root.after(60000, self.autosave_loop)
        self.build_login_ui()

    def add_placeholder(self, entry, text):
        entry.insert(0, text)
        entry.config(fg='gray')
        self.placeholders[entry] = text

        def on_focus_in(event):
            if entry.get() == text:
                entry.delete(0, tk.END)
                entry.config(fg='white')

        def on_focus_out(event):
            if not entry.get():
                entry.insert(0, text)
                entry.config(fg='gray')

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)

    def build_login_ui(self):
        self.login_frame = tk.Frame(self.root, padx=30, pady=30, bg="#2e2e2e")
        tk.Label(self.login_frame, text="Enter Master Password\n(first run creates vault):",
                 font=("Arial", 14), fg="white", bg="#2e2e2e").pack(pady=(0, 10))

        self.login_entry = tk.Entry(self.login_frame, show="*", width=30,
                                    font=("Arial", 14), bg="#3e3e3e", fg="white", insertbackground="white")
        self.login_entry.pack()
        self.login_entry.focus_set()

        tk.Button(self.login_frame, text="Unlock Vault", font=("Arial", 12),
                  command=self.handle_login, width=20).pack(pady=(10, 0))

        self.login_frame.pack(fill="both", expand=True)

    def handle_login(self):
        pwd = self.login_entry.get().strip()
        if not pwd:
            return

        if os.path.exists(VAULT_FILE):
            try:
                with open(VAULT_FILE, "rb") as f:
                    encrypted = f.read()
                self.data = decrypt_data(encrypted, pwd)
            except Exception as e:
                self.login_entry.delete(0, tk.END)
                return
        else:
            self.data = {}
            with open(VAULT_FILE, "wb") as f:
                f.write(encrypt_data(self.data, pwd))


        self.master_password = pwd
        self.login_frame.destroy()
        self.build_main_ui()

    def build_main_ui(self):
        self.root.configure(bg="#2e2e2e")
        self.main_frame = tk.Frame(self.root, bg="#2e2e2e")
        self.main_frame.pack(fill="both", expand=True)

        chat_frame = tk.Frame(self.main_frame, padx=10, pady=10, bg="#2e2e2e")
        chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False)

        self.chat_log = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, height=30, width=50,
                                                  font=("Arial", 12), state='disabled',
                                                  bg="#1e1e1e", fg="white", insertbackground="white")
        self.chat_log.pack(padx=5, pady=5, fill=tk.BOTH)

        self.chat_entry = tk.Entry(chat_frame, width=40, font=("Arial", 12),
                                   bg="#3e3e3e", fg="white", insertbackground="white")
        self.add_placeholder(self.chat_entry, "Ask something like: what's my main school login?")
        self.chat_entry.pack(side=tk.LEFT, padx=(5, 0), pady=5)
        self.chat_entry.bind("<Return>", lambda event: self.ask_ai_for_key())

        tk.Button(chat_frame, text="Ask AI", font=("Arial", 12), command=self.ask_ai_for_key).pack(side=tk.LEFT, padx=5)

        vault_frame = tk.Frame(self.main_frame, padx=10, pady=10, bg="#2e2e2e")
        vault_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        tk.Label(vault_frame, text="Add New Entry", fg="white", bg="#2e2e2e", font=("Arial", 14)).pack()

        self.key_entry = tk.Entry(vault_frame, font=("Arial", 12), width=30, bg="#3e3e3e", fg="white", insertbackground="white")
        self.add_placeholder(self.key_entry, "Entry name (e.g. github)")
        self.key_entry.pack(pady=5)

        self.username_entry = tk.Entry(vault_frame, font=("Arial", 12), width=30, bg="#3e3e3e", fg="white", insertbackground="white")
        self.add_placeholder(self.username_entry, "Username")
        self.username_entry.pack(pady=5)

        self.password_entry = tk.Entry(vault_frame, font=("Arial", 12), width=30, bg="#3e3e3e", fg="white", insertbackground="white")
        self.add_placeholder(self.password_entry, "Password")
        self.password_entry.pack(pady=5)

        self.notes_entry = tk.Entry(vault_frame, font=("Arial", 12), width=30, bg="#3e3e3e", fg="white", insertbackground="white")
        self.add_placeholder(self.notes_entry, "Notes")
        self.notes_entry.pack(pady=5)

        self.alias_entry = tk.Entry(vault_frame, font=("Arial", 12), width=30, bg="#3e3e3e", fg="white", insertbackground="white")
        self.add_placeholder(self.alias_entry, "Aliases")
        self.alias_entry.pack(pady=5)

        tk.Button(vault_frame, text="Save Entry", command=self.save_entry, font=("Arial", 12)).pack(pady=(5, 10))

        self.entries_text = scrolledtext.ScrolledText(vault_frame, width=80, height=20,
                                                      font=("Courier", 13), wrap=tk.WORD,
                                                      bg="#1e1e1e", fg="white", state='disabled')
        self.entries_text.pack(pady=5, fill=tk.BOTH, expand=True)
        self.entries_text.bind("<Button-1>", self.handle_click_on_entry)

        self.edit_button = tk.Button(vault_frame, text="Edit Selected", font=("Arial", 12), command=self.edit_selected_entry)
        self.delete_button = tk.Button(vault_frame, text="Delete Selected", font=("Arial", 12), command=self.delete_selected_entry)

        self.refresh_entries()

    def autosave_loop(self):
        if self.master_password and self.dirty:
            with open(VAULT_FILE, "wb") as f:
                f.write(encrypt_data(self.data, self.master_password))
            self.dirty = False
        self.root.after(60000, self.autosave_loop)

    def refresh_entries(self):
        self.entries_text.configure(state='normal')
        self.entries_text.delete("1.0", tk.END)
        self.entry_key_lines = {}

        for tag in self.entries_text.tag_names():
            self.entries_text.tag_delete(tag)

        for key, creds in self.data.items():
            username = creds.get("username", "").strip() or "n/a"
            password = creds.get("password", "").strip() or "n/a"
            notes = creds.get("notes", "").strip() or "n/a"
            aliases = creds.get("aliases", "").strip() or "n/a"

            start_index = self.entries_text.index(tk.INSERT)
            block = (
                f"[{key}]\n"
                f"  Username: {username} | Password: {password}\n"
                f"  Notes: {notes}     | Aliases: {aliases}\n\n"
            )
            self.entries_text.insert(tk.END, block)
            end_index = self.entries_text.index(tk.INSERT)

            tag_name = f"tag_{key}"
            self.entries_text.tag_add(tag_name, start_index, end_index)
            self.entry_key_lines[(start_index, end_index)] = (key, tag_name)

        self.entries_text.configure(state='disabled')
        self.edit_button.pack_forget()
        self.delete_button.pack_forget()
        self.selected_key = None
        self.selected_tag = None

    def handle_click_on_entry(self, event):
        index = self.entries_text.index(f"@{event.x},{event.y}")
        for (start, end), (key, tag) in self.entry_key_lines.items():
            if self.entries_text.compare(start, "<=", index) and self.entries_text.compare(index, "<", end):
                self.selected_key = key
                self.selected_tag = tag

                self.entries_text.configure(state='normal')
                for _, (_, other_tag) in self.entry_key_lines.items():
                    self.entries_text.tag_configure(other_tag, background="#1e1e1e")
                self.entries_text.tag_configure(tag, background="#333366")
                self.entries_text.configure(state='disabled')

                self.edit_button.pack(pady=(5, 2))
                self.delete_button.pack(pady=(0, 10))
                return

        self.selected_key = None
        self.selected_tag = None
        self.edit_button.pack_forget()
        self.delete_button.pack_forget()

    def edit_selected_entry(self):
        if not self.selected_key:
            return
        creds = self.data.get(self.selected_key, {})

        self.key_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.notes_entry.delete(0, tk.END)
        self.alias_entry.delete(0, tk.END)

        self.key_entry.insert(0, self.selected_key)
        self.username_entry.insert(0, creds.get("username", ""))
        self.password_entry.insert(0, creds.get("password", ""))
        self.notes_entry.insert(0, creds.get("notes", ""))
        self.alias_entry.insert(0, creds.get("aliases", ""))

        self.data.pop(self.selected_key)
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypt_data(self.data, self.master_password))
        self.dirty = True
        self.refresh_entries()

    def delete_selected_entry(self):
        if not self.selected_key:
            return
        if self.selected_key in self.data:
            self.data.pop(self.selected_key)
            with open(VAULT_FILE, "wb") as f:
                f.write(encrypt_data(self.data, self.master_password))
            self.dirty = True
        self.refresh_entries()

    def save_entry(self):
        def clean_input(entry):
            val = entry.get().strip()
            return val if val and val != self.placeholders.get(entry) else "n/a"

        key = clean_input(self.key_entry).lower()
        if not key or key == "n/a":
            return

        self.data[key] = {
            "username": clean_input(self.username_entry),
            "password": clean_input(self.password_entry),
            "notes": clean_input(self.notes_entry),
            "aliases": clean_input(self.alias_entry)
        }

        with open(VAULT_FILE, "wb") as f:
            f.write(encrypt_data(self.data, self.master_password))
        self.dirty = True

        for entry in [self.key_entry, self.username_entry, self.password_entry, self.notes_entry, self.alias_entry]:
            entry.delete(0, tk.END)
            placeholder = self.placeholders.get(entry)
            if placeholder:
                self.add_placeholder(entry, placeholder)

        self.refresh_entries()

    def log_message(self, sender, message):
        self.chat_log.configure(state='normal')
        if sender == "You":
            self.chat_log.tag_configure("user", justify="right", foreground="white")
            self.chat_log.insert(tk.END, f"{message}\n\n", "user")
        else:
            self.chat_log.tag_configure("ai", justify="left", foreground="white")
            self.chat_log.insert(tk.END, f"{sender}: {message}\n\n", "ai")
        self.chat_log.see(tk.END)
        self.chat_log.configure(state='disabled')

    def ask_ai_for_key(self):
        user_input = self.chat_entry.get().strip()
        if not user_input:
            return
        self.log_message("You", user_input)
        self.chat_entry.delete(0, tk.END)
        self.log_message("AI", "Finding login info...")

        entries = [
            f"{k} ← notes: {self.data[k].get('notes', '')}, aliases: {self.data[k].get('aliases', '')}"
            for k in self.data
        ]
        ai_prompt = "\n".join(entries) + f"\nUser query: {user_input}"
        try:
            match = ask_ollama(ai_prompt)
        except Exception:
            self.log_message("AI", "Sorry, I couldn't connect to the AI.")
            return

        result = self.data.get(match)
        if result:
            msg = (
                f"Here's what I found for '{match}':\n"
                f"Username: {result.get('username', 'n/a')}\n"
                f"Password: {result.get('password', 'n/a')}\n"
                f"Notes: {result.get('notes', 'n/a')}"
            )
        else:
            msg = f"Sorry, I couldn't find any credentials for '{match}'."

        self.log_message("AI", msg)
        # Automatically scroll to and highlight the matching entry
        for (start, end), (key, tag) in self.entry_key_lines.items():
            if key == match:
                self.entries_text.configure(state='normal')
                self.entries_text.tag_configure(tag, background="#333366")
                self.entries_text.see(start)  # Scroll to the start of the entry
                self.entries_text.configure(state='disabled')

                self.selected_key = key
                self.selected_tag = tag
                self.edit_button.pack(pady=(5, 2))
                self.delete_button.pack(pady=(0, 10))
                break

if __name__ == "__main__":
    root = tk.Tk()
    app = SafePadApp(root)

    def on_close():
        if app.master_password:
            with open(VAULT_FILE, "wb") as f:
                f.write(encrypt_data(app.data, app.master_password))
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()