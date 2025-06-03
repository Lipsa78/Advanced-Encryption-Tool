import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

# ---------- Core Encryption Logic ----------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_text(plaintext: str, password: str) -> str:
    salt, iv = os.urandom(16), os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padding_len = 16 - (len(plaintext) % 16)
    padded = plaintext + chr(padding_len) * padding_len
    ciphertext = encryptor.update(padded.encode()) + encryptor.finalize()
    return urlsafe_b64encode(salt + iv + ciphertext).decode()

def decrypt_text(ciphertext: str, password: str) -> str:
    try:
        data = urlsafe_b64decode(ciphertext)
        salt, iv, cipherbytes = data[:16], data[16:32], data[32:]
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(cipherbytes) + decryptor.finalize()
        padding_len = padded[-1]
        return padded[:-padding_len].decode()
    except Exception:
        return None

def encrypt_file(filepath: str, password: str):
    with open(filepath, "rb") as f:
        data = f.read()
    salt, iv = os.urandom(16), os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padding_len = 16 - (len(data) % 16)
    padded = data + bytes([padding_len]) * padding_len
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    with open(filepath + ".enc", "wb") as f:
        f.write(salt + iv + ciphertext)

def decrypt_file(filepath: str, password: str):
    with open(filepath, "rb") as f:
        data = f.read()
    salt, iv, cipherbytes = data[:16], data[16:32], data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(cipherbytes) + decryptor.finalize()
    padding_len = padded[-1]
    decrypted = padded[:-padding_len]
    output_path = filepath.replace(".enc", ".dec")
    with open(output_path, "wb") as f:
        f.write(decrypted)

def file_size(file_path):
    size = os.path.getsize(file_path)
    return f"{round(size / 1024, 2)} KB"

# ---------- GUI ----------
def run_gui():
    window = tk.Tk()
    window.title("Advanced Encryption Tool")

    theme = {'dark': {'bg': '#1e1e1e', 'fg': 'white', 'entry_bg': '#2d2d2d', 'button_bg': '#444444'},
             'light': {'bg': '#f0f0f0', 'fg': 'black', 'entry_bg': 'white', 'button_bg': '#dddddd'}}
    current_theme = 'dark'

    def apply_theme():
        th = theme[current_theme]
        window.configure(bg=th['bg'])
        for widget in window.winfo_children():
            if isinstance(widget, (tk.Entry, tk.Text)):
                widget.configure(bg=th['entry_bg'], fg=th['fg'], insertbackground=th['fg'])
            elif isinstance(widget, tk.Label):
                widget.configure(bg=th['bg'], fg=th['fg'])
            elif isinstance(widget, tk.Button):
                widget.configure(bg=th['button_bg'], fg=th['fg'])

    def toggle_theme():
        nonlocal current_theme
        current_theme = 'light' if current_theme == 'dark' else 'dark'
        apply_theme()

    def do_encrypt():
        text = entry_input.get("1.0", tk.END).strip()
        password = entry_password.get()
        if not text or not password:
            messagebox.showwarning("Input Error", "Text and password are required.")
            return
        encrypted = encrypt_text(text, password)
        entry_output.delete("1.0", tk.END)
        entry_output.insert(tk.END, encrypted)

    def do_decrypt():
        text = entry_input.get("1.0", tk.END).strip()
        password = entry_password.get()
        if not text or not password:
            messagebox.showwarning("Input Error", "Text and password are required.")
            return
        decrypted = decrypt_text(text, password)
        if decrypted:
            entry_output.delete("1.0", tk.END)
            entry_output.insert(tk.END, decrypted)
        else:
            messagebox.showerror("Decryption Failed", "Invalid password or corrupted data.")

    def save_output():
        data = entry_output.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Output Empty", "No output to save.")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if filepath:
            with open(filepath, "w") as f:
                f.write(data)
            messagebox.showinfo("Saved", f"Output saved to {filepath}")

    def select_file_encrypt():
        filepath = filedialog.askopenfilename()
        if filepath:
            password = entry_password.get()
            progress.start()
            encrypt_file(filepath, password)
            progress.stop()
            messagebox.showinfo("File Encrypted", f"Saved: {filepath}.enc\nSize: {file_size(filepath + '.enc')}")

    def select_file_decrypt():
        filepath = filedialog.askopenfilename()
        if filepath:
            password = entry_password.get()
            progress.start()
            decrypt_file(filepath, password)
            progress.stop()
            messagebox.showinfo("File Decrypted", f"Saved: {filepath.replace('.enc', '.dec')}\nSize: {file_size(filepath.replace('.enc', '.dec'))}")

    tk.Label(window, text="Enter Text or Ciphertext:").pack()
    entry_input = tk.Text(window, height=5, width=60)
    entry_input.pack()

    tk.Label(window, text="Enter Password:").pack()
    entry_password = tk.Entry(window, show='*', width=40)
    entry_password.pack()

    tk.Button(window, text="Encrypt Text", command=do_encrypt).pack(pady=2)
    tk.Button(window, text="Decrypt Text", command=do_decrypt).pack(pady=2)
    tk.Button(window, text="Save Output to File", command=save_output).pack(pady=2)
    tk.Button(window, text="Encrypt File", command=select_file_encrypt).pack(pady=2)
    tk.Button(window, text="Decrypt File", command=select_file_decrypt).pack(pady=2)

    tk.Label(window, text="Output:").pack()
    entry_output = tk.Text(window, height=5, width=60)
    entry_output.pack()

    progress = ttk.Progressbar(window, mode='indeterminate')
    progress.pack(pady=5)

    tk.Button(window, text="Toggle Theme", command=toggle_theme).pack(pady=5)

    apply_theme()
    window.mainloop()

if __name__ == "__main__":
    run_gui()
