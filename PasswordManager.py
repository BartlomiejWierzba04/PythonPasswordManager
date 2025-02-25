import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import os
import base64
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        
        # GUI Elements
        self.website_label = tk.Label(root, text="Website:")
        self.website_entry = tk.Entry(root, width=30)
        self.username_label = tk.Label(root, text="Username:")
        self.username_entry = tk.Entry(root, width=30)
        self.password_label = tk.Label(root, text="Password:")
        self.password_entry = tk.Entry(root, width=30)
        self.master_pw_label = tk.Label(root, text="Master Password:")
        self.master_pw_entry = tk.Entry(root, show="*", width=30)
        
        self.save_button = tk.Button(root, text="Save", command=self.save_password)
        self.retrieve_button = tk.Button(root, text="Retrieve", command=self.retrieve_password)
        
        # Layout
        self.website_label.grid(row=0, column=0, padx=10, pady=5)
        self.website_entry.grid(row=0, column=1, padx=10, pady=5)
        self.username_label.grid(row=1, column=0, padx=10, pady=5)
        self.username_entry.grid(row=1, column=1, padx=10, pady=5)
        self.password_label.grid(row=2, column=0, padx=10, pady=5)
        self.password_entry.grid(row=2, column=1, padx=10, pady=5)
        self.master_pw_label.grid(row=3, column=0, padx=10, pady=5)
        self.master_pw_entry.grid(row=3, column=1, padx=10, pady=5)
        self.save_button.grid(row=4, column=0, padx=10, pady=10)
        self.retrieve_button.grid(row=4, column=1, padx=10, pady=10)

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        return kdf.derive(password.encode())

    def encrypt_data(self, key, iv, data):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt_data(self, key, iv, ciphertext):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def save_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        master_pw = self.master_pw_entry.get()

        if not all([website, username, password, master_pw]):
            messagebox.showerror("Error", "All fields are required!")
            return

        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self.derive_key(master_pw, salt)
        
        data = json.dumps({"username": username, "password": password}).encode()
        ciphertext = self.encrypt_data(key, iv, data)

        entry = {
            "website": website,
            "salt": base64.b64encode(salt).decode(),
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

        try:
            with open("passwords.json", "r") as f:
                entries = json.load(f)
        except FileNotFoundError:
            entries = []

        entries.append(entry)

        with open("passwords.json", "w") as f:
            json.dump(entries, f)

        messagebox.showinfo("Success", "Credentials saved securely!")
        self.clear_fields()

    def retrieve_password(self):
        website = self.website_entry.get()
        master_pw = self.master_pw_entry.get()

        try:
            with open("passwords.json", "r") as f:
                entries = json.load(f)
        except FileNotFoundError:
            messagebox.showerror("Error", "No passwords stored yet!")
            return

        for entry in entries:
            if entry["website"] == website:
                try:
                    salt = base64.b64decode(entry["salt"])
                    iv = base64.b64decode(entry["iv"])
                    ciphertext = base64.b64decode(entry["ciphertext"])
                    key = self.derive_key(master_pw, salt)
                    
                    decrypted_data = self.decrypt_data(key, iv, ciphertext)
                    credentials = json.loads(decrypted_data.decode())
                    
                    # Populate the username and password fields
                    self.username_entry.delete(0, tk.END)
                    self.username_entry.insert(0, credentials["username"])
                    self.password_entry.delete(0, tk.END)
                    self.password_entry.insert(0, credentials["password"])
                    return
                except Exception as e:
                    messagebox.showerror("Error", "Decryption failed. Wrong master password?")
                    return

        messagebox.showinfo("Not Found", "No credentials found for this website")

    def clear_fields(self):
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.master_pw_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
