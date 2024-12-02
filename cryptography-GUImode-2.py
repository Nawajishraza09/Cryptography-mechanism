import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import scrolledtext
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import os

# Padding functions for DES
def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def unpad(text):
    return text.rstrip()

# Generate DES key
def generate_des_key():
    key = get_random_bytes(8)  # DES key is 8 bytes long
    with open("des_key.key", "wb") as key_file:
        key_file.write(key)
    return key

# DES encryption
def des_encrypt(text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(text)
    ciphertext = cipher.encrypt(padded_text.encode('utf-8'))
    return ciphertext

# DES decryption
def des_decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_padded_text = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded_text.decode('utf-8'))

# Generate AES key
def generate_aes_key():
    key = get_random_bytes(16)  # AES key is 16 bytes long
    with open("aes_key.key", "wb") as key_file:
        key_file.write(key)
    return key

# AES encryption
def aes_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return nonce + ciphertext

# AES decryption
def aes_decrypt(ciphertext, key):
    nonce = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

# Generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("rsa_private_key.pem", "wb") as prv_file:
        prv_file.write(private_key)
    with open("rsa_public_key.pem", "wb") as pub_file:
        pub_file.write(public_key)
    return private_key, public_key

# RSA encryption
def rsa_encrypt(text, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(text.encode('utf-8'))
    return ciphertext

# RSA decryption
def rsa_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext).decode('utf-8')

# Generate ECC keys
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("ecc_private_key.pem", "wb") as prv_file:
        prv_file.write(private_key_pem)
    with open("ecc_public_key.pem", "wb") as pub_file:
        pub_file.write(public_key_pem)
    return private_key_pem, public_key_pem

# ECC encryption
def ecc_encrypt(text, public_key):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    temp_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_key = temp_private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    cipher = AES.new(derived_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    temp_public_key = temp_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return temp_public_key + nonce + ciphertext

# ECC decryption
def ecc_decrypt(ciphertext, private_key):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    public_key_pem = ciphertext[:91]  # Length of public key in PEM format
    nonce = ciphertext[91:107]  # Nonce is 16 bytes
    ciphertext = ciphertext[107:]
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    cipher = AES.new(derived_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

# Hash text using SHA256
def hash_text(text):
    hash_obj = SHA256.new(data=text.encode('utf-8'))
    return hash_obj.hexdigest()

# Verify hash
def verify_hash(text, hash_value):
    hash_obj = SHA256.new(data=text.encode('utf-8'))
    return hash_obj.hexdigest() == hash_value

# GUI functions
def encrypt_des():
    text = input_text.get("1.0", tk.END).strip()
    des_key = generate_des_key()
    encrypted_text = des_encrypt(text, des_key)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, base64.b64encode(encrypted_text).decode('utf-8'))
    messagebox.showinfo("Success", "DES encryption completed. Key saved as des_key.key.")

def decrypt_des():
    encrypted_text_base64 = input_text.get("1.0", tk.END).strip()
    try:
        encrypted_text = base64.b64decode(encrypted_text_base64)
    except Exception as e:
        messagebox.showerror("Error", f"Invalid base64 encoding: {e}")
        return
    
    key_file = filedialog.askopenfilename()
    try:
        with open(key_file, "rb") as key_in_file:
            des_key = key_in_file.read()
        decrypted_text = des_decrypt(encrypted_text, des_key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", f"Error during decryption: {e}")

def encrypt_aes():
    text = input_text.get("1.0", tk.END).strip()
    aes_key = generate_aes_key()
    encrypted_text = aes_encrypt(text, aes_key)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, base64.b64encode(encrypted_text).decode('utf-8'))
    messagebox.showinfo("Success", "AES encryption completed. Key saved as aes_key.key.")

def decrypt_aes():
    encrypted_text_base64 = input_text.get("1.0", tk.END).strip()
    try:
        encrypted_text = base64.b64decode(encrypted_text_base64)
    except Exception as e:
        messagebox.showerror("Error", f"Invalid base64 encoding: {e}")
        return

    key_file = filedialog.askopenfilename()
    try:
        with open(key_file, "rb") as key_in_file:
            aes_key = key_in_file.read()
        decrypted_text = aes_decrypt(encrypted_text, aes_key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", f"Error during decryption: {e}")

def encrypt_rsa():
    text = input_text.get("1.0", tk.END).strip()
    private_key, public_key = generate_rsa_keys()
    encrypted_text = rsa_encrypt(text, public_key)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, base64.b64encode(encrypted_text).decode('utf-8'))
    messagebox.showinfo("Success", "RSA encryption completed. Keys saved as rsa_private_key.pem and rsa_public_key.pem.")

def decrypt_rsa():
    encrypted_text_base64 = input_text.get("1.0", tk.END).strip()
    try:
        encrypted_text = base64.b64decode(encrypted_text_base64)
    except Exception as e:
        messagebox.showerror("Error", f"Invalid base64 encoding: {e}")
        return

    key_file = filedialog.askopenfilename()
    try:
        with open(key_file, "rb") as key_in_file:
            private_key = key_in_file.read()
        decrypted_text = rsa_decrypt(encrypted_text, private_key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", f"Error during decryption: {e}")

def encrypt_ecc():
    text = input_text.get("1.0", tk.END).strip()
    private_key, public_key = generate_ecc_keys()
    encrypted_text = ecc_encrypt(text, public_key)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, base64.b64encode(encrypted_text).decode('utf-8'))
    messagebox.showinfo("Success", "ECC encryption completed. Keys saved as ecc_private_key.pem and ecc_public_key.pem.")

def decrypt_ecc():
    encrypted_text_base64 = input_text.get("1.0", tk.END).strip()
    try:
        encrypted_text = base64.b64decode(encrypted_text_base64)
    except Exception as e:
        messagebox.showerror("Error", f"Invalid base64 encoding: {e}")
        return

    key_file = filedialog.askopenfilename()
    try:
        with open(key_file, "rb") as key_in_file:
            private_key = key_in_file.read()
        decrypted_text = ecc_decrypt(encrypted_text, private_key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", f"Error during decryption: {e}")

def hash_sha256():
    text = input_text.get("1.0", tk.END).strip()
    hash_value = hash_text(text)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, hash_value)
    messagebox.showinfo("Success", "Text hashed successfully.")

def verify_sha256():
    text = input_text.get("1.0", tk.END).strip()
    hash_value = output_text.get("1.0", tk.END).strip()
    if verify_hash(text, hash_value):
        messagebox.showinfo("Success", "Hash verified successfully!")
    else:
        messagebox.showerror("Error", "Hash verification failed!")

# GUI setup
root = tk.Tk()
root.title("Cryptography GUI")
root.configure(bg="#2E2E2E")

tk.Label(root, text="Input Text", fg="white", bg="#2E2E2E").grid(row=0, column=0, padx=10, pady=10)
input_text = scrolledtext.ScrolledText(root, height=10, width=50, bg="#121212", fg="white", insertbackground="white")
input_text.grid(row=1, column=0, padx=10, pady=10)

tk.Label(root, text="Output Text", fg="white", bg="#2E2E2E").grid(row=0, column=1, padx=10, pady=10)
output_text = scrolledtext.ScrolledText(root, height=10, width=50, bg="#121212", fg="white", insertbackground="white")
output_text.grid(row=1, column=1, padx=10, pady=10)

button_config = {"bg": "#008CBA", "fg": "white", "activebackground": "#005F73"}

tk.Button(root, text="Encrypt DES", command=encrypt_des, **button_config).grid(row=2, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt DES", command=decrypt_des, **button_config).grid(row=2, column=1, padx=10, pady=10)
tk.Button(root, text="Encrypt AES", command=encrypt_aes, **button_config).grid(row=3, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt AES", command=decrypt_aes, **button_config).grid(row=3, column=1, padx=10, pady=10)
tk.Button(root, text="Encrypt RSA", command=encrypt_rsa, **button_config).grid(row=4, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt RSA", command=decrypt_rsa, **button_config).grid(row=4, column=1, padx=10, pady=10)
tk.Button(root, text="Encrypt ECC", command=encrypt_ecc, **button_config).grid(row=5, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt ECC", command=decrypt_ecc, **button_config).grid(row=5, column=1, padx=10, pady=10)
tk.Button(root, text="Hash SHA256", command=hash_sha256, **button_config).grid(row=6, column=0, padx=10, pady=10)
tk.Button(root, text="Verify SHA256", command=verify_sha256, **button_config).grid(row=6, column=1, padx=10, pady=10)

root.mainloop()