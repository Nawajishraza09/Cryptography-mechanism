import os
import tkinter as tk
from tkinter import simpledialog, messagebox
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# DES Functions
def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext.encode(), DES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return encrypted_text

def des_decrypt(encrypted_text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_padded_text = cipher.decrypt(encrypted_text)
    decrypted_text = unpad(decrypted_padded_text, DES.block_size)
    return decrypted_text.decode()

# AES Functions
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_text = pad(plaintext.encode(), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return iv + encrypted_text

def aes_decrypt(encrypted_text, key):
    iv = encrypted_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_text = cipher.decrypt(encrypted_text[AES.block_size:])
    decrypted_text = unpad(decrypted_padded_text, AES.block_size)
    return decrypted_text.decode()

# RSA Functions
def rsa_encrypt(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_text = cipher.encrypt(plaintext.encode())
    return encrypted_text

def rsa_decrypt(encrypted_text, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_text = cipher.decrypt(encrypted_text)
    return decrypted_text.decode()

# ECC Functions
def ecc_generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

def ecc_encrypt(plaintext, shared_key):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(shared_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def ecc_decrypt(ciphertext, shared_key):
    iv = ciphertext[:12]
    tag = ciphertext[12:28]
    ciphertext = ciphertext[28:]
    decryptor = Cipher(
        algorithms.AES(shared_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode()

# SHA Functions
def sha_hash(plaintext):
    hasher = SHA256.new()
    hasher.update(plaintext.encode())
    return hasher.hexdigest()

def verify_sha_hash(plaintext, hashed_text):
    return sha_hash(plaintext) == hashed_text

# Initialize Global Declaration
private_key, public_key = None, None

# GUI Functions
def perform_encryption():
    algorithm = selected_algorithm.get()
    plaintext = simpledialog.askstring("Input", "Enter the plaintext:")
    if not plaintext:
        return
    
    if algorithm == "DES":
        key = get_random_bytes(8)
        encrypted_text = des_encrypt(plaintext, key)
        decrypted_text = des_decrypt(encrypted_text, key)
    elif algorithm == "AES":
        key = get_random_bytes(32)
        encrypted_text = aes_encrypt(plaintext, key)
        decrypted_text = aes_decrypt(encrypted_text, key)
    elif algorithm == "RSA":
        rsa_key = RSA.generate(2048)
        public_key = rsa_key.publickey()
        private_key = rsa_key
        encrypted_text = rsa_encrypt(plaintext, public_key)
        decrypted_text = rsa_decrypt(encrypted_text, private_key)
    elif algorithm == "ECC":
        private_key, public_key = ecc_generate_keys()
        peer_private_key, peer_public_key = ecc_generate_keys()
        shared_key = derive_shared_key(private_key, peer_public_key)
        peer_shared_key = derive_shared_key(peer_private_key, public_key)
        encrypted_text = ecc_encrypt(plaintext, shared_key)
        decrypted_text = ecc_decrypt(encrypted_text, peer_shared_key)
    elif algorithm == "SHA":
        hashed_text = sha_hash(plaintext)
        verified = verify_sha_hash(plaintext, hashed_text)
        messagebox.showinfo("Result", f"SHA-256 Hash: {hashed_text}")
        return
    else:
        messagebox.showerror("Error", "Unknown algorithm selected.")
        return

    messagebox.showinfo("Result", f"Encrypted Text: {encrypted_text}\nDecrypted Text: {decrypted_text}")

# Main GUI setup
root = tk.Tk()
root.title("Cryptography Software")

selected_algorithm = tk.StringVar(value="DES")

tk.Label(root, text="Select Cryptography Algorithm:").pack()

tk.Radiobutton(root, text="DES", variable=selected_algorithm, value="DES").pack(anchor=tk.W)
tk.Radiobutton(root, text="AES", variable=selected_algorithm, value="AES").pack(anchor=tk.W)
tk.Radiobutton(root, text="RSA", variable=selected_algorithm, value="RSA").pack(anchor=tk.W)
tk.Radiobutton(root, text="ECC", variable=selected_algorithm, value="ECC").pack(anchor=tk.W)
tk.Radiobutton(root, text="SHA", variable=selected_algorithm, value="SHA").pack(anchor=tk.W)

tk.Button(root, text="Encrypt/Decrypt", command=perform_encryption).pack()

root.mainloop()