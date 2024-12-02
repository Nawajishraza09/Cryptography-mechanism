from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64

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
    shared_key = ec.generate_private_key(ec.SECP256R1(), default_backend()).exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),  # Use hashes module here
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    cipher = AES.new(derived_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) + nonce + ciphertext

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

def main():
    while True:
        print("Select an option:")
        print("1. Symmetric Encryption (DES)")
        print("2. Symmetric Encryption (AES)")
        print("3. Asymmetric Encryption (RSA)")
        print("4. Asymmetric Encryption (ECC)")
        print("5. Hash and Verify (SHA256)")
        print("6. Exit")
        choice = input("Enter choice: ")

        if choice == '1':
            text = input("Enter text to be encrypted using DES: ")
            des_key = generate_des_key()
            encrypted_text = des_encrypt(text, des_key)
            print("Encrypted text:", base64.b64encode(encrypted_text).decode('utf-8'))
            key_file = input("Enter the key file to decrypt: ").strip('\'"')
            try:
                with open(key_file, "rb") as key_in_file:
                    des_key = key_in_file.read()
                encrypted_text = base64.b64decode(input("Enter the encrypted text: ").strip())
                decrypted_text = des_decrypt(encrypted_text, des_key)
                print("Decrypted text:", decrypted_text)
            except Exception as e:
                print(f"Error during decryption: {e}")

        elif choice == '2':
            text = input("Enter text to be encrypted using AES: ")
            aes_key = generate_aes_key()
            encrypted_text = aes_encrypt(text, aes_key)
            print("Encrypted text:", base64.b64encode(encrypted_text).decode('utf-8'))
            key_file = input("Enter the key file to decrypt: ").strip('\'"')
            try:
                with open(key_file, "rb") as key_in_file:
                    aes_key = key_in_file.read()
                encrypted_text = base64.b64decode(input("Enter the encrypted text: ").strip())
                decrypted_text = aes_decrypt(encrypted_text, aes_key)
                print("Decrypted text:", decrypted_text)
            except Exception as e:
                print(f"Error during decryption: {e}")

        elif choice == '3':
            text = input("Enter text to be encrypted using RSA: ")
            private_key, public_key = generate_rsa_keys()
            encrypted_text = rsa_encrypt(text, public_key)
            print("Encrypted text:", base64.b64encode(encrypted_text).decode('utf-8'))
            key_file = input("Enter the private key file to decrypt: ").strip('\'"')
            try:
                with open(key_file, "rb") as key_in_file:
                    private_key = key_in_file.read()
                encrypted_text = base64.b64decode(input("Enter the encrypted text: ").strip())
                decrypted_text = rsa_decrypt(encrypted_text, private_key)
                print("Decrypted text:", decrypted_text)
            except Exception as e:
                print(f"Error during decryption: {e}")

        elif choice == '4':
            text = input("Enter text to be encrypted using ECC: ")
            private_key, public_key = generate_ecc_keys()
            encrypted_text = ecc_encrypt(text, public_key)
            print("Encrypted text:", base64.b64encode(encrypted_text).decode('utf-8'))
            key_file = input("Enter the private key file to decrypt: ").strip('\'"')
            try:
                with open(key_file, "rb") as key_in_file:
                    private_key_pem = key_in_file.read()
                encrypted_text = base64.b64decode(input("Enter the encrypted text: ").strip())
                decrypted_text = ecc_decrypt(encrypted_text, private_key_pem)
                print("Decrypted text:", decrypted_text)
            except Exception as e:
                print(f"Error during decryption: {e}")

        elif choice == '5':
            text = input("Enter text to be hashed: ")
            hash_value = hash_text(text)
            print("Hash value:", hash_value)
            text_to_verify = input("Enter text to verify against hash: ")
            if verify_hash(text_to_verify, hash_value):
                print("Hash verified successfully!")
            else:
                print("Hash verification failed!")

        elif choice == '6':
            break

        else:
            print("Invalid choice! Please select a valid option.")

if __name__ == "__main__":
    main()