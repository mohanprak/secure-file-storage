from Crypto.Cipher import AES
import os

KEY = b"ThisIsASecretKey"  # 16 bytes

def pad(data):
    padding = 16 - len(data) % 16
    return data + bytes([padding]) * padding

def unpad(data):
    padding = data[-1]
    return data[:-padding]

def encrypt_file(input_path, output_path):
    cipher = AES.new(KEY, AES.MODE_CBC)
    iv = cipher.iv

    with open(input_path, "rb") as f:
        data = f.read()

    data = pad(data)
    encrypted_data = cipher.encrypt(data)

    with open(output_path, "wb") as f:
        f.write(iv + encrypted_data)

def decrypt_file(input_path, output_path):
    with open(input_path, "rb") as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    decrypted_data = cipher.decrypt(encrypted_data)

    decrypted_data = unpad(decrypted_data)

    with open(output_path, "wb") as f:
        f.write(decrypted_data)