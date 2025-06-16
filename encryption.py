import json
import base64
import hashlib
from cryptography.fernet import Fernet

def derive_key(master_password):
    """
    Derive a 32-byte Fernet-compatible key from the master password.
    """
    password_bytes = master_password.encode()
    key = hashlib.sha256(password_bytes).digest()
    return base64.urlsafe_b64encode(key)


def encrypt_data(data, master_password):
    """
    Encrypt a Python dict `data` with the master password, returning bytes.
    """
    key = derive_key(master_password)
    fernet = Fernet(key)
    json_data = json.dumps(data).encode()
    return fernet.encrypt(json_data)


def decrypt_data(encrypted_data, master_password):
    """
    Decrypt encrypted bytes with the master password, returning a dict.
    """
    key = derive_key(master_password)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data)
    return json.loads(decrypted.decode())