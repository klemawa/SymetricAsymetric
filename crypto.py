# cryptography_utils.py

from cryptography.fernet import Fernet
import paramiko
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generujKluczSymmetric():
    """Generowanie klucza i zwracanie go w HEX"""
    key = Fernet.generate_key()
    return key.hex()

def szyfrowanieTekstuKluczSymmetric(message, key_hex):
    """Szyfrowanie tekstu z wygenerowanym klluczem"""
    key = bytes.fromhex(key_hex)
    f = Fernet(key)
    zaszyfrowanyTekst = f.encrypt(message.encode())
    return zaszyfrowanyTekst

def odszyfrowanieTekstuKluczSymmetric(zaszyfrowanyTekst, key_hex):
    """Odszyfrowanie tekstu z wygenerowanym kluczem"""
    key = bytes.fromhex(key_hex)
    f = Fernet(key)
    odszyfrowanyTekst = f.decrypt(zaszyfrowanyTekst).decode()
    return odszyfrowanyTekst

def generowanieAsymmetricKeypair():
    """Generwoanie asymetrycznego klucza publicznego i prywatnego"""
    kluczPrywatny = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    kluczPubliczny = kluczPrywatny.public_key()
    kluczPrywatnyHex = kluczPrywatny.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()
    kluczPublicznyHex = kluczPubliczny.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex()
    return kluczPrywatnyHex, kluczPublicznyHex
    
