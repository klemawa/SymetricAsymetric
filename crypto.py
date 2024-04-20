
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
    """Generowanie asymetrycznej pary kluczy"""
    kluczPrywatny = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    kluczPubliczny = kluczPrywatny.public_key()
    kluczPrywatnyPem = kluczPrywatny.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    kluczPublicznyPem = kluczPubliczny.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    kluczPrywatnyHex = kluczPrywatnyPem.hex()
    kluczPublicznyHex = kluczPublicznyPem.hex()
    return kluczPrywatnyHex, kluczPublicznyHex

def generujPodpisWiadomosci(message, private_key_hex):
    """Generuje podpis wiadomości za pomocą klucza prywatnego."""
    private_key = serialization.load_pem_private_key(
        bytes.fromhex(private_key_hex),
        password=None,
        backend=default_backend()
    )
    podpis = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return podpis.hex()


def generujPodpisKluczaPrywatnego(message, private_key_hex):
    """Generuje podpis wiadomości za pomocą klucza prywatnego."""
    private_key = serialization.load_pem_private_key(
        bytes.fromhex(private_key_hex),
        password=None,
        backend=default_backend()
    )
    podpis = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return podpis.hex()

def szyfrujWiadomoscKluczemPublicznym(message, kluczPublicznyHex):
    """Szyfruje wiadomość za pomocą klucza publicznego."""
    kluczPubliczny = serialization.load_pem_public_key(
        bytes.fromhex(kluczPublicznyHex),
        default_backend()
    )
    zaszyfrowanaWiadomosc = kluczPubliczny.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return zaszyfrowanaWiadomosc.hex()

def deszyfrujWiadomoscKluczemPrywatnym(encryptedMessage, kluczPrywatnyHex):
    """Deszyfruje wiadomość za pomocą klucza prywatnego."""
    kluczPrywatny = serialization.load_pem_private_key(
        bytes.fromhex(kluczPrywatnyHex),
        password=None,
        backend=default_backend()
    )
    odszyfrowanaWiadomosc = kluczPrywatny.decrypt(
        bytes.fromhex(encryptedMessage),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return odszyfrowanaWiadomosc.decode()

    
