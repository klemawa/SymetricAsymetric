
from fastapi import FastAPI, HTTPException
from typing import Dict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from crypto import (
    generujKluczSymmetric,
    szyfrowanieTekstuKluczSymmetric,
    odszyfrowanieTekstuKluczSymmetric,
    generowanieAsymmetricKeypair,
    generujPodpisKluczaPrywatnego
)

app = FastAPI()

kluczSymmetric = None
asymmetricKeys = {'private': None, 'public': None}

@app.get("/symmetric/key")
async def getKluczSymmetric():
    """Zwraca wygenerowany klucz"""
    global kluczSymmetric
    kluczSymmetric = generujKluczSymmetric()
    return {"Klucz": kluczSymmetric}

@app.post("/symmetric/key")
async def setKluczSymmetric(key_hex: str):
    """Ustawienie klucza na serwerze."""
    global kluczSymmetric
    kluczSymmetric = key_hex
    return {"Wiadomość": "Symmetric key set successfully."}

@app.post("/symmetric/encode")
async def szyfrowanieSymmetric(message: str):
    """Szyfrowanie tekstu z wygenerowanym kluczem"""
    global kluczSymmetric
    if kluczSymmetric is None:
        raise HTTPException(status_code=400, detail="Symmetric key not set.")
    zaszyfrowanyTekst = szyfrowanieTekstuKluczSymmetric(message, kluczSymmetric)
    return {"Zaszyfrowany tekst": zaszyfrowanyTekst.decode()}

@app.post("/symmetric/decode")
async def odszyfrowanieSymmetric(zaszyfrowanyTekst: str):
    """Odszyfrowanie tekstu z wygenerowanym kluczem"""
    global kluczSymmetric
    if kluczSymmetric is None:
        raise HTTPException(status_code=400, detail="Symmetric key not set.")
    odszyfrowanyTekst = odszyfrowanieTekstuKluczSymmetric(zaszyfrowanyTekst.encode(), kluczSymmetric)
    return {"Odszyfrowany tekst": odszyfrowanyTekst}

@app.get("/asymmetric/key")
async def getAsymmetricKeys():
    """Zwraca wygenerowaną asymmetric parę kluczy"""
    kluczPrywatnyHex, kluczPublicznyHex = generowanieAsymmetricKeypair()
    asymmetricKeys['private'] = kluczPrywatnyHex  # Ustawienie klucza prywatnego
    asymmetricKeys['public'] = kluczPublicznyHex
    return {"Prywatny klucz": kluczPrywatnyHex, "Publiczny klucz": kluczPublicznyHex}

@app.post("/asymmetric/key")
async def setAsymmetricKeys(private_key_hex: str, public_key_hex: str):
    """Ustawienie kluczy asymetrycznych na serwerze."""
    global asymmetricKeys
    asymmetricKeys['private'] = private_key_hex
    asymmetricKeys['public'] = public_key_hex
    return {"Wiadomość": "Asymmetric keys set successfully."}

@app.post("/asymmetric/verify")
async def signMessage(message: str):
    """Podpisuje wiadomość przy użyciu aktualnie ustawionego klucza prywatnego."""
    global asymmetricKeys
    
    if asymmetricKeys['private'] is None:
        raise HTTPException(status_code=400, detail="Private key not set.")
    
    kluczPrywatnyHex = asymmetricKeys['private']
    podpis = generujPodpisKluczaPrywatnego(message, kluczPrywatnyHex)
    
    return {"SignedMessage": podpis}


@app.post("/asymmetric/sign")
async def verifySignature(message: str, signature: str):
    """Weryfikuje, czy podpis wiadomości jest prawidłowy przy użyciu aktualnie ustawionego klucza publicznego."""
    global asymmetricKeys
    
    if asymmetricKeys['public'] is None:
        raise HTTPException(status_code=400, detail="Public key not set.")
    
    public_key_pem = asymmetricKeys['public']
    kluczPubliczny = serialization.load_pem_public_key(bytes.fromhex(public_key_pem), default_backend())
    
    try:
        kluczPubliczny.verify(
            bytes.fromhex(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {"Message": "Signature verified successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid signature.")
    
@app.post("/asymmetric/encode")
async def encryptMessage(message: str):
    """Szyfruje wiadomość za pomocą aktualnie ustawionego klucza publicznego."""
    global asymmetricKeys
    
    if asymmetricKeys['public'] is None:
        raise HTTPException(status_code=400, detail="Public key not set.")
    
    public_key_pem = asymmetricKeys['public']
    kluczPubliczny = serialization.load_pem_public_key(bytes.fromhex(public_key_pem), default_backend())
    
    zaszyfrowanaWiadomosc = kluczPubliczny.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return {"Zaszyfrowany Tekst": zaszyfrowanaWiadomosc.hex()}

@app.post("/asymmetric/decode")
async def decryptMessage(encryptedMessage: str):
    """Deszyfruje wiadomość za pomocą aktualnie ustawionego klucza prywatnego."""
    global asymmetricKeys
    
    if asymmetricKeys['private'] is None:
        raise HTTPException(status_code=400, detail="Private key not set.")
    
    private_key_pem = asymmetricKeys['private']
    kluczPrywatny = serialization.load_pem_private_key(bytes.fromhex(private_key_pem), password=None, backend=default_backend())
    
    odszyfrowanaWiadomosc = kluczPrywatny.decrypt(
        bytes.fromhex(encryptedMessage),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return {"Odszyfrowany Tekst": odszyfrowanaWiadomosc.decode()}

