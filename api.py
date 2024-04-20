# api_service.py
import logging
from fastapi import FastAPI, HTTPException
from typing import Dict
from crypto import (
    generujKluczSymmetric,
    szyfrowanieTekstuKluczSymmetric,
    odszyfrowanieTekstuKluczSymmetric,
    generowanieAsymmetricKeypair,
    podpisywanieWiadomosci,
    veryfikacjaZKluczemPublicznym,
    szyfrowanieTekstuKluczPubliczny,
    odszyfrowanieTekstuKluczPrywatny,
)

app = FastAPI()
logger = logging.getLogger(__name__)
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


