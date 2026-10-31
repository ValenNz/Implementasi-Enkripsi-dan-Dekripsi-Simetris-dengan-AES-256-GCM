"""
Implementasi Enkripsi dan Dekripsi Simetris dengan AES-256-GCM.
Program CLI untuk praktikum Keamanan Siber - Pertemuan 06.
Nama file: NIM_Nama_AES.py
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def turunkan_kunci(kata_sandi: str, salt: bytes) -> bytes:
    """Menurunkan kunci AES-256 (32 byte) dari kata sandi menggunakan PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        kata_sandi.encode("utf-8"),
        salt,
        iterations=200_000,
        dklen=32,
    )


def enkripsi(teks: str, kata_sandi: str) -> str:
    """
    Mengenkripsi plaintext menjadi ciphertext Base64.
    Payload = salt (16 byte) + nonce (12 byte) + ciphertext+tag.
    """
    if not teks:
        raise ValueError("Plaintext tidak boleh kosong.")

    salt = os.urandom(16)
    nonce = os.urandom(12)

    kunci = turunkan_kunci(kata_sandi, salt)
    aesgcm = AESGCM(kunci)

    plaintext_bytes = teks.encode("utf-8")
    ciphertext_bytes = aesgcm.encrypt(nonce, plaintext_bytes, None)

    payload = salt + nonce + ciphertext_bytes
    return base64.b64encode(payload).decode("utf-8")


def dekripsi(ciphertext_b64: str, kata_sandi: str) -> str:
    """
    Mendekripsi ciphertext Base64 menjadi plaintext.
    Memvalidasi format Base64 dan panjang payload sebelum proses.
    """
    # validate=True menolak karakter di luar alfabet Base64 secara eksplisit
    try:
        payload = base64.b64decode(ciphertext_b64, validate=True)
    except (base64.binascii.Error, ValueError) as exc:
        raise ValueError(f"Format Base64 tidak valid: {exc}") from exc

    # Minimal payload = 16 (salt) + 12 (nonce) + 16 (tag tanpa data) = 44 byte
    if len(payload) < 44:
        raise ValueError(
            f"Ciphertext terlalu pendek (diterima {len(payload)} byte, minimal 44 byte)."
        )

    salt = payload[:16]
    nonce = payload[16:28]
    ciphertext_bytes = payload[28:]

    kunci = turunkan_kunci(kata_sandi, salt)
    aesgcm = AESGCM(kunci)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_bytes, None)

    return plaintext_bytes.decode("utf-8")


def main() -> None:
    """Menu utama CLI untuk enkripsi dan dekripsi."""
    while True:
        print("\n=== ENKRIPSI SIMETRIS (AES-256-GCM) ===")
        print("1. Enkripsi teks")
        print("2. Dekripsi teks")
        print("0. Keluar")
        pilihan = input("Pilih menu: ").strip()

        if pilihan == "0":
            print("Program selesai.")
            break

        if pilihan not in {"1", "2"}:
            print("Pilihan menu tidak valid. Silakan pilih 1, 2, atau 0.")
            continue

        if pilihan == "1":
            pesan = input("Masukkan plaintext: ")
        else:
            pesan = input("Masukkan ciphertext Base64: ")

        kata_sandi = input("Masukkan kata sandi: ")
        if not kata_sandi:
            print("Kata sandi tidak boleh kosong.")
            continue

        try:
            if pilihan == "1":
                hasil = enkripsi(pesan, kata_sandi)
                print("Ciphertext (Base64):", hasil)
            else:
                hasil = dekripsi(pesan, kata_sandi)
                print("Plaintext:", hasil)
        except InvalidTag:
            print("Dekripsi gagal: kata sandi salah atau ciphertext telah dimodifikasi.")
        except ValueError as ve:
            print(f"Dekripsi gagal: {ve}")
        except UnicodeDecodeError:
            print("Dekripsi gagal: hasil dekripsi bukan teks UTF-8 yang valid.")
        except Exception as exc:
            print(f"Terjadi kesalahan tak terduga: {exc}")


if __name__ == "__main__":
    main()