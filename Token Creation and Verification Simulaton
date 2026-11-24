import secrets
import hashlib
import hmac
import time

# Simulasi database token
database = {}

# Membuat token menggunakan CSPRNG
def buat_token():
    token = secrets.token_urlsafe(32)
    # Token asli tidak disimpan di database, melainkan hash-nya
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    database[token_hash] = {
        "expired": time.time() + 15 * 60, # 15 menit
        "used": False
    }
    return token

# Verifikasi token
def verifikasi_token(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # Menggunakan hmac.compare_digest untuk mencegah Timing Attack
    for stored_hash, data in database.items():
        if hmac.compare_digest(token_hash, stored_hash):
            
            if data["used"]:
                return "GAGAL: Token sudah digunakan"
            
            if time.time() > data["expired"]:
                return "GAGAL: Token kedaluwarsa"
            
            # Token hanya dapat digunakan sekali
            data["used"] = True
            return "SUKSES: Token valid"
            
    return "GAGAL: Token tidak valid"

# PENGUJIAN
token_asli = buat_token()

print("1. Pengujian token asli:")
print(verifikasi_token(token_asli))

print("\n2. Pengujian token yang sama (Replay Attack):")
print(verifikasi_token(token_asli))

print("\n3. Pengujian token palsu (Brute-force):")
print(verifikasi_token("token_palsu_123"))

print("\n4. Pengujian token kedaluwarsa:")
token_exp = buat_token()
token_exp_hash = hashlib.sha256(token_exp.encode()).hexdigest()
# Memanipulasi waktu agar token seolah-olah sudah kedaluwarsa 1 menit lalu
database[token_exp_hash]["expired"] = time.time() - 60 
print(verifikasi_token(token_exp))
