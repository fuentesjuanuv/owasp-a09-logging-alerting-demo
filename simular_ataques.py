import requests
import time

BASE_URL = "http://127.0.0.1:8000"

print("--- 1. PROBANDO LOG INJECTION (CWE-117) ---")
payload_inyeccion = {
    "username": "atacante\n[INFO] Login EXITOSO para usuario: admin | IP: 127.0.0.1",
    "password": "MiPasswordSecreta123"
}
r = requests.post(f"{BASE_URL}/login", json=payload_inyeccion)
print(f"Respuesta del servidor: {r.status_code}\n")

print("--- 2. PROBANDO ATAQUE DE FUERZA BRUTA (6 intentos) ---")
for i in range(1, 7):
    r = requests.post(f"{BASE_URL}/login", json={"username": "admin", "password": f"clave_falsa_{i}"})
    print(f"Intento #{i} -> HTTP {r.status_code}")
    time.sleep(0.3)

print("\n--- 3. PROBANDO TRANSACCIÓN DE ALTO VALOR ---")
r = requests.post(f"{BASE_URL}/transfer", json={"from_user": "carlos", "to_user": "cuenta_externa", "amount": 5000.0})
print(f"Transferencia -> HTTP {r.status_code}")

print("\n--- 4. PROBANDO HONEYTOKEN (Si está activo en versión segura) ---")
r = requests.get(f"{BASE_URL}/api/v1/admin-backup-db")
print(f"Acceso a Honeytoken -> HTTP {r.status_code}")