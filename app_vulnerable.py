from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel

app = FastAPI(title="API Bancaria - Versión Vulnerable (Antes)")

# Base de datos simulada
USUARIOS_DB = {
    "admin": "SuperSecreto2026!",
    "carlos": "Clave1234"
}

class LoginRequest(BaseModel):
    username: str
    password: str

class TransferRequest(BaseModel):
    from_user: str
    to_user: str
    amount: float

@app.post("/login")
def login(data: LoginRequest):
    # FALLO 1 (CWE-532): Se registra la contraseña en texto plano en el log
    # FALLO 2 (CWE-778): No se guarda IP, timestamp ISO ni formato estructurado
    # FALLO 3 (CWE-117): Se concatena el input directo permitiendo Log Injection
    with open("vulnerable.log", "a", encoding="utf-8") as f:
        f.write(f"Intento de login -> Usuario: {data.username} | Password: {data.password}\n")

    if data.username in USUARIOS_DB and USUARIOS_DB[data.username] == data.password:
        return {"status": "ok", "message": f"Bienvenido {data.username}"}
    
    # FALLO 4: No hay conteo de intentos fallidos ni alertas de fuerza bruta
    raise HTTPException(status_code=401, detail="Credenciales inválidas")

@app.post("/transfer")
def transfer(data: TransferRequest):
    # FALLO 5 (CWE-223): Transacción crítica sin pista de auditoría (audit trail)
    return {
        "status": "transferred",
        "detail": f"${data.amount} enviados de {data.from_user} a {data.to_user}"
    }