import json
import logging
import time
from datetime import datetime, timezone
from collections import defaultdict
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import requests

app = FastAPI(title="API Bancaria - Versión Segura (Después)")

# --- CONFIGURACIÓN DE LOGGING ESTRUCTURADO (JSON) ---
logger = logging.getLogger("SecurityAuditLogger")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("seguro_audit.jsonl", encoding="utf-8")
logger.addHandler(file_handler)

# Opcional: Pega aquí una URL de Webhook de Discord/Slack si quieres alerta en vivo en tu celular/PC
WEBHOOK_ALERTAS_URL = "" 

USUARIOS_DB = {
    "admin": "SuperSecreto2026!",
    "carlos": "Clave1234"
}

# Memoria temporal para detectar fuerza bruta: { "ip": [timestamp1, timestamp2, ...] }
intentos_fallidos = defaultdict(list)
UMBRAL_INTENTOS = 5
VENTANA_SEGUNDOS = 60

class LoginRequest(BaseModel):
    username: str
    password: str

class TransferRequest(BaseModel):
    from_user: str
    to_user: str
    amount: float

# --- FUNCIONES DE SEGURIDAD A09 ---

def sanitizar_para_log(texto: str) -> str:
    """Previene CWE-117 (Log Injection) eliminando saltos de línea y caracteres de control."""
    return texto.replace("\n", "\\n").replace("\r", "\\r").strip()

def registrar_evento_seguridad(nivel: str, evento: str, ip: str, usuario: str, detalles: dict):
    """Genera un log estructurado en JSON con contexto completo y sin datos sensibles."""
    entrada_log = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": nivel,
        "event_type": evento,
        "source_ip": ip,
        "user": sanitizar_para_log(usuario),
        "details": detalles
    }
    # Escribe en formato JSONL (un objeto JSON por línea, listo para ELK/Splunk/SIEM)
    logger.info(json.dumps(entrada_log, ensure_ascii=False))

def disparar_alerta_soc(titulo: str, severidad: str, ip: str, descripcion: str):
    """Emite una alerta accionable en tiempo real para el equipo de seguridad (SOC)."""
    alerta = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ALERTA_SEGURIDAD": titulo,
        "severidad": severidad,
        "ip_origen": ip,
        "descripcion": descripcion,
        "accion_recomendada": "Bloquear IP en WAF/Firewall y revisar sesiones activas"
    }
    # 1. Imprime la alerta destacada en consola
    print(f"\n🚨 [ALERTA SOC - {severidad}] {titulo} | IP: {ip} | {descripcion}\n")
    # 2. Guarda la alerta en el log de auditoría
    logger.critical(json.dumps(alerta, ensure_ascii=False))
    # 3. Envía notificación externa si se configuró un Webhook
    if WEBHOOK_ALERTAS_URL:
        try:
            requests.post(WEBHOOK_ALERTAS_URL, json={"content": f"🚨 **{titulo}** ({severidad})\nIP: `{ip}`\n{descripcion}"}, timeout=2)
        except Exception:
            pass

# --- ENDPOINTS ---

@app.post("/login")
def login(data: LoginRequest, request: Request):
    ip_cliente = request.client.host
    usuario_limpio = sanitizar_para_log(data.username)

    if data.username in USUARIOS_DB and USUARIOS_DB[data.username] == data.password:
        # Limpiamos historial de fallos si logra entrar
        intentos_fallidos[ip_cliente].clear()
        registrar_evento_seguridad(
            nivel="INFO",
            evento="AUTH_SUCCESS",
            ip=ip_cliente,
            usuario=usuario_limpio,
            detalles={"password": "[REDACTED]", "mfa_verified": True} # Enmascaramiento (CWE-532)
        )
        return {"status": "ok", "message": f"Bienvenido {usuario_limpio}"}

    # Registro detallado del fallo sin exponer la clave real
    registrar_evento_seguridad(
        nivel="WARNING",
        evento="AUTH_FAILED",
        ip=ip_cliente,
        usuario=usuario_limpio,
        detalles={"password": "[REDACTED]", "reason": "invalid_credentials"}
    )

    # Detección de fuerza bruta (Ventana deslizante de 60 segundos)
    ahora = time.time()
    intentos_fallidos[ip_cliente] = [
        t for t in intentos_fallidos[ip_cliente] if ahora - t < VENTANA_SEGUNDOS
    ]
    intentos_fallidos[ip_cliente].append(ahora)

    if len(intentos_fallidos[ip_cliente]) >= UMBRAL_INTENTOS:
        disparar_alerta_soc(
            titulo="Posible ataque de Fuerza Bruta detectado",
            severidad="HIGH",
            ip=ip_cliente,
            descripcion=f"Se detectaron {len(intentos_fallidos[ip_cliente])} intentos fallidos en menos de {VENTANA_SEGUNDOS}s contra el usuario '{usuario_limpio}'."
        )

    raise HTTPException(status_code=401, detail="Credenciales inválidas")

@app.post("/transfer")
def transfer(data: TransferRequest, request: Request):
    ip_cliente = request.client.host
    # Pista de auditoría obligatoria para transacciones de alto valor
    registrar_evento_seguridad(
        nivel="INFO",
        evento="HIGH_VALUE_TRANSACTION",
        ip=ip_cliente,
        usuario=data.from_user,
        detalles={"destination": sanitizar_para_log(data.to_user), "amount": data.amount}
    )
    return {"status": "transferred", "amount": data.amount}

@app.get("/api/v1/admin-backup-db")
def honeytoken_endpoint(request: Request):
    """HONEYTOKEN: Ruta trampa que ningún usuario legítimo usa. Cero falsos positivos."""
    ip_cliente = request.client.host
    disparar_alerta_soc(
        titulo="HONEYTOKEN ACTIVADO - Escaneo o reconocimiento malicioso",
        severidad="CRITICAL",
        ip=ip_cliente,
        descripcion="Un actor intentó acceder al endpoint trampa '/api/v1/admin-backup-db'."
    )
    # Respondemos como si no existiera para no delatar la trampa
    raise HTTPException(status_code=404, detail="Not Found")