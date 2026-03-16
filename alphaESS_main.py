import requests
import json
import base64
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5
from Crypto.Util.Padding import pad
from datetime import datetime, timedelta, timezone # <-- CAMBIO 1: Importamos timezone
from google.cloud import storage
from dateutil.parser import parse # <-- CAMBIO 2: Importamos el parser de dateutil

# --- CONFIGURACIÓN ---
BUCKET_NAME = os.environ.get('GCS_BUCKET_NAME')
STATE_FILE_NAME = 'alphaess_last_state.json'
MINUTOS_A_BUSCAR = 15

# --- Definir la zona horaria del usuario (UTC-3) ---
USER_TZ = timezone(timedelta(hours=-3)) # <-- CAMBIO 3: Definimos tu zona horaria

# --- Helper function para convertir la hora ---
def parse_and_convert_time(time_str): # <-- CAMBIO 4: Nueva función de ayuda
    """Parsea un string de fecha (posiblemente UTC) y lo convierte a la hora local (USER_TZ)"""
    if not time_str:
        return "N/A"
    try:
        # 'parse' de dateutil es genial para manejar varios formatos ISO
        utc_dt = parse(time_str)
        # Convertir a la zona horaria del usuario
        local_dt = utc_dt.astimezone(USER_TZ)
        return local_dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        # Si falla el parseo, devolver el string original
        return time_str

# --- 1. LÓGICA DE AUTENTICACIÓN (Sin cambios) ---
def encrypt_password_aes(username, password):
    try:
        username_bytes = username.encode('utf-8')
        password_bytes = password.encode('utf-8')
        key = SHA256.new(username_bytes).digest()
        iv = MD5.new(username_bytes).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(pad(password_bytes, AES.block_size))
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        print(f"Error en encriptación: {e}")
        return None

def get_session_token(username, password):
    login_url = "https://cloud.alphaess.com/api/usercenter/cloud/user/login"
    encrypted_password = encrypt_password_aes(username, password)
    if not encrypted_password:
        return None
    payload = {"username": username, "password": encrypted_password}
    try:
        response = requests.post(login_url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})
        token = data.get("token")
        login_co_id = data.get("loginCoId")
        if token and login_co_id:
            print("✅ Login exitoso.")
            return {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "loginCoId": login_co_id
            }
        else:
            print(f"❌ Login fallido. Respuesta: {response.json()}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"❌ ERROR en la petición de login: {e}")
        return None

# --- 2. LÓGICA DE OBTENCIÓN DE DATOS (Sin cambios) ---
def get_current_system_status(headers):
    url = "https://sgcloud.alphaess.com/api/stable/home/getSystemPage"
    params = {"pageIndex": 1, "pageSize": 100}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        systems = response.json().get("data", {}).get("rows", [])
        status_dict = {sys['sysSn']: sys['emsStatus'] for sys in systems}
        print(f"Sistemas encontrados y su estado: {status_dict}")
        return status_dict
    except Exception as e:
        print(f"🚨 Error obteniendo estado de sistemas: {e}")
        return None

def get_recent_faults(headers):
    url = "https://sgcloud.alphaess.com/api/stable/essFault/getEssFaultList"
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(minutes=MINUTOS_A_BUSCAR)
    params = {
        "pageIndex": 1, "pageSize": 100,
        "createBegin": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "createEnd": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "logType": 0
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        faults = response.json().get("data", {}).get("rows", [])
        if faults:
            print(f"Se encontraron {len(faults)} fallas en los últimos {MINUTOS_A_BUSCAR} min.")
        return faults
    except Exception as e:
        print(f"🚨 Error obteniendo fallas recientes: {e}")
        return []

# --- 3. LÓGICA DE MANEJO DE ESTADO (Sin cambios) ---
def get_last_state(storage_client, bucket_name):
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(STATE_FILE_NAME)
        if blob.exists():
            print("Leyendo estado anterior desde GCS.")
            return json.loads(blob.download_as_text())
        else:
            print("No se encontró estado anterior. Se creará uno nuevo.")
    except Exception as e:
        print(f"No se pudo leer el archivo de estado, se creará uno nuevo. Error: {e}")
    return {"systems": {}, "seen_fault_ids": []}

def save_current_state(storage_client, bucket_name, state_data):
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(STATE_FILE_NAME)
        blob.upload_from_string(json.dumps(state_data, indent=2), content_type='application/json')
        print("✅ Estado actual guardado en GCS.")
    except Exception as e:
        print(f"🚨 Error al guardar el estado en GCS: {e}")

# --- 4. LÓGICA DE NOTIFICACIONES (Sin cambios) ---
def send_alert_email(subject, body, recipient_email):
    sender_email = os.environ.get("SENDER_EMAIL")
    sender_password = os.environ.get("SENDER_PASSWORD")
    if not all([sender_email, sender_password]):
        print("❌ Faltan credenciales de email (SENDER_EMAIL o SENDER_PASSWORD).")
        return
    msg = MIMEMultipart()
    msg['From'] = f"Alerta AlphaESS <{sender_email}>"
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        print(f"✅ Alerta enviada a {recipient_email}.")
    except Exception as e:
        print(f"🚨 Error al enviar alerta por email: {e}")

# --- 5. FUNCIÓN PRINCIPAL (Aquí están los cambios para el email) ---
def main(event=None, context=None):
    username = os.environ.get("ALPHA_USERNAME")
    password = os.environ.get("ALPHA_PASSWORD")
    recipient_email = os.environ.get("RECIPIENT_EMAIL")
    if not all([username, password, recipient_email, BUCKET_NAME]):
        print(f"❌ Error: Faltan variables de entorno. Asegúrate de que GCS_BUCKET_NAME ('{BUCKET_NAME}') está configurada.")
        return 'Configuración incompleta', 500

    headers = get_session_token(username, password)
    if not headers:
        send_alert_email("🚨 ALERTA CRÍTICA: Falla en Login de AlphaESS", 
                         "El script de monitoreo no pudo iniciar sesión en la plataforma AlphaESS. No se podrán recibir alertas hasta que esto se solucione.", 
                         recipient_email)
        return 'Fallo de autenticación', 500
        
    storage_client = storage.Client()
    last_state = get_last_state(storage_client, BUCKET_NAME)
    current_systems_status = get_current_system_status(headers)
    recent_faults = get_recent_faults(headers)

    if current_systems_status is None:
        print("No se pudo obtener el estado actual de los sistemas. Abortando chequeo.")
        return "Error de API", 500
        
    alerts_to_send_body = []
    last_systems_state = last_state.get("systems", {})
    ALERT_STATES = ["Offline", "Fault", "Protection"]
    
    for sn, current_status in current_systems_status.items():
        last_status = last_systems_state.get(sn, "Unknown")
        if current_status in ALERT_STATES and last_status not in ALERT_STATES:
            print(f"¡ALERTA! Equipo {sn} entró en estado: {current_status}.")
            alerts_to_send_body.append(f"""
            <li><b>Equipo en Alerta:</b> {sn} 
                <br><b>Estado Nuevo:</b> {current_status} 
                (Estado Anterior: {last_status})</li>
            """)
        elif current_status == "Normal" and last_status in ALERT_STATES:
            print(f"¡INFO! Equipo {sn} está ONLINE nuevamente.")
            alerts_to_send_body.append(f"""
            <li><b>Equipo Recuperado:</b> {sn} 
                <br><b>Estado Nuevo:</b> {current_status} 
                (Estado Anterior: {last_status})</li>
            """)
        elif current_status in ALERT_STATES and last_status in ALERT_STATES and current_status != last_status:
             print(f"¡ALERTA! Equipo {sn} cambió su estado de alerta: {last_status} -> {current_status}.")
             alerts_to_send_body.append(f"""
             <li><b>Cambio de Estado:</b> {sn} 
                <br><b>Estado Nuevo:</b> {current_status} 
                (Estado Anterior: {last_status})</li>
             """)

    seen_fault_ids = set(last_state.get("seen_fault_ids", []))
    new_fault_ids_to_save = list(seen_fault_ids)

    for fault in recent_faults:
        fault_id = f"{fault['sysSn']}_{fault['happenTime']}_{fault.get('errorCode', 'N/A')}"
        if fault_id not in seen_fault_ids:
            print(f"¡ALERTA! Nueva falla detectada: {fault_id}")
            
            # Convertimos la hora de la falla a tu hora local
            fault_time_local = parse_and_convert_time(fault['happenTime']) # <-- CAMBIO 5
            
            body = f"""
            <li>
                <b>Nueva Falla en {fault['sysSn']}:</b>
                <ul>
                    <li><b>Fecha (Hora Local):</b> {fault_time_local}</li>
                    <li><b>Descripción:</b> {fault['errorContent']}</li>
                    <li><b>Código:</b> {fault.get('errorCode', 'N/A')}</li>
                </ul>
            </li>
            """
            alerts_to_send_body.append(body)
            new_fault_ids_to_save.append(fault_id)

    if alerts_to_send_body:
        subject_prefix = "🚨 ALERTA" if any(s in "".join(alerts_to_send_body) for s in ALERT_STATES) else "✅ INFO"
        subject = f"{subject_prefix} Monitoreo AlphaESS - {len(alerts_to_send_body)} Novedad(es)"
        
        # Obtenemos la hora actual en TU zona horaria
        hora_local_actual = datetime.now(USER_TZ).strftime('%Y-%m-%d %H:%M:%S') # <-- CAMBIO 6
        
        full_email_body = f"""
        <html>
        <body>
            <h3>Novedades de Sistemas AlphaESS</h3>
            <p>Se detectaron los siguientes eventos a las {hora_local_actual} (Hora Local UTC-3):</p>
            <ul>
                {"".join(alerts_to_send_body)}
            </ul>
        </body>
        </html>
        """
        send_alert_email(subject, full_email_body, recipient_email)
    else:
        print("✅ Sin novedades. No se enviará email.")

    cutoff_date_str = (datetime.utcnow() - timedelta(days=3)).isoformat()
    recent_seen_faults = [fid for fid in new_fault_ids_to_save if fid.split('_')[1] > cutoff_date_str]
    new_state_to_save = {
        "systems": current_systems_status,
        "seen_fault_ids": recent_seen_faults
    }
    save_current_state(storage_client, BUCKET_NAME, new_state_to_save)
    
    return 'Chequeo de alertas completado.', 200
