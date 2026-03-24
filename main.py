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
from datetime import datetime, timedelta, timezone
from dateutil.parser import parse


# --- CONFIGURACIÓN ---
STATE_FILE_NAME = os.environ.get("STATE_FILE_NAME", "/data/alphaess_last_state.json")
MINUTOS_A_BUSCAR = 15

# Zona horaria local del usuario (UTC-3)
USER_TZ = timezone(timedelta(hours=-3))


# --- MANEJO DE ESTADO LOCAL ---
def load_state():
    if os.path.exists(STATE_FILE_NAME):
        try:
            with open(STATE_FILE_NAME, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️ No se pudo leer el archivo de estado. Se usará uno nuevo. Error: {e}")
    return {"systems": {}, "seen_fault_ids": []}


def save_state(state):
    try:
        state_dir = os.path.dirname(STATE_FILE_NAME)
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)

        with open(STATE_FILE_NAME, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)

        print(f"✅ Estado guardado en {STATE_FILE_NAME}")
    except Exception as e:
        print(f"🚨 Error al guardar el estado local: {e}")


# --- HELPER PARA CONVERTIR FECHAS ---
def parse_and_convert_time(time_str):
    """Parsea un string de fecha y lo convierte a la zona horaria local (USER_TZ)."""
    if not time_str:
        return "N/A"

    try:
        parsed_dt = parse(time_str)

        # Si viene sin timezone, asumimos UTC
        if parsed_dt.tzinfo is None:
            parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)

        local_dt = parsed_dt.astimezone(USER_TZ)
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return time_str


# --- 1. AUTENTICACIÓN ---
def encrypt_password_aes(username, password):
    try:
        username_bytes = username.encode("utf-8")
        password_bytes = password.encode("utf-8")

        key = SHA256.new(username_bytes).digest()
        iv = MD5.new(username_bytes).digest()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(pad(password_bytes, AES.block_size))

        return base64.b64encode(encrypted_bytes).decode("utf-8")
    except Exception as e:
        print(f"❌ Error en encriptación: {e}")
        return None


def get_session_token(username, password):
    login_url = "https://cloud.alphaess.com/api/usercenter/cloud/user/login"
    encrypted_password = encrypt_password_aes(username, password)

    if not encrypted_password:
        return None

    payload = {
        "username": username,
        "password": encrypted_password
    }

    try:
        response = requests.post(login_url, json=payload, timeout=10)
        response.raise_for_status()

        resp_json = response.json()
        data = resp_json.get("data")

        if not isinstance(data, dict):
            print(f"❌ Login fallido. Respuesta inesperada: {resp_json}")
            return None

        token = data.get("token")
        login_co_id = data.get("loginCoId")

        if token and login_co_id:
            print("✅ Login exitoso.")
            return {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "loginCoId": login_co_id
            }

        print(f"❌ Login fallido. Respuesta: {resp_json}")
        return None

    except requests.exceptions.RequestException as e:
        print(f"❌ ERROR en la petición de login: {e}")
        return None
    except ValueError as e:
        print(f"❌ La respuesta no vino en JSON válido: {e}")
        return None


# --- 2. OBTENCIÓN DE DATOS ---
def get_current_system_status(headers):
    url = "https://sgcloud.alphaess.com/api/stable/home/getSystemPage"
    params = {"pageIndex": 1, "pageSize": 100}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()

        systems = response.json().get("data", {}).get("rows", [])
        status_dict = {sys["sysSn"]: sys["emsStatus"] for sys in systems}

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
        "pageIndex": 1,
        "pageSize": 100,
        "createBegin": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "createEnd": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "logType": 0
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()

        faults = response.json().get("data", {}).get("rows", [])
        if faults:
            print(f"✅ Se encontraron {len(faults)} fallas en los últimos {MINUTOS_A_BUSCAR} min.")

        return faults

    except Exception as e:
        print(f"🚨 Error obteniendo fallas recientes: {e}")
        return []


# --- 3. NOTIFICACIONES ---
def send_alert_email(subject, body, recipient_email):
    sender_email = os.environ.get("SENDER_EMAIL")
    sender_password = os.environ.get("SENDER_PASSWORD")

    if not all([sender_email, sender_password]):
        print("❌ Faltan credenciales de email (SENDER_EMAIL o SENDER_PASSWORD).")
        return

    msg = MIMEMultipart()
    msg["From"] = f"Alerta AlphaESS <{sender_email}>"
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "html"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()

        print(f"✅ Alerta enviada a {recipient_email}.")

    except Exception as e:
        print(f"🚨 Error al enviar alerta por email: {e}")


# --- 4. FUNCIÓN PRINCIPAL ---
def main(event=None, context=None):
    username = os.environ.get("ALPHA_USERNAME")
    password = os.environ.get("ALPHA_PASSWORD")
    recipient_email = os.environ.get("RECIPIENT_EMAIL")

    if not all([username, password, recipient_email]):
        print("❌ Error: faltan variables de entorno requeridas.")
        return "Configuración incompleta", 500

    headers = get_session_token(username, password)
    if not headers:
        send_alert_email(
            "🚨 ALERTA CRÍTICA: Falla en Login de AlphaESS",
            "El script de monitoreo no pudo iniciar sesión en la plataforma AlphaESS. No se podrán recibir alertas hasta que esto se solucione.",
            recipient_email
        )
        return "Fallo de autenticación", 500

    last_state = load_state()
    current_systems_status = get_current_system_status(headers)
    recent_faults = get_recent_faults(headers)

    if current_systems_status is None:
        print("❌ No se pudo obtener el estado actual de los sistemas. Abortando chequeo.")
        return "Error de API", 500

    alerts_to_send_body = []
    last_systems_state = last_state.get("systems", {})
    ALERT_STATES = ["Offline", "Fault", "Protection"]

    # Revisar cambios de estado de equipos
    for sn, current_status in current_systems_status.items():
        last_status = last_systems_state.get(sn, "Unknown")

        if current_status in ALERT_STATES and last_status not in ALERT_STATES:
            print(f"🚨 ALERTA: Equipo {sn} entró en estado {current_status}.")
            alerts_to_send_body.append(f"""
            <li><b>Equipo en Alerta:</b> {sn}
                <br><b>Estado Nuevo:</b> {current_status}
                (Estado Anterior: {last_status})</li>
            """)

        elif current_status == "Normal" and last_status in ALERT_STATES:
            print(f"✅ INFO: Equipo {sn} volvió a estado Normal.")
            alerts_to_send_body.append(f"""
            <li><b>Equipo Recuperado:</b> {sn}
                <br><b>Estado Nuevo:</b> {current_status}
                (Estado Anterior: {last_status})</li>
            """)

        elif current_status in ALERT_STATES and last_status in ALERT_STATES and current_status != last_status:
            print(f"🚨 ALERTA: Equipo {sn} cambió estado {last_status} -> {current_status}.")
            alerts_to_send_body.append(f"""
            <li><b>Cambio de Estado:</b> {sn}
                <br><b>Estado Nuevo:</b> {current_status}
                (Estado Anterior: {last_status})</li>
            """)

    # Revisar fallas nuevas
    seen_fault_ids = set(last_state.get("seen_fault_ids", []))
    new_fault_ids_to_save = list(seen_fault_ids)

    for fault in recent_faults:
        sys_sn = fault.get("sysSn", "N/A")
        happen_time = fault.get("happenTime", "N/A")
        error_code = fault.get("errorCode", "N/A")
        error_content = fault.get("errorContent", "Sin descripción")

        fault_id = f"{sys_sn}_{happen_time}_{error_code}"

        if fault_id not in seen_fault_ids:
            print(f"🚨 Nueva falla detectada: {fault_id}")

            fault_time_local = parse_and_convert_time(happen_time)

            body = f"""
            <li>
                <b>Nueva Falla en {sys_sn}:</b>
                <ul>
                    <li><b>Fecha (Hora Local):</b> {fault_time_local}</li>
                    <li><b>Descripción:</b> {error_content}</li>
                    <li><b>Código:</b> {error_code}</li>
                </ul>
            </li>
            """

            alerts_to_send_body.append(body)
            new_fault_ids_to_save.append(fault_id)

    # Enviar email si hubo novedades
    if alerts_to_send_body:
        subject_prefix = "🚨 ALERTA" if any(state in "".join(alerts_to_send_body) for state in ALERT_STATES) else "✅ INFO"
        subject = f"{subject_prefix} Monitoreo AlphaESS - {len(alerts_to_send_body)} Novedad(es)"

        hora_local_actual = datetime.now(USER_TZ).strftime("%Y-%m-%d %H:%M:%S")

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

    # Limpiar fallas viejas del cache (últimos 3 días)
    cutoff_date_str = (datetime.utcnow() - timedelta(days=3)).isoformat()
    recent_seen_faults = [
        fid for fid in new_fault_ids_to_save
        if fid.split("_")[1] > cutoff_date_str
    ]

    new_state_to_save = {
        "systems": current_systems_status,
        "seen_fault_ids": recent_seen_faults
    }

    save_state(new_state_to_save)

    return "Chequeo de alertas completado.", 200


if __name__ == "__main__":
    main()