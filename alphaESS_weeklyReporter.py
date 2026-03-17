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
import pandas as pd
from dateutil.parser import parse

# --- CONFIGURACIÓN DE ZONA HORARIA ---
# Definimos tu zona horaria (UTC-3)
USER_TZ = timezone(timedelta(hours=-3))

def parse_and_convert_time(time_str):
    """Parsea un string de fecha UTC y lo convierte a la hora local (USER_TZ)"""
    if not time_str:
        return "N/A"
    try:
        # dateutil.parser es excelente para manejar diferentes formatos de fecha/hora
        utc_dt = parse(time_str)
        # Aseguramos que sea consciente de la zona horaria UTC si no lo es
        if utc_dt.tzinfo is None:
            utc_dt = utc_dt.replace(tzinfo=timezone.utc)

        local_dt = utc_dt.astimezone(USER_TZ)
        return local_dt
    except Exception as e:
        print(f"Error parseando fecha {time_str}: {e}")
        return None

# --- 1. LÓGICA DE AUTENTICACIÓN (Idéntica) ---
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

# --- 2. LÓGICA DE OBTENCIÓN DE DATOS (Consulta Mensual) ---
def get_monthly_faults(headers):
    """Obtiene todas las fallas ocurridas en el mes actual."""
    url = "https://sgcloud.alphaess.com/api/stable/essFault/getEssFaultList"

    # Obtenemos las fechas en UTC para la consulta de la API
    end_time_utc = datetime.now(timezone.utc)
    start_time_utc = end_time_utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    params = {
        "pageIndex": 1,
        "pageSize": 500, # Un número alto para traer todas las del mes
        "createBegin": start_time_utc.strftime("%Y-%m-%d %H:%M:%S"),
        "createEnd": end_time_utc.strftime("%Y-%m-%d %H:%M:%S"),
        "logType": 0 
    }

    print(f"Consultando fallas del mes: {start_time_utc.date()} al {end_time_utc.date()} (UTC)...")

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        fault_response = response.json()

        if fault_response.get("data") and fault_response["data"]["rows"]:
            faults = fault_response["data"]["rows"]
            print(f"✅ Se encontraron {len(faults)} fallas en el mes.")
            return faults
        else:
            print("✅ No se encontraron fallas en el mes actual.")
            return []

    except Exception as e:
        print(f"🚨 Error al obtener la lista de fallas mensuales: {e}")
        return None

# --- 3. LÓGICA DE ENVÍO DE EMAIL (Con filtrado semanal) ---
def send_report_email(monthly_faults, recipient_email):
    sender_email = os.environ.get("SENDER_EMAIL")
    sender_password = os.environ.get("SENDER_PASSWORD")

    if not all([sender_email, sender_password]):
        print("❌ Faltan credenciales de email.")
        return

    fecha_reporte = datetime.now(USER_TZ).strftime('%Y-%m-%d')
    subject = f"Reporte Semanal de Fallas AlphaESS - {fecha_reporte}"

    msg = MIMEMultipart()
    msg['From'] = f"Reporte AlphaESS <{sender_email}>"
    msg['To'] = recipient_email
    msg['Subject'] = subject

    # --- FILTRADO DE DATOS (Aquí ocurre la magia) ---
    # 1. Definimos el inicio de la ventana semanal
    start_of_week_local = datetime.now(USER_TZ) - timedelta(days=7)
    weekly_faults = []

    # 2. Filtramos la lista mensual
    if monthly_faults:
        for fault in monthly_faults:
            fault_time_local = parse_and_convert_time(fault['happenTime'])
            if fault_time_local and fault_time_local >= start_of_week_local:
                # Añadimos la fecha ya convertida para usarla en el reporte
                fault['happenTimeLocal'] = fault_time_local.strftime('%Y-%m-%d %H:%M:%S')
                weekly_faults.append(fault)

    # 3. Preparamos el cuerpo del email
    body_html = f"<h3>Reporte Semanal de Fallas del Sistema AlphaESS ({fecha_reporte} UTC-3)</h3>"

    if weekly_faults:
        body_html += f"<p>Se encontraron {len(weekly_faults)} fallas en los últimos 7 días:</p>"

        df = pd.DataFrame(weekly_faults)

        # Seleccionar y renombrar columnas para el reporte
        df_report = df[['sysSn', 'happenTimeLocal', 'errorContent', 'errorCode']]
        df_report.columns = ['Sistema (SN)', 'Fecha (Hora Local UTC-3)', 'Descripción', 'Código']

        # Ordenar por fecha, de más nueva a más vieja
        df_report.sort_values(by='Fecha (Hora Local UTC-3)', ascending=False, inplace=True)

        body_html += df_report.to_html(index=False, justify='left', border=1)

    else:
        body_html += "<p>No se registraron fallas en los últimos 7 días.</p>"

    msg.attach(MIMEText(body_html, 'html'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        print(f"✅ Reporte enviado exitosamente a {recipient_email}.")
    except Exception as e:
        print(f"🚨 Error al enviar el reporte por email: {e}")

# --- 4. FUNCIÓN PRINCIPAL (Entry Point) ---
def main(event=None, context=None):
    username = os.environ.get("ALPHA_USERNAME")
    password = os.environ.get("ALPHA_PASSWORD")
    recipient_email = os.environ.get("RECIPIENT_EMAIL")

    if not all([username, password, recipient_email]):
        print("❌ Error: Faltan variables de entorno.")
        return 'Configuración incompleta', 500

    headers = get_session_token(username, password)
    if not headers:
        # Aún así enviamos el email, informando del fallo de login
        send_report_email(None, recipient_email)
        return 'Fallo de autenticación', 500

    # 1. Obtiene todas las fallas del mes
    monthly_faults = get_monthly_faults(headers)

    if monthly_faults is not None:
        # 2. La función de email se encarga de filtrar por la última semana
        send_report_email(monthly_faults, recipient_email)
        return 'Reporte completado.', 200
    else:
        return 'Error obteniendo fallas.', 500

if __name__ == "__main__":
    main()