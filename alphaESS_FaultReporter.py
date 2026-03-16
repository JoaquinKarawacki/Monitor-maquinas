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
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import pandas as pd

# --- 1. Lógica de Autenticación y Encriptación (Tu código adaptado) ---

def encrypt_password_aes(username, password):
    """Encripta la contraseña usando AES, SHA256 y MD5."""
    username_bytes = username.encode('utf-8')
    password_bytes = password.encode('utf-8')
    key = SHA256.new(username_bytes).digest()
    iv = MD5.new(username_bytes).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(password_bytes, AES.block_size))
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def get_session_token_and_coid(username, password):
    """Obtiene el token de sesión y el ID de la compañía."""
    login_url = "https://cloud.alphaess.com/api/usercenter/cloud/user/login"
    encrypted_password = encrypt_password_aes(username, password)
    payload = {"username": username, "password": encrypted_password}

    try:
        response = requests.post(login_url, json=payload)
        response.raise_for_status()
        login_data = response.json().get("data", {})
        token = login_data.get("token")
        login_co_id = login_data.get("loginCoId")
        if token and login_co_id:
            print("✅ Login exitoso.")
            return token, login_co_id
        else:
            print("❌ Login fallido:", response.json())
            return None, None
    except requests.exceptions.HTTPError as err:
        print(f"❌ ERROR en la petición de login: {err}")
        return None, None

# --- 2. Lógica para Obtener las Fallas ---

def get_faults_for_current_month(headers):
    """Obtiene todas las fallas ocurridas en el mes calendario actual."""
    fault_list_url = "https://sgcloud.alphaess.com/api/stable/essFault/getEssFaultList"
    
    # Calcular fechas para el mes actual (del día 1 al último día)
    today = datetime.now().date()
    first_day = today.replace(day=1)
    last_day = first_day + relativedelta(months=1) - relativedelta(days=1)
    
    params = {
        "pageIndex": 1,
        "pageSize": 100,
        "createBegin": first_day.strftime("%Y-%m-%d"),
        "createEnd": last_day.strftime("%Y-%m-%d"),
        "logType": 0
    }
    
    print(f"Consultando fallas desde {first_day.strftime('%Y-%m-%d')} hasta {last_day.strftime('%Y-%m-%d')}...")
    
    try:
        response = requests.get(fault_list_url, headers=headers, params=params)
        response.raise_for_status()
        fault_response = response.json()
        
        if fault_response.get("data") and fault_response["data"]["rows"]:
            faults = fault_response["data"]["rows"]
            print(f"✅ Se encontraron {len(faults)} fallas.")
            return faults
        else:
            print("✅ No se encontraron fallas en el mes actual.")
            return []
            
    except Exception as e:
        print(f"🚨 Error al obtener la lista de fallas: {e}")
        return None

# --- 3. Lógica para Enviar el Correo ---

def send_email(faults_html, recipient_email):
    """Envía un email con el reporte de fallas."""
    # Credenciales del email. Las obtendremos de variables de entorno por seguridad.
    sender_email = os.environ.get("SENDER_EMAIL")
    sender_password = os.environ.get("SENDER_PASSWORD")
    
    if not sender_email or not sender_password:
        print("❌ Faltan credenciales de email (SENDER_EMAIL o SENDER_PASSWORD).")
        return

    subject = f"Reporte Mensual de Fallas AlphaESS - {datetime.now().strftime('%Y-%m-%d')}"
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    # Cuerpo del email
    body = "<h3>Reporte Mensual de Fallas del Sistema AlphaESS</h3>"
    if faults_html:
        body += "<p>A continuación se detallan las fallas registradas en el último mes:</p>"
        body += faults_html
    else:
        body += "<p>No se registraron fallas en el último mes.</p>"
        
    msg.attach(MIMEText(body, 'html'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        print(f"✅ Email enviado exitosamente a {recipient_email}.")
    except Exception as e:
        print(f"🚨 Error al enviar el email: {e}")


# --- 4. Función Principal (Entry Point para Google Cloud Function) ---

def main(event=None, context=None):
    """Función principal que se ejecuta en la nube."""
    # Obtener credenciales de AlphaESS desde Secret Manager (configurado en la Cloud Function)
    username = os.environ.get("ALPHA_USERNAME")
    password = os.environ.get("ALPHA_PASSWORD")
    recipient_email = os.environ.get("RECIPIENT_EMAIL")

    if not username or not password or not recipient_email:
        print("❌ Faltan variables de entorno: ALPHA_USERNAME, ALPHA_PASSWORD o RECIPIENT_EMAIL.")
        return 'Configuración incompleta', 500

    token, co_id = get_session_token_and_coid(username, password)
    
    if not token:
        return 'Fallo en la autenticación', 500
        
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "loginCoId": co_id
    }
    
    faults = get_faults_for_current_month(headers)
    
    faults_html = None
    if faults:
        # Convertir la lista de fallas a un DataFrame de pandas y luego a una tabla HTML
        faults_df = pd.DataFrame(faults)
        faults_df = faults_df[['sysSn', 'happenTime', 'errorContent', 'errorCode']]
        faults_df.rename(columns={
            'sysSn': 'Sistema (SN)',
            'happenTime': 'Fecha de Ocurrencia',
            'errorContent': 'Descripción',
            'errorCode': 'Código'
        }, inplace=True)
        # Formatear la tabla HTML para que sea más legible
        faults_html = faults_df.to_html(index=False, justify='left', border=1)

    send_email(faults_html, recipient_email)
    
    return 'Proceso completado', 200