
import pandas as pd
import dns.resolver
import streamlit as st
import socket
import unicodedata
import re
import ssl
import whois
import concurrent.futures
import time
from datetime import datetime
from functools import lru_cache

st.set_page_config(page_title="Analizador de Correos – Fusión WHOIS", layout="wide")
st.title("📬 Analizador de Correos – Fusión WHOIS")

PERSONALES = ["gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "protonmail.com"]
SERVICIOS = [
    {"Identificador": r'include:sendgrid\.net', "Servicio": "SendGrid", "Categoría": "Email Transaccional / Marketing"},
    {"Identificador": r'include:mailgun\.org', "Servicio": "Mailgun", "Categoría": "Email Transaccional / Marketing"},
    # Agrega más servicios aquí según sea necesario
]
SERVICIOS_DICT = {svc['Identificador']: (svc['Servicio'], svc['Categoría']) for svc in SERVICIOS}
DNS_TIMEOUT = 5
MAX_WORKERS = 15

@lru_cache(maxsize=1024)
def obtener_spf(dominio):
    try:
        respuestas = dns.resolver.resolve(dominio, 'TXT', lifetime=DNS_TIMEOUT)
        for r in respuestas:
            txt_record = b''.join(r.strings).decode()
            if "v=spf1" in txt_record:
                return txt_record
    except Exception:
        return "No encontrado"
    return "No encontrado"

@lru_cache(maxsize=1024)
def obtener_dmarc(dominio):
    try:
        respuestas = dns.resolver.resolve(f"_dmarc.{dominio}", 'TXT', lifetime=DNS_TIMEOUT)
        for r in respuestas:
            txt_record = b''.join(r.strings).decode()
            if "v=DMARC1" in txt_record:
                return txt_record
        return "Registro DMARC no encontrado"
    except Exception:
        return "Error DNS"

@lru_cache(maxsize=1024)
def verificar_ssl(dominio):
    try:
        contexto = ssl.create_default_context()
        contexto.check_hostname = True
        contexto.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((dominio, 443), timeout=3) as sock:
            with contexto.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                return "Válido" if not_after else "Sin fecha de expiración"
    except Exception as e:
        return f"Error: {str(e)}"

def obtener_whois_completo(dominio):
    resultado = {
        "creation_date": "N/D",
        "expiration_date": "N/D",
        "registrar": "N/D",
        "status": "N/D"
    }
    try:
        info = whois.whois(dominio, ignore_returncode=1, timeout=10)

        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            resultado["creation_date"] = creation.strftime("%Y-%m-%d")

        expiration = info.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        if isinstance(expiration, datetime):
            resultado["expiration_date"] = expiration.strftime("%Y-%m-%d")

        if info.registrar:
            resultado["registrar"] = str(info.registrar)

        if info.status:
            resultado["status"] = str(info.status)

    except Exception as e:
        resultado["status"] = f"Error WHOIS: {str(e)}"

    return resultado

def detectar_proveedor_avanzado(dominio):
    try:
        respuesta = dns.resolver.resolve(dominio, 'MX', lifetime=DNS_TIMEOUT)
        registros = [r.exchange.to_text().rstrip('.') for r in respuesta]

        proveedores = {
            r'proofpoint|pphosted': "Proofpoint",
            r'iphmx': "Cisco IronPort",
            r'mimecast': "Mimecast",
            r'barracuda': "Barracuda",
            r'outlook|protection\.outlook': "Microsoft 365",
            r'google|googlemail': "Google Workspace",
            r'zoho': "Zoho Mail",
            r'secureserver': "GoDaddy"
        }

        for registro in registros:
            for patron, proveedor in proveedores.items():
                if re.search(patron, registro, re.IGNORECASE):
                    return proveedor
        return f"Otro ({registros[0]})"
    except Exception:
        return "Error DNS"

def validar_email(email):
    if not isinstance(email, str):
        return False
    return bool(re.match(r'^[\w\.-]+@[a-zA-Z\d\.-]+\.[a-zA-Z]{2,}$', email))

def detectar_servicio_y_categoria(spf):
    if not spf or not isinstance(spf, str):
        return "No identificado", "No clasificado"

    for patron, (servicio, categoria) in SERVICIOS_DICT.items():
        if re.search(patron, spf):
            return servicio, categoria
    return "No identificado", "No clasificado"

def procesar_dominio(dominio):
    spf = obtener_spf(dominio)
    dmarc = obtener_dmarc(dominio)
    ssl = verificar_ssl(dominio)
    whois_data = obtener_whois_completo(dominio)
    proveedor_mx = detectar_proveedor_avanzado(dominio)
    servicio, categoria = detectar_servicio_y_categoria(spf)

    return {
        "Dominio": dominio,
        "SPF": spf,
        "DMARC": dmarc,
        "SSL": ssl,
        "WHOIS (Creación)": whois_data.get("creation_date"),
        "WHOIS (Expiración)": whois_data.get("expiration_date"),
        "WHOIS (Registrar)": whois_data.get("registrar"),
        "WHOIS (Estado)": whois_data.get("status"),
        "Proveedor de Correo": proveedor_mx,
        "Servicio Detectado": servicio,
        "Categoría Funcional": categoria
    }

archivo = st.file_uploader("Sube tu archivo CSV de contactos", type="csv")

if archivo:
    try:
        df = pd.read_csv(archivo).rename(columns=lambda x: x.strip())

        email_cols = [col for col in df.columns if 'email' in col.lower()]
        if not email_cols:
            st.error("No se encontró columna de correo electrónico")
            st.stop()

        df["Email"] = df[email_cols[0]]
        df["Dominio"] = df["Email"].apply(lambda x: x.split("@")[-1].lower() if validar_email(x) else "")
        df["Tipo de Correo"] = df["Dominio"].apply(lambda d: "Personal" if d in PERSONALES else "Corporativo" if d else "Desconocido")

        dominios_unicos = [d for d in df["Dominio"].dropna().unique() if d]

        if not dominios_unicos:
            st.warning("No se encontraron dominios válidos para analizar")
            st.stop()

        st.info(f"Analizando {len(dominios_unicos)} dominios...")
        progreso = st.progress(0)
        diagnostico = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futuros = {executor.submit(procesar_dominio, dom): dom for dom in dominios_unicos}
            for i, futuro in enumerate(concurrent.futures.as_completed(futuros)):
                diagnostico.append(futuro.result())
                progreso.progress((i + 1) / len(dominios_unicos))

        df_diagnostico = pd.DataFrame(diagnostico)

        st.subheader("🧠 Diagnóstico Técnico")
        st.dataframe(df_diagnostico)

        csv_diag = df_diagnostico.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Descargar diagnóstico", csv_diag, "diagnostico_correos.csv", "text/csv")

    except Exception as e:
        st.error(f"Error crítico: {str(e)}")
