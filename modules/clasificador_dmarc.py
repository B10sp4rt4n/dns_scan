import streamlit as st
from modules.clasificador_dmarc import clasificar_dmarc

import pandas as pd
from urllib.parse import urlparse
import validators

# 🧩 Sidebar: Carga dinámica del Detection Log
st.sidebar.subheader("📁 Cargar Detection Log")
archivo_csv = st.sidebar.file_uploader("Selecciona archivo CSV", type="csv")

if archivo_csv is not None:
    try:
        df_detection_log = pd.read_csv(archivo_csv)
        st.session_state["df_log"] = df_detection_log
        st.sidebar.success("✔️ Archivo cargado correctamente.")
    except Exception as e:
        st.sidebar.error(f"❌ Error al leer el archivo: {e}")

# Importaciones explícitas de cada módulo
from modules import scanner_ssl
from modules import scanner_dns
from modules import scanner_headers
from modules import cruzador_detection_log
from modules import generador_resumen
from modules import scanner_mx
from modules import whois_checker
import modules.explicador_hallazgos as explicador_hallazgos
import modules.scanner_dns_actual as scanner_dns_actual

# 🔧 Función para limpiar el dominio ingresado
def limpiar_dominio(dominio: str) -> str:
    """
    Limpia el dominio eliminando 'https://', 'http://' y 'www.' si están presentes.
    """
    if dominio.startswith("http://") or dominio.startswith("https://"):
        parsed = urlparse(dominio)
        dominio_limpio = parsed.netloc
    else:
        dominio_limpio = dominio

    return dominio_limpio.replace("www.", "").strip()

# Tabs para navegación
tabs = st.tabs(["Diagnóstico", "Resumen"])

with tabs[0]:  # Diagnóstico
    st.header("🔎 Diagnóstico de Dominio")
    dominio_input = st.text_input("🌐 Ingrese dominio a evaluar", "")

    if dominio_input:
        dominio = limpiar_dominio(dominio_input)

        if not validators.domain(dominio):
            st.error("❌ El dominio ingresado no es válido. Asegúrate de que tenga un formato correcto como ejemplo.com.")
        else:
            with st.spinner("Evaluando dominio..."):
                # Ejecutar cada módulo de análisis
                ssl_result = scanner_ssl.validar_ssl(dominio)
                dns_result = scanner_dns.revisar_registros(dominio)
        clasificacion_dmarc = clasificar_dmarc(dns_result['dmarc'])
        hallazgos.update(clasificacion_dmarc)
        headers_result = scanner_headers.detectar_headers(dominio)
        mx_result = scanner_mx.scanner_mx(dominio)
        whois_result = whois_checker.analizar_whois(dominio)
        dns_actual = scanner_dns_actual.obtener_dns_actual(dominio)

        # Cruce con Detection Log si se cargó
        if "df_log" in st.session_state:
            en_csv, linea_detectada = cruzador_detection_log.verificar_csv(dominio, st.session_state["df_log"])
        else:
            en_csv = False
            linea_detectada = ""

        # Consolidar hallazgos
        hallazgos = {
            "ssl_valido": ssl_result,
            "spf_valido": dns_result["spf"],
            "dmarc_valido": dns_result["dmarc"],
            "headers_seguridad": headers_result,
            "aparece_en_csv": en_csv,
            "mx": mx_result,
            "whois": whois_result,
            "dns_actual": dns_actual
        }

        # Guardar resultados en sesión (fuera del spinner)
        st.session_state["hallazgos"] = hallazgos
        st.session_state["resumen"] = generador_resumen.generar_resumen(dominio, hallazgos)

        st.success("✅ Diagnóstico completado. Revisa el resumen en la pestaña correspondiente.")

with tabs[1]:  # Resumen
    if "resumen" in st.session_state:
        st.text_area("📋 Resumen técnico generado", st.session_state["resumen"], height=400)
        st.download_button("⬇️ Descargar .txt", st.session_state["resumen"].encode("utf-8"),
                           file_name=f"Resumen_{dominio}.txt", mime="text/plain")
        st.subheader("🧠 Explicación técnica")
        explicacion = explicador_hallazgos.explicar_hallazgos(st.session_state["hallazgos"])
        st.text_area("Detalles del diagnóstico", explicacion, height=300)
    else:
        st.info("Realiza primero un diagnóstico para ver el resumen y su explicación.")

# --- NUEVAS FUNCIONES AGREGADAS DESDE CHECKMAIL ---

import dns.resolver
import socket
import ssl
import whois
import unicodedata

def limpiar_texto(texto):
    if not isinstance(texto, str):
        return texto
    texto = texto.replace("ñ", "n").replace("Ñ", "N")
    texto = unicodedata.normalize("NFKD", texto).encode("ASCII", "ignore").decode("utf-8")
    return texto

def detectar_proveedor_avanzado(dominio):
    try:
        respuesta = dns.resolver.resolve(dominio, 'MX', lifetime=5)
        registros = [r.exchange.to_text().lower() for r in respuesta]
        for registro in registros:
            if any(x in registro for x in ["pphosted.com", "proofpoint.com", "emaildefense.proofpoint.com"]):
                return "Proofpoint"
            if "iphmx.com" in registro:
                return "Cisco IronPort"
            if "mimecast.com" in registro:
                return "Mimecast"
            if "barracuda" in registro:
                return "Barracuda"
            if "outlook" in registro or "protection.outlook.com" in registro:
                return "Microsoft 365"
            if "google.com" in registro or "googlemail.com" in registro:
                return "Google Workspace"
            if "zoho" in registro:
                return "Zoho Mail"
            if "secureserver.net" in registro:
                return "GoDaddy"
        return f"Otro ({registros[0]})"
    except Exception:
        return "Error/Desconocido"

# Base de servicios detectables desde SPF
df_servicios = pd.DataFrame([
    {"Identificador": "sendgrid.net", "Servicio": "SendGrid", "Categoría": "Email Transaccional / Marketing"},
    {"Identificador": "mailgun.org", "Servicio": "Mailgun", "Categoría": "Email Transaccional / Marketing"},
    {"Identificador": "amazonses.com", "Servicio": "Amazon SES", "Categoría": "Email Transaccional / Marketing"},
    {"Identificador": "hubspotemail.net", "Servicio": "HubSpot", "Categoría": "Email Marketing / CRM Integrado"},
    {"Identificador": "mail.zendesk.com", "Servicio": "Zendesk", "Categoría": "Soporte / Ticketing"},
    {"Identificador": "spf.tmes.trendmicro.com", "Servicio": "Trend Micro", "Categoría": "Filtering / Relay"},
    {"Identificador": "proofpoint.com", "Servicio": "Proofpoint", "Categoría": "Filtering / Relay"},
    {"Identificador": "protection.outlook.com", "Servicio": "Microsoft 365", "Categoría": "Correo Empresarial"},
    {"Identificador": "_spf.google.com", "Servicio": "Google Workspace", "Categoría": "Correo Empresarial"},
    {"Identificador": "zoho.com", "Servicio": "Zoho Mail", "Categoría": "Correo Empresarial"}
])

def detectar_servicio_y_categoria(spf):
    for _, fila in df_servicios.iterrows():
        if pd.notna(spf) and fila["Identificador"] in spf:
            return pd.Series([fila["Servicio"], fila["Categoría"]])
    return pd.Series(["No identificado", "No clasificado"])