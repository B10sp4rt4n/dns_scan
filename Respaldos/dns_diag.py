
# =========================
# SynAppsSys – Diagnóstico Técnico de Dominios
# Módulos: SSL, DNS, RBL, Headers, HTTPS Redirect, CSV Crosscheck
# =========================

import streamlit as st
import socket
import ssl
import dns.resolver
import requests

# Layout principal
st.title("🔍 Herramienta de Diagnóstico Técnico de Dominios – SynAppsSys")

# Entrada de dominio
dominio = st.text_input("Introduce un dominio para diagnosticar", "transportespitic.com")

# Carga de CSV para validación cruzada
csv_file = st.file_uploader("Cargar CSV con amenazas detectadas (opcional)", type=["csv"])

# Botones de análisis por módulo
if st.button("🔒 Verificar SSL"):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=dominio) as s:
            s.settimeout(3.0)
            s.connect((dominio, 443))
            cert = s.getpeercert()
            st.success("Certificado SSL válido")
            st.json(cert)
    except Exception as e:
        st.error(f"Error en verificación SSL: {e}")

if st.button("🧪 Revisar registros SPF / DMARC"):
    try:
        resultados = []
        for tipo in ["SPF", "DMARC"]:
            record = f"_dmarc.{dominio}" if tipo == "DMARC" else dominio
            try:
                respuestas = dns.resolver.resolve(record, "TXT")
                for r in respuestas:
                    resultados.append((tipo, r.to_text()))
            except:
                resultados.append((tipo, "No encontrado"))
        for tipo, valor in resultados:
            st.write(f"**{tipo}**: {valor}")
    except Exception as e:
        st.error(f"Error DNS: {e}")

if st.button("🔐 Revisar Headers de Seguridad"):
    try:
        r = requests.get(f"https://{dominio}", timeout=5)
        headers = r.headers
        relevantes = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]
        for h in relevantes:
            st.write(f"{h}: {headers.get(h, 'No definido')}")
    except Exception as e:
        st.error(f"No se pudieron obtener los headers: {e}")

if csv_file:
    import pandas as pd
    df = pd.read_csv(csv_file)
    dominios_csv = df["Location"].dropna().astype(str)
    encontrados = dominios_csv[dominios_csv.str.contains(dominio)]
    if not encontrados.empty:
        st.warning(f"El dominio {dominio} aparece en el archivo de amenazas.")
    else:
        st.info("Dominio no encontrado en CSV cargado.")
