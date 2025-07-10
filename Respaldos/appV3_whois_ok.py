import streamlit as st
import pandas as pd

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
from modules import scanner_ssl, scanner_dns, scanner_headers, cruzador_detection_log, generador_resumen
from modules import whois_checker

import modules.explicador_hallazgos as explicador_hallazgos

import modules.cruzador_detection_log as cruzador_detection_log

import modules.whois_checker as scanner_whois


# Tabs para navegación
tabs = st.tabs(["Diagnóstico", "Resumen"])

with tabs[0]:  # Diagnóstico
    st.header("🔎 Diagnóstico de Dominio")
    dominio = st.text_input("🌐 Ingrese dominio a evaluar", "")

    if dominio:
        with st.spinner("Evaluando dominio..."):

            # Ejecutar cada módulo de análisis
            ssl_result = scanner_ssl.validar_ssl(dominio)
            dns_result = scanner_dns.revisar_registros(dominio)
            headers_result = scanner_headers.detectar_headers(dominio)
            mx_result = scanner_mx.scanner_mx(dominio)
            whois_result = whois_checker.analizar_whois(dominio)

            # Cruce con Detection Log si se cargó
            if "df_log" in st.session_state:
                en_csv, linea_detectada = cruzador_detection_log.verificar_csv(dominio, st.session_state["df_log"])
            else:
                en_csv = False

            # Consolidar hallazgos
            hallazgos = {
                "ssl_valido": ssl_result,
                "spf_valido": dns_result["spf"],
                "dmarc_valido": dns_result["dmarc"],
                "headers_seguridad": headers_result,
                "aparece_en_csv": en_csv,
                "mx": mx_result, 
                "whois": whois_result # ← Agregado aquí
            }

            # Guardar resultados en sesión
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
