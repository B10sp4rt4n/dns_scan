
import streamlit as st
import pandas as pd
from urllib.parse import urlparse
import validators
import sys
import os

sys.path.append(os.path.abspath("modules"))

from modules import scanner_ssl
from modules.generador_narrativa import generar_narrativa
from modules import scanner_dns
from modules import scanner_headers
from modules import cruzador_detection_log
from modules import generador_resumen
from modules import scanner_mx
from modules import whois_checker
import modules.explicador_hallazgos as explicador_hallazgos
import modules.scanner_dns_actual as scanner_dns_actual
from modules.detector_extendido import detectar_servicios_relacionados_completo

# ✅ Función integrada directamente (sin importar el módulo)
# Función auxiliar
def limpiar_dominio(dominio: str) -> str:
    if dominio.startswith("http://") or dominio.startswith("https://"):
        parsed = urlparse(dominio)
        dominio_limpio = parsed.netloc
    else:
        dominio_limpio = dominio
    return dominio_limpio.replace("www.", "").strip()

# UI
st.sidebar.subheader("📁 Cargar Detection Log")
archivo_csv = st.sidebar.file_uploader("Selecciona archivo CSV", type="csv")

if archivo_csv is not None:
    try:
        df_detection_log = pd.read_csv(archivo_csv)
        st.session_state["df_log"] = df_detection_log
        st.sidebar.success("✔️ Archivo cargado correctamente.")
    except Exception as e:
        st.sidebar.error(f"❌ Error al leer el archivo: {e}")

tabs = st.tabs(["Diagnóstico", "Resumen"])

with tabs[0]:
    st.header("🔎 Diagnóstico de Dominio")
    dominio_input = st.text_input("🌐 Ingrese dominio a evaluar", "")

    if dominio_input:
        dominio = limpiar_dominio(dominio_input)
        if not validators.domain(dominio):
            st.error("❌ El dominio ingresado no es válido.")
        else:
            with st.spinner("Evaluando dominio..."):
                ssl_result = scanner_ssl.validar_ssl(dominio)
                dns_result = scanner_dns.revisar_registros(dominio)
                headers_result = scanner_headers.detectar_headers(dominio)
                mx_result = scanner_mx.scanner_mx(dominio)
                whois_result = whois_checker.analizar_whois(dominio)
                dns_actual = scanner_dns_actual.obtener_dns_actual(dominio)
        txt_records = dns_actual.get("TXT", [])
        spf_txt = next((t for t in txt_records if isinstance(t, str) and t.startswith("v=spf1")), "")
        dmarc_txt = next((t for t in txt_records if isinstance(t, str) and "v=DMARC1" in t), "")

        detalles = detectar_servicios_relacionados_completo(
            spf=spf_txt,
            dmarc=dmarc_txt,
            mx_records=dns_actual.get("MX", []),
            ns_records=dns_actual.get("NS", []),
            txt_records=txt_records
        )

        en_csv, linea_detectada = False, ""
        if "df_log" in st.session_state:
            en_csv, linea_detectada = cruzador_detection_log.verificar_csv(dominio, st.session_state["df_log"])

        hallazgos = {
            "ssl_valido": ssl_result,
            "spf_valido": bool(dns_result.get("spf")),
            "dmarc_valido": bool(dns_result.get("dmarc")),
            "headers_seguridad": headers_result,
            "aparece_en_csv": en_csv,
            "mx": mx_result,
            "whois": whois_result,
            "dns_actual": dns_actual,
            "servicios_relacionados": detalles.get("servicios_relacionados", []),
            "spf_politica": detalles.get("spf_politica"),
            "dmarc_subdominios": detalles.get("dmarc_subdominios"),
            "verificaciones_txt": detalles.get("verificaciones_txt")
        }

        narrativa = generar_narrativa(hallazgos)
        st.markdown(narrativa)

        st.session_state["hallazgos"] = hallazgos
        st.session_state["resumen"] = generador_resumen.generar_resumen(dominio, hallazgos)
        st.success("✅ Diagnóstico completado. Revisa el resumen en la pestaña correspondiente.")

with tabs[1]:
    if "resumen" in st.session_state:
        st.text_area("📋 Resumen técnico generado", st.session_state["resumen"], height=400)
        st.download_button("⬇️ Descargar .txt", st.session_state["resumen"].encode("utf-8"),
                           file_name=f"Resumen_{dominio}.txt", mime="text/plain")
        st.subheader("🧠 Explicación técnica")
        explicacion = explicador_hallazgos.explicar_hallazgos(st.session_state["hallazgos"])
        st.text_area("Detalles del diagnóstico", explicacion, height=300)
