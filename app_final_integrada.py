
import streamlit as st
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
from modules import detector_servicios  # 👈 Nuevo módulo integrado
import modules.explicador_hallazgos as explicador_hallazgos
import modules.scanner_dns_actual as scanner_dns_actual

# 🔧 Función para limpiar el dominio ingresado
def limpiar_dominio(dominio: str) -> str:
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
                headers_result = scanner_headers.detectar_headers(dominio)
                mx_result = scanner_mx.scanner_mx(dominio)
                whois_result = whois_checker.analizar_whois(dominio)
                dns_actual = scanner_dns_actual.obtener_dns_actual(dominio)

                # Detección avanzada de servicios desde SPF/DMARC
                servicios_detectados = detector_servicios.detectar_servicios_relacionados(
                    dns_result.get("spf", ""), dns_result.get("dmarc", "")
                )

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
                    "dns_actual": dns_actual,
                    "servicios_detectados": servicios_detectados  # 👈 Se incluye como hallazgo
                }

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

        # 🧩 Mostrar tabla de servicios relacionados detectados
        servicios_detectados = st.session_state["hallazgos"].get("servicios_detectados", [])
        if servicios_detectados:
            st.subheader("🔍 Servicios detectados desde SPF / DMARC")
        with st.expander("ℹ️ ¿Qué significa esta tabla de servicios detectados?"):
            st.markdown("""
Este análisis identifica automáticamente qué servicios de correo están autorizados por el dominio evaluado, usando SPF y DMARC públicos.

Se examinan proveedores empresariales (como **Microsoft 365**, **Google Workspace**), plataformas de marketing y CRM (**Mailchimp**, **HubSpot**), y gateways de seguridad (**Proofpoint**, **Mimecast**).

✅ Esto te permite:
- Verificar herramientas activas.
- Detectar configuraciones heredadas o innecesarias.
- Auditar sin depender del cliente.
- Proponer mejoras de seguridad o consolidación.

Si ves servicios como `pphosted.com` o `spf.protection.outlook.com`, probablemente hay filtrado avanzado activo.

Si ves muchos de marketing, podría haber automatizaciones no controladas o riesgos reputacionales.

Este análisis es clave para entender la higiene del dominio y orientar propuestas técnicas.
""")
        with st.expander("ℹ️ ¿Qué significa esta tabla de servicios detectados?"):
            st.markdown("""
Este análisis identifica automáticamente qué servicios de correo están autorizados por el dominio evaluado, usando SPF y DMARC públicos.

Se examinan proveedores empresariales (como **Microsoft 365**, **Google Workspace**), plataformas de marketing y CRM (**Mailchimp**, **HubSpot**), y gateways de seguridad (**Proofpoint**, **Mimecast**).

✅ Esto te permite:
- Verificar herramientas activas.
- Detectar configuraciones heredadas o innecesarias.
- Auditar sin depender del cliente.
- Proponer mejoras de seguridad o consolidación.

Si ves servicios como `pphosted.com` o `spf.protection.outlook.com`, probablemente hay filtrado avanzado activo.

Si ves muchos de marketing, podría haber automatizaciones no controladas o riesgos reputacionales.

Este análisis es clave para entender la higiene del dominio y orientar propuestas técnicas.
""")
            st.info("No se detectaron servicios específicos desde los registros SPF / DMARC.")
    else:
        st.info("Realiza primero un diagnóstico para ver el resumen y su explicación.")