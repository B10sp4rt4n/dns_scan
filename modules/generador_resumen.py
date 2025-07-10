
from datetime import datetime

def generar_resumen(dominio: str, hallazgos: dict) -> str:
    fecha = datetime.today().strftime("%d/%m/%Y")
    resumen = f"""📋 Resumen técnico generado – Diagnóstico de dominio
Dominio evaluado: {dominio}
Fecha de análisis: {fecha}

"""

    # SSL
    if hallazgos.get("ssl_valido"):
        resumen += "🔐 Seguridad SSL\n- Resultado: ✅ Certificado válido.\n- Riesgo: Bajo.\n\n"
    else:
        resumen += "🔐 Seguridad SSL\n- Resultado: ❌ Certificado inválido o ausente.\n- Riesgo: Alto. Posibilidad de interceptación de datos.\n\n"

    # SPF
    if hallazgos.get("spf_valido"):
        resumen += "📤 Registro SPF\n- Resultado: ✅ Configurado correctamente.\n- Riesgo: Bajo.\n\n"
    else:
        resumen += "📤 Registro SPF\n- Resultado: ❌ No detectado.\n- Riesgo: Medio. Posible suplantación por correo.\n\n"

    # DMARC
    if hallazgos.get("dmarc_valido"):
        resumen += "📩 Registro DMARC\n- Resultado: ✅ Detectado y funcional.\n- Riesgo: Bajo.\n\n"
    else:
        resumen += "📩 Registro DMARC\n- Resultado: ❌ No configurado.\n- Riesgo: Medio. No hay control sobre correos no autorizados.\n\n"

    # Headers
    if hallazgos.get("headers_seguridad"):
        resumen += "🛡️ Headers HTTP de Seguridad\n- Resultado: ✅ Headers presentes.\n- Riesgo: Bajo.\n\n"
    else:
        resumen += "🛡️ Headers HTTP de Seguridad\n- Resultado: ❌ No detectados.\n- Riesgo: Medio. Exposición a ataques comunes.\n\n"

    # CSV Detection
    if hallazgos.get("aparece_en_csv"):
        resumen += "🚨 Coincidencia en registros de amenazas\n- Resultado: ✅ Aparece en logs recientes.\n- Riesgo: Crítico. Requiere atención prioritaria.\n\n"
    else:
        resumen += "🚨 Coincidencia en registros de amenazas\n- Resultado: ❌ No se encontró en el registro actual.\n- Riesgo: Bajo.\n\n"

    # Información WHOIS
    whois = hallazgos.get("whois")
    if whois:
        resumen += "🔎 Información WHOIS\n"

        if "error" in whois:
            resumen += f"- ❌ Error al consultar WHOIS: {whois['error']}\n\n"
        else:
            resumen += f"- Dominio: {whois.get('Dominio', 'Desconocido')}\n"
            resumen += f"- Registrante: {whois.get('Registrante')}\n"
            resumen += f"- Organización: {whois.get('Organización')}\n"
            resumen += f"- País: {whois.get('País')}\n"
            resumen += f"- Proveedor (Registrar): {whois.get('Proveedor (Registrar)')}\n"
            resumen += f"- Fecha de creación: {whois.get('Creado en')}\n"
            resumen += f"- Fecha de expiración: {whois.get('Expira en')}\n"
            resumen += f"- Última actualización: {whois.get('Última actualización')}\n"
            resumen += f"- Privacidad WHOIS: {whois.get('Privacidad WHOIS')}\n"

            ocultos = whois.get("Campos ocultos")
            if isinstance(ocultos, list):
                resumen += f"- Campos ocultos: {', '.join(ocultos)}\n"
            else:
                resumen += f"- Campos ocultos: {ocultos}\n"

            resumen += "\n"

        dns_actual = hallazgos.get("dns_actual")
        if dns_actual:
            resumen += "📡 Registros DNS actuales\n"

            registros_a = dns_actual.get("A")
            if isinstance(registros_a, list) and registros_a:
                resumen += "- 🌐 Direcciones IP (A):\n"
                for ip in registros_a:
                    resumen += f"    • {ip}\n"
            else:
                resumen += f"- 🌐 Direcciones IP (A): {registros_a or 'No disponibles'}\n"

            hostnames = dns_actual.get("Hostnames")
            if isinstance(hostnames, list) and hostnames:
                resumen += "- 🔁 Resolución inversa (PTR):\n"
                for host in hostnames:
                    resumen += f"    • {host}\n"

            registros_ns = dns_actual.get("NS")
            if isinstance(registros_ns, list) and registros_ns:
                resumen += "- 🧭 Servidores de nombres (NS):\n"
                for ns in registros_ns:
                    resumen += f"    • {ns}\n"
            else:
                resumen += f"- 🧭 Servidores de nombres (NS): {registros_ns or 'No disponibles'}\n"

            registros_mx = dns_actual.get("MX")
            if isinstance(registros_mx, list) and registros_mx:
                resumen += "- 📬 Registros de correo (MX):\n"
                for mx in registros_mx:
                    resumen += f"    • {mx}\n"
            else:
                resumen += f"- 📬 Registros de correo (MX): {registros_mx or 'No disponibles'}\n"

            registros_txt = dns_actual.get("TXT")
            if isinstance(registros_txt, list) and registros_txt:
                resumen += "- 📝 Registros TXT:\n"
                for txt in registros_txt:
                    resumen += f"    • {txt}\n"
            else:
                resumen += f"- 📝 Registros TXT: {registros_txt or 'No disponibles'}\n"

            resumen += "\n"

    # Servicios detectados por SPF/DMARC
    servicios = hallazgos.get("servicios_relacionados", [])
    if servicios:
        resumen += "📦 Servicios detectados en los registros SPF/DMARC:\n"
        for s in servicios:
            resumen += f"- {s['Servicio']} ({s['Categoría']}) → detectado en: {s['Origen']}\n"
        resumen += "\n"

    resumen += "🔎 Conclusión: Se recomienda una evaluación técnica detallada y medidas correctivas inmediatas en los puntos señalados."

    return resumen
