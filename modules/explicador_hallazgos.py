
def explicar_hallazgos(hallazgos: dict) -> str:
    explicacion = []

    # SSL
    if hallazgos.get("ssl_valido"):
        explicacion.append("✅ El certificado SSL está activo y válido.")
    else:
        explicacion.append("⚠️ El dominio no tiene un certificado SSL válido o no respondió correctamente por HTTPS.")

    # SPF
    if hallazgos.get("spf_valido"):
        explicacion.append("✅ Se detectó un registro SPF configurado correctamente.")
    else:
        explicacion.append("⚠️ No se encontró un registro SPF válido. Esto puede facilitar la suplantación de identidad (spoofing).")

    # DMARC
    if hallazgos.get("dmarc_valido"):
        explicacion.append("✅ El dominio tiene un registro DMARC válido, lo cual ayuda a proteger contra fraudes.")
    else:
        explicacion.append("⚠️ No se detectó un registro DMARC válido. Esto deja al dominio expuesto a ataques de phishing.")

    # Headers de seguridad
    headers = hallazgos.get("headers_seguridad", [])
    if headers:
        explicacion.append(f"🔐 Se detectaron los siguientes encabezados de seguridad en la respuesta HTTP: {', '.join(headers)}.")
    else:
        explicacion.append("⚠️ No se detectaron encabezados de seguridad en la respuesta HTTP. Esto puede exponer a riesgos en aplicaciones web.")

    # Registro en CSV
    if hallazgos.get("aparece_en_csv"):
        explicacion.append("📄 Este dominio aparece registrado en el Detection Log proporcionado.")
    else:
        explicacion.append("ℹ️ Este dominio no aparece en el Detection Log cargado.")

    # WHOIS
    whois_info = hallazgos.get("whois", "")
    if whois_info:
        explicacion.append("🗂️ WHOIS: Información de registro disponible.")
    else:
        explicacion.append("ℹ️ No se obtuvo información WHOIS relevante.")

    # DNS actual
    dns_actual = hallazgos.get("dns_actual", {})
    spf_txt = ""
    dmarc_txt = ""

    if isinstance(dns_actual, dict) and "TXT" in dns_actual:
        for valor in dns_actual["TXT"]:
            if valor.startswith("v=spf1"):
                spf_txt = valor
            elif "v=DMARC1" in valor:
                dmarc_txt = valor

    # Servicios detectados desde SPF/DMARC
    servicios = hallazgos.get("servicios_relacionados", [])
    if servicios:
        explicacion.append("📦 Se detectaron servicios relacionados con proveedores de correo y seguridad:")
        for servicio in servicios:
            explicacion.append(f"• {servicio['Servicio']} ({servicio['Categoría']}) → detectado en: {servicio['Origen']}")
    else:
        explicacion.append("🔍 No se detectaron servicios específicos en los registros SPF o DMARC. Esto podría indicar una configuración limitada o no declarada.")


    # Análisis extendido: SPF política
    politica_spf = hallazgos.get("spf_politica")
    if politica_spf == "~all":
        explicacion.append("⚠️ El registro SPF usa política blanda (~all). Considera usar '-all' para mayor seguridad.")
    elif politica_spf == "?all":
        explicacion.append("⚠️ El registro SPF permite cualquier servidor (?all). Esto reduce significativamente la protección.")
    elif politica_spf == "-all":
        explicacion.append("✅ El registro SPF tiene una política estricta (-all).")

    # Política para subdominios en DMARC
    politica_subdominios = hallazgos.get("dmarc_subdominios")
    if politica_subdominios:
        explicacion.append(f"🔧 Política DMARC para subdominios: {politica_subdominios}")

    # Verificaciones conocidas desde TXT
    verificaciones = hallazgos.get("verificaciones_txt", [])
    if verificaciones:
        explicacion.append("📌 Se detectaron registros TXT de validación:")
        for ver in verificaciones:
            explicacion.append(f"• {ver}")

    return "\n".join(explicacion)
