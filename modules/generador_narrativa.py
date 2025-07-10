def generar_narrativa(hallazgos: dict) -> str:
    narrativa = []

    # Nivel 1: Seguridad del canal y del sitio
    narrativa.append("🔹 **Nivel 1: Seguridad del Canal y del Sitio**")
    if hallazgos.get("ssl_valido"):
        narrativa.append("✅ El certificado SSL está activo y válido.")
    else:
        narrativa.append("⚠️ No se detectó un certificado SSL válido.")

    headers = hallazgos.get("headers_seguridad", [])
    if headers:
        narrativa.append(f"🔐 Encabezados HTTP de seguridad presentes: {', '.join(headers)}.")
    else:
        narrativa.append("⚠️ No se detectaron encabezados HTTP de seguridad.")

    if hallazgos.get("servicios_relacionados"):
        imperva = [s for s in hallazgos["servicios_relacionados"] if s["Servicio"].lower() == "imperva"]
        if imperva:
            narrativa.append("✅ Se detectó el uso de servicios de infraestructura protegida como Imperva.")

    narrativa.append("")  # Salto de línea

    # Nivel 2: Seguridad y políticas de correo
    narrativa.append("🔹 **Nivel 2: Seguridad y Políticas de Correo**")
    if hallazgos.get("spf_valido"):
        narrativa.append("✅ Se detectó un registro SPF configurado correctamente.")
    else:
        narrativa.append("⚠️ No se detectó un registro SPF válido.")

    if hallazgos.get("spf_politica"):
        narrativa.append(f"📌 El registro SPF utiliza la política: `{hallazgos['spf_politica']}`.")

    if hallazgos.get("dmarc_valido"):
        narrativa.append("✅ El dominio cuenta con un registro DMARC válido.")
    else:
        narrativa.append("⚠️ No se detectó un registro DMARC válido.")

    servicios = hallazgos.get("servicios_relacionados", [])
    if servicios:
        narrativa.append("📦 Servicios de correo y seguridad detectados:")
        for s in servicios:
            narrativa.append(f"• {s['Servicio']} ({s['Categoría']}) → detectado en: {s['Origen']}")

    narrativa.append("")  # Salto de línea

    # Nivel 3: Verificaciones técnicas
    narrativa.append("🔹 **Nivel 3: Verificaciones Técnicas**")
    if hallazgos.get("whois"):
        narrativa.append("🗂️ Información WHOIS disponible.")
    else:
        narrativa.append("ℹ️ No se obtuvo información WHOIS.")

    txts = hallazgos.get("txt_validaciones", [])
    if txts:
        narrativa.append("📌 Se detectaron los siguientes registros TXT de validación:")
        for r in txts:
            narrativa.append(f"• {r}")

    narrativa.append("")  # Salto de línea

    # Nivel 4: Riesgos y amenazas
    narrativa.append("🔹 **Nivel 4: Riesgos y Coincidencias con Amenazas**")
    if hallazgos.get("aparece_en_csv"):
        narrativa.append("🚨 El dominio aparece en los registros de amenazas cargados.")
    else:
        narrativa.append("✅ El dominio no presenta coincidencias con amenazas conocidas.")

    narrativa.append("")  # Fin
    return "\n".join(narrativa)
