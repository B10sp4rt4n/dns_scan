def detectar_servicios_relacionados_completo(spf: str, dmarc: str = "", mx_records: list = None, ns_records: list = None, txt_records: list = None) -> dict:
    servicios_detectados = []
    verificaciones_txt = []
    spf_politica = ""
    dmarc_subdominios = ""
    detalles_ptr = []

    identificadores_servicios = [
        {"Identificador": "spf.protection.outlook.com", "Servicio": "Microsoft 365", "Categoría": "Correo Empresarial"},
        {"Identificador": "spf-002f7d02.pphosted.com", "Servicio": "Proofpoint", "Categoría": "Filtering / Relay"},
        {"Identificador": "pphosted.com", "Servicio": "Proofpoint", "Categoría": "Filtering / Relay"},
        {"Identificador": "aspmx.l.google.com", "Servicio": "Google MX", "Categoría": "Correo Empresarial"},
        {"Identificador": "impervasecuredns.net", "Servicio": "Imperva", "Categoría": "CDN / Seguridad Web"},
        {"Identificador": "cloudflare", "Servicio": "Cloudflare", "Categoría": "CDN / Seguridad Web"},
        {"Identificador": "amazonses.com", "Servicio": "Amazon SES", "Categoría": "Email Transaccional / Marketing"},
        {"Identificador": "spf.mailjet.com", "Servicio": "Mailjet", "Categoría": "Email Transaccional / Marketing"},
        {"Identificador": "smtp.office365.com", "Servicio": "Exchange Online", "Categoría": "Correo Empresarial"}
    ]

    # Analizar SPF
    if spf:
        if "-all" in spf:
            spf_politica = "-all"
        elif "~all" in spf:
            spf_politica = "~all"
        elif "?all" in spf:
            spf_politica = "?all"

    # Analizar DMARC
    if dmarc and "sp=" in dmarc:
        dmarc_subdominios = dmarc.split("sp=")[-1].split(";")[0].strip()

    # Unificar fuentes a analizar
    textos_analizar = [str(spf), str(dmarc)]
    if mx_records:
        textos_analizar += [str(mx) for mx in mx_records]
    if ns_records:
        textos_analizar += [str(ns) for ns in ns_records]
    if txt_records:
        textos_analizar += [str(txt) for txt in txt_records]

        # Extraer verificaciones comunes
        for txt in txt_records:
            if any(k in txt for k in ["spycloud", "globalsign", "MS=", "wombat-verification", "google-site-verification"]):
                verificaciones_txt.append(txt)

    for entrada in textos_analizar:
        entrada_lower = entrada.lower()
        for s in identificadores_servicios:
            if s["Identificador"].lower() in entrada_lower:
                detectado = {
                    "Servicio": s["Servicio"],
                    "Categoría": s["Categoría"],
                    "Origen": entrada.strip()
                }
                if detectado not in servicios_detectados:
                    servicios_detectados.append(detectado)

    return {
        "servicios_relacionados": servicios_detectados,
        "spf_politica": spf_politica,
        "dmarc_subdominios": dmarc_subdominios,
        "verificaciones_txt": verificaciones_txt
    }
