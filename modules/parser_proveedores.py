
def identificar_proveedores(spf: str = "", dmarc: str = "", mx_registros: list = None, ns_registros: list = None) -> list:
    if mx_registros is None:
        mx_registros = []
    if ns_registros is None:
        ns_registros = []

    # Base de datos unificada de identificadores
    proveedores_base = [
        # Correo empresarial
        {"Identificador": "_spf.google.com", "Servicio": "Google Workspace", "Categoría": "Correo Empresarial"},
        {"Identificador": "protection.outlook.com", "Servicio": "Microsoft 365", "Categoría": "Correo Empresarial"},
        {"Identificador": "spf.protection.outlook.com", "Servicio": "Microsoft 365", "Categoría": "Correo Empresarial"},
        {"Identificador": "smtp.office365.com", "Servicio": "Microsoft Exchange Online", "Categoría": "Correo Empresarial"},
        {"Identificador": "zoho.com", "Servicio": "Zoho Mail", "Categoría": "Correo Empresarial"},
        {"Identificador": "yandex.net", "Servicio": "Yandex Mail", "Categoría": "Correo Empresarial"},
        {"Identificador": "secureserver.net", "Servicio": "GoDaddy Email", "Categoría": "Correo Empresarial"},
        {"Identificador": "1and1.com", "Servicio": "IONOS", "Categoría": "Correo Empresarial"},

        # Filtering / Relay
        {"Identificador": "pphosted.com", "Servicio": "Proofpoint", "Categoría": "Filtering / Relay"},
        {"Identificador": "proofpoint.com", "Servicio": "Proofpoint", "Categoría": "Filtering / Relay"},
        {"Identificador": "emaildefense.proofpoint.com", "Servicio": "Proofpoint Advanced", "Categoría": "Filtering / Relay"},
        {"Identificador": "mimecast.com", "Servicio": "Mimecast", "Categoría": "Filtering / Relay"},
        {"Identificador": "barracudanetworks.com", "Servicio": "Barracuda", "Categoría": "Filtering / Relay"},
        {"Identificador": "spf.tmes.trendmicro.com", "Servicio": "Trend Micro", "Categoría": "Filtering / Relay"},
        {"Identificador": "messagelabs.com", "Servicio": "Broadcom / Symantec", "Categoría": "Filtering / Relay"},
        {"Identificador": "smtpcorp.com", "Servicio": "Trustwave", "Categoría": "Filtering / Relay"},

        # Marketing / CRM
        {"Identificador": "sendgrid.net", "Servicio": "SendGrid", "Categoría": "Email Transaccional / Marketing"},
        {"Identificador": "mailchimp.com", "Servicio": "Mailchimp", "Categoría": "Email Transaccional / Marketing"},
        {"Identificador": "amazonses.com", "Servicio": "Amazon SES", "Categoría": "Email Transaccional / Marketing"},
        {"Identificador": "mailgun.org", "Servicio": "Mailgun", "Categoría": "Email Transaccional / Marketing"},
        {"Identificador": "hubspotemail.net", "Servicio": "HubSpot", "Categoría": "CRM / Marketing"},
        {"Identificador": "sparkpost.com", "Servicio": "SparkPost", "Categoría": "Email Transaccional / Marketing"},

        # Firma / Identidad / DNS
        {"Identificador": "impervasecuredns.net", "Servicio": "Imperva", "Categoría": "DNS Seguro / WAF"},
        {"Identificador": "globalsign-domain-verification", "Servicio": "GlobalSign", "Categoría": "Validación / Certificación"},
        {"Identificador": "spycloud-domain-verification", "Servicio": "SpyCloud", "Categoría": "Validación / Ciberseguridad"},
        {"Identificador": "wombat-verification", "Servicio": "Wombat", "Categoría": "Validación / Awareness"},
        {"Identificador": "ms=", "Servicio": "Microsoft", "Categoría": "Validación / Integración"}
    ]

    encontrados = []
    texto_busqueda = f"{spf or ''} {dmarc or ''}".lower()

    # Buscar en SPF/DMARC
    for s in proveedores_base:
        if s["Identificador"].lower() in texto_busqueda:
            encontrados.append({**s, "Origen": "SPF/DMARC"})

    # Buscar en MX
    for mx in mx_registros:
        for s in proveedores_base:
            if s["Identificador"].lower() in mx.lower():
                encontrados.append({**s, "Origen": "MX"})

    # Buscar en NS
    for ns in ns_registros:
        for s in proveedores_base:
            if s["Identificador"].lower() in ns.lower():
                encontrados.append({**s, "Origen": "NS"})

    return encontrados
