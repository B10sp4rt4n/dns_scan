import dns.resolver

def scanner_mx(dominio):
    resultado = {
        "dominio": dominio,
        "mx_records": [],
        "proveedor_detectado": "Desconocido",
        "riesgo_mx": "No evaluado",
        "observaciones": "No se pudo determinar la configuración MX."
    }

    try:
        respuestas = dns.resolver.resolve(dominio, 'MX')
        for rdata in respuestas:
            host = str(rdata.exchange).rstrip('.')
            prioridad = rdata.preference
            resultado["mx_records"].append({"host": host, "priority": prioridad})

        # Ordenar por prioridad
        resultado["mx_records"].sort(key=lambda x: x["priority"])

        # Detección de proveedor
        hostnames = [mx["host"] for mx in resultado["mx_records"]]
        proveedor = "Desconocido"
        if any("google.com" in h for h in hostnames):
            proveedor = "Google Workspace"
        elif any("outlook.com" in h or "protection.outlook.com" in h for h in hostnames):
            proveedor = "Microsoft 365"
        elif any("zoho.com" in h for h in hostnames):
            proveedor = "Zoho Mail"
        elif any("secureserver.net" in h for h in hostnames):
            proveedor = "GoDaddy Mail"
        elif any("yahoo.com" in h for h in hostnames):
            proveedor = "Yahoo Mail"
        elif any("icloud.com" in h for h in hostnames):
            proveedor = "iCloud Mail"
        elif any("mailgun.org" in h or "sendgrid.net" in h for h in hostnames):
            proveedor = "SMTP como servicio (Mailgun, SendGrid, etc.)"
        elif any(dominio in h for h in hostnames):
            proveedor = "Servidor propio"

        resultado["proveedor_detectado"] = proveedor

        # Evaluación de riesgo (simplificada por ahora)
        if proveedor == "Servidor propio":
            resultado["riesgo_mx"] = "Medio"
            resultado["observaciones"] = "Servidor autogestionado, se recomienda revisar políticas de autenticación SMTP."
        elif proveedor == "Desconocido":
            resultado["riesgo_mx"] = "Alto"
            resultado["observaciones"] = "No se pudo determinar el proveedor, puede haber configuración deficiente."
        else:
            resultado["riesgo_mx"] = "Bajo"
            resultado["observaciones"] = f"Proveedor confiable detectado: {proveedor}. Requiere revisar SPF y DMARC."

    except Exception as e:
        resultado["riesgo_mx"] = "Crítico"
        resultado["observaciones"] = f"Error al consultar registros MX: {e}"

    return resultado

