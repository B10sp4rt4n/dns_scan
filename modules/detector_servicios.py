
def detectar_servicios_relacionados(spf: str, dmarc: str = "") -> list:
    servicios = [
        {"Identificador": "pphosted.com", "Servicio": "Proofpoint", "Categoría": "Filtering / Relay"},
        {"Identificador": "spf.protection.outlook.com", "Servicio": "Microsoft 365", "Categoría": "Correo Empresarial"},
        {"Identificador": "protection.outlook.com", "Servicio": "Microsoft 365", "Categoría": "Correo Empresarial"},
    ]

    encontrados = []
    texto_busqueda = f"{spf or ''} {dmarc or ''}".lower()
    print(f"[DEBUG] Texto SPF/DMARC combinado: {texto_busqueda}")

    for s in servicios:
        ident = s["Identificador"].lower()
        if ident in texto_busqueda:
            encontrados.append({
                "Servicio": s["Servicio"],
                "Identificador": s["Identificador"],
                "Categoría": s["Categoría"],
                "Origen": "SPF/DMARC"
            })

    print(f"[DEBUG] Servicios encontrados: {encontrados}")
    return encontrados
