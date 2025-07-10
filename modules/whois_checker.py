import whois
from datetime import datetime

def analizar_whois(dominio):
    try:
        datos = whois.whois(dominio)

        # Función auxiliar para convertir fechas y listas
        def formatear_fecha(fecha):
            if isinstance(fecha, list):
                fecha = fecha[0]
            return fecha.strftime("%Y-%m-%d") if isinstance(fecha, datetime) else str(fecha)

        # Detectar campos ocultos
        campos_ocultos = []
        nombre = datos.get('name')
        organizacion = datos.get('org')
        proveedor = datos.get('registrar')

        if not nombre:
            campos_ocultos.append("Nombre del registrante")
        if not organizacion:
            campos_ocultos.append("Organización")

        # Heurística para detectar servicios de privacidad conocidos
        privacidad_detectada = False
        if organizacion:
            privacidad_detectada = any(kw in organizacion.lower() for kw in [
                "privacy", "guard", "proxy", "private", "whois", "protection", "data protected"
            ])

        resultado = {
            "Dominio": dominio,
            "Registrante": nombre or "Oculto/No disponible",
            "Organización": organizacion or "Oculto/No disponible",
            "País": datos.get('country') or "No especificado",
            "Proveedor (Registrar)": proveedor or "Desconocido",
            "Creado en": formatear_fecha(datos.get('creation_date')),
            "Expira en": formatear_fecha(datos.get('expiration_date')),
            "Última actualización": formatear_fecha(datos.get('updated_date')),
            "Privacidad WHOIS": "Sí" if campos_ocultos or privacidad_detectada else "No",
            "Campos ocultos": campos_ocultos or "Ninguno"
        }

        return resultado

    except Exception as e:
        
        return {"error": f"No se pudo obtener información WHOIS: {e}"}
    
if __name__ == "__main__":
    dominio = input("Introduce un dominio para analizar (ej: openai.com): ").strip()
    resultado = analizar_whois(dominio)
    for clave, valor in resultado.items():
        print(f"{clave}: {valor}")

def scanner_whois(dominio):
    return analizar_whois(dominio)
