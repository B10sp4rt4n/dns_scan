import dns.resolver
import socket

def obtener_dns_actual(dominio: str) -> dict:
    resultados = {}

    # Registro A
    try:
        respuesta_a = dns.resolver.resolve(dominio, 'A')
        resultados["A"] = [r.to_text() for r in respuesta_a]
    except Exception as e:
        resultados["A"] = f"Error: {e}"

    # Hostnames inversos (PTR)
    if isinstance(resultados.get("A"), list):
        resultados["Hostnames"] = []
        for ip in resultados["A"]:
            try:
                host = socket.gethostbyaddr(ip)[0]
                resultados["Hostnames"].append(f"{ip} → {host}")
            except Exception:
                resultados["Hostnames"].append(f"{ip} → (sin PTR válido)")

    # Registro NS
    try:
        respuesta_ns = dns.resolver.resolve(dominio, 'NS')
        resultados["NS"] = [r.to_text() for r in respuesta_ns]
    except Exception as e:
        resultados["NS"] = f"Error: {e}"

    # Registro MX
    try:
        respuesta_mx = dns.resolver.resolve(dominio, 'MX')
        resultados["MX"] = [r.to_text() for r in respuesta_mx]
    except Exception as e:
        resultados["MX"] = f"Error: {e}"

    # Registro TXT (opcional)
    try:
        respuesta_txt = dns.resolver.resolve(dominio, 'TXT')
        resultados["TXT"] = [r.to_text().strip('"') for r in respuesta_txt]
    except Exception:
        resultados["TXT"] = "No encontrado o no aplicable."

    return resultados
