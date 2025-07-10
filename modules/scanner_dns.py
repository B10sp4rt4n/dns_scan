import dns.resolver

def revisar_registros(dominio: str) -> dict:
    spf = False
    dmarc = False

    try:
        respuestas_spf = dns.resolver.resolve(dominio, "TXT")
        for r in respuestas_spf:
            if "v=spf1" in r.to_text():
                spf = True
                break
    except Exception:
        pass

    try:
        respuestas_dmarc = dns.resolver.resolve(f"_dmarc.{dominio}", "TXT")
        for r in respuestas_dmarc:
            if "v=DMARC1" in r.to_text():
                dmarc = True
                break
    except Exception:
        pass

    return {
        "spf": spf,
        "dmarc": dmarc
    }
