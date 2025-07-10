
import ssl
import socket

def validar_ssl(dominio: str, puerto: int = 443, timeout: int = 5) -> bool:
    """
    Valida si el dominio tiene un certificado SSL válido.
    Retorna True si el certificado es válido, False si no se puede verificar.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, puerto), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                return bool(cert)
    except Exception:
        return False
