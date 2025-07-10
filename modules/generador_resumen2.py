
from datetime import datetime

def generar_resumen(dominio: str, hallazgos: dict, linea_detectada: str = "") -> str:
    fecha = datetime.today().strftime("%d/%m/%Y")
    resumen = f"""📋 Resumen técnico generado – Diagnóstico de dominio
Dominio evaluado: {dominio}
Fecha de análisis: {fecha}

"""

    # SSL
    if hallazgos.get("ssl_valido"):
        resumen += "🔐 Seguridad SSL\n- Resultado: ✅ Certificado válido.\n- Riesgo: Bajo.\n\n"
    else:
        resumen += "🔐 Seguridad SSL\n- Resultado: ❌ Certificado inválido o ausente.\n- Riesgo: Alto. Posibilidad de interceptación de datos.\n\n"

    # SPF
    if hallazgos.get("spf_valido"):
        resumen += "📤 Registro SPF\n- Resultado: ✅ Configurado correctamente.\n- Riesgo: Bajo.\n\n"
    else:
        resumen += "📤 Registro SPF\n- Resultado: ❌ No detectado.\n- Riesgo: Medio. Posible suplantación por correo.\n\n"

    # DMARC
    if hallazgos.get("dmarc_valido"):
        resumen += "📩 Registro DMARC\n- Resultado: ✅ Detectado y funcional.\n- Riesgo: Bajo.\n\n"
    else:
        resumen += "📩 Registro DMARC\n- Resultado: ❌ No configurado.\n- Riesgo: Medio. No hay control sobre correos no autorizados.\n\n"

    # Headers
    if hallazgos.get("headers_seguridad"):
        resumen += "🛡️ Headers HTTP de Seguridad\n- Resultado: ✅ Headers presentes.\n- Riesgo: Bajo.\n\n"
    else:
        resumen += "🛡️ Headers HTTP de Seguridad\n- Resultado: ❌ No detectados.\n- Riesgo: Medio. Exposición a ataques comunes.\n\n"

    # CSV Detection Log
    if hallazgos.get("aparece_en_csv"):
        resumen += (
            "🚨 Coincidencia en registros de amenazas\n"
            "- Resultado: 🚨 Este dominio fue encontrado en el archivo de detección cargado (Detection Log).\n"
        )
        if linea_detectada:
            resumen += f"- Registro detectado: {linea_detectada}\n"
        resumen += "- Riesgo: Crítico. Puede haber sido objetivo o fuente de eventos de seguridad recientes.\n\n"
    else:
        resumen += (
            "🟢 Coincidencia en registros de amenazas\n"
            "- Resultado: 🟢 El dominio no se encontró en el archivo de detección cargado.\n"
            "- Riesgo: Bajo. No hay evidencia en los registros actuales que lo vincule con actividad sospechosa.\n\n"
        )

    resumen += "🔎 Conclusión: Se recomienda una evaluación técnica detallada y medidas correctivas inmediatas en los puntos señalados."

    return resumen
