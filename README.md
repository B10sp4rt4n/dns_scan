# 🧠 DNS Diagnóstico

**DNS Diagnóstico** es una herramienta diseñada para analizar y diagnosticar configuraciones DNS de dominios, ideal para auditar seguridad, detectar errores comunes, y obtener información clave sobre registros y políticas.

## 🚀 Funcionalidades principales

- 🔍 Consulta de registros DNS (A, MX, TXT, SPF, etc.)
- 🔐 Verificación de políticas de seguridad como SPF, DKIM, DMARC
- 🌐 Resolución WHOIS y estado de dominio
- 📊 Interfaz interactiva con `Streamlit`
- 🧰 Módulos separados para pruebas, respaldo y desarrollo incremental

## 🧩 Estructura del proyecto

```
dns_diagnostico/
├── app.py                   # Aplicación principal
├── app_final_integrada.py  # Versión final consolidada
├── Respaldo/               # Versiones anteriores y pruebas
│   ├── appV2.py
│   ├── appV3_whois_ok.py
│   └── dns_diag.py
├── modules/                # Módulos auxiliares (opcional según versión)
├── requirements.txt        # Dependencias del proyecto
└── README.md               # Este archivo
```

## ⚙️ Instalación

1. Clona este repositorio:

```bash
git clone https://github.com/B10sp4rt4n/dns_scan.git
cd dns_scan
```

2. Instala los requerimientos:

```bash
pip install -r requirements.txt
```

3. Ejecuta la app (si usas Streamlit):

```bash
streamlit run app.py
```

## 💡 Uso sugerido

Ideal para:
- Auditores de ciberseguridad
- Equipos de IT y DevOps
- Consultores de infraestructura
- Validación de dominios corporativos

## 📌 Requisitos recomendados

- Python 3.9+
- Conexión a internet
- Entorno virtual (opcional pero recomendable)

## 📬 Contacto

Desarrollado por **Salvador Ruiz Esparza**  
Comentarios, mejoras o colaboraciones son bienvenidas.
