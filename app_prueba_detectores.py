
import streamlit as st

def detectar_servicios_relacionados(spf: str, dmarc: str = "") -> list:
    servicios = [
        {"Identificador": "pphosted.com", "Servicio": "Proofpoint", "Categoría": "Filtering / Relay"},
        {"Identificador": "spf.protection.outlook.com", "Servicio": "Microsoft 365", "Categoría": "Correo Empresarial"},
        {"Identificador": "protection.outlook.com", "Servicio": "Microsoft 365", "Categoría": "Correo Empresarial"},
    ]

    encontrados = []
    texto_busqueda = f"{spf or ''} {dmarc or ''}".lower()
    st.write("🧪 Texto combinado:", texto_busqueda)

    for s in servicios:
        ident = s["Identificador"].lower()
        if ident in texto_busqueda:
            encontrados.append({
                "Servicio": s["Servicio"],
                "Identificador": s["Identificador"],
                "Categoría": s["Categoría"],
                "Origen": "SPF/DMARC"
            })

    return encontrados

st.title("🔍 Prueba de detección de servicios en SPF/DMARC")

spf_input = st.text_area("📝 Registro SPF", value="v=spf1 a mx ip4:177.242.144.64/26 ip4:200.188.9.192/26 include:spf-002f7d02.pphosted.com include:spf.protection.outlook.com -all")
dmarc_input = st.text_area("📝 Registro DMARC", value="")

if st.button("Detectar servicios"):
    servicios = detectar_servicios_relacionados(spf_input, dmarc_input)
    if servicios:
        st.success("✅ Servicios detectados:")
        for s in servicios:
            st.write(f"- **{s['Servicio']}** ({s['Categoría']}) → detectado en: {s['Origen']}")
    else:
        st.warning("❌ No se detectaron servicios.")
