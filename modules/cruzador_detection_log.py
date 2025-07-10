
def verificar_csv(dominio: str, df_log) -> tuple[bool, str]:
    """
    Verifica si el dominio aparece dentro de cualquier celda del DataFrame.
    Devuelve (True, línea coincidente) o (False, "").
    """
    if df_log is None or df_log.empty:
        return False, ""

    dominio = dominio.strip().lower()

    for i, row in df_log.iterrows():
        for value in row:
            if isinstance(value, (str, int, float)):
                if dominio in str(value).lower():
                    return True, str(row.to_dict())

    return False, ""
