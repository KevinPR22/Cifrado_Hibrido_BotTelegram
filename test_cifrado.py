# ============================================================
#  test_cifrado.py — Suite de pruebas unitarias locales
# ============================================================

import sys
sys.stdout.reconfigure(encoding='utf-8')

from cifrado import cifrar, descifrar, info_clave, registrar_evento

CLAVE_BASE = "ClaveSistemas2026"

def ejecutar_diagnostico():
    registrar_evento("DIAGNOSTICO", "Iniciando suite automatizada de pruebas criptográficas.")

    print("\n" + "="*60)
    print("  1. AUDITORÍA DEL PIPELINE DE MEMORIA")
    print("="*60)
    print(info_clave(CLAVE_BASE).replace("*", "").replace("`", ""))

    print("\n" + "="*60)
    print("  2. INTEGRIDAD DE CICLO COMPLETO (Cifrar -> Descifrar)")
    print("="*60)

    criptograma = None
    try:
        mensaje_test = "Prueba de Integridad del Proyecto"
        criptograma = cifrar(mensaje_test, CLAVE_BASE)
        print(f"  [+] Trama en tránsito (Base64) : {criptograma}")

        texto_claro = descifrar(criptograma, CLAVE_BASE)
        print(f"  [+] Payload restaurado         : {texto_claro}")

        assert mensaje_test == texto_claro, "Error crítico: Discrepancia de datos."
        print("\n  ✅ COMPROBACIÓN DE INTEGRIDAD LOGRADA: ÉXITO")

    except Exception as e:
        print(f"  [-] Error detectado: {e}")

    print("\n" + "="*60)
    print("  3. SIMULACIÓN DE CLAVE ERRÓNEA")
    print("="*60)

    if criptograma:
        clave_atacante = "ClaveIncorrecta"
        try:
            descifrar(criptograma, clave_atacante)
            print("  [-] VULNERABILIDAD: Se permitió descifrar con llave incorrecta.")
        except Exception:
            print("  ✅ FILTRO DE AUTENTICIDAD CORRECTO: Motor rechazó la llave inválida.")

    print("\n" + "="*60)
    print("  4. PRUEBAS DE CARACTERES ESPECIALES")
    print("="*60)

    casos = [
        # (descripción, mensaje, clave)
        ("Emojis en mensaje",       "Hola 🔐 mundo 😀 fiesta 🎉",             CLAVE_BASE),
        ("Tildes en mensaje",       "Información, protección, señal, función", CLAVE_BASE),
        ("Ñ y latinos",             "El niño español añadió la señal",         CLAVE_BASE),
        ("Símbolos (@#€)",          "Precio €500 | correo: test@server.com #cifrado", CLAVE_BASE),
        ("Clave con tildes/ñ",      "Mensaje de prueba normal",                "CláveÑoña2026"),
        ("Clave con símbolo €",     "Mensaje de prueba normal",                "Clave€Secreta"),
        ("Clave con emoji 🔑",      "Mensaje de prueba normal",                "Clave🔑Segura"),
        ("Mensaje y clave mixtos",  "🔐 Contraseña: ñoño€100 @test #ok",      "Séguridàd🛡️"),
    ]

    todos_ok = True
    for nombre, mensaje, clave in casos:
        try:
            cifrado_esp   = cifrar(mensaje, clave)
            descifrado_esp = descifrar(cifrado_esp, clave)
            ok = (mensaje == descifrado_esp)
            if ok:
                preview = mensaje if len(mensaje) <= 35 else mensaje[:32] + "..."
                print(f"  ✅ OK  [{nombre}]: '{preview}'")
            else:
                print(f"  ❌ FALLO [{nombre}]: roundtrip no coincide")
                todos_ok = False
        except Exception as e:
            print(f"  ❌ ERROR [{nombre}]: {e}")
            todos_ok = False

    print()
    if todos_ok:
        print("  ✅ TODOS LOS CARACTERES ESPECIALES PASAN CORRECTAMENTE")
    else:
        print("  ❌ ALGUNOS CASOS FALLARON — revisar errores arriba")

    print("\n" + "="*60)
    print("  Diagnóstico Finalizado de Forma Exitosa")
    print("="*60)

if __name__ == "__main__":
    ejecutar_diagnostico()
