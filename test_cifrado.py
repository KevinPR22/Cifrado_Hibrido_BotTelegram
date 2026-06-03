# ============================================================
#  test_cifrado.py — Suite de Pruebas Unitarias Locales
#  Script para hacer pruebas aisladas en la terminal
# ============================================================

import sys
# Forzamos la codificación UTF-8 en la terminal para evitar cuelgues 
# al imprimir caracteres especiales 
sys.stdout.reconfigure(encoding='utf-8')

from cifrado import cifrar, descifrar, info_clave, registrar_evento

# Clave por defecto utilizada a lo largo de las pruebas
CLAVE_BASE = "ClaveSistemas2026"

def ejecutar_diagnostico():
    """Ejecuta una batería de pruebas automatizadas sobre el motor criptográfico."""
    registrar_evento("DIAGNOSTICO", "Iniciando suite automatizada de pruebas criptográficas locales.")

    print("\n" + "="*60)
    print("  1. AUDITORÍA DEL PIPELINE DE MEMORIA")
    print("="*60)
    # Visualiza la transformación paso a paso de la clave en memoria
    print(info_clave(CLAVE_BASE).replace("*", "").replace("`", ""))

    print("\n" + "="*60)
    print("  2. INTEGRIDAD DE CICLO COMPLETO (Cifrar -> Descifrar)")
    print("="*60)
    
    # Prueba que el algoritmo es 100% reversible sin pérdida de datos
    criptograma = None
    try:
        mensaje_test = "Prueba de Integridad del Proyecto"
        criptograma = cifrar(mensaje_test, CLAVE_BASE)
        print(f"  [+] Trama en tránsito (Base64) : {criptograma}")

        texto_claro = descifrar(criptograma, CLAVE_BASE)
        print(f"  [+] Payload restaurado         : {texto_claro}")

        assert mensaje_test == texto_claro, "Error crítico: Discrepancia de datos."
        print("\n  [OK] COMPROBACIÓN DE INTEGRIDAD LOGRADA: ÉXITO")

    except Exception as e:
        print(f"  [FALLO] Error detectado: {e}")

    print("\n" + "="*60)
    print("  3. SIMULACIÓN DE DEFENSA (Clave Errónea)")
    print("="*60)
    
    # Prueba que el motor de descifrado rechace un ataque con clave falsa
    if criptograma:
        clave_atacante = "ClaveIncorrecta123"
        try:
            descifrar(criptograma, clave_atacante)
            print("  [FALLO] VULNERABILIDAD: Se permitió descifrar con llave incorrecta.")
        except Exception:
            print("  [OK] FILTRO DE AUTENTICIDAD CORRECTO: Motor rechazó la llave inválida.")

    print("\n" + "="*60)
    print("  4. VALIDACIÓN DE LÍMITES Y SEGURIDAD (Edge Cases)")
    print("="*60)
    
    # Prueba las validaciones de seguridad contra desbordamiento y división por cero
    try:
        cifrar("Mensaje", "")
        print("  [FALLO] El sistema aceptó una clave vacía.")
    except ValueError:
        print("  [OK] El sistema bloqueó correctamente una clave vacía.")

    try:
        clave_gigante = "EstaClaveEsDemasiadoLargaYDeberiaFallarInmediatamente"
        cifrar("Mensaje", clave_gigante)
        print("  [FALLO] El sistema permitió una clave mayor a 32 bytes (Riesgo de truncamiento).")
    except ValueError:
        print("  [OK] El sistema bloqueó correctamente una clave que excede los 32 bytes.")

    print("\n" + "="*60)
    print("  5. PRUEBAS DE ESTRÉS DE MEMORIA (Caracteres Especiales)")
    print("="*60)

    # Prueba la estabilidad del UTF-8 frente a entradas complejas y símbolos raros
    casos = [
        ("Emojis en mensaje",       "Hola mundo fiesta",             CLAVE_BASE),
        ("Tildes en mensaje",       "Información, protección, señal", CLAVE_BASE),
        ("Símbolos especiales",     "Precio €500 | test@server.com",  CLAVE_BASE),
        ("Clave con tildes/ñ",      "Mensaje de prueba normal",       "CláveÑoña2026"),
        ("Clave con símbolos",      "Mensaje de prueba normal",       "Clave€Secreta"),
        ("Mensaje y clave mixtos",  "Contraseña: ñoño€100",           "Séguridàd"),
    ]

    todos_ok = True
    for nombre, mensaje, clave in casos:
        try:
            cifrado_esp    = cifrar(mensaje, clave)
            descifrado_esp = descifrar(cifrado_esp, clave)
            ok = (mensaje == descifrado_esp)
            if ok:
                preview = mensaje if len(mensaje) <= 35 else mensaje[:32] + "..."
                print(f"  [OK] [{nombre}]: '{preview}'")
            else:
                print(f"  [FALLO] [{nombre}]: roundtrip no coincide")
                todos_ok = False
        except Exception as e:
            print(f"  [FALLO] ERROR [{nombre}]: {e}")
            todos_ok = False

    print()
    if todos_ok:
        print("  [OK] TODOS LOS CASOS DE ESTRÉS PASAN CORRECTAMENTE")
    else:
        print("  [FALLO] ALGUNOS CASOS FALLARON — revisar errores arriba")

    print("\n" + "="*60)
    print("  Diagnóstico Finalizado de Forma Exitosa")
    print("="*60)

if __name__ == "__main__":
    ejecutar_diagnostico()