# ============================================================
#  cifrado.py — Motor de cifrado
#  Pipeline: UTF-8 → Padding Cíclico → Transposición → XOR Dinámico → AES-256 CBC
# ============================================================
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

def registrar_evento(accion: str, detalle: str):
    """Registra eventos en la consola del servidor para monitoreo."""
    ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ahora}] [CORE-CRYPTO] {accion.upper()} -> {detalle}")

def clave_a_bytes(clave: str) -> list[int]:
    """
    Fase 1: Conversión UTF-8.
    Transforma el texto plano a un arreglo de valores numéricos (bytes) 
    para soportar caracteres Unicode de forma estable.
    """
    return list(clave.encode('utf-8'))

def aplicar_padding(valores_bytes: list[int], longitud: int = 32) -> list[int]:
    """
    Fase 2: Padding Cíclico.
    Extiende el arreglo mediante repetición cíclica hasta alcanzar 
    exactamente los 32 bytes exigidos por el estándar AES-256.
    """
    resultado = []
    i = 0
    while len(resultado) < longitud:
        resultado.append(valores_bytes[i % len(valores_bytes)])
        i += 1
    return resultado[:longitud]

def transponer(valores: list[int]) -> list[int]:
    """
    Fase 3: Transposición de Bloques.
    Invierte la secuencia y permuta los extremos para romper 
    la linealidad estructural generada por el padding.
    """
    copia = list(valores)
    copia.reverse()
    copia[:4], copia[-4:] = copia[-4:], copia[:4]
    return copia

def aplicar_salt(valores: list[int], clave_usuario: str) -> list[int]:
    """
    Fase 4: Salting XOR Dinámico.
    Ofusca los bytes aplicando una operación XOR con un salt calculado 
    algebraicamente a partir de la longitud original de la clave.
    """
    salt_dinamico = (len(clave_usuario) * 17) % 251
    if salt_dinamico == 0:
        salt_dinamico = 11
    return [(v ^ salt_dinamico) for v in valores]

def construir_llave(clave_usuario: str) -> bytes:
    """Coordina la ejecución secuencial del pipeline de derivación en memoria."""
    bytes_vals = clave_a_bytes(clave_usuario)
    
    # Control de excepciones: Prevención de división por cero
    if len(bytes_vals) == 0:
        registrar_evento("SEGURIDAD", "Llave rechazada. El búfer está vacío.")
        raise ValueError("La clave simétrica no puede estar vacía.")

    # Control de excepciones: Mitigación contra truncamiento silencioso
    if len(bytes_vals) > 32:
        registrar_evento("SEGURIDAD", f"Llave rechazada. Excede límite: {len(bytes_vals)} bytes.")
        raise ValueError("La clave excede el límite estricto de 32 bytes.")
        
    padded      = aplicar_padding(bytes_vals, 32)
    transpuesta = transponer(padded)
    salted      = aplicar_salt(transpuesta, clave_usuario)
    
    return bytes(salted)

def cifrar(mensaje: str, clave_usuario: str) -> str:
    """Cifra el mensaje con AES-256 CBC y empaqueta la trama en Base64."""
    if len(mensaje) > 2500:
        registrar_evento("SEGURIDAD", f"Mensaje rechazado. Longitud excedida: {len(mensaje)}.")
        raise ValueError("El mensaje supera el límite de 2500 caracteres.")
        
    registrar_evento("CIFRADO_INICIO", f"Procesando trama de {len(mensaje)} caracteres.")
    
    llave  = construir_llave(clave_usuario)
    cipher = AES.new(llave, AES.MODE_CBC) 
    
    ct = cipher.encrypt(pad(mensaje.encode('utf-8'), AES.block_size))
    resultado = base64.b64encode(cipher.iv + ct).decode('utf-8')
    
    registrar_evento("CIFRADO_FIN", "Trama encapsulada exitosamente.")
    return resultado

def descifrar(mensaje_cifrado: str, clave_usuario: str) -> str:
    """Aísla el IV de la trama cifrada y restaura el texto plano original."""
    registrar_evento("DESCIFRADO_INICIO", "Recuperando flujo de bytes.")
    llave      = construir_llave(clave_usuario)
    raw        = base64.b64decode(mensaje_cifrado)
    
    iv         = raw[:16]
    ct         = raw[16:]
    
    cipher     = AES.new(llave, AES.MODE_CBC, iv=iv)
    texto      = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    
    registrar_evento("DESCIFRADO_FIN", "Texto plano restaurado.")
    return texto

def info_clave(clave_usuario: str) -> str:
    """Reporte de auditoría para visualización en pruebas de escritorio."""
    bytes_vals  = clave_a_bytes(clave_usuario)
    padded      = aplicar_padding(bytes_vals, 32)
    transpuesta = transponer(padded)
    salted      = aplicar_salt(transpuesta, clave_usuario)
    salt_usado  = (len(clave_usuario) * 17) % 251
    if salt_usado == 0: salt_usado = 11

    lineas = [
        "*Seguimiento del proceso de transformación de la clave:*",
        f"• Entrada original: `{clave_usuario}` (Long: {len(clave_usuario)})",
        f"• Paso 1 – Estado Bytes UTF-8: `{bytes_vals}`",
        f"• Paso 2 – Padding Cíclico: `{padded}`",
        f"• Paso 3 – Transposición de Bloques: `{transpuesta}`",
        f"• Paso 4 – Salt XOR ({salt_usado}): `{salted}`",
        f"• Llave Final (Hexadecimal): `{bytes(salted).hex()}`",
    ]
    return "\n".join(lineas)