# Plataforma de Cifrado Híbrido AES-256 sobre Telegram

Sistema de mensajería segura que implementa un pipeline de derivación de clave de diseño propio acoplado al estándar criptográfico AES-256 en modo CBC, utilizando la API de Telegram como capa de transporte.

## Algoritmo Implementado

El núcleo técnico del proyecto es la transformación estructural de la clave ingresada por el usuario antes de alimentar el motor de cifrado:

```text
Clave del usuario
     │
     ▼
[1] Conversión a UTF-8          → Soporte seguro para caracteres Unicode y extendidos.
     │
     ▼
[2] Padding Cíclico             → Expansión de la clave hasta 32 bytes (Requisito estricto de AES-256).
     │
     ▼
[3] Transposición de Bloques    → Inversión de secuencia y cruce de extremos para destruir patrones lineales.
     │
     ▼
[4] Salting (XOR Dinámico)      → Ofuscación a nivel de bits utilizando la fórmula: (longitud * 17) mod 251.
     │
     ▼
[5] AES-256 (Modo CBC)          → Cifrado estándar de la industria con inyección de Vector de Inicialización (IV).
     │
     ▼
[6] Codificación Base64         → Empaquetado de caracteres para evitar la corrupción de datos en la transmisión.

## Instalación

# 1. Instalar dependencias requeridas
pip install -r requirements.txt

# 2. Configurar el bot en Telegram
#    - Buscar a @BotFather en la aplicación
#    - Ejecutar el comando /newbot y seguir las instrucciones
#    - Copiar el TOKEN HTTP API generado

# 3. Vincular credenciales en el código
#    - Abrir el archivo bot.py
#    - Reemplazar la variable con el token obtenido:
#      TOKEN = "TU_TOKEN_AQUI"

# 4. Iniciar el servidor
python bot.py

##Pruebas Locales

```bash
python test_cifrado.py
```

## Archivos del proyecto

| Archivo | Descripción |
|---|---|
| `cifrado.py` | Motor de cifrado: toda la lógica del algoritmo |
| `bot.py` | Bot de Telegram: interfaz de usuario |
| `test_cifrado.py` | Pruebas locales del algoritmo |
| `requirements.txt` | Dependencias |

## Comandos del bot

- `/start` — Inicia el bot y muestra el menú
- `/cancelar` — Cancela la operación actual

## Tecnologías usadas

- **Python 3.10+**
- **AES-256 CBC** (pycryptodome) — Estándar de cifrado
- **python-telegram-bot** — Interfaz de comunicación cliente-servidor
- **Base64** — Encoding para transmisión segura de datos binarios
