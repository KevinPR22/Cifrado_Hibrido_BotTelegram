# 🔐 Bot de Cifrado AES-256 para Telegram

Bot de Telegram que implementa un algoritmo de cifrado compuesto personalizado.

## Algoritmo implementado

```
Clave usuario
     │
     ▼
[1] Conversión a ASCII        → 'CASA' = [67, 65, 83, 65]
     │
     ▼
[2] Padding hasta 32 bytes    → repite hasta completar AES-256
     │
     ▼
[3] Transposición             → intercala mitades del array
     │
     ▼
[4] Salt (XOR con 7)          → dificulta análisis de patrones
     │
     ▼
[5] AES-256 CBC               → cifrado estándar de industria
     │
     ▼
[6] Base64                    → texto seguro para transmitir
```

## Instalación

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Crear tu bot en Telegram
#    - Abre Telegram y busca @BotFather
#    - Escribe /newbot y sigue los pasos
#    - Copia el TOKEN que te da

# 3. Pegar el token en bot.py
#    Abre bot.py y reemplaza esta línea:
#    TOKEN = "PON_AQUI_TU_TOKEN_DE_BOTFATHER"

# 4. Correr el bot
python bot.py
```

## Probar sin Telegram (primero)

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
- **AES-256 CBC** (pycryptodome) — Estándar de cifrado de industria
- **python-telegram-bot** — Interfaz de comunicación cliente-servidor
- **Base64** — Encoding para transmisión segura de datos binarios
