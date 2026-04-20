# Threat Intel Digest

Pipeline automatizado de recopilación, análisis y resumen de inteligencia de amenazas de ciberseguridad.

---

## Qué problema resuelve

Los analistas de seguridad necesitan mantenerse al día con un volumen enorme de información: nuevas vulnerabilidades, campañas de malware, IOCs (Indicators of Compromise) y alertas de threat intelligence que se publican diariamente en múltiples fuentes.

Revisar manualmente cada fuente todos los días es ineficiente y propenso a omisiones. **Threat Intel Digest** automatiza ese proceso: recopila información de fuentes confiables, la filtra, la resume con IA y la entrega en un reporte diario directo a tu email o canal de Telegram — listo para analizar.

---

## Qué hace exactamente

1. **Recopila** artículos y alertas desde feeds RSS de fuentes especializadas en ciberseguridad
2. **Consulta** APIs de threat intelligence para enriquecer la información con IOCs, reputación de IPs y hashes maliciosos
3. **Resume** el contenido usando un modelo de lenguaje (LLM), extrayendo los puntos críticos de cada ítem
4. **Entrega** un reporte diario consolidado vía email o Telegram

---

## Fuentes de información

### RSS Feeds

| Fuente | Descripcion |
|---|---|
| [The Hacker News](https://thehackernews.com) | Noticias de ciberseguridad de alto impacto |
| [Krebs on Security](https://krebsonsecurity.com) | Investigacion profunda sobre amenazas y fraude |
| [BleepingComputer](https://bleepingcomputer.com) | Vulnerabilidades, ransomware y malware |
| [CISA Alerts](https://www.cisa.gov/news-events/cybersecurity-advisories) | Advisories oficiales del gobierno de EE.UU. |

### APIs de Threat Intelligence

| API | Uso |
|---|---|
| [VirusTotal](https://virustotal.com) | Analisis de hashes, IPs y dominios maliciosos |
| [AbuseIPDB](https://abuseipdb.com) | Reputacion y reporte de IPs abusivas |

---

## Stack tecnologico

- **Python 3.10+**
- `feedparser` — parseo de RSS feeds
- `requests` — consumo de APIs REST
- `anthropic` — resumen con LLM (Claude)
- `smtplib` — envio de reportes por email
- `python-telegram-bot` — envio de reportes por Telegram
- `schedule` — ejecucion periodica automatizada
- `python-dotenv` — manejo seguro de credenciales

---

## Estructura del proyecto

```
threat-intel-digest/
├── src/
│   ├── collectors/
│   │   ├── rss_collector.py       # Recopila articulos desde feeds RSS
│   │   └── api_collector.py       # Consulta APIs de threat intel
│   ├── processors/
│   │   ├── summarizer.py          # Resume contenido con LLM
│   │   └── filter.py              # Filtra items relevantes por severidad
│   ├── notifiers/
│   │   ├── email_notifier.py      # Envia reporte por email
│   │   └── telegram_notifier.py   # Envia reporte por Telegram
│   └── main.py                    # Orquestador principal
├── config/
│   └── sources.yaml               # Lista de feeds y APIs configurables
├── tests/
│   ├── test_rss_collector.py
│   ├── test_api_collector.py
│   └── test_summarizer.py
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Instalacion

### 1. Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/threat-intel-digest.git
cd threat-intel-digest
```

### 2. Crear y activar entorno virtual

```bash
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar variables de entorno

Copia el archivo de ejemplo y completa tus credenciales:

```bash
cp .env.example .env
```

Edita `.env` con tus datos:

```env
# API Keys
VIRUSTOTAL_API_KEY=tu_api_key
ABUSEIPDB_API_KEY=tu_api_key
ANTHROPIC_API_KEY=tu_api_key

# Email (si usas Gmail, activa "contrasenas de aplicacion")
EMAIL_SENDER=tu_email@gmail.com
EMAIL_PASSWORD=tu_contrasena_de_aplicacion
EMAIL_RECIPIENT=destino@email.com

# Telegram
TELEGRAM_BOT_TOKEN=tu_bot_token
TELEGRAM_CHAT_ID=tu_chat_id

# Scheduler
SCHEDULE_TIME=08:00
```

**Nunca subas el archivo `.env` a GitHub.** Ya esta incluido en el `.gitignore`.

---

## Uso

### Ejecutar manualmente

```bash
python src/main.py
```

### Programar ejecucion diaria

```bash
python src/main.py --scheduled
```

El proceso corre en segundo plano y envia el reporte todos los dias a la hora definida en `SCHEDULE_TIME`.

---

## Ejemplo de reporte generado

```
THREAT INTEL DIGEST — 2026-04-19
==================================

[CRITICO] CVE-2026-XXXX — RCE sin autenticacion en Apache 2.4.x
Afecta versiones anteriores a 2.4.62. Parche disponible.
Fuente: https://thehackernews.com/...

[ALTO] Nueva campana de ransomware apunta a infraestructura critica en Europa
IOCs: 3 IPs, 2 dominios, 1 hash SHA-256 reportados.
Fuente: https://bleepingcomputer.com/...

[MEDIO] Incremento del 40% en escaneos desde AS en Europa del Este
IP con mayor actividad: 185.220.101.45 — 3.200 reportes en 24hs.
Fuente: AbuseIPDB

==================================
Items procesados: 47 | Relevantes: 3 | Tiempo: 12s
```

---

## Roadmap

- [x] Diseno de arquitectura
- [x] Collector de RSS feeds
- [x] Integracion con VirusTotal y AbuseIPDB
- [x] Modulo de resumen con LLM
- [x] Notificador por Telegram
- [x] Notificador por email
- [x] Filtrado por severidad y palabras clave
- [x] Tests unitarios para todos los modulos
- [ ] Soporte para mas fuentes (AlienVault OTX, Shodan)
- [ ] Dashboard web opcional

---

## Consideraciones de seguridad

- Las credenciales se manejan exclusivamente mediante variables de entorno
- Ninguna API key o contrasena se almacena en el codigo fuente
- El archivo `.env` esta excluido del control de versiones via `.gitignore`

---

## Licencia

MIT License — libre para usar, modificar y distribuir con atribucion.

---

*Proyecto desarrollado como herramienta de practica en threat intelligence y automatizacion de seguridad.*
