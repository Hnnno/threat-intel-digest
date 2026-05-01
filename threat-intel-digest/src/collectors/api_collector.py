"""
api_collector.py
Consulta APIs de threat intelligence (VirusTotal, AbuseIPDB, AlienVault OTX, Shodan)
para enriquecer el reporte con IOCs, reputacion de IPs y analisis de hashes.
"""

import os
import requests
import logging

logger = logging.getLogger(__name__)

VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE  = "https://api.abuseipdb.com/api/v2"
OTX_BASE        = "https://otx.alienvault.com/api/v1"
SHODAN_BASE     = "https://api.shodan.io"


def get_virustotal_ip_report(ip: str) -> dict | None:
    """
    Consulta la reputacion de una IP en VirusTotal.
    Retorna un resumen con el veredicto y cantidad de detecciones.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.warning("VIRUSTOTAL_API_KEY no configurada. Saltando consulta.")
        return None

    url = f"{VIRUSTOTAL_BASE}/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())

        return {
            "ip": ip,
            "malicious_votes": malicious,
            "total_engines": total,
            "verdict": "malicious" if malicious > 3 else "clean",
        }

    except requests.RequestException as e:
        logger.error(f"Error consultando VirusTotal para IP {ip}: {e}")
        return None


def get_abuseipdb_report(ip: str, max_age_days: int = 30) -> dict | None:
    """
    Consulta AbuseIPDB para obtener el historial de reportes de una IP.
    Retorna el abuse confidence score y cantidad de reportes.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.warning("ABUSEIPDB_API_KEY no configurada. Saltando consulta.")
        return None

    url = f"{ABUSEIPDB_BASE}/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": False}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]

        return {
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "is_tor": data.get("isTor", False),
        }

    except requests.RequestException as e:
        logger.error(f"Error consultando AbuseIPDB para IP {ip}: {e}")
        return None


def get_top_abusive_ips(limit: int = 5) -> list[dict]:
    """
    Obtiene las IPs mas reportadas en AbuseIPDB en las ultimas 24hs.
    Usa el endpoint /blacklist.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.warning("ABUSEIPDB_API_KEY no configurada. Saltando blacklist.")
        return []

    url = f"{ABUSEIPDB_BASE}/blacklist"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"confidenceMinimum": 90, "limit": limit}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        entries = response.json().get("data", [])

        return [
            {
                "ip": e.get("ipAddress"),
                "abuse_confidence_score": e.get("abuseConfidenceScore"),
                "total_reports": e.get("totalReports"),
                "country": e.get("countryCode"),
                "last_reported": e.get("lastReportedAt"),
            }
            for e in entries
        ]

    except requests.RequestException as e:
        logger.error(f"Error obteniendo blacklist de AbuseIPDB: {e}")
        return []


def collect_all() -> dict:
    """
    Punto de entrada principal del modulo.
    Retorna un diccionario con todos los datos recopilados desde APIs.
    """
    top_ips    = get_top_abusive_ips(limit=5)
    otx_pulses = get_otx_latest_pulses(limit=5)

    return {
        "top_abusive_ips": top_ips,
        "otx_pulses":      otx_pulses,
    }


def get_otx_latest_pulses(limit: int = 5) -> list[dict]:
    """
    Obtiene los pulsos mas recientes de AlienVault OTX.
    Cada pulso representa una campana de amenaza con IOCs asociados.
    """
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        logger.warning("OTX_API_KEY no configurada. Saltando consulta a AlienVault OTX.")
        return []

    url = f"{OTX_BASE}/pulses/subscribed"
    headers = {"X-OTX-API-KEY": api_key}
    params = {"limit": limit}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        pulses = response.json().get("results", [])

        return [
            {
                "name": p.get("name", "Sin nombre"),
                "description": p.get("description", ""),
                "author": p.get("author_name", "Unknown"),
                "tags": p.get("tags", []),
                "ioc_count": len(p.get("indicators", [])),
                "created": p.get("created", ""),
                "url": f"https://otx.alienvault.com/pulse/{p.get('id', '')}",
            }
            for p in pulses
        ]

    except requests.RequestException as e:
        logger.error(f"Error consultando AlienVault OTX: {e}")
        return []


def get_shodan_ip_info(ip: str) -> dict | None:
    """
    Consulta Shodan para obtener informacion de puertos abiertos y servicios
    expuestos de una IP determinada.
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logger.warning("SHODAN_API_KEY no configurada. Saltando consulta a Shodan.")
        return None

    url = f"{SHODAN_BASE}/shodan/host/{ip}"
    params = {"key": api_key}

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        return {
            "ip": ip,
            "org": data.get("org", "Unknown"),
            "country": data.get("country_name", "Unknown"),
            "open_ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "vulnerabilities": list(data.get("vulns", {}).keys()),
        }

    except requests.RequestException as e:
        logger.error(f"Error consultando Shodan para IP {ip}: {e}")
        return None