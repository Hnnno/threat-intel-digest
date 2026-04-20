"""
rss_collector.py
Recopila articulos recientes desde feeds RSS de fuentes de ciberseguridad.
"""

import feedparser
import yaml
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "sources.yaml"


def load_config() -> dict:
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


def fetch_feed(feed_url: str, feed_name: str, max_age_hours: int) -> list[dict]:
    """
    Descarga y parsea un feed RSS.
    Retorna una lista de articulos dentro del periodo de tiempo configurado.
    """
    try:
        parsed = feedparser.parse(feed_url)
    except Exception as e:
        logger.error(f"Error al parsear feed '{feed_name}': {e}")
        return []

    if parsed.bozo:
        logger.warning(f"Feed '{feed_name}' tiene errores de formato pero se continua.")

    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    articles = []

    for entry in parsed.entries:
        published = None

        if hasattr(entry, "published_parsed") and entry.published_parsed:
            published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        elif hasattr(entry, "updated_parsed") and entry.updated_parsed:
            published = datetime(*entry.updated_parsed[:6], tzinfo=timezone.utc)

        if published and published < cutoff:
            continue

        articles.append({
            "source": feed_name,
            "title": entry.get("title", "Sin titulo"),
            "url": entry.get("link", ""),
            "summary": entry.get("summary", ""),
            "published": published.isoformat() if published else None,
        })

    logger.info(f"Feed '{feed_name}': {len(articles)} articulos recopilados.")
    return articles


def collect_all() -> list[dict]:
    """
    Recopila articulos de todos los feeds configurados en sources.yaml.
    Retorna una lista consolidada de articulos.
    """
    config = load_config()
    feeds = config.get("rss_feeds", [])
    max_age = config.get("max_age_hours", 24)
    max_items = config.get("max_items_per_feed", 10)

    all_articles = []

    for feed in feeds:
        articles = fetch_feed(feed["url"], feed["name"], max_age)
        all_articles.extend(articles[:max_items])

    logger.info(f"Total articulos recopilados desde RSS: {len(all_articles)}")
    return all_articles
