"""
main.py
Orquestador principal de Threat Intel Digest.

Uso:
    python src/main.py               # Ejecuta una vez inmediatamente
    python src/main.py --scheduled   # Ejecuta diariamente a la hora en SCHEDULE_TIME
"""

import os
import sys
import time
import logging
import argparse
import schedule
from dotenv import load_dotenv

load_dotenv()

from collectors import rss_collector, api_collector
from processors import filter as article_filter, summarizer
from notifiers import telegram_notifier, email_notifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger(__name__)


def run_pipeline() -> None:
    """
    Ejecuta el pipeline completo:
    1. Recopila articulos desde RSS
    2. Obtiene datos de APIs de threat intel
    3. Filtra y clasifica por severidad
    4. Resume con IA
    5. Envia el reporte por el notificador configurado
    """
    logger.info("Iniciando pipeline de Threat Intel Digest...")

    # 1. Recopilacion
    rss_articles = rss_collector.collect_all()
    api_data = api_collector.collect_all()

    # 2. Filtrado y clasificacion
    relevant_articles = article_filter.filter_and_classify(rss_articles)

    # 3. Resumen con IA
    summarized_articles = summarizer.summarize_all(relevant_articles)

    # 4. Notificacion
    notifier = os.getenv("NOTIFIER", "telegram").strip().lower()

    if notifier == "telegram":
        success = telegram_notifier.send(summarized_articles, api_data)
    elif notifier == "email":
        success = email_notifier.send(summarized_articles, api_data)
    elif notifier == "ambos":
        t_ok = telegram_notifier.send(summarized_articles, api_data)
        e_ok = email_notifier.send(summarized_articles, api_data)
        success = t_ok and e_ok
    else:
        logger.error(f"Notificador no reconocido: '{notifier}'. Usa: telegram, email, ambos.")
        success = False

    if success:
        logger.info("Pipeline completado exitosamente.")
    else:
        logger.error("El pipeline finalizo con errores en la notificacion.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Threat Intel Digest")
    parser.add_argument(
        "--scheduled",
        action="store_true",
        help="Ejecuta el pipeline diariamente a la hora definida en SCHEDULE_TIME",
    )
    args = parser.parse_args()

    if args.scheduled:
        schedule_time = os.getenv("SCHEDULE_TIME", "08:00")
        logger.info(f"Modo programado activado. Ejecucion diaria a las {schedule_time}.")
        schedule.every().day.at(schedule_time).do(run_pipeline)

        # Primera ejecucion inmediata al arrancar
        run_pipeline()

        while True:
            schedule.run_pending()
            time.sleep(60)
    else:
        run_pipeline()


if __name__ == "__main__":
    main()
