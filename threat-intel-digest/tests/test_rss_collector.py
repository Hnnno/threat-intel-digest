"""
test_rss_collector.py
Tests unitarios para el modulo rss_collector.
"""

import pytest
from unittest.mock import patch, MagicMock
from src.collectors.rss_collector import fetch_feed, collect_all


MOCK_ENTRY = MagicMock()
MOCK_ENTRY.title = "Critical RCE vulnerability found in Apache"
MOCK_ENTRY.link = "https://example.com/article"
MOCK_ENTRY.summary = "A critical remote code execution vulnerability was discovered."
MOCK_ENTRY.published_parsed = (2026, 4, 19, 8, 0, 0, 0, 0, 0)
MOCK_ENTRY.get = lambda key, default="": {
    "title": MOCK_ENTRY.title,
    "link": MOCK_ENTRY.link,
    "summary": MOCK_ENTRY.summary,
}.get(key, default)


@patch("src.collectors.rss_collector.feedparser.parse")
def test_fetch_feed_returns_articles(mock_parse):
    mock_parse.return_value = MagicMock(bozo=False, entries=[MOCK_ENTRY])
    articles = fetch_feed("https://fake-feed.com/rss", "Test Feed", max_age_hours=24)
    assert len(articles) == 1
    assert articles[0]["title"] == "Critical RCE vulnerability found in Apache"
    assert articles[0]["source"] == "Test Feed"


@patch("src.collectors.rss_collector.feedparser.parse")
def test_fetch_feed_handles_error(mock_parse):
    mock_parse.side_effect = Exception("Connection error")
    articles = fetch_feed("https://fake-feed.com/rss", "Bad Feed", max_age_hours=24)
    assert articles == []


@patch("src.collectors.rss_collector.fetch_feed")
@patch("src.collectors.rss_collector.load_config")
def test_collect_all_aggregates_feeds(mock_config, mock_fetch):
    mock_config.return_value = {
        "rss_feeds": [
            {"name": "Feed A", "url": "https://a.com/rss"},
            {"name": "Feed B", "url": "https://b.com/rss"},
        ],
        "max_age_hours": 24,
        "max_items_per_feed": 10,
    }
    mock_fetch.return_value = [{"title": "Article", "source": "Feed", "url": "", "summary": "", "published": None}]
    articles = collect_all()
    assert len(articles) == 2
