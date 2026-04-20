"""
test_filter.py
Tests unitarios para el modulo de filtrado y clasificacion por severidad.
"""

import pytest
from unittest.mock import patch
from src.processors.filter import classify_article, filter_and_classify

MOCK_KEYWORDS = {
    "critical": ["RCE", "zero-day", "ransomware"],
    "high": ["vulnerability", "CVE", "malware"],
    "medium": ["patch", "advisory"],
}


@patch("src.processors.filter.load_keywords", return_value=MOCK_KEYWORDS)
def test_classify_critical(mock_kw):
    article = {"title": "New zero-day found in Windows", "summary": "Details here."}
    assert classify_article(article, MOCK_KEYWORDS) == "critical"


@patch("src.processors.filter.load_keywords", return_value=MOCK_KEYWORDS)
def test_classify_high(mock_kw):
    article = {"title": "CVE-2026-1234 disclosed", "summary": "Affects Linux kernel."}
    assert classify_article(article, MOCK_KEYWORDS) == "high"


@patch("src.processors.filter.load_keywords", return_value=MOCK_KEYWORDS)
def test_classify_low(mock_kw):
    article = {"title": "Tech company releases new logo", "summary": "Rebranding news."}
    assert classify_article(article, MOCK_KEYWORDS) == "low"


@patch("src.processors.filter.load_keywords", return_value=MOCK_KEYWORDS)
def test_filter_removes_low_severity(mock_kw):
    articles = [
        {"title": "ransomware hits hospitals", "summary": ""},
        {"title": "Company rebrands", "summary": ""},
        {"title": "CVE-2026-9999 advisory", "summary": ""},
    ]
    result = filter_and_classify(articles)
    assert len(result) == 2
    titles = [a["title"] for a in result]
    assert "Company rebrands" not in titles


@patch("src.processors.filter.load_keywords", return_value=MOCK_KEYWORDS)
def test_filter_orders_by_severity(mock_kw):
    articles = [
        {"title": "patch released", "summary": ""},
        {"title": "ransomware campaign", "summary": ""},
        {"title": "CVE disclosed", "summary": ""},
    ]
    result = filter_and_classify(articles)
    severities = [a["severity"] for a in result]
    assert severities[0] == "critical"
