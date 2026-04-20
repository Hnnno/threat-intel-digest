"""
test_summarizer.py
Tests unitarios para el modulo de resumen con IA.
"""

import pytest
from unittest.mock import patch, MagicMock
from src.processors.summarizer import summarize_article, summarize_all


SAMPLE_ARTICLE = {
    "title": "Critical RCE in Apache HTTP Server",
    "summary": "A critical remote code execution vulnerability was found in Apache HTTP Server versions prior to 2.4.62.",
    "severity": "critical",
    "url": "https://example.com/article",
}


@patch("src.processors.summarizer.anthropic.Anthropic")
@patch.dict("os.environ", {"ANTHROPIC_API_KEY": "fake-key"})
def test_summarize_article_returns_text(mock_anthropic_class):
    mock_client = MagicMock()
    mock_anthropic_class.return_value = mock_client
    mock_client.messages.create.return_value = MagicMock(
        content=[MagicMock(text="Apache HTTP Server tiene una vulnerabilidad critica de RCE. Actualizar a 2.4.62.")]
    )

    result = summarize_article(SAMPLE_ARTICLE)
    assert isinstance(result, str)
    assert len(result) > 0


@patch("src.processors.summarizer.anthropic.Anthropic")
@patch.dict("os.environ", {"ANTHROPIC_API_KEY": "fake-key"})
def test_summarize_article_fallback_on_error(mock_anthropic_class):
    mock_client = MagicMock()
    mock_anthropic_class.return_value = mock_client
    mock_client.messages.create.side_effect = Exception("API error")

    result = summarize_article(SAMPLE_ARTICLE)
    assert result == SAMPLE_ARTICLE["summary"]


@patch.dict("os.environ", {}, clear=True)
def test_summarize_article_no_api_key():
    result = summarize_article(SAMPLE_ARTICLE)
    assert result == SAMPLE_ARTICLE["summary"]


@patch("src.processors.summarizer.summarize_article")
def test_summarize_all_adds_ai_summary(mock_summarize):
    mock_summarize.return_value = "Resumen generado por IA."
    articles = [SAMPLE_ARTICLE.copy(), SAMPLE_ARTICLE.copy()]
    result = summarize_all(articles)
    assert all("ai_summary" in a for a in result)
    assert result[0]["ai_summary"] == "Resumen generado por IA."
