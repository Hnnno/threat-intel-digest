"""
test_api_collector.py
Tests unitarios para el modulo de consulta a APIs de threat intelligence.
"""

import pytest
from unittest.mock import patch, MagicMock
from src.collectors.api_collector import (
    get_virustotal_ip_report,
    get_abuseipdb_report,
    get_top_abusive_ips,
    collect_all,
)

SAMPLE_IP = "185.220.101.45"


@patch("src.collectors.api_collector.requests.get")
@patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "fake-key"})
def test_virustotal_returns_report(mock_get):
    mock_get.return_value = MagicMock(
        status_code=200,
        json=lambda: {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10,
                        "undetected": 50,
                        "harmless": 5,
                        "suspicious": 0,
                        "timeout": 0,
                    }
                }
            }
        },
    )
    mock_get.return_value.raise_for_status = MagicMock()

    result = get_virustotal_ip_report(SAMPLE_IP)
    assert result is not None
    assert result["ip"] == SAMPLE_IP
    assert result["verdict"] == "malicious"
    assert result["malicious_votes"] == 10


@patch("src.collectors.api_collector.requests.get")
@patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "fake-key"})
def test_virustotal_handles_request_error(mock_get):
    mock_get.side_effect = Exception("Connection refused")
    result = get_virustotal_ip_report(SAMPLE_IP)
    assert result is None


@patch.dict("os.environ", {}, clear=True)
def test_virustotal_no_api_key():
    result = get_virustotal_ip_report(SAMPLE_IP)
    assert result is None


@patch("src.collectors.api_collector.requests.get")
@patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "fake-key"})
def test_abuseipdb_returns_report(mock_get):
    mock_get.return_value = MagicMock(
        status_code=200,
        json=lambda: {
            "data": {
                "abuseConfidenceScore": 95,
                "totalReports": 320,
                "countryCode": "RU",
                "isp": "FakeISP",
                "isTor": False,
            }
        },
    )
    mock_get.return_value.raise_for_status = MagicMock()

    result = get_abuseipdb_report(SAMPLE_IP)
    assert result is not None
    assert result["abuse_confidence_score"] == 95
    assert result["country"] == "RU"
    assert result["is_tor"] is False


@patch("src.collectors.api_collector.requests.get")
@patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "fake-key"})
def test_abuseipdb_handles_request_error(mock_get):
    mock_get.side_effect = Exception("Timeout")
    result = get_abuseipdb_report(SAMPLE_IP)
    assert result is None


@patch("src.collectors.api_collector.requests.get")
@patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "fake-key"})
def test_get_top_abusive_ips_returns_list(mock_get):
    mock_get.return_value = MagicMock(
        status_code=200,
        json=lambda: {
            "data": [
                {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 100,
                    "totalReports": 500,
                    "countryCode": "CN",
                    "lastReportedAt": "2026-04-19T06:00:00Z",
                }
            ]
        },
    )
    mock_get.return_value.raise_for_status = MagicMock()

    result = get_top_abusive_ips(limit=1)
    assert len(result) == 1
    assert result[0]["ip"] == "1.2.3.4"
    assert result[0]["abuse_confidence_score"] == 100


@patch.dict("os.environ", {}, clear=True)
def test_get_top_abusive_ips_no_api_key():
    result = get_top_abusive_ips()
    assert result == []


@patch("src.collectors.api_collector.get_top_abusive_ips")
def test_collect_all_structure(mock_top_ips):
    mock_top_ips.return_value = []
    result = collect_all()
    assert "top_abusive_ips" in result
    assert isinstance(result["top_abusive_ips"], list)
