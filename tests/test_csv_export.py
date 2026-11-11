"""CSV exports must emit actual values for both SQLite and PostgreSQL row wrappers."""

import csv
import io
from contextlib import contextmanager

from app.db_backend import PostgreSQLRow


def test_csv_export_handles_postgresql_mapping_rows(system, monkeypatch):
    from app import intelligence

    client, _, _ = system

    class FakeConnection:
        def execute(self, sql):
            assert "FROM observations" in sql
            return [
                PostgreSQLRow(
                    ("ip", "port", "proto", "service", "product", "source", "seen_at"),
                    ("192.0.2.254", 443, "tcp", "https", "Fixture Server", "pg-csv-fixture", "2026-11-11T20:00:00Z"),
                )
            ]

    @contextmanager
    def fake_connection():
        yield FakeConnection()

    monkeypatch.setattr(intelligence, "connection", fake_connection)
    response = client.get("/api/reports/export.csv")
    assert response.status_code == 200, response.text
    assert list(csv.DictReader(io.StringIO(response.text))) == [
        {
            "ip": "192.0.2.254",
            "port": "443",
            "protocol": "tcp",
            "service": "https",
            "product": "Fixture Server",
            "source": "pg-csv-fixture",
            "observed_at": "2026-11-11T20:00:00Z",
        }
    ]


def test_csv_export_includes_imported_observations(system, admin_headers):
    client, _, _ = system
    imported = client.post(
        "/api/admin/import",
        headers=admin_headers,
        json={
            "provenance": "csv-export-fixture",
            "observations": [
                {
                    "ip": "192.0.2.250",
                    "port": 8443,
                    "service": "https",
                    "product": "ExampleServer",
                    "banner": "synthetic-test-only",
                    "observed_at": "2026-11-11T19:42:00Z",
                }
            ],
        },
    )
    assert imported.status_code == 200, imported.text

    response = client.get("/api/reports/export.csv")
    assert response.status_code == 200, response.text
    rows = list(csv.DictReader(io.StringIO(response.text)))
    matching = [r for r in rows if r["ip"] == "192.0.2.250" and r["source"] == "csv-export-fixture"]
    assert len(matching) == 1
    row = matching[0]
    assert row["port"] == "8443"
    assert row["protocol"] == "tcp"
    assert row["service"] == "https"
    assert row["product"] == "ExampleServer"
    assert row["observed_at"] == "2026-11-11T19:42:00Z"
