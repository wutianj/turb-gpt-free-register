"""End-to-end smoke test for the local unlimited Roxy API."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import requests

API_BASE = "http://127.0.0.1:50100"


def main() -> int:
    health = requests.get(f"{API_BASE}/health", timeout=5).json()
    if health.get("code") != 0:
        print("API unhealthy:", health)
        return 1

    create_body = {
        "name": "adapt-e2e",
        "os": "Windows",
        "workspaceId": "90143",
        "projectId": "97471",
    }
    created = requests.post(
        f"{API_BASE}/browser/create", json=create_body, timeout=90
    ).json()
    if created.get("code") != 0 or not created.get("data", {}).get("dirId"):
        print("create failed:", created)
        return 1
    data = created["data"]
    dir_id = data["dirId"]
    print("created dirId:", dir_id)

    opened = requests.post(
        f"{API_BASE}/browser/open",
        json={"dirId": dir_id, "workspaceId": "90143", "forceOpen": True},
        timeout=120,
    ).json()
    if opened.get("code") != 0 or not opened.get("data", {}).get("http"):
        print("open failed:", opened)
        return 1
    http_port = opened["data"]["http"].split(":")[-1]
    version = requests.get(f"http://127.0.0.1:{http_port}/json/version", timeout=5).json()
    print("CDP browser:", version.get("Browser"))

    closed = requests.post(
        f"{API_BASE}/browser/close", json={"dirId": dir_id}, timeout=60
    ).json()
    print("close code:", closed.get("code"))
    deleted = requests.post(
        f"{API_BASE}/browser/delete", json={"dirId": dir_id}, timeout=60
    ).json()
    print("delete code:", deleted.get("code"))
    return 0 if closed.get("code") == 0 and deleted.get("code") == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
