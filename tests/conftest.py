import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROUTING = {
    "uac": {"site": "UAC", "universite": "UAC", "subnet": "10.24.0.0/16",
            "pfsense_url": "https://10.24.112.34:10443",
            "pfsense_alias": "authorized_clients",
            "api_key_secret": "pfsense-key-uac", "theme": "uac"},
    "up": {"site": "UP", "universite": "UP", "subnet": "10.25.0.0/16",
           "pfsense_url": "https://10.25.112.34:10443",
           "pfsense_alias": "authorized_clients",
           "api_key_secret": "pfsense-key-up", "theme": "up"},
}


@pytest.fixture()
def routing(tmp_path):
    from app.config import CampusRouting
    path = tmp_path / "routing.json"
    path.write_text(json.dumps(ROUTING))
    return CampusRouting(str(path))


@pytest.fixture()
def redis():
    import fakeredis.aioredis
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture()
def settings():
    from app.config import Settings
    return Settings(trusted_proxies="10.42.0.0/16,127.0.0.1/32",
                    session_ttl=3600, arp_cache_ttl=45,
                    campus_lock_ttl_ms=2000, rate_limit_per_minute=5)
