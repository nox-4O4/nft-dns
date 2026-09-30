from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import List


@dataclass
class ModelEntry:
    set_name: str
    fqdn: str
    family: str
    typeof: int
    table: str
    ip_list: List[str]
    ttl: int | None
    rr_dns: bool
    next_update: datetime.datetime | None
