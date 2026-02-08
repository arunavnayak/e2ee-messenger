import os
import threading
import time

import psutil
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": time.time()}


@router.get("/system-status")
def get_system_status():
    process = psutil.Process(os.getpid())
    mem_mb = process.memory_info().rss / (1024 * 1024)

    return {
        "memory": {
            "used_mb": round(mem_mb, 2),
            "limit_mb": 512,
            "utilization": f"{(mem_mb / 512) * 100:.1f}%"
        },
        "cpu_percent": process.cpu_percent(interval=0.1),
        "threads": threading.active_count()
    }
