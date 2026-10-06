"""OS abstraction layer: the only package that may contain OS-specific logic."""

from jarvis.osal.base import OSAdapter
from jarvis.osal.detect import create_adapter, detect_platform_name
from jarvis.osal.inventory import build_inventory

__all__ = ["OSAdapter", "build_inventory", "create_adapter", "detect_platform_name"]
