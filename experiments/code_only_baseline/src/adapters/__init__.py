"""Verified native adapters plus explicit user-defined field mappings."""
from .base import Adaptation, AdapterOptions
from .primevul import PrimeVulAdapter
from .megavul import MegaVulAdapter
from .mapped import MappedAdapter


def get_adapter(name, options, mapping=None):
    if name == "primevul":
        return PrimeVulAdapter(options)
    if name == "megavul":
        return MegaVulAdapter(options)
    if name == "mapped":
        return MappedAdapter(options, mapping)
    raise ValueError(f"unsupported adapter {name}; use an explicit verified field mapping")
