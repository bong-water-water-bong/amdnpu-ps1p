"""ps1p - AMD NPU $PS1p firmware container parser/extractor."""

__version__ = "0.1.0"
__all__ = [
    "PS1pContainer",
    "PS1pHeader",
    "PartitionTable",
    "PartitionEntry",
    "BlobAnalyzer",
    "parse_ps1p",
    "open_ps1p",
]

# Submodules will be created in later tasks.
# Lazy imports to allow scaffolding to exist without all modules.
def __getattr__(name):
    import importlib
    module_map = {
        "PS1pContainer": "ps1p.container",
        "open_ps1p": "ps1p.container",
        "parse_ps1p": "ps1p.container",
        "PS1pHeader": "ps1p.header",
        "PartitionTable": "ps1p.partition",
        "PartitionEntry": "ps1p.partition",
        "BlobAnalyzer": "ps1p.blob",
    }
    if name in module_map:
        mod = importlib.import_module(module_map[name])
        return getattr(mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
