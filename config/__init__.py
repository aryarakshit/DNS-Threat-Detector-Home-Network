"""Configuration loader for DNS DGA Threat Detector."""
from pathlib import Path
import yaml

CONFIG_PATH = Path(__file__).resolve().parent / "detector_config.yaml"

def load_config(config_path: Path | str | None = None) -> dict:
    """Load detector configuration from YAML."""
    path = Path(config_path) if config_path else CONFIG_PATH
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

__all__ = ["load_config", "CONFIG_PATH"]
