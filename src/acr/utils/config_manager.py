from rich.console import Console
from rich.panel import Panel
from pathlib import Path
from typing import Any
import yaml

from .helpers import get_main_table, get_rules_table
from ..core import ReviewConfig, Rule, SeverityLevel



def _config_to_dict(config: ReviewConfig) -> dict[str, Any]:
    """Convert ReviewConfig to dictionary for serialization."""
    return {
        "rules": {
            rule_id: {
                "enabled": rule.enabled,
                "severity": rule.severity.value,
                "parameters": rule.parameters
            }
            for rule_id, rule in config.rules.items()
        },
        "ignore_patterns": config.ignore_patterns,
        "exclude_paths": config.exclude_paths,
        "max_line_length": config.max_line_length,
        "strict": config.strict,
        "output_format": config.output_format
    }


def _dict_to_config(data: dict[str, Any]) -> ReviewConfig:
    """Convert dictionary to ReviewConfig object."""
    rules: dict[str, Any] = {}


    for rule_id, rule_data in data.get("rules", {}).items():
        rules[rule_id] = Rule(
            id=rule_id,
            name=rule_data.get("name", rule_id.replace("_", " ").title()),
            description=rule_data.get("description", ""),
            enabled=rule_data.get("enabled", True),
            severity=SeverityLevel(rule_data.get("severity", "warning")),
            parameters=rule_data.get("parameters", {})
        )

    return ReviewConfig(
        rules=rules,
        ignore_patterns=data.get("ignore_patterns", []),
        exclude_paths=data.get("exclude_paths", []),
        max_line_length=data.get("max_line_length", 100),
        strict=data.get("strict", False),
        output_format=data.get("output_format", "text")
    )


def load_config(config_path: Path) -> ReviewConfig:
    """Load configuration from YAML file."""
    if not config_path.exists():
        return ReviewConfig()

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f) or {}

        return _dict_to_config(config_data)

    except (yaml.YAMLError, KeyError, ValueError) as e:
        raise ValueError(f"Invalid configuration file {config_path}: {e}")


def save_config(config: ReviewConfig, config_path: Path) -> None:
    """Save configuration to YAML file."""
    config_data = _config_to_dict(config)

    # Ensure directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with open(config_path, 'w', encoding='utf-8') as f:
        yaml.dump(config_data, f, default_flow_style=False, indent=2)


def update_config_value(config_path: Path, key_path: str, value: Any) -> None:
    """Update specific configuration value."""
    config = load_config(config_path)

    # Convert key path like "rules.magic_number.enabled" to nested dict access
    keys = key_path.split('.')
    current = _config_to_dict(config)

    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]

    current[keys[-1]] = value


    updated_config = _dict_to_config(_config_to_dict(config))
    save_config(updated_config, config_path)


def show_config(config: ReviewConfig) -> None:
    """Display current configuration in a formatted way."""

    console = Console()

    main_table = get_main_table(config)

    console.print(Panel(main_table, title="⚙️ [bold]Main Settings[/bold]"))


    rules_table = get_rules_table(config)

    console.print(Panel(rules_table, title="📋 [bold]Rules Configuration[/bold]"))


    if config.ignore_patterns or config.exclude_paths:
        ignore_panel = Panel(
            "\n".join([
                "[bold]Ignore Patterns:[/bold]",
                *[f"  • {pattern}" for pattern in config.ignore_patterns],
                "\n[bold]Exclude Paths:[/bold]",
                *[f"  • {path}" for path in config.exclude_paths]
            ]),
            title="🚫 [bold]Ignored Paths[/bold]"
        )

        console.print(ignore_panel)


def create_default_config(config_path: Path) -> None:
    """Create default configuration file."""
    default_config = ReviewConfig()

    save_config(default_config, config_path)


def validate_config(config_path: Path) -> bool:
    """Validate configuration file."""
    try:
        load_config(config_path)
        return True

    except ValueError:
        return False