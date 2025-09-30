import logging

from typing import Final


APP_VERSION: Final[str] = '0.1.0'
DESCRIPTION: Final[str] = '''
🔍 [bold]ACR - Automated Code Review[/bold]

Your code quality assistant.

[bold]Features:[/bold]
  • Static code analysis
  • Security vulnerability scanning  
  • Code style enforcement
  • Git integration

[bold]Quick start:[/bold]
  [cyan]acr review current[/cyan]    - Analyze current changes
  [cyan]acr install hook[/cyan]      - Set up automatic reviews
  [cyan]acr config init[/cyan]       - Configure for your project
'''


def configure_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        datefmt="%Y-%m-%d %H:%M:%S",
        format="[%(asctime)s.%(msecs)03d] %(funcName)20s %(module)s:%(lineno)d %(levelname)-8s - %(message)s"
    )