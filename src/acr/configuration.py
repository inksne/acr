import logging

from typing import Final


APP_VERSION: Final[str] = '0.1.2'

MAX_LINES_FUNCTION: Final[int] = 50
MAX_COMPLEXITY: Final[int] = 10

DEFAULT_MAX_LINE_LENGTH: Final[int] = 100
DEFAULT_OUTPUT_FORMAT: Final[str] = 'text'
DEFAULT_FILES_ANALYZED: Final[int] = 0
DEFAULT_TOTAL_ISSUES: Final[int] = 0
DEFAULT_DURATION: Final[float] = 0.0

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