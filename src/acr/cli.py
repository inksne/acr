import typer
from rich.console import Console

import sys

from .configuration import APP_VERSION, DESCRIPTION

from .foo import app as foo_app



app = typer.Typer(name='reviewbot', help=DESCRIPTION, no_args_is_help=True, rich_markup_mode='rich')

app.add_typer(foo_app)

console = Console()


@app.callback(invoke_without_command=True)
def callback(ctx: typer.Context, version: bool = typer.Option(False, '--version', '-v', help='Show version and exit')):
    if version:
        console.print(f'ACR {APP_VERSION}')
        raise typer.Exit()

    if not version and ctx.invoked_subcommand is None:
        console.print('Use [bold]--help[/bold] to view available commands.')
        raise typer.Exit(1)

    if sys.version_info < (3, 8):
        console.print('Python [bold]3.8[/bold] or higher required.')
        raise typer.Exit(1)


if __name__ == '__main__':
    app()