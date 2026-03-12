# Contributing to fastapi-mcp

Thank you for taking the time to contribute! 🎉

## Development setup

```bash
git clone https://github.com/YOUR_USERNAME/fastapi-mcp
cd fastapi-mcp
uv sync --extra dev
```

## Running tests

```bash
uv run pytest                    # run all tests
uv run pytest -v                 # verbose output
uv run pytest tests/test_parser.py   # single file
```

## Code style

This project uses **ruff** for linting and formatting:

```bash
uv run ruff check .      # lint
uv run ruff format .     # auto-format
```

## Submitting a pull request

1. Fork the repo and create a feature branch: `git checkout -b feat/my-feature`
2. Write tests for your change
3. Ensure `pytest` and `ruff check .` both pass
4. Ensure type checks pass: `mypy fastapi_mcp`
5. Open a PR against `main` with a clear description

## Reporting issues

Please include:
- Python version (`python --version`)
- fastapi-mcp version (`uv run python -c "import fastapi_mcp; print(fastapi_mcp.__version__)"`)
- Minimal reproducible example
- Full traceback
