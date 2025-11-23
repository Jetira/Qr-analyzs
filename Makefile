# QR Güvenlik Servisi - Makefile
# Local development setup and runtime commands
#
# SETUP INSTRUCTIONS:
# 1. Install Python 3.11+ on your system
# 2. Run: make venv
# 3. Activate venv:
#    - Linux/macOS: source .venv/bin/activate
#    - Windows (PowerShell): .venv\Scripts\Activate.ps1
#    - Windows (CMD): .venv\Scripts\activate.bat
# 4. Run: make install
# 5. Copy .env.example to .env and configure your settings
# 6. Ensure PostgreSQL is running with the database created
# 7. Run: make run

.PHONY: venv install run lint test clean help

# Default Python executable
PYTHON := python3
VENV := .venv
VENV_PYTHON := $(VENV)/bin/python
VENV_PIP := $(VENV)/bin/pip

# For Windows compatibility
ifeq ($(OS),Windows_NT)
	VENV_PYTHON := $(VENV)/Scripts/python.exe
	VENV_PIP := $(VENV)/Scripts/pip.exe
endif

help:
	@echo "QR Güvenlik Servisi - Available Commands:"
	@echo "  make venv       Create Python virtual environment"
	@echo "  make install    Install all dependencies"
	@echo "  make run        Run the FastAPI application"
	@echo "  make lint       Run code linting (if configured)"
	@echo "  make test       Run tests (placeholder)"
	@echo "  make clean      Remove virtual environment and cache files"
	@echo ""
	@echo "Setup workflow:"
	@echo "  1. make venv"
	@echo "  2. Activate venv (source .venv/bin/activate)"
	@echo "  3. make install"
	@echo "  4. Configure .env file"
	@echo "  5. make run"

venv:
	@echo "Creating virtual environment..."
	$(PYTHON) -m venv $(VENV)
	@echo "Virtual environment created in $(VENV)"
	@echo "Activate it with:"
	@echo "  - Linux/macOS: source .venv/bin/activate"
	@echo "  - Windows (PowerShell): .venv\\Scripts\\Activate.ps1"

install:
	@echo "Installing dependencies..."
	$(VENV_PIP) install --upgrade pip
	$(VENV_PIP) install -r requirements.txt
	@echo "Dependencies installed successfully!"

run:
	@echo "Starting QR Güvenlik Servisi..."
	@echo "API docs will be available at: http://localhost:8000/docs"
	$(VENV_PYTHON) -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

lint:
	@echo "Linting code (placeholder - install ruff or flake8 if needed)"
	# $(VENV_PYTHON) -m ruff check app/

test:
	@echo "Running tests (placeholder - implement tests as needed)"
	# $(VENV_PYTHON) -m pytest tests/

clean:
	@echo "Cleaning up..."
	rm -rf $(VENV)
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "Cleanup complete!"
