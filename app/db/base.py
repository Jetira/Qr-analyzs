"""
Database base configuration and declarative base.
"""
from sqlalchemy.ext.declarative import declarative_base

# SQLAlchemy declarative base
Base = declarative_base()

# Import all models here for Alembic to detect them
# This ensures migrations work correctly
def import_models():
    """Import all models for Alembic."""
    from app.models import scan  # noqa
    # Add more model imports as needed
