"""Manual target PostgreSQL setup checks."""

from db_gateway.targetdb.check import SETUP_VERSION, Problem, check_target_db

__all__ = ["Problem", "SETUP_VERSION", "check_target_db"]
