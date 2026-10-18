"""Personal roles and their group memberships (plan §0 and §4 step 9).

Creating a user's personal role *fully* -- credentials, sessions -- is M1; the
permission model only needs the role to exist with the right attributes and
memberships:

* :func:`ensure_user_role`: create ``u_<user_id>`` as ``LOGIN INHERIT`` if it
  does not exist, fix an existing ``NOINHERIT`` role and make sure it is an
  inheriting member of ``gw_managed``. One transaction, idempotent.
* :func:`sync_user_memberships`: make the role a member of exactly the ``g_*``
  roles that OpenFGA says it should belong to.
* :func:`on_session_start`: both, under the per-connection lock, for M1's
  session code to call when a user's session begins.

Everything runs as the connection's admin account, which owns the
prerequisites in ``docs/target-db-setup.md`` (``CREATEROLE`` and ``ADMIN
OPTION`` on ``gw_managed``). A missing privilege fails the call and is
reported; nothing is worked around (plan §9).
"""

from db_gateway.provisioner.roles import (
    ensure_user_role,
    on_session_start,
    sync_user_memberships,
)

__all__ = ["ensure_user_role", "on_session_start", "sync_user_memberships"]
