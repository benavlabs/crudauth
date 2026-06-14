"""Guard against LOGICAL_FIELDS drift.

The registration-gating set (REGISTRATION_GATED_FIELDS = LOGICAL_FIELDS -
ALLOWED) and the hook projection (to_dict iterates LOGICAL_FIELDS) both *trust*
LOGICAL_FIELDS to be complete. The field-name strings are a deliberate public
contract (adopters write them in column_map / register_extra_fields), so they
stay as literals - but the literals and LOGICAL_FIELDS must not drift into two
independent copies. These tests make drift fail CI instead of silently dropping
a field from gating / the hook contract.
"""

from __future__ import annotations

import pathlib
import re

from crudauth.constants import LOGICAL_FIELDS
from crudauth.models.mixin import AuthUserMixin

# Mixin columns that are audit metadata, not part of the logical contract.
_NON_CONTRACT_COLUMNS = {"created_at", "updated_at"}

# Field name passed by literal to a repository accessor, on any ``repo``-suffixed
# receiver (``self`` inside the repo; ``ctx.repo``/``runtime.repo``/``self.repo``
# elsewhere):
#   .get(obj, "name" ...) | .set_field(obj, "name" ...) | .has/col/_attr("name")
_ACCESSOR_RE = re.compile(
    r'(?:self|repo)\.(?:get|set_field)\(\s*\w+,\s*"([a-z0-9_]+)"'
    r'|(?:self|repo)\.(?:has|col|_attr)\(\s*"([a-z0-9_]+)"'
)


def test_logical_fields_match_auth_user_mixin() -> None:
    # AuthUserMixin is the canonical shipped model; LOGICAL_FIELDS must be exactly
    # its contract columns so a column added to the mixin can't be silently
    # missing from gating / the hook contract (and vice versa).
    mixin_columns = set(AuthUserMixin.__annotations__) - _NON_CONTRACT_COLUMNS
    assert set(LOGICAL_FIELDS) == mixin_columns


def test_repo_accessor_literals_are_declared() -> None:
    # every logical-field name read/written by literal through a repo accessor -
    # anywhere in the package, not just repository.py - must be declared in
    # LOGICAL_FIELDS, or to_dict() and the gating set silently skip it (e.g. a
    # field typo'd straight into a transport).
    import crudauth

    root = pathlib.Path(crudauth.__file__).parent
    used: set[str] = set()
    for path in root.rglob("*.py"):
        used |= {a or b for a, b in _ACCESSOR_RE.findall(path.read_text())}
    undeclared = used - set(LOGICAL_FIELDS)
    assert undeclared == set(), (
        f"repo accessors reference logical fields absent from LOGICAL_FIELDS: {sorted(undeclared)}"
    )
