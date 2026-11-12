"""The MySQL tier must FAIL, not skip, when the server answers and refuses the login.

`mysql_engine` skipped on any connection error. When the local credentials changed from
sentinel to wiestell (2026-11-12), every developer whose volume predated the change got
"Access denied" and the whole tier reported as skipped with "container unreachable",
which reads as a pass. These run in the default tier, so they need no database.
"""

import pymysql
import pytest
import sqlalchemy.exc

from tests.conftest_mysql import REFUSED_BY_SERVER, mysql_error_code


def _wrapped(code, message):
    """How the error actually arrives: pymysql's, wrapped by SQLAlchemy."""
    return sqlalchemy.exc.OperationalError("SELECT 1", {}, pymysql.err.OperationalError(code, message))


@pytest.mark.parametrize(
    "code, message",
    [
        (1045, "Access denied for user 'root'@'172.19.0.1' (using password: YES)"),
        (1044, "Access denied for user 'wiestell'@'%' to database 'wiestell_test'"),
        (1049, "Unknown database 'wiestell_test'"),
    ],
)
def test_a_refusal_by_the_server_is_classified_as_refused(code, message):
    assert mysql_error_code(_wrapped(code, message)) in REFUSED_BY_SERVER


@pytest.mark.parametrize(
    "exc",
    [
        _wrapped(2003, "Can't connect to MySQL server on '127.0.0.1' ([Errno 111] refused)"),
        _wrapped(2013, "Lost connection to MySQL server during query"),
        ConnectionRefusedError(111, "Connection refused"),
        RuntimeError("no numeric code at all"),
    ],
)
def test_an_unreachable_server_still_skips(exc):
    """A developer without Docker must keep a green default run."""
    assert mysql_error_code(exc) not in REFUSED_BY_SERVER
