"""The `ensure_closed` monkeypatch must survive an aiomysql upgrade.

`database.py::_patch_aiomysql` replaces `aiomysql.Connection.ensure_closed` to swallow
RuntimeError from an already-dead TCP transport. That happens when the shared host closes
an idle connection (`wait_timeout`) while SQLAlchemy still holds a reference: SQLAlchemy
calls `ensure_closed()` from pool-cleanup paths that do NOT route through the
`handle_error` event, so the error propagates to the caller instead of being handled.

**Why this needs its own test.** The patch is applied inside a `try/except ImportError`,
so if it ever stopped attaching it would do so SILENTLY - the app would import fine and
fail later, intermittently, only under connection churn on a shared host. Verifying it
after every aiomysql bump was a manual step in Spec 6 §1.1; this makes it automatic.

Deliberately no `mysql` marker: it needs no database, only the installed package.
"""

import inspect

import aiomysql


class TestTheEnsureClosedPatchStillApplies:
    def test_the_upstream_method_exists_and_is_async(self):
        """If upstream renamed or desugared it, the patch would target nothing."""
        import app.database  # noqa: F401 - importing triggers the patch

        method = aiomysql.Connection.ensure_closed
        assert callable(method)
        assert inspect.iscoroutinefunction(method), (
            "ensure_closed is no longer a coroutine, so `await`ing it would fail"
        )

    def test_the_patch_actually_replaced_the_original(self):
        """The failure mode this guards is silence, so assert the substitution happened."""
        import app.database  # noqa: F401

        method = aiomysql.Connection.ensure_closed
        assert "_safe_ensure_closed" in getattr(method, "__qualname__", ""), (
            f"ensure_closed is {method.__qualname__!r}, not the patched wrapper. The "
            "try/except ImportError in _patch_aiomysql swallows failures, so this would "
            "otherwise surface only as intermittent RuntimeErrors under connection churn."
        )

    def test_the_upstream_signature_is_still_self_only(self):
        """A new required argument would break every pool-cleanup call site.

        The replacement is defined as `async def _safe_ensure_closed(self)`. If upstream
        added a parameter, SQLAlchemy would call it with an argument the patch cannot
        accept, and the TypeError would surface from pool teardown.
        """
        import app.database  # noqa: F401

        signature = str(inspect.signature(aiomysql.Connection.ensure_closed))
        assert signature == "(self)", (
            f"the patched ensure_closed signature is {signature}, not '(self)'. Check "
            "whether upstream changed it -- per Spec 6, report rather than rewriting the "
            "patch."
        )

    def test_the_patched_version_is_recorded(self):
        """A bump should be a deliberate act with the patch re-verified against it."""
        import pathlib

        requirements = (pathlib.Path(__file__).resolve().parents[1]
                        / "requirements.txt").read_text(encoding="utf-8")
        assert f"aiomysql=={aiomysql.__version__}" in requirements, (
            f"installed aiomysql is {aiomysql.__version__} but requirements.txt pins a "
            "different version. The patch is verified against the pinned one, so these "
            "must agree."
        )
