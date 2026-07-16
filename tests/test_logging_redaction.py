"""
Handler-level token redaction tests (CONF-03).

Every test proves BOTH that the redacted output IS present (non-empty,
"***REDACTED***" visible) AND that the secret is absent. A caplog-only
test could pass vacuously because setup_logging() clears pytest's own
capture handler (root_logger.handlers.clear()) -- so these tests read
REAL handler output: a StringIO StreamHandler with a fresh
TokenRedactionFilter for unit-level cases, and a real file handler
created by setup_logging() for the propagation/idempotency cases.
"""

import io
import logging
import threading

from src.fortigate_mcp.config.models import LoggingConfig
from src.fortigate_mcp.core.logging import (
    TokenRedactionFilter,
    get_logger,
    register_secrets,
    setup_logging,
)


def _stringio_logger(name, secrets=None):
    """Throwaway logger + StringIO handler with a FRESH TokenRedactionFilter
    instance (never the module-level shared instance) so unit tests never
    pollute each other's secret registries."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.handlers.clear()

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    filt = TokenRedactionFilter()
    if secrets:
        filt.register(secrets)
    handler.addFilter(filt)
    logger.addHandler(handler)

    return logger, stream


def test_bare_known_secret_redacted_in_handler_output():
    """Bare secret -- no "Bearer" word anywhere -- proves known-secret
    replacement independently of the Bearer regex."""
    logger, stream = _stringio_logger(
        "test.redaction.bare", secrets={"test-token-not-real"}
    )

    logger.error("password is test-token-not-real")

    out = stream.getvalue()
    assert out != ""
    assert "***REDACTED***" in out
    assert "test-token-not-real" not in out


def test_bearer_pattern_redacted_without_registry():
    """Empty registry -- proves the Bearer pattern independently of the
    known-secrets set."""
    logger, stream = _stringio_logger("test.redaction.bearer")

    logger.error("header was Authorization: Bearer some-unregistered-token")

    out = stream.getvalue()
    assert out != ""
    assert "Bearer ***REDACTED***" in out
    assert "some-unregistered-token" not in out


def test_unrelated_message_untouched():
    """An unrelated message passes through byte-identical."""
    logger, stream = _stringio_logger(
        "test.redaction.unrelated", secrets={"test-token-not-real"}
    )

    logger.error("Device connected successfully")

    out = stream.getvalue()
    assert "Device connected successfully" in out


def test_setup_logging_redacts_propagated_child_records_via_file_handler(tmp_path):
    """The propagation case the root-logger design missed: a filter placed
    on the root LOGGER never sees records emitted by a child logger like
    get_logger("tools...") -- only ancestor HANDLERS receive propagated
    records directly. Proven against a REAL setup_logging()-created file
    handler, not caplog."""
    log_file = tmp_path / "test.log"
    setup_logging(
        LoggingConfig(level="INFO", console=False, file=str(log_file)),
        secrets={"test-token-not-real"},
    )

    child_logger = get_logger("tools.testcomponent")
    child_logger.error("device auth failed with token test-token-not-real")

    for handler in logging.getLogger().handlers:
        handler.flush()

    content = log_file.read_text()
    assert content != ""
    assert "***REDACTED***" in content
    assert "test-token-not-real" not in content


def test_exception_traceback_redacted():
    """A secret embedded in an exception message must not leak through the
    appended traceback (record.exc_text scrubbing)."""
    logger, stream = _stringio_logger(
        "test.redaction.traceback", secrets={"test-token-not-real"}
    )

    try:
        raise RuntimeError("boom test-token-not-real")
    except RuntimeError:
        logger.error("request failed", exc_info=True)

    out = stream.getvalue()
    assert out != ""
    assert "Traceback" in out
    assert "***REDACTED***" in out
    assert "test-token-not-real" not in out


def test_register_secrets_after_setup(tmp_path):
    """register_secrets() called AFTER setup_logging() still redacts
    subsequent log lines (mutable registry)."""
    log_file = tmp_path / "late.log"
    setup_logging(LoggingConfig(level="INFO", console=False, file=str(log_file)))

    register_secrets({"late-registered-token-not-real"})

    child_logger = get_logger("tools.lateregistration")
    child_logger.error("token was late-registered-token-not-real")

    for handler in logging.getLogger().handlers:
        handler.flush()

    content = log_file.read_text()
    assert content != ""
    assert "***REDACTED***" in content
    assert "late-registered-token-not-real" not in content


def test_setup_logging_idempotent_no_filter_accumulation(tmp_path):
    """Repeated setup_logging() calls do not accumulate filters on a
    handler, and a secret registered before the second call still
    redacts after it (module-level shared filter instance, not a
    per-call new one)."""
    log_file = tmp_path / "idempotent.log"
    config = LoggingConfig(level="INFO", console=False, file=str(log_file))

    setup_logging(config)
    register_secrets({"idempotent-token-not-real"})
    setup_logging(config)

    root_logger = logging.getLogger()
    assert root_logger.handlers, "expected at least one handler after setup_logging"
    for handler in root_logger.handlers:
        filter_count = sum(
            isinstance(f, TokenRedactionFilter) for f in handler.filters
        )
        assert filter_count == 1

    child_logger = get_logger("tools.idempotency")
    child_logger.error("token was idempotent-token-not-real")

    for handler in root_logger.handlers:
        handler.flush()

    content = log_file.read_text()
    assert content != ""
    assert "***REDACTED***" in content
    assert "idempotent-token-not-real" not in content


def test_concurrent_register_and_filter_never_raises():
    """CR-02 regression: register() must never mutate the live `_secrets`
    set in place while filter() (called on every log record, on any
    thread) is iterating a snapshot of it via scrub_secrets(). Reproduces
    the exact concurrent-writer / concurrent-reader pattern that raised
    `RuntimeError: Set changed size during iteration` before the fix."""
    filt = TokenRedactionFilter()
    errors = []

    def writer():
        for i in range(500):
            filt.register({f"concurrent-secret-{i}"})

    def reader():
        record = logging.LogRecord(
            "test.redaction.concurrent", logging.INFO, __file__, 1,
            "background log line during registration churn", None, None,
        )
        for _ in range(500):
            try:
                filt.filter(record)
            except Exception as exc:  # pragma: no cover - failure path only
                errors.append(str(exc))

    threads = [threading.Thread(target=writer) for _ in range(2)]
    threads += [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
