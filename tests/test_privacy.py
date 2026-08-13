"""The load-bearing privacy invariant.

engine.py's module docstring states it plainly: "Nothing here logs clipboard
content. Findings carry offsets and rule ids only." This file is what enforces
that promise — across scanning, redaction, and every log record either emits,
at any level, the literal secret text must never appear.
"""

from __future__ import annotations

import dataclasses
import logging

import pytest

from safepaste.detector import Detector, Finding
from safepaste.redactor import redact

SECRET = "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"
TEXT = f"AWS_SECRET_ACCESS_KEY={SECRET}"


def test_secret_never_appears_in_logs(
    detector: Detector, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="safepaste")

    findings = detector.scan(TEXT)
    assert findings  # sanity: we actually planted a detectable secret
    redact(TEXT, findings)

    # This must not be vacuous: confirm records were actually captured before
    # trusting their absence of the secret.
    assert caplog.records, "expected scan()/redact() to emit at least one log record"

    for record in caplog.records:
        assert SECRET not in record.getMessage()
    assert SECRET not in caplog.text  # the fully formatted output too


def test_secret_never_appears_in_finding_repr(detector: Detector) -> None:
    findings = detector.scan(TEXT)
    assert findings
    for f in findings:
        assert SECRET not in repr(f)


def test_finding_has_no_attribute_holding_the_secret_text(detector: Detector) -> None:
    findings: list[Finding] = detector.scan(TEXT)
    assert findings
    for f in findings:
        for field in dataclasses.fields(f):
            value = getattr(f, field.name)
            # Findings carry offsets (int) and rule/label/category metadata
            # (short fixed strings) only — never a slice of the scanned text.
            assert value != SECRET
            if isinstance(value, str):
                assert SECRET not in value
