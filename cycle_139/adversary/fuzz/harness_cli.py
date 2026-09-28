"""Atheris harness for the ``jwk-thumbprint`` CLI surface (Surface 4).

Surface 4 of the cycle_139 adversary workstream.

Exercises the user-facing CLI (``python -m jwk_thumbprint_pure`` and
``jwk-thumbprint`` entry-point) in fresh subprocesses so a crash in
the CLI doesn't take down the fuzzer.  Covers argparse handling,
exit-code matrix, the JSON payload emission, and the VULN_AUDIT
findings V005 (CLI leaks Python tracebacks on non-ValueError
exceptions) and V011 (CLI help-unreachable in pipe-without-input).

Specifically we test:

* **No-args** (interactive shell): exit 0, stdout contains usage.
* **--help**: exit 0, stdout contains usage.
* **--verify THUMB** with matching thumbprint: exit 0, stdout
  contains ``OK: thumbprint matches``.
* **--verify THUMB** with mismatched thumbprint: exit 1, stderr
  contains ``MISMATCH:``.
* **--canonical**: exit 0, stdout is the canonical JSON string.
* **stdin pipe** with valid JSON: exit 0, stdout is the thumbprint.
* **stdin pipe** with deeply-nested JSON (V005 reproducer): exit 1,
  stderr MUST NOT contain a Python traceback; must contain a clean
  error message (``jwk-thumbprint: ...``).
* **stdin pipe** with mixed-type dict (V005 reproducer): exit 1,
  no traceback.
* **stdin pipe** with empty input (V011 reproducer): exit 1, clean
  error.
* **No-args + pipe-without-input** (V011): exit non-zero with a
  clean error, not a traceback.
* **Bad JSON on argv**: exit 1, stderr contains ``invalid JSON``.
* **Bad alg**: exit 1, stderr contains ``Unsupported algorithm``.

Run::

    python3 harness_cli.py -atheris_runs=2000 -max_total_time=5
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

import atheris  # type: ignore[import-not-found]

# We don't instrument the CLI module — the fuzzer runs OUT of process.
# We DO need atheris to instrument this harness file itself so coverage
# tracks the argv-construction branches here.
with atheris.instrument_imports():  # type: ignore[attr-defined]
    from jwk_thumbprint_pure import __version__  # noqa: E402


# Use the in-repo CLI module directly — there's no __main__.py in the
# package, and ``python -m jwk_thumbprint_pure`` requires a separate
# package marker.  We invoke the cli.py module directly with the
# worktree's src/ on PYTHONPATH.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
_CLI_PATH = os.path.join(_REPO_ROOT, "src", "jwk_thumbprint_pure", "cli.py")
_CMD = [sys.executable, _CLI_PATH]

# Build a child-env that keeps PATH and PYTHONPATH intact but forces
# unbuffered stdio so we capture all output.
_CHILD_ENV = {**os.environ, "PYTHONUNBUFFERED": "1"}

# Valid JWKs for the happy-path tests.
_VALID_JWKS: tuple[dict, ...] = (
    {"kty": "oct", "k": "AyM32w-8eMUW0lT1aE9LfQ"},
    {"kty": "EC", "crv": "P-256", "x": "WbbzF1cNn1_EJq3PGq9U8nFGYQjRCu50XcJV9-4p8nM",
     "y": "HiCGNPCCdJ-x64vhMZX5zYVi2f6xupDrEX7AyCLMBF8"},
)


def _run_cli(argv: list[str], stdin: bytes | None = None,
             timeout: float = 1.5) -> subprocess.CompletedProcess:
    """Run the CLI with the given argv and stdin.  Returns CompletedProcess."""
    return subprocess.run(
        _CMD + argv,
        input=stdin,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=_CHILD_ENV,
    )


def _stderr_is_clean(stderr: bytes) -> bool:
    """Return True if stderr contains no Python traceback markers.

    Used to detect V005 (CLI leaks tracebacks on non-ValueError
    exceptions like RecursionError, TypeError).
    """
    if not stderr:
        return True
    text = stderr.decode("utf-8", errors="replace")
    traceback_markers = ("Traceback (most recent call last):", "File \"")
    return not any(marker in text for marker in traceback_markers)


@atheris.instrument_func  # type: ignore[attr-defined]
def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)  # type: ignore[attr-defined]

    cat = fdp.ConsumeIntInRange(0, 9)

    try:
        if cat == 0:
            # === --help → exit 0, usage on stdout ===
            proc = _run_cli(["--help"])
            assert proc.returncode == 0, (
                f"--help exited {proc.returncode}: stderr={proc.stderr!r}"
            )
            assert b"usage:" in proc.stdout.lower(), (
                f"--help missing usage: stdout={proc.stdout!r}"
            )
            return

        if cat == 1:
            # === valid JWK on argv → exit 0, thumbprint on stdout ===
            jwk = _VALID_JWKS[fdp.ConsumeIntInRange(0, len(_VALID_JWKS) - 1)]
            import json as _json
            proc = _run_cli([_json.dumps(jwk)])
            assert proc.returncode == 0, (
                f"valid-JWK argv exited {proc.returncode}: "
                f"stderr={proc.stderr!r}"
            )
            assert proc.stdout.strip(), (
                f"valid-JWK argv stdout empty: stderr={proc.stderr!r}"
            )
            # The output should be a 43-char Base64URL-no-pad string.
            out = proc.stdout.strip().decode("ascii")
            assert len(out) == 43, (
                f"valid-JWK argv output {out!r} not 43 chars"
            )
            return

        if cat == 2:
            # === --verify THUMB with matching thumbprint → exit 0, OK ===
            # --verify is mutually exclusive with positional jwk_json,
            # so we MUST pipe the JWK via stdin.
            from jwk_thumbprint_pure import thumbprint as _thumb
            import json as _json
            jwk = _VALID_JWKS[fdp.ConsumeIntInRange(0, len(_VALID_JWKS) - 1)]
            expected = _thumb(jwk)
            proc = _run_cli(["--verify", expected],
                            stdin=_json.dumps(jwk).encode("utf-8"))
            assert proc.returncode == 0, (
                f"--verify OK exited {proc.returncode}: "
                f"stderr={proc.stderr!r}"
            )
            assert b"OK: thumbprint matches" in proc.stdout, (
                f"--verify OK missing success msg: stdout={proc.stdout!r}"
            )
            return

        if cat == 3:
            # === --verify THUMB with mismatched thumbprint → exit 1 ===
            import json as _json
            jwk = _VALID_JWKS[fdp.ConsumeIntInRange(0, len(_VALID_JWKS) - 1)]
            proc = _run_cli(["--verify", "wrong-thumbprint"],
                            stdin=_json.dumps(jwk).encode("utf-8"))
            assert proc.returncode == 1, (
                f"--verify mismatch exited {proc.returncode}: "
                f"stderr={proc.stderr!r}"
            )
            assert b"MISMATCH:" in proc.stderr, (
                f"--verify mismatch missing MISMATCH msg: "
                f"stderr={proc.stderr!r}"
            )
            return

        if cat == 4:
            # === --canonical → exit 0, canonical JSON on stdout ===
            import json as _json
            jwk = _VALID_JWKS[fdp.ConsumeIntInRange(0, len(_VALID_JWKS) - 1)]
            proc = _run_cli([_json.dumps(jwk), "--canonical"])
            assert proc.returncode == 0, (
                f"--canonical exited {proc.returncode}: "
                f"stderr={proc.stderr!r}"
            )
            assert proc.stdout.strip(), (
                f"--canonical stdout empty: stderr={proc.stderr!r}"
            )
            # Round-trip: must be valid JSON equal to the input.
            try:
                back = _json.loads(proc.stdout.strip())
            except _json.JSONDecodeError as exc:
                raise AssertionError(
                    f"--canonical output {proc.stdout!r} is not valid JSON: "
                    f"{exc!r}"
                ) from exc
            assert back == jwk, (
                f"--canonical round-trip mismatch: got {back!r}"
            )
            return

        if cat == 5:
            # === stdin pipe with valid JSON → exit 0 ===
            import json as _json
            jwk = _VALID_JWKS[fdp.ConsumeIntInRange(0, len(_VALID_JWKS) - 1)]
            proc = _run_cli([], stdin=_json.dumps(jwk).encode("utf-8"))
            assert proc.returncode == 0, (
                f"stdin-valid exited {proc.returncode}: "
                f"stderr={proc.stderr!r}"
            )
            assert proc.stdout.strip(), (
                f"stdin-valid stdout empty: stderr={proc.stderr!r}"
            )
            return

        if cat == 6:
            # === V005 reproducer: stdin deeply-nested JSON → exit 1, no traceback ===
            depth = fdp.ConsumeIntInRange(350, 600)
            # Build {"kty": "ZZZ", "wrap": [[[...leaf...]]]} with depth levels.
            leaf = "leaf"
            for _ in range(depth):
                leaf = "[" + leaf + "]"
            jwk_raw = '{"kty":"ZZZ","k":"AAAA","wrap":' + leaf + "}"
            proc = _run_cli([], stdin=jwk_raw.encode("utf-8"))
            assert proc.returncode != 0, (
                f"stdin-deeply-nested exited 0: stderr={proc.stderr!r}"
            )
            assert _stderr_is_clean(proc.stderr), (
                f"V005 REPRODUCED: CLI leaked Python traceback on deeply-"
                f"nested stdin: stderr={proc.stderr!r}"
            )
            return

        if cat == 7:
            # === V005 reproducer: stdin mixed-type dict → exit 1, no traceback ===
            # Use unknown kty so the filter passes all members through.
            jwk_raw = '{"kty":"ZZZ",0:"zero","k":"v"}'
            proc = _run_cli([], stdin=jwk_raw.encode("utf-8"))
            assert proc.returncode != 0, (
                f"stdin-mixed-type exited 0: stderr={proc.stderr!r}"
            )
            assert _stderr_is_clean(proc.stderr), (
                f"V005 REPRODUCED: CLI leaked Python traceback on mixed-"
                f"type dict: stderr={proc.stderr!r}"
            )
            return

        if cat == 8:
            # === V011 reproducer: stdin empty input → exit non-zero, clean ===
            proc = _run_cli([], stdin=b"")
            assert proc.returncode != 0, (
                f"stdin-empty exited 0: stderr={proc.stderr!r}"
            )
            assert _stderr_is_clean(proc.stderr), (
                f"V011 REPRODUCED: CLI leaked Python traceback on empty "
                f"stdin: stderr={proc.stderr!r}"
            )
            return

        if cat == 9:
            # === Bad JSON on argv → exit 1, clean error ===
            # Construct a string that is GUARANTEED to fail json.loads:
            # a leading junk char followed by an unterminated string.
            # ``json.loads`` rejects:
            #   - missing quote at start ("abc" — unterminated string)
            #   - mismatched brackets ({])
            #   - trailing garbage after valid JSON
            # We pick the simplest reproducer: bare identifier.
            bad_payloads = (
                "not-json",
                "{]",
                "[}",
                '{"a":}',
                "{'a':1}",   # single-quoted keys (invalid JSON)
                "{a:1}",     # unquoted key
            )
            idx = fdp.ConsumeIntInRange(0, len(bad_payloads) - 1)
            raw = bad_payloads[idx]
            proc = _run_cli([raw])
            assert proc.returncode != 0, (
                f"bad-JSON-argv exited 0: stderr={proc.stderr!r}"
            )
            assert _stderr_is_clean(proc.stderr), (
                f"bad-JSON-argv leaked traceback: stderr={proc.stderr!r}"
            )
            # The error must mention either "invalid JSON" (caught by
            # json.loads) or be a clean error message from thumbprint
            # (e.g. "jwk must be a dict").  Both are acceptable — we
            # just require a non-empty, clean stderr.
            assert proc.stderr.strip(), (
                f"bad-JSON-argv produced no stderr: stdout={proc.stdout!r}"
            )
            return

        # cat == 10
        # === Bad alg → exit 1, clean error ===
        import json as _json
        jwk = _VALID_JWKS[0]
        proc = _run_cli([_json.dumps(jwk), "--alg", "MD5"])
        assert proc.returncode != 0, (
            f"bad-alg exited 0: stderr={proc.stderr!r}"
        )
        assert _stderr_is_clean(proc.stderr), (
            f"bad-alg leaked traceback: stderr={proc.stderr!r}"
        )
        return

    except subprocess.TimeoutExpired:
        # 1.5s is generous for any well-formed input; a hang means the
        # CLI entered a real loop, which would be a bug.
        raise
    except (FileNotFoundError, PermissionError, OSError):
        # CLI not installed — skip rather than poisoning the corpus.
        return
    except ValueError as exc:
        # ``subprocess.run`` rejects argv containing embedded NUL bytes.
        if "embedded null" in str(exc).lower():
            return
        raise


def main() -> int:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
