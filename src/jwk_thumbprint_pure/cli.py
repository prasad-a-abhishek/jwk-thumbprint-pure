"""
CLI for jwk-thumbprint-pure.

Usage:
    jwk-thumbprint '{"kty":"RSA","n":"...","e":"..."}'
    echo '{"kty":"EC",...}' | jwk-thumbprint
    jwk-thumbprint --verify THUMBPRINT '{"kty":"oct","k":"..."}'
"""

import argparse
import json
import sys

from jwk_thumbprint_pure.thumbprint import thumbprint, verify


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="jwk-thumbprint",
        description="Compute or verify RFC 7638 JWK Thumbprints.",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "jwk_json",
        nargs="?",
        default=None,
        help="JWK as a JSON string on the command line.",
    )
    group.add_argument(
        "--verify",
        dest="expected_thumbprint",
        metavar="THUMBPRINT",
        help="Verify the computed thumbprint matches this expected value.",
    )
    parser.add_argument(
        "--alg",
        default="SHA-256",
        help="Hash algorithm (default: SHA-256, RFC 7638 only defines SHA-256).",
    )
    parser.add_argument(
        "--canonical",
        action="store_true",
        help="Output the RFC 8785 canonical JSON instead of the thumbprint.",
    )

    args = parser.parse_args()

    # Read JWK from stdin or argument
    if args.jwk_json is not None:
        jwk_raw = args.jwk_json
    elif not sys.stdin.isatty():
        jwk_raw = sys.stdin.read()
    else:
        parser.print_help()
        return 0

    try:
        jwk = json.loads(jwk_raw)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"jwk-thumbprint: invalid JSON: {e}\n")
        return 1

    try:
        if args.canonical:
            from jwk_thumbprint_pure.canonical import canonical_json
            sys.stdout.write(canonical_json(jwk) + "\n")
        else:
            t = thumbprint(jwk, args.alg)
            if args.expected_thumbprint is not None:
                ok = verify(jwk, args.expected_thumbprint, args.alg)
                if ok:
                    sys.stdout.write("OK: thumbprint matches\n")
                    return 0
                else:
                    sys.stderr.write(f"MISMATCH: computed={t} expected={args.expected_thumbprint}\n")
                    return 1
            else:
                sys.stdout.write(t + "\n")
                return 0
    except ValueError as e:
        sys.stderr.write(f"jwk-thumbprint: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
