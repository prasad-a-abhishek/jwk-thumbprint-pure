# Changelog
All notable changes to this project are documented here.

## [0.1.1] - 2026-09-28
### Fixed
- **verify()** now catches `RecursionError` and returns `False` instead of leaking the exception (closes F-003 + F-004 V002 RecursionError DoS findings from cycle_139/@repo-adversary).

## [0.1.0] - 2026-09-28
### Added
- Initial release. Pure-Python RFC 7638 JWK Thumbprint (SHA-256 + RFC 8785 JCS canonical JSON), zero dependencies. 147/147 tests passing.
