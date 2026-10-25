# Bundled wordlist policy

## What ships with v2

The package and Docker image include only `utils/wordlists/common_secrets.txt`, a
small six-entry starter list intended for smoke tests and quick, authorized checks.
It is not a comprehensive password corpus and does not imply exhaustive coverage.

No larger wordlist is downloaded or bundled automatically. This keeps package and
image contents reviewable and avoids silently adding third-party corpus licensing,
provenance, size, or integrity risks.

## Supplying a larger list

A larger list is an operator-controlled opt-in. Supply it explicitly with
`--wordlist /path/to/authorized-list.txt`, or deliberately set
`JWT_ANALYZER_WORDLIST_PATH`. Only use data you are authorized to test. Treat custom
wordlists as sensitive files and do not commit them to the repository or include
their contents in reports or logs.

Any future larger built-in corpus must be versioned, reviewed for provenance and
licensing, and accompanied by a committed SHA-256 checksum manifest that CI verifies
before package or image creation.
