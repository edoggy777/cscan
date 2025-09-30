CScan – C Source Code Vulnerability Scanner
===========================================

CScan is a command-line tool for analyzing C source code for memory safety
and security vulnerabilities, including buffer overflows, memory leaks,
use-after-free, null pointer dereferences, format string vulnerabilities,
and array bounds violations.

Features
--------

- Scan single C files or entire directories recursively
- Detects high-risk vulnerabilities with confidence scoring
- Generates detailed JSON reports
- CLI flags for custom confidence thresholds and output files
- Supports verbose output for debugging

Installation
------------

Install via PyPI (or TestPyPI for testing):

    pip install cscan

Usage
-----

Scan a single file:

    cscan scan vulnerable.c

Scan a directory recursively with custom confidence threshold:

    cscan scan src/ --recursive --confidence 0.8 --output report.json

Enable verbose output:

    cscan scan src/ -v

Output
------

- Prints vulnerabilities to the terminal, grouped by severity
- Generates JSON report (if --output specified) with:
  - Metadata (scan time, scanner version, files analyzed)
  - Findings (detailed per-vulnerability information)
  - Summary statistics by severity, type, and file

Example
-------

CRITICAL SEVERITY (2 findings):
------------------------------------------------------------
[Buffer Overflow] example.c:42
Function: copy_input
Confidence: 100%
Description: Unsafe function 'strcpy()' without bounds checking
Recommendation: Use strncpy() with proper size limits
CWE: CWE-120

[Use After Free] example.c:78
Function: cleanup
Confidence: 85%
Description: Variable 'ptr' used after being freed
Recommendation: Set pointer to NULL after free()
CWE: CWE-416

License
-------

MIT License © 2025 Evan Kirtz

