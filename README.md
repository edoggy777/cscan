C Source Code Vulnerability Scanner

A static analysis tool that detects memory safety and security vulnerabilities in C source code. 
Identifies buffer overflows, memory leaks, use-after-free bugs, null pointer dereferences, format string vulnerabilities, and array bounds violations.
Provides detailed reports with exact line numbers, code snippets, and remediation recommendations.
Designed for security researchers, developers, and bug bounty hunters analyzing C programs.

Quick Usage

Scan a single C file
python3 c_scanner.py scan vulnerable.c

Scan a directory recursively
python3 c_scanner.py scan src/ --recursive

Generate JSON report
python3 c_scanner.py scan program.c --output report.json

Adjust confidence threshold (0.0-1.0)
python3 c_scanner.py scan code.c --confidence 0.85

Verbose output
python3 c_scanner.py scan file.c --verbose

What It Detects

| Vulnerability Type | Severity | Example |
|-------------------|----------|---------|
| Buffer Overflow | CRITICAL | `strcpy()`, `gets()`, `sprintf()` |
| Memory Leak | HIGH | `malloc()` without `free()` |
| Use After Free | CRITICAL | Using pointer after `free()` |
| Double Free | CRITICAL | Calling `free()` twice on same pointer |
| Null Pointer Deref | HIGH | Dereferencing without NULL check |
| Format String | HIGH | `printf(user_input)` |
| Array Out of Bounds | HIGH | Accessing beyond array size |

Installation

**Requirements**: Python 3.8+

No additional dependencies required
python3 c_scanner.py scan --help
```

Example Output

```
============================================================
SCAN RESULTS
============================================================
Files analyzed: 1
Vulnerabilities found: 8

CRITICAL SEVERITY (3 findings):
------------------------------------------------------------

[Buffer Overflow] vulnerable.c:12
Function: unsafe_copy
Confidence: 85%
Description: Unsafe function 'strcpy()': Unsafe string copy without bounds checking
Recommendation: Use strncpy() or strlcpy() with proper size limits
CWE: CWE-120

Code:
      10 | void unsafe_copy(char* input) {
      11 |     char buffer[100];
>>>   12 |     strcpy(buffer, input);
      13 |     printf("%s\n", buffer);
      14 | }

[Use After Free] vulnerable.c:28
Function: memory_bug
Confidence: 85%
Description: Variable 'ptr' used after being freed
Recommendation: Set pointer to NULL after free() and check before use
CWE: CWE-416

Code:
      26 |     free(ptr);
      27 |     
>>>   28 |     strcpy(ptr, "data");
      29 | }
```

## Test File

python3 c_scanner.py scan vuln.c
