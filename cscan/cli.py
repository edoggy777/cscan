#!/usr/bin/env python3
"""
C Source Code Vulnerability Scanner - CLI Entry Point
Analyzes C source code for memory safety and security vulnerabilities
"""

import os
import re
import sys
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability found in C code"""
    finding_id: str
    vulnerability_type: str
    severity: str
    confidence: float
    file_path: str
    line_number: int
    function_name: str
    code_snippet: str
    description: str
    recommendation: str
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class CSourceScanner:
    """Main C source code vulnerability scanner"""
    
    def __init__(self, confidence_threshold: float = 0.75):
        self.confidence_threshold = confidence_threshold
        self.findings = []
        self.files_analyzed = 0
        self.functions_analyzed = 0
        
    def scan_file(self, file_path: str) -> List[VulnerabilityFinding]:
        """Scan a single C file"""
        logger.info(f"📄 Scanning: {file_path}")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
        
        findings = []
        
        # Initialize analyzers
        buffer_analyzer = BufferOverflowDetector(file_path, content, lines)
        memory_analyzer = MemoryLeakDetector(file_path, content, lines)
        pointer_analyzer = PointerSafetyAnalyzer(file_path, content, lines)
        format_analyzer = FormatStringDetector(file_path, content, lines)
        array_analyzer = ArrayBoundsChecker(file_path, content, lines)
        
        # Run all analyzers
        findings.extend(buffer_analyzer.analyze())
        findings.extend(memory_analyzer.analyze())
        findings.extend(pointer_analyzer.analyze())
        findings.extend(format_analyzer.analyze())
        findings.extend(array_analyzer.analyze())
        
        # Filter by confidence
        high_confidence = [f for f in findings if f.confidence >= self.confidence_threshold]
        
        self.findings.extend(high_confidence)
        self.files_analyzed += 1
        
        return high_confidence
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[VulnerabilityFinding]:
        """Scan all C files in a directory"""
        logger.info(f"📁 Scanning directory: {directory}")
        
        c_files = []
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith(('.c', '.h')):
                        c_files.append(os.path.join(root, file))
        else:
            for file in os.listdir(directory):
                if file.endswith(('.c', '.h')):
                    c_files.append(os.path.join(directory, file))
        
        logger.info(f"Found {len(c_files)} C/header files")
        
        for c_file in c_files:
            try:
                self.scan_file(c_file)
            except Exception as e:
                logger.error(f"Error scanning {c_file}: {e}")
        
        return self.findings
    
    def generate_report(self, output_file: str = None) -> str:
        """Generate vulnerability report"""
        if not output_file:
            output_file = f"c_vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            'metadata': {
                'scan_time': datetime.now().isoformat(),
                'scanner_version': '1.2.0',
                'files_analyzed': self.files_analyzed,
                'total_findings': len(self.findings),
                'confidence_threshold': self.confidence_threshold
            },
            'findings': [f.to_dict() for f in self.findings],
            'summary': self._generate_summary()
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"📊 Report saved: {output_file}")
        return output_file
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        by_file = defaultdict(int)
        
        for finding in self.findings:
            by_severity[finding.severity] += 1
            by_type[finding.vulnerability_type] += 1
            by_file[finding.file_path] += 1
        
        return {
            'by_severity': dict(by_severity),
            'by_type': dict(by_type),
            'by_file': dict(by_file)
        }

class BufferOverflowDetector:
    """Detects buffer overflow vulnerabilities"""
    
    def __init__(self, file_path: str, content: str, lines: List[str]):
        self.file_path = file_path
        self.content = content
        self.lines = lines
        self.findings = []
        self.buffer_sizes = self._extract_buffer_sizes()
        
        self.unsafe_functions = {
            'strcpy': {
                'description': 'Unsafe string copy without bounds checking',
                'recommendation': 'Use strncpy() or strlcpy() with proper size limits',
                'severity': 'CRITICAL',
                'cwe': 'CWE-120'
            },
            'strcat': {
                'description': 'Unsafe string concatenation without bounds checking',
                'recommendation': 'Use strncat() with proper size limits',
                'severity': 'CRITICAL',
                'cwe': 'CWE-120'
            },
            'gets': {
                'description': 'Extremely dangerous function with no bounds checking',
                'recommendation': 'Use fgets() instead with size limit',
                'severity': 'CRITICAL',
                'cwe': 'CWE-120'
            },
            'sprintf': {
                'description': 'Unsafe formatted string without bounds checking',
                'recommendation': 'Use snprintf() with buffer size',
                'severity': 'HIGH',
                'cwe': 'CWE-120'
            },
            'vsprintf': {
                'description': 'Unsafe variadic formatted string',
                'recommendation': 'Use vsnprintf() with buffer size',
                'severity': 'HIGH',
                'cwe': 'CWE-120'
            },
            'scanf': {
                'description': 'Unsafe input without size limits',
                'recommendation': 'Use fgets() or specify field width in format',
                'severity': 'HIGH',
                'cwe': 'CWE-120'
            },
            'memcpy': {
                'description': 'Memory copy that may overflow if size is incorrect',
                'recommendation': 'Validate size parameter against destination buffer',
                'severity': 'HIGH',
                'cwe': 'CWE-120'
            }
        }
    
    def _extract_buffer_sizes(self) -> Dict[str, int]:
        """Extract buffer size declarations from code"""
        buffer_sizes = {}
        
        for line in self.lines:
            match = re.search(r'char\s+(\w+)\s*\[\s*(\d+)\s*\]', line)
            if match:
                buffer_name = match.group(1)
                size = int(match.group(2))
                buffer_sizes[buffer_name] = size
            
            match = re.search(r'char\s+(\w+)\s*\[\s*(\d+)\s*\]\s*;', line)
            if match:
                buffer_name = match.group(1)
                size = int(match.group(2))
                buffer_sizes[buffer_name] = size
        
        return buffer_sizes
    
    def analyze(self) -> List[VulnerabilityFinding]:
        """Analyze for buffer overflow vulnerabilities"""
        for func_name, func_info in self.unsafe_functions.items():
            self._detect_unsafe_function(func_name, func_info)
        
        return self.findings
    
    def _detect_unsafe_function(self, func_name: str, func_info: Dict[str, str]):
        """Detect usage of unsafe function"""
        pattern = rf'\b{func_name}\s*\('
        
        for line_num, line in enumerate(self.lines, 1):
            if re.match(r'^\s*//', line) or re.match(r'^\s*/\*', line):
                continue
            
            if re.search(pattern, line):
                function_name = self._get_enclosing_function(line_num)
                code_snippet = self._get_code_snippet(line_num, context=2)
                confidence = self._calculate_confidence(func_name, line, line_num)
                
                if confidence < 0.5:
                    continue
                
                self.findings.append(VulnerabilityFinding(
                    finding_id=f"BUF_{func_name.upper()}_{line_num}",
                    vulnerability_type="Buffer Overflow",
                    severity=func_info['severity'],
                    confidence=confidence,
                    file_path=self.file_path,
                    line_number=line_num,
                    function_name=function_name,
                    code_snippet=code_snippet,
                    description=f"Unsafe function '{func_name}()': {func_info['description']}",
                    recommendation=func_info['recommendation'],
                    cwe_id=func_info['cwe']
                ))
    
    def _calculate_confidence(self, func_name: str, line: str, line_num: int) -> float:
        """Calculate confidence score based on context"""
        confidence = 0.85
        
        context = self._get_surrounding_lines(line_num, 3)
        
        if any('sizeof' in ctx_line for ctx_line in context):
            confidence = 0.65
        
        if any('strlen' in ctx_line for ctx_line in context):
            confidence = 0.70
        
        if func_name == 'gets':
            return 1.0
        
        if func_name in ['strcpy', 'strcat']:
            match = re.search(rf'{func_name}\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)', line)
            if match:
                dest = match.group(1).strip()
                src = match.group(2).strip()
                
                if src.startswith('"') and src.endswith('"'):
                    string_content = src[1:-1]
                    string_content = string_content.replace('\\n', '\n')
                    string_content = string_content.replace('\\t', '\t')
                    string_content = string_content.replace('\\\\', '\\')
                    string_content = string_content.replace('\\"', '"')
                    src_length = len(string_content) + 1
                    
                    dest_clean = dest.strip().split('[')[0].split('.')[0].split('->')[0]
                    
                    dest_size = None
                    if dest_clean in self.buffer_sizes:
                        dest_size = self.buffer_sizes[dest_clean]
                    else:
                        member_match = re.search(r'\.(\w+)$', dest) or re.search(r'->(\w+)$', dest)
                        if member_match:
                            member_name = member_match.group(1)
                            if member_name in self.buffer_sizes:
                                dest_size = self.buffer_sizes[member_name]
                    
                    if dest_size is not None:
                        if src_length <= dest_size:
                            return 0.3
                        else:
                            return 1.0
        
        return confidence
    
    def _get_enclosing_function(self, line_num: int) -> str:
        """Find the function containing this line"""
        for i in range(line_num - 1, max(0, line_num - 100), -1):
            line = self.lines[i]
            match = re.search(r'\b(\w+)\s*\([^)]*\)\s*\{', line)
            if match:
                return match.group(1)
        return "unknown"
    
    def _get_code_snippet(self, line_num: int, context: int = 2) -> str:
        """Get code snippet with context lines"""
        start = max(0, line_num - context - 1)
        end = min(len(self.lines), line_num + context)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{prefix}{i+1:4d} | {self.lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def _get_surrounding_lines(self, line_num: int, context: int) -> List[str]:
        """Get surrounding lines for context analysis"""
        start = max(0, line_num - context - 1)
        end = min(len(self.lines), line_num + context)
        return self.lines[start:end]

class MemoryLeakDetector:
    """Detects memory leak vulnerabilities"""
    
    def __init__(self, file_path: str, content: str, lines: List[str]):
        self.file_path = file_path
        self.content = content
        self.lines = lines
        self.findings = []
    
    def analyze(self) -> List[VulnerabilityFinding]:
        """Analyze for memory leaks"""
        functions = self._extract_functions()
        
        for func_name, func_lines, start_line in functions:
            self._analyze_function_memory(func_name, func_lines, start_line)
        
        return self.findings
    
    def _extract_functions(self) -> List[Tuple[str, List[str], int]]:
        """Extract functions from source code"""
        functions = []
        current_func = None
        func_lines = []
        func_start = 0
        brace_count = 0
        
        for line_num, line in enumerate(self.lines, 1):
            if re.match(r'^\s*(/\*|//|#)', line):
                continue
            
            if current_func is None:
                match = re.search(r'\b(\w+)\s*\([^)]*\)\s*\{', line)
                if match:
                    current_func = match.group(1)
                    func_start = line_num
                    func_lines = [line]
                    brace_count = line.count('{') - line.count('}')
            else:
                func_lines.append(line)
                brace_count += line.count('{') - line.count('}')
                
                if brace_count == 0:
                    functions.append((current_func, func_lines, func_start))
                    current_func = None
                    func_lines = []
        
        return functions
    
    def _analyze_function_memory(self, func_name: str, func_lines: List[str], start_line: int):
        """Analyze a function for memory leaks"""
        func_code = '\n'.join(func_lines)
        
        alloc_pattern = r'\b(malloc|calloc|realloc)\s*\('
        free_pattern = r'\bfree\s*\('
        
        alloc_count = len(re.findall(alloc_pattern, func_code))
        free_count = len(re.findall(free_pattern, func_code))
        
        if alloc_count > 0:
            for i, line in enumerate(func_lines):
                if re.search(alloc_pattern, line):
                    remaining_code = '\n'.join(func_lines[i:])
                    
                    var_match = re.search(r'(\w+)\s*=\s*(?:malloc|calloc|realloc)', line)
                    if var_match:
                        var_name = var_match.group(1)
                        
                        if f'free({var_name})' not in remaining_code and f'free ({var_name})' not in remaining_code:
                            if 'return' in remaining_code:
                                line_num = start_line + i
                                
                                self.findings.append(VulnerabilityFinding(
                                    finding_id=f"LEAK_{func_name}_{line_num}",
                                    vulnerability_type="Memory Leak",
                                    severity="HIGH",
                                    confidence=0.80,
                                    file_path=self.file_path,
                                    line_number=line_num,
                                    function_name=func_name,
                                    code_snippet=self._get_code_snippet(line_num, 3),
                                    description=f"Allocated memory in variable '{var_name}' may not be freed on all paths",
                                    recommendation="Ensure free() is called on all code paths, including error paths",
                                    cwe_id="CWE-401"
                                ))
        
        if alloc_count > free_count and alloc_count > 0:
            for i, line in enumerate(func_lines):
                if re.search(alloc_pattern, line):
                    line_num = start_line + i
                    
                    self.findings.append(VulnerabilityFinding(
                        finding_id=f"LEAK_IMBALANCE_{func_name}_{line_num}",
                        vulnerability_type="Memory Leak",
                        severity="MEDIUM",
                        confidence=0.70,
                        file_path=self.file_path,
                        line_number=line_num,
                        function_name=func_name,
                        code_snippet=self._get_code_snippet(line_num, 2),
                        description=f"Function has {alloc_count} allocation(s) but only {free_count} free(s)",
                        recommendation="Verify all allocated memory is properly freed",
                        cwe_id="CWE-401"
                    ))
                    break
    
    def _get_code_snippet(self, line_num: int, context: int) -> str:
        """Get code snippet around line number"""
        start = max(0, line_num - context - 1)
        end = min(len(self.lines), line_num + context)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{prefix}{i+1:4d} | {self.lines[i]}")
        
        return '\n'.join(snippet_lines)

class PointerSafetyAnalyzer:
    """Analyzes pointer usage for safety issues"""
    
    def __init__(self, file_path: str, content: str, lines: List[str]):
        self.file_path = file_path
        self.content = content
        self.lines = lines
        self.findings = []
    
    def analyze(self) -> List[VulnerabilityFinding]:
        """Analyze pointer safety"""
        self._detect_use_after_free()
        self._detect_double_free()
        self._detect_null_pointer_deref()
        
        return self.findings
    
    def _detect_use_after_free(self):
        """Detect use-after-free vulnerabilities"""
        functions = self._extract_functions_uaf()
        
        for func_name, func_lines, start_line in functions:
            self._analyze_function_uaf(func_name, func_lines, start_line)
    
    def _extract_functions_uaf(self) -> List[Tuple[str, List[Tuple[int, str]], int]]:
        """Extract functions with their line numbers for UAF analysis"""
        functions = []
        current_func = None
        func_lines = []
        func_start = 0
        brace_count = 0
        
        for line_num, line in enumerate(self.lines, 1):
            if re.match(r'^\s*(/\*|//|#)', line):
                continue
            
            if current_func is None:
                match = re.search(r'\b(\w+)\s*\([^)]*\)\s*\{', line)
                if match:
                    current_func = match.group(1)
                    func_start = line_num
                    func_lines = [(line_num, line)]
                    brace_count = line.count('{') - line.count('}')
            else:
                func_lines.append((line_num, line))
                brace_count += line.count('{') - line.count('}')
                
                if brace_count == 0:
                    functions.append((current_func, func_lines, func_start))
                    current_func = None
                    func_lines = []
        
        return functions
    
    def _analyze_function_uaf(self, func_name: str, func_lines: List[Tuple[int, str]], start_line: int):
        """Analyze a single function for use-after-free bugs"""
        freed_vars = {}
        malloc_vars = set()
        
        for line_num, line in func_lines:
            if re.match(r'^\s*//', line):
                continue
            
            malloc_match = re.search(r'(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(', line)
            if malloc_match:
                var_name = malloc_match.group(1)
                malloc_vars.add(var_name)
            
            free_match = re.search(r'free\s*\(\s*(\w+)\s*\)', line)
            if free_match:
                var_name = free_match.group(1)
                if var_name in malloc_vars:
                    freed_vars[var_name] = line_num
            
            for freed_var, freed_line in list(freed_vars.items()):
                if freed_var in line and 'free' not in line:
                    if re.search(rf'\*{freed_var}|{freed_var}\s*->', line) or \
                       re.search(rf'{freed_var}\s*\[', line) or \
                       re.search(rf'\b{freed_var}\s*\(', line):
                        
                        self.findings.append(VulnerabilityFinding(
                            finding_id=f"UAF_{freed_var}_{line_num}",
                            vulnerability_type="Use After Free",
                            severity="CRITICAL",
                            confidence=0.85,
                            file_path=self.file_path,
                            line_number=line_num,
                            function_name=func_name,
                            code_snippet=self._get_code_snippet(line_num, 3),
                            description=f"Variable '{freed_var}' used after being freed at line {freed_line}",
                            recommendation="Set pointer to NULL after free() and check before use",
                            cwe_id="CWE-416"
                        ))
                
                if re.search(rf'{freed_var}\s*=', line) and 'free' not in line:
                    del freed_vars[freed_var]
                    if 'malloc' in line or 'calloc' in line or 'realloc' in line:
                        malloc_vars.add(freed_var)
    
    def _detect_double_free(self):
        """Detect double free vulnerabilities"""
        freed_vars = {}
        
        for line_num, line in enumerate(self.lines, 1):
            if re.match(r'^\s*//', line):
                continue
            
            free_match = re.search(r'free\s*\(\s*(\w+)\s*\)', line)
            if free_match:
                var_name = free_match.group(1)
                
                if var_name in freed_vars:
                    function_name = self._get_enclosing_function(line_num)
                    first_free = freed_vars[var_name]
                    
                    self.findings.append(VulnerabilityFinding(
                        finding_id=f"DBL_FREE_{var_name}_{line_num}",
                        vulnerability_type="Double Free",
                        severity="CRITICAL",
                        confidence=0.90,
                        file_path=self.file_path,
                        line_number=line_num,
                        function_name=function_name,
                        code_snippet=self._get_code_snippet(line_num, 3),
                        description=f"Variable '{var_name}' freed twice (first at line {first_free})",
                        recommendation="Set pointer to NULL after first free()",
                        cwe_id="CWE-415"
                    ))
                else:
                    freed_vars[var_name] = line_num
            
            for var_name in list(freed_vars.keys()):
                if re.search(rf'{var_name}\s*=(?!=)', line) and 'free' not in line:
                    del freed_vars[var_name]
    
    def _detect_null_pointer_deref(self):
        """Detect potential null pointer dereferences"""
        for line_num, line in enumerate(self.lines, 1):
            deref_patterns = [
                r'(\w+)\s*->',
                r'\*\s*(\w+)',
                r'(\w+)\s*\['
            ]
            
            for pattern in deref_patterns:
                match = re.search(pattern, line)
                if match:
                    var_name = match.group(1)
                    
                    context_lines = self._get_surrounding_lines(line_num, 5)
                    has_null_check = any(
                        re.search(rf'{var_name}\s*(!= NULL|== NULL|!{var_name})', ctx)
                        for ctx in context_lines
                    )
                    
                    if not has_null_check:
                        is_from_alloc = any(
                            re.search(rf'{var_name}\s*=\s*(malloc|calloc)', ctx)
                            for ctx in context_lines
                        )
                        
                        if is_from_alloc:
                            function_name = self._get_enclosing_function(line_num)
                            
                            self.findings.append(VulnerabilityFinding(
                                finding_id=f"NULL_DEREF_{var_name}_{line_num}",
                                vulnerability_type="Null Pointer Dereference",
                                severity="HIGH",
                                confidence=0.75,
                                file_path=self.file_path,
                                line_number=line_num,
                                function_name=function_name,
                                code_snippet=self._get_code_snippet(line_num, 2),
                                description=f"Pointer '{var_name}' dereferenced without NULL check",
                                recommendation="Check if pointer is NULL before dereferencing",
                                cwe_id="CWE-476"
                            ))
                            break
    
    def _get_enclosing_function(self, line_num: int) -> str:
        """Find enclosing function name"""
        for i in range(line_num - 1, max(0, line_num - 100), -1):
            match = re.search(r'\b(\w+)\s*\([^)]*\)\s*\{', self.lines[i])
            if match:
                return match.group(1)
        return "unknown"
    
    def _get_code_snippet(self, line_num: int, context: int) -> str:
        """Get code snippet"""
        start = max(0, line_num - context - 1)
        end = min(len(self.lines), line_num + context)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{prefix}{i+1:4d} | {self.lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def _get_surrounding_lines(self, line_num: int, context: int) -> List[str]:
        """Get surrounding lines"""
        start = max(0, line_num - context - 1)
        end = min(len(self.lines), line_num + context)
        return self.lines[start:end]

class FormatStringDetector:
    """Detects format string vulnerabilities"""
    
    def __init__(self, file_path: str, content: str, lines: List[str]):
        self.file_path = file_path
        self.content = content
        self.lines = lines
        self.findings = []
    
    def analyze(self) -> List[VulnerabilityFinding]:
        """Analyze for format string vulnerabilities"""
        format_functions = ['printf', 'fprintf', 'sprintf', 'snprintf', 'syslog']
        
        for line_num, line in enumerate(self.lines, 1):
            for func in format_functions:
                pattern = rf'{func}\s*\(\s*(\w+)\s*\)'
                match = re.search(pattern, line)
                
                if match:
                    var_name = match.group(1)
                    
                    if not re.search(rf'{func}\s*\(\s*"', line):
                        function_name = self._get_enclosing_function(line_num)
                        
                        self.findings.append(VulnerabilityFinding(
                            finding_id=f"FMT_STR_{func}_{line_num}",
                            vulnerability_type="Format String Vulnerability",
                            severity="HIGH",
                            confidence=0.85,
                            file_path=self.file_path,
                            line_number=line_num,
                            function_name=function_name,
                            code_snippet=self._get_code_snippet(line_num, 2),
                            description=f"Format string from variable in {func}() call",
                            recommendation=f"Use {func}(\"%s\", {var_name}) to prevent format string attacks",
                            cwe_id="CWE-134"
                        ))
        
        return self.findings
    
    def _get_enclosing_function(self, line_num: int) -> str:
        """Find enclosing function"""
        for i in range(line_num - 1, max(0, line_num - 100), -1):
            match = re.search(r'\b(\w+)\s*\([^)]*\)\s*\{', self.lines[i])
            if match:
                return match.group(1)
        return "unknown"
    
    def _get_code_snippet(self, line_num: int, context: int) -> str:
        """Get code snippet"""
        start = max(0, line_num - context - 1)
        end = min(len(self.lines), line_num + context)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{prefix}{i+1:4d} | {self.lines[i]}")
        
        return '\n'.join(snippet_lines)

class ArrayBoundsChecker:
    """Checks array bounds violations"""
    
    def __init__(self, file_path: str, content: str, lines: List[str]):
        self.file_path = file_path
        self.content = content
        self.lines = lines
        self.findings = []
        self.array_sizes = {}
    
    def analyze(self) -> List[VulnerabilityFinding]:
        """Analyze array bounds"""
        self._find_array_declarations()
        self._check_array_accesses()
        
        return self.findings
    
    def _find_array_declarations(self):
        """Find array declarations and their sizes"""
        for line in self.lines:
            match = re.search(r'\b(int|char|float|double|long|short)\s+(\w+)\s*\[\s*(\d+)\s*\]\s*[;=]', line)
            if match:
                array_name = match.group(2)
                array_size = int(match.group(3))
                self.array_sizes[array_name] = array_size
            
            match = re.search(r'\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]\s*;', line)
            if match:
                array_name = match.group(1)
                array_size = int(match.group(2))
                self.array_sizes[array_name] = array_size
    
    def _check_array_accesses(self):
        """Check for out-of-bounds array accesses"""
        for line_num, line in enumerate(self.lines, 1):
            if re.search(r'\b(int|char|float|double|long|short|struct)\s+\w+\s*\[\s*\d+\s*\]', line):
                continue
            
            for array_name, array_size in self.array_sizes.items():
                pattern = rf'\b{array_name}\s*\[\s*(\d+|0x[0-9a-fA-F]+)\s*\]'
                matches = re.finditer(pattern, line)
                
                for match in matches:
                    line_before_match = line[:match.start()]
                    if re.search(r'\b(int|char|float|double|long|short|struct)\s+$', line_before_match):
                        continue
                    
                    index_str = match.group(1)
                    
                    try:
                        if index_str.startswith('0x'):
                            index = int(index_str, 16)
                        else:
                            index = int(index_str)
                        
                        if index >= array_size:
                            function_name = self._get_enclosing_function(line_num)
                            
                            self.findings.append(VulnerabilityFinding(
                                finding_id=f"BOUNDS_{array_name}_{line_num}",
                                vulnerability_type="Array Out of Bounds",
                                severity="HIGH",
                                confidence=1.0,
                                file_path=self.file_path,
                                line_number=line_num,
                                function_name=function_name,
                                code_snippet=self._get_code_snippet(line_num, 2),
                                description=f"Array '{array_name}' accessed at index {index}, but size is {array_size}",
                                recommendation="Check array index is within bounds",
                                cwe_id="CWE-125"
                            ))
                    except ValueError:
                        pass
                
                if f'{array_name}[' in line and ('for' in line or 'while' in line):
                    if re.search(r'\b(int|char|float|double|long|short|struct)\s+', line):
                        continue
                    
                    context = self._get_surrounding_lines(line_num, 3)
                    has_bounds_check = any(
                        re.search(rf'<\s*{array_size}|<=\s*{array_size-1}', ctx)
                        for ctx in context
                    )
                    
                    if not has_bounds_check:
                        function_name = self._get_enclosing_function(line_num)
                        
                        self.findings.append(VulnerabilityFinding(
                            finding_id=f"LOOP_BOUNDS_{array_name}_{line_num}",
                            vulnerability_type="Potential Array Out of Bounds in Loop",
                            severity="MEDIUM",
                            confidence=0.70,
                            file_path=self.file_path,
                            line_number=line_num,
                            function_name=function_name,
                            code_snippet=self._get_code_snippet(line_num, 3),
                            description=f"Loop accessing array '{array_name}' without visible bounds check",
                            recommendation=f"Ensure loop condition limits index to < {array_size}",
                            cwe_id="CWE-125"
                        ))
    
    def _get_enclosing_function(self, line_num: int) -> str:
        """Find enclosing function"""
        for i in range(line_num - 1, max(0, line_num - 100), -1):
            match = re.search(r'\b(\w+)\s*\([^)]*\)\s*\{', self.lines[i])
            if match:
                return match.group(1)
        return "unknown"
    
    def _get_code_snippet(self, line_num: int, context: int) -> str:
        """Get code snippet"""
        start = max(0, line_num - context - 1)
        end = min(len(self.lines), line_num + context)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{prefix}{i+1:4d} | {self.lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def _get_surrounding_lines(self, line_num: int, context: int) -> List[str]:
        """Get surrounding lines"""
        start = max(0, line_num - context - 1)
        end = min(len(self.lines), line_num + context)
        return self.lines[start:end]


def main():
    """Main CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='C Source Code Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cscan scan vulnerable.c
  cscan scan src/ --recursive
  cscan scan main.c --confidence 0.8 --output report.json
        """
    )
    
    parser.add_argument('command', choices=['scan'], help='Command to execute')
    parser.add_argument('target', help='C file or directory to scan')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Recursively scan directory')
    parser.add_argument('-c', '--confidence', type=float, default=0.75,
                       help='Minimum confidence threshold (0.0-1.0)')
    parser.add_argument('-o', '--output', help='Output report file')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    scanner = CSourceScanner(confidence_threshold=args.confidence)
    
    if os.path.isfile(args.target):
        findings = scanner.scan_file(args.target)
    elif os.path.isdir(args.target):
        findings = scanner.scan_directory(args.target, recursive=args.recursive)
    else:
        print(f"Error: {args.target} not found")
        return 1
    
    print(f"\n{'='*60}")
    print(f"SCAN RESULTS")
    print(f"{'='*60}")
    print(f"Files analyzed: {scanner.files_analyzed}")
    print(f"Vulnerabilities found: {len(findings)}")
    
    if findings:
        print(f"\n{'='*60}")
        print("VULNERABILITIES FOUND:")
        print(f"{'='*60}\n")
        
        by_severity = defaultdict(list)
        for finding in findings:
            by_severity[finding.severity].append(finding)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                print(f"\n{severity} SEVERITY ({len(by_severity[severity])} findings):")
                print("-" * 60)
                
                for finding in by_severity[severity]:
                    print(f"\n[{finding.vulnerability_type}] {finding.file_path}:{finding.line_number}")
                    print(f"Function: {finding.function_name}")
                    print(f"Confidence: {finding.confidence:.0%}")
                    print(f"Description: {finding.description}")
                    print(f"Recommendation: {finding.recommendation}")
                    if finding.cwe_id:
                        print(f"CWE: {finding.cwe_id}")
                    print(f"\nCode:")
                    print(finding.code_snippet)
                    print()
    else:
        print("\n✅ No vulnerabilities found!")
    
    if args.output:
        report_file = scanner.generate_report(args.output)
        print(f"\n📊 Detailed report saved to: {report_file}")
    
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
