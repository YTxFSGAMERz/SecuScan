## Summary
This PR introduces a robust, defense-in-depth layer to the file analysis engine to prevent attackers from bypassing security checks by spoofing malicious payloads with benign file extensions (e.g., renaming an `.exe` to `.pdf`).

## Architectural Changes
- **Core Signatures (`backend/secuscan/core/magic_signatures.py`)**: Created a centralized mapping of cryptographic hex headers (such as `MZ`, `\x7fELF`, and `%PDF`) to their true MIME types.
- **File Analyzer (`backend/secuscan/scanners/file_analyzer.py`)**: Added an inspection layer that reads the first 8 bytes of an analyzed file in binary mode. If the true signature indicates an executable but the extension suggests a benign file (like `.txt` or `.jpg`), the engine immediately raises a `FileSpoofingAlert` and quarantines the file.
- **Tests (`testing/backend/test_magic_verification.py`)**: Added unit tests to verify the quarantine protocol correctly traps mocked ELF binaries disguised as `.txt` files while allowing legitimate PDFs to pass.

*Note: Submitted as part of GirlScript Summer of Code (GSSoC) 2026.*
