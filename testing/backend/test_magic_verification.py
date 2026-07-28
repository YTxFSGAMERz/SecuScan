import os
import pytest
from backend.secuscan.scanners.file_analyzer import analyze_file, FileSpoofingAlert

def test_elf_disguised_as_txt(tmp_path):
    # Create a mock ELF binary
    fake_payload = tmp_path / "harmless.txt"
    with open(fake_payload, 'wb') as f:
        f.write(b'\x7fELF\x01\x01\x01\x00' + b'\x00' * 16)
        
    with pytest.raises(FileSpoofingAlert) as exc:
        analyze_file(str(fake_payload))
        
    assert "harmless.txt extension (.txt) does not match binary signature (Linux Executable (ELF))" in str(exc.value)

def test_legitimate_pdf(tmp_path):
    legit_pdf = tmp_path / "document.pdf"
    with open(legit_pdf, 'wb') as f:
        f.write(b'%PDF-1.4\n' + b'\x00' * 16)
        
    result = analyze_file(str(legit_pdf))
    assert result == "PDF Document"
