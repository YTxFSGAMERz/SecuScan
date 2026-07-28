import os
from backend.secuscan.core.magic_signatures import MAGIC_SIGNATURES, FileSpoofingAlert

def analyze_file(filepath: str):
    """
    Analyzes a file by checking its magic signature to prevent extension spoofing.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    ext = os.path.splitext(filepath)[1].lower()
    
    with open(filepath, 'rb') as f:
        header = f.read(8)
        
    actual_type = None
    for sig, (mime, desc) in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            actual_type = desc
            break
            
    # Simple check for spoofing an executable as an image or text
    if actual_type in ('Windows Executable (PE)', 'Linux Executable (ELF)'):
        if ext in ('.txt', '.jpg', '.png', '.pdf'):
            raise FileSpoofingAlert(
                f"[CRITICAL] {filepath} extension ({ext}) does not match binary signature ({actual_type}). Quarantining file!"
            )
            
    return actual_type or "Unknown"
