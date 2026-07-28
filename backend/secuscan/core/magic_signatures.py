MAGIC_SIGNATURES = {
    b'MZ': ('application/x-msdownload', 'Windows Executable (PE)'),
    b'\x7fELF': ('application/x-executable', 'Linux Executable (ELF)'),
    b'PK\x03\x04': ('application/zip', 'ZIP Archive / Office Open XML'),
    b'%PDF': ('application/pdf', 'PDF Document'),
    b'\xff\xd8\xff': ('image/jpeg', 'JPEG Image'),
    b'\x89PNG\r\n\x1a\n': ('image/png', 'PNG Image')
}

class FileSpoofingAlert(Exception):
    pass
