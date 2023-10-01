import os
import sys
import win32api
import win32file
import win32security
import pywintypes

#### Requires pywin32 
def get_assembly_info(dll_path):
    try:
        # Get the file version information
        version_info = win32api.GetFileVersionInfo(dll_path, "\\")

        # Extract assembly information with fallback values
        assembly_keys = ['ProductName', 'FileDescription', 'FileVersion', 'LegalCopyright', 'CompanyName','OriginalFilename','InternalName']

        # Default language and code page values (English, United States)
        language, code_page = 0x0409, 0x04B0

        for key in assembly_keys:
            try:
                value = win32api.GetFileVersionInfo(dll_path,
                                                    '\\StringFileInfo\\{:04X}{:04X}\\{}'.format(language, code_page,
                                                                                                key))
            except pywintypes.error:
                value = 'N/A'

            print(key + ': ' + value)

    except pywintypes.error as e:
        print('Error: {}'.format(e))


def get_signature_info(dll_path):
    try:
        # Get the file's digital signature information
        file_info = win32security.GetFileSecurity(dll_path, win32security.OWNER_SECURITY_INFORMATION)
        owner_sid = file_info.GetSecurityDescriptorOwner()
        owner_name, _, _ = win32security.LookupAccountSid(None, owner_sid)

        # Print digital signature information
        print('Signed by: {}'.format(owner_name))

    except pywintypes.error as e:
        print('Error: {}'.format(e))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scan_dll.py <path_to_dll>")
        sys.exit(1)

    dll_path = sys.argv[1]

    if not os.path.isfile(dll_path):
        print("File not found.")
        sys.exit(1)

    print("Assembly Information:")
    get_assembly_info(dll_path)

    print("\nDigital Signature Information:")
    get_signature_info(dll_path)
