import os
import pefile
import sys

def get_exported_functions(dll_path):
    exported_functions = []
    try:
        pe = pefile.PE(dll_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name is not None:
                    exported_functions.append(exp.name.decode())
    except pefile.PEFormatError:
        pass
    return exported_functions

def enumerate_dll_exports(directory):
    dll_files = [file for file in os.listdir(directory) if file.endswith('.dll')]
    exported_functions = {}
    for file in dll_files:
        file_path = os.path.join(directory, file)
        print(f"Enumerating: {file}")
        exported_functions[file] = get_exported_functions(file_path)
    return exported_functions

def main():
    path = sys.argv[1]
    exported_functions = enumerate_dll_exports(path)

    # Redirect standard output to a file
    with open('exported_functions.txt', 'w') as f:
        sys.stdout = f

        for dll, functions in exported_functions.items():
            print(f'--- {dll} ---')
            for function in functions:
                print(function)
            print()

    # Restore standard output
    sys.stdout = sys.__stdout__
    print("Exported functions have been saved to 'exported_functions.txt'.")

if __name__ == '__main__':
    main()
