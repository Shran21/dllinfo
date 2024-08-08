import subprocess
import sys

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    import pefile
except ImportError:
    install("pefile")
    import pefile

try:
    import pandas as pd
except ImportError:
    install("pandas")
    import pandas as pd

def analyze_dll(dll_path):
    try:
        pe = pefile.PE(dll_path)
    except FileNotFoundError:
        raise Exception(f"File not found: {dll_path}")
    except pefile.PEFormatError:
        raise Exception(f"Not a valid PE file: {dll_path}")

    dll_info = {
        "EntryPoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "ImageBase": hex(pe.OPTIONAL_HEADER.ImageBase),
        "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
        "DllCharacteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        "Sections": [(section.Name.decode().strip(), hex(section.VirtualAddress), section.SizeOfRawData) for section in pe.sections],
    }

    imported_functions = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                imported_functions.append({
                    "DLL": entry.dll.decode(),
                    "Function": imp.name.decode() if imp.name else None,
                    "Address": hex(imp.address)
                })

    dll_info["ImportedFunctions"] = imported_functions

    exported_functions = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exported_functions.append({
                "Ordinal": exp.ordinal,
                "Address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                "Name": exp.name.decode() if exp.name else None
            })

    dll_info["ExportedFunctions"] = exported_functions

    return dll_info

def display_dll_info(dll_path):
    dll_info = analyze_dll(dll_path)
    
    print("DLL Basic Information:")
    print(f"Entry Point: {dll_info['EntryPoint']}")
    print(f"Image Base: {dll_info['ImageBase']}")
    print(f"Number of Sections: {dll_info['NumberOfSections']}")
    print(f"Dll Characteristics: {dll_info['DllCharacteristics']}")
    print("\nSections:")
    for section in dll_info["Sections"]:
        print(f"Name: {section[0]}, Virtual Address: {section[1]}, Size of Raw Data: {section[2]}")

    print("\nExported Functions:")
    for func in dll_info["ExportedFunctions"]:
        print(f"Ordinal: {func['Ordinal']}, Address: {func['Address']}, Name: {func['Name']}")

    print("\nImported Functions:")
    for func in dll_info["ImportedFunctions"]:
        print(f"From DLL: {func['DLL']}, Function: {func['Function']}, Address: {func['Address']}")

if __name__ == "__main__":
    dll_path = "bsg.dll"
    display_dll_info(dll_path)
