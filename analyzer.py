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
        raise FileNotFoundError(f"File not found: {dll_path}")
    except pefile.PEFormatError:
        raise ValueError(f"Not a valid PE file: {dll_path}")

    dll_info = {
        "EntryPoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "ImageBase": hex(pe.OPTIONAL_HEADER.ImageBase),
        "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
        "DllCharacteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        "Sections": [(section.Name.decode().strip(), hex(section.VirtualAddress), section.SizeOfRawData, hex(section.Misc_VirtualSize), hex(section.Characteristics), hex(section.PointerToRawData)) for section in pe.sections],
        "FileAlignment": pe.OPTIONAL_HEADER.FileAlignment,
        "SectionAlignment": pe.OPTIONAL_HEADER.SectionAlignment,
        "Subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown"),
        "MachineType": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "Unknown"),
        "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
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

    if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        relocations = []
        for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            for reloc in base_reloc.entries:
                relocations.append({
                    "Virtual Address": hex(reloc.rva),
                    "Type": pefile.RELOCATION_TYPE.get(reloc.type, "Unknown")
                })
        dll_info["Relocations"] = relocations

    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        resources = []
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = str(resource_type.name)
            else:
                name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, "Unknown")
            if name is not None:
                for resource_id in resource_type.directory.entries:
                    for resource_lang in resource_id.directory.entries:
                        data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                        resources.append({
                            "Type": name,
                            "Lang": hex(resource_lang.data.lang),
                            "Sublang": hex(resource_lang.data.sublang),
                            "Size": resource_lang.data.struct.Size,
                            "Data": data[:64]
                        })
        dll_info["Resources"] = resources

    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        debug_entries = []
        for debug in pe.DIRECTORY_ENTRY_DEBUG:
            debug_entries.append({
                "AddressOfRawData": hex(debug.struct.AddressOfRawData),
                "PointerToRawData": hex(debug.struct.PointerToRawData),
                "TimeDateStamp": debug.struct.TimeDateStamp,
                "MajorVersion": debug.struct.MajorVersion,
                "MinorVersion": debug.struct.MinorVersion,
                "Type": debug.struct.Type,
                "SizeOfData": debug.struct.SizeOfData
            })
        dll_info["DebugInfo"] = debug_entries

    if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        tls_info = {
            "StartAddressOfRawData": hex(pe.DIRECTORY_ENTRY_TLS.struct.StartAddressOfRawData),
            "EndAddressOfRawData": hex(pe.DIRECTORY_ENTRY_TLS.struct.EndAddressOfRawData),
            "AddressOfIndex": hex(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex),
            "AddressOfCallBacks": hex(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks),
            "SizeOfZeroFill": pe.DIRECTORY_ENTRY_TLS.struct.SizeOfZeroFill,
            "Characteristics": hex(pe.DIRECTORY_ENTRY_TLS.struct.Characteristics)
        }
        dll_info["TLSInfo"] = tls_info

    if hasattr(pe, 'DIRECTORY_ENTRY_IAT'):
        iat_entries = []
        for entry in pe.DIRECTORY_ENTRY_IAT:
            iat_entries.append({
                "Address": hex(entry.address),
                "Name": entry.name.decode() if entry.name else None
            })
        dll_info["IAT"] = iat_entries

    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        delay_imports = []
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            for imp in entry.imports:
                delay_imports.append({
                    "DLL": entry.dll.decode(),
                    "Function": imp.name.decode() if imp.name else None,
                    "Address": hex(imp.address)
                })
        dll_info["DelayImports"] = delay_imports

    if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
        bound_imports = []
        for entry in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
            bound_imports.append({
                "DLL": entry.name.decode(),
                "TimeDateStamp": entry.struct.TimeDateStamp
            })
        dll_info["BoundImports"] = bound_imports

    if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
        load_config = {
            "Size": pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size,
            "TimeDateStamp": pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.TimeDateStamp,
            "GuardFlags": hex(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags) if hasattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct, 'GuardFlags') else None
        }
        dll_info["LoadConfig"] = load_config

    if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
        security_entries = []
        for security in pe.DIRECTORY_ENTRY_SECURITY:
            security_entries.append({
                "Offset": security.struct.Offset,
                "Size": security.struct.Size,
                "Flags": security.struct.Flags,
                "Revision": security.struct.Revision,
                "Certificate": security.struct.Certificate[:64]
            })
        dll_info["Security"] = security_entries

    if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'CLR_RUNTIME_HEADER'):
        clr_info = {
            "Size": pe.OPTIONAL_HEADER.CLR_RUNTIME_HEADER.Size,
            "Flags": hex(pe.OPTIONAL_HEADER.CLR_RUNTIME_HEADER.Flags),
            "MetaData": hex(pe.OPTIONAL_HEADER.CLR_RUNTIME_HEADER.MetaData.VirtualAddress)
        }
        dll_info["CLRInfo"] = clr_info

    return dll_info

def display_dll_info(dll_path):
    dll_info = analyze_dll(dll_path)

    print("DLL Basic Information:")
    print(f"Entry Point: {dll_info['EntryPoint']}")
    print(f"Image Base: {dll_info['ImageBase']}")
    print(f"Number of Sections: {dll_info['NumberOfSections']}")
    print(f"Dll Characteristics: {dll_info['DllCharacteristics']}")
    print(f"File Alignment: {dll_info['FileAlignment']}")
    print(f"Section Alignment: {dll_info['SectionAlignment']}")
    print(f"Subsystem: {dll_info['Subsystem']}")
    print(f"Machine Type: {dll_info['MachineType']}")
    print(f"Time Date Stamp: {dll_info['TimeDateStamp']}")
    
    print("\nSections:")
    for section in dll_info["Sections"]:
        print(f"Name: {section[0]}, Virtual Address: {section[1]}, Size of Raw Data: {section[2]}, Virtual Size: {section[3]}, Characteristics: {section[4]}, Pointer To Raw Data: {section[5]}")

    print("\nExported Functions:")
    for func in dll_info["ExportedFunctions"]:
        print(f"Ordinal: {func['Ordinal']}, Address: {func['Address']}, Name: {func['Name']}")

    print("\nImported Functions:")
    for func in dll_info["ImportedFunctions"]:
        print(f"From DLL: {func['DLL']}, Function: {func['Function']}, Address: {func['Address']}")

    if "Relocations" in dll_info:
        print("\nBase Relocations:")
        for reloc in dll_info["Relocations"]:
            print(f"Virtual Address: {reloc['Virtual Address']}, Type: {reloc['Type']}")

    if "Resources" in dll_info:
        print("\nResources:")
        for resource in dll_info["Resources"]:
            print(f"Type: {resource['Type']}, Lang: {resource['Lang']}, Sublang: {resource['Sublang']}, Size: {resource['Size']}, Data (first 64 bytes): {resource['Data']}")

    if "DebugInfo" in dll_info:
        print("\nDebug Information:")
        for debug in dll_info["DebugInfo"]:
            print(f"AddressOfRawData: {debug['AddressOfRawData']}, PointerToRawData: {debug['PointerToRawData']}, TimeDateStamp: {debug['TimeDateStamp']}, SizeOfData: {debug['SizeOfData']}")

    if "TLSInfo" in dll_info:
        print("\nTLS Information:")
        for key, value in dll_info["TLSInfo"].items():
            print(f"{key}: {value}")

    if "IAT" in dll_info:
        print("\nImport Address Table (IAT):")
        for iat in dll_info["IAT"]:
            print(f"Address: {iat['Address']}, Name: {iat['Name']}")

    if "DelayImports" in dll_info:
        print("\nDelay Imports:")
        for imp in dll_info["DelayImports"]:
            print(f"From DLL: {imp['DLL']}, Function: {imp['Function']}, Address: {imp['Address']}")

    if "BoundImports" in dll_info:
        print("\nBound Imports:")
        for bound in dll_info["BoundImports"]:
            print(f"From DLL: {bound['DLL']}, TimeDateStamp: {bound['TimeDateStamp']}")

    if "LoadConfig" in dll_info:
        print("\nLoad Configuration:")
        for key, value in dll_info["LoadConfig"].items():
            print(f"{key}: {value}")

    if "Security" in dll_info:
        print("\nSecurity Information (Certificate):")
        for sec in dll_info["Security"]:
            print(f"Offset: {sec['Offset']}, Size: {sec['Size']}, Flags: {sec['Flags']}, Certificate (first 64 bytes): {sec['Certificate']}")

    if "CLRInfo" in dll_info:
        print("\nCLR Header Information:")
        for key, value in dll_info["CLRInfo"].items():
            print(f"{key}: {value}")

if __name__ == "__main__":
    dll_path = "bsg.dll"
    display_dll_info(dll_path)
