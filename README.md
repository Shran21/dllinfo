# DLL Analyzer Script

This script is designed to analyze and extract detailed information from a DLL (Dynamic Link Library) file. 
### Features

- **Basic Information**: Retrieves basic details such as entry point, image base, number of sections, and DLL characteristics.
- **Sections**: Lists all sections in the DLL along with their virtual addresses, sizes, characteristics, and more.
- **Imported Functions**: Displays all functions imported by the DLL, including their names and addresses.
- **Exported Functions**: Lists all functions exported by the DLL, along with their ordinals and addresses.
- **Relocations**: Shows base relocation entries, including virtual addresses and relocation types.
- **Resources**: Extracts information about resources within the DLL, such as icons, images, and strings.
- **Debug Information**: Provides details on debug entries, including raw data pointers and timestamps.
- **TLS Information**: Displays Thread Local Storage (TLS) data related to the DLL.
- **Import Address Table (IAT)**: Lists the IAT entries, including function names and addresses.
- **Delay Imports**: Shows functions that are delay-imported by the DLL.
- **Bound Imports**: Lists bound imports along with their timestamps.
- **Load Configuration**: Extracts the load configuration data from the DLL.
- **Security Information**: Displays details about the security certificates in the DLL.
- **CLR Header Information**: Provides information about the CLR header, if present.

### Installation

To use this script, you need to have Python installed on your system. The script automatically installs the necessary dependencies if they are not already installed.


------------------------------------

Ez a szkript egy DLL (Dynamic Link Library) fájl részletes elemzésére és információinak kinyerésére szolgál. 

### Funkciók

- **Alapvető információk**: Alapvető részletek kinyerése, például a belépési pont, az image base, a szakaszok száma és a DLL jellemzői.
- **Szekciók**: A DLL összes szekciójának listája, beleértve a virtuális címeket, méreteket, jellemzőket stb.
- **Importált függvények**: Az összes importált függvény megjelenítése a DLL-ben, beleértve azok neveit és címeit.
- **Exportált függvények**: Az összes exportált függvény listája a DLL-ben, azok ordinaljaival és címeivel.
- **Relokációk**: A bázisrelokációs bejegyzések megjelenítése, beleértve a virtuális címeket és a relokáció típusát.
- **Erőforrások**: Az erőforrásokkal kapcsolatos információk kinyerése a DLL-ben, például ikonok, képek és stringek.
- **Debug információk**: Debug bejegyzések részletezése, beleértve a nyers adatmutatókat és az időbélyegeket.
- **TLS információk**: A DLL-hez kapcsolódó Thread Local Storage (TLS) adatok megjelenítése.
- **Import Address Table (IAT)**: Az IAT bejegyzések listázása, beleértve a függvényneveket és címeket.
- **Késleltetett importálások**: Azokat a függvényeket jeleníti meg, amelyeket a DLL késleltetve importál.
- **Bound Imports**: A bound imports listája az időbélyegzőkkel együtt.
- **Load Configuration**: A DLL load konfigurációs adatainak kinyerése.
- **Biztonsági információk**: A DLL biztonsági tanúsítványaival kapcsolatos részletek megjelenítése.
- **CLR fejléc információk**: Információk a CLR fejlécről, ha van ilyen.

### Telepítés

A szkript használatához Python telepítése szükséges a rendszeren. A szkript automatikusan telepíti a szükséges függőségeket, ha azok még nincsenek telepítve.


