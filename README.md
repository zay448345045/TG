# TPGate

TPShell (and ACE) bypass for x86-64 Windows games.

![Version](https://img.shields.io/badge/version-0.3.0-blue)
![License](https://img.shields.io/badge/license-AGPL--3.0-green)

TPGate uses Zig 0.17.0, which you can download here:
- [Windows x86_64](https://zig.dynamibyte.com/zig-x86_64-windows-0.17.0.zip)
- [Linux x86_64](https://zig.dynamibyte.com/zig-x86_64-linux-0.17.0.tar.xz)
- [Other builds](https://zig.dynamibyte.com/#0.17.0)

## Usage

1. Configure `config.zon` if needed
2. Build with `zig build`
3. Back up the game's `*Base.dll` beside its executable
4. Copy `zig-out/bin/tpgate.dll` beside the executable under the Base DLL's exact filename
5. Launch the game normally

To undo the replacement, remove the copied DLL and restore the backup.

## Notes

- The game must import its Base DLL by ordinal 1. TPGate does not include a launcher or injector.
- The game's imported `*Base.dll` is TPShell; TPGate replaces it.
- TPGate reconstructs the executable's protected code and compressed sections, restores imports from TPShell's recipe, then runs the original entry point.
- It redirects `LoadLibrary*`, `GetProcAddress`, and `FreeLibrary` imports in loaded DLLs and restores TPShell native fragments there, including in DLLs loaded later.
- By default, TPGate blocks `ACE-Base64.dll` when loaded through redirected `LoadLibrary*` functions.
- See tested games [here](TESTED.md).
