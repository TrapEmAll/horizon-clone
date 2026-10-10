# Horizon-compatible clean-room prototype

This project is an independent, non-destructive inspector for Xbox 360
content containers. It is guided by static observations of an authorized
Horizon 2.9.0.0 installation, but contains no Horizon binaries, resources, or
copied implementation code.

## Current scope

- Recognizes the observed `CON ` content-container signature.
- Reports size and SHA-256 fingerprint.
- Parses the STFS metadata header and file table for `CON`, `LIVE`, and `PIRS`.
- Lists entries and extracts files with path traversal protection.
- Parses extracted XDBF/GPD indexes and common string entries.
- Supports same-size raw XDBF entry replacement while preserving table layout.
- Repackages XDBF entries to different payload sizes within existing data
  capacity and can remove entries while rebuilding free-space metadata.
- Edits observed achievement payload fields: achievement ID, image ID,
  gamerscore, flags, and bounded UTF-16LE name changes.
- Provides a registry/plugin boundary for title-specific package editors.
- Extracts printable UTF-16LE and ASCII strings with byte offsets.
- Emits a JSON report suitable for later parser fixtures.
- Replaces an existing STFS file with same-size bytes in place and rebuilds
  the complete STFS hash tree plus the metadata digest.
- Rebuilds and verifies level-0, level-1, and top-level STFS hash tables for
  allocations within the supported three-level range, while explicitly
  reporting that RSA package signing has not been checked.
- Provides a provider-oriented RSA PKCS#1 v1.5/SHA-256 boundary for
  authorized local test or development keys.
- Exposes STFS hash verification and same-size replacement from the desktop
  front end with explicit unsigned-mutation status.
- Exposes variable-size STFS repacking and fixed-width display-name/title-ID
  metadata editing from the desktop front end, also with explicit
  unsigned-mutation status.
- Exposes observed XDBF achievement editing from the desktop front end,
  including gamerscore, flags, and bounded name changes.
- Supports fixed-width display-name, title-ID, and content-type metadata
  mutation through the library and CLI.
- Repackages entries to different sizes within existing STFS allocation
  capacity, updating file-table records and hashes.
- Resolves and rehashes level-2 STFS hash-table indirection for large
  allocations without growing the package's physical allocation.
- Removes file-table entries safely when the resulting package fits the
  existing allocation capacity.

RSA signing remains behind an authorized signing-provider boundary. This
clean-room project does not contain private Xbox/Microsoft signing keys and
does not claim that a rewritten package is console-valid until an authorized
provider signs it.

## Usage

```powershell
python -m work.horizon_clone C:\path\to\container --json
python -m work.horizon_clone C:\path\to\container --output report.json
python -m work.horizon_clone C:\path\to\container --list
python -m work.horizon_clone C:\path\to\container --extract-dir extracted
python -m work.horizon_clone C:\path\to\container --extract-dir extracted --extract Account
python -m work.horizon_clone C:\path\to\container --verify-hashes
python -m work.horizon_clone C:\path\to\container --replace Account --replacement account.bin --write mutated.con
python -m work.horizon_clone C:\path\to\container --display-name "Edited Profile" --write renamed.con
python -m work.horizon_clone C:\path\to\container --repack Account --repack-source account.bin --write repacked.con
python -m work.horizon_clone C:\path\to\container --remove Account --write without-account.con
python -m work.horizon_clone extracted\FFFE07D1.gpd --json
python -m work.horizon_clone extracted\FFFE07D1.gpd --xdbf-replace 5 --xdbf-source payload.bin --write edited.gpd
python -m work.horizon_clone extracted\FFFE07D1.gpd --xdbf-remove 5 --write without-entry.gpd
python -m work.horizon_clone extracted\FFFE07D1.gpd --achievement 5 --gamerscore 1000 --achievement-flags 1 --write achievement.gpd
python -m work.horizon_app
```

The supplied sample can be used as a read-only fixture:

```powershell
python -m work.horizon_clone C:\Users\sjisg\Desktop\E9ECC9141E317C7B --output report.json
```

