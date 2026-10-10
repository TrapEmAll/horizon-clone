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
- Extracts printable UTF-16LE and ASCII strings with byte offsets.
- Emits a JSON report suitable for later parser fixtures.
- Replaces an existing STFS file with same-size bytes in place and rebuilds
  affected data-block hashes plus the metadata-header hash.
- Verifies data-block and metadata-header hashes while explicitly reporting
  that RSA package signing has not been checked.
- Provides a provider-oriented RSA PKCS#1 v1.5/SHA-256 boundary for
  authorized local test or development keys.
- Exposes STFS hash verification and same-size replacement from the desktop
  front end with explicit unsigned-mutation status.

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
python -m work.horizon_clone extracted\FFFE07D1.gpd --json
python -m work.horizon_app
```

The supplied sample can be used as a read-only fixture:

```powershell
python -m work.horizon_clone C:\Users\sjisg\Desktop\E9ECC9141E317C7B --output report.json
```

