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
- Provides a library API for enumerating parseable XDBF payloads embedded in STFS GPD files.
- Provides a normalized library API for enumerating observed achievements across embedded GPDs.
- Edits observed namespace-5 XDBF UTF-16BE string entries with bounded repacking.
- Supports same-size raw XDBF entry replacement while preserving table layout.
- Repackages XDBF entries to different payload sizes within existing data
  capacity and can remove entries while rebuilding free-space metadata.
- Edits observed achievement payload fields: achievement ID, image ID,
  gamerscore, flags, and bounded UTF-16LE name changes.
- Provides a registry/plugin boundary for title-specific package editors.
- Provides a functional XDBF/GPD editor plugin API for inspection, entry
  replacement, bounded repacking, observed text edits, and achievement edits.
- Exposes REA-observed Skyrim enum member names for Shouts, Perks, and Magic;
  numeric values and save offsets remain intentionally unclaimed until fixture
  evidence establishes them.
- Exposes the retained REA-observed Gears of War 3 `EntryID` labels; numeric
  values and save offsets remain unclaimed until fixture evidence establishes
  them.
- Exposes the 103 retained REA-observed Halo general-class type names; field
  layouts, save offsets, and mutation behavior remain unclaimed. It also
  exposes observed per-type field counts and an aggregate 1,102-method/
  140-property surface as structural metadata only, including the exact
  observed getter/setter property names.
- Exposes REA-observed shared catalog names for `ProfileLoadout` and
  `SaveEntryCategory`; enum values and package offsets remain unclaimed until
  fixture evidence establishes them.
- Exposes seven additional REA-observed title catalogs (Dragon Ball Xenoverse,
  Code Veronica X, Devil May Cry, Ninja Gaiden 3, State of Decay, Castle
  Crashers, and Saints Row) with type/field counts only.
- Exposes the observed six-field `Horizon.ProfileData` member contract as
  typed metadata without claiming its opaque Account-file layout.
- Exposes the two REA-observed `Horizon.ProfileData` resource getters with
  unresolved `class:957` return-type identities; it does not infer image data
  or Account-file offsets from those declarations.
- Reports aggregate REA coverage for the observed Skyrim, Gears of War 3, and
  Halo editor families without publishing proprietary-derived member labels.
- Provides `NativeSaveBinding`, an explicit provider-only model of the
  recovered `RtsSaveDecrypt`/`RtsSaveEncrypt` signatures; it does not load
  `class3.dll` or infer the save-crypto protocol.
- Provides `LzoBinding`, an explicit provider-only model of the four recovered
  LZO signatures, without loading `lzo.dll` or claiming codec semantics.
- Tracks the REA-observed embedded managed-resource surface (205 payloads)
  separately from implementation claims.
- Exposes that resource-surface report through `--resource-surface` without
  copying or executing shipped resources.
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
- Exposes capacity-bounded STFS file insertion from the desktop front end.
- Reads and replaces bounded STFS thumbnail and title-thumbnail payloads.
- Inspects STFS public certificate descriptors, package-signature digests, and
  all 16 license slots, and reports the stored metadata-header SHA-1 match
  without claiming RSA signature validity.
- Exposes observed XDBF achievement editing from the desktop front end,
  including gamerscore, flags, and bounded name changes.
- Supports fixed-width display-name, title-ID, and content-type metadata
  mutation through the library and CLI.
- Supports bounded display-description, publisher-name, title-name, and
  transfer-flag metadata mutation through the library and CLI.
- Repackages entries to different sizes within existing STFS allocation
  capacity, updating file-table records and hashes.
- Adds new root or existing-directory STFS files when both file-table slots and
  data-block capacity are available.
- Removes STFS files from the desktop front end when the resulting package fits
  the existing allocation capacity.
- Renames STFS files or directories within their existing parent directory from
  both the CLI and desktop front end.
- Adds empty STFS directories when file-table capacity permits, from both the
  CLI and desktop front end.
- Removes empty STFS directories through the same entry-removal workflow.
- Resolves and rehashes level-2 STFS hash-table indirection for large
  allocations without growing the package's physical allocation.
- Removes file-table entries safely when the resulting package fits the
  existing allocation capacity.

The managed executable declares 14 native module references and 54 P/Invoke
imports, including `class3.dll` save encrypt/decrypt exports and the
`Horizon.dll`/`HVMRun64.dll` DNG/HVM exports. `--native-surface` exposes this
declaration-only inventory. REA recovers managed declaration shapes for the
save-crypto, LZO, runtime, and user-string imports, but native protocols and
parameter semantics remain unresolved until authenticated native analysis or a
compatible test provider is available. REA also resolves the managed `Startup` caller for the runtime
checks and the `CheckString` caller for the user-string exports; the clone
does not load or invoke those DLLs implicitly.

`--device-surface` reports the observed device-exploration members, including
device thumbnail properties and the `i8` `DeviceSize` property. Device
enumeration, FATX/USB behavior, and IOCTL semantics remain provider-boundary
items.

`DeviceBinding` exposes the observed signed-64-bit `DeviceSize` property
through an explicit provider boundary; it never opens or enumerates a
physical device.

The recovered DNG/HVM declarations are exposed through an explicit
`NativeRuntimeBinding` provider boundary. It never loads the original runtime
implicitly and leaves native argument semantics to the supplied provider.

RSA signing remains behind an authorized signing-provider boundary. The
library supports detached signatures over caller-labeled development regions,
but does not infer Xbox signed regions. This clean-room project does not
contain private Xbox/Microsoft signing keys and does not claim that a rewritten
package is console-valid until an authorized provider signs it.

`--in-place` is an explicit destructive opt-in for local development: it
overwrites the input container after the same rehashing pipeline used by
`--write`. Mutated packages remain unsigned unless an authorized provider
performs the required signing step.
`--backup` saves the original bytes before the atomic replacement and is only
valid with `--in-place`.

## Usage

```powershell
python -m work.horizon_clone C:\path\to\container --json
python -m work.horizon_clone C:\path\to\container --capabilities
python -m work.horizon_clone C:\path\to\container --catalog halo
python -m work.horizon_clone C:\path\to\container --output report.json
python -m work.horizon_clone C:\path\to\container --list
python -m work.horizon_clone C:\path\to\profile.con --list-xdbf
python -m work.horizon_clone C:\path\to\profile.con --list-achievements
python -m work.horizon_clone C:\path\to\profile.con --achievements-output achievements.json
python -m work.horizon_clone C:\path\to\container --extract-dir extracted
python -m work.horizon_clone C:\path\to\container --extract-dir extracted --extract Account
python -m work.horizon_clone C:\path\to\container --verify-hashes
python -m work.horizon_clone C:\path\to\container --security
python -m work.horizon_clone C:\path\to\container --replace Account --replacement account.bin --write mutated.con
python -m work.horizon_clone C:\path\to\container --replace Account --replacement account.bin --in-place
python -m work.horizon_clone C:\path\to\container --replace Account --replacement account.bin --in-place --backup original.con
python -m work.horizon_clone C:\path\to\container --display-name "Edited Profile" --write renamed.con
python -m work.horizon_clone C:\path\to\container --repack Account --repack-source account.bin --write repacked.con
python -m work.horizon_clone C:\path\to\container --remove Account --write without-account.con
python -m work.horizon_clone C:\path\to\container --add sidecar.bin --add-source sidecar.bin --write with-sidecar.con
python -m work.horizon_clone C:\path\to\container --rename cache/ph.dat --new-name ph2.dat --write renamed-file.con
python -m work.horizon_clone C:\path\to\container --mkdir cache/NewFolder --write with-directory.con
python -m work.horizon_clone C:\path\to\container --move cache/ph.dat --move-to AvatarAssets --new-name ph2.dat --write moved-file.con
python -m work.horizon_clone C:\path\to\container --thumbnail-source thumbnail.bin --write with-thumbnail.con
python -m work.horizon_clone C:\path\to\container --thumbnail-output thumbnail.bin --title-thumbnail-output title-thumbnail.bin
python -m work.horizon_clone extracted\FFFE07D1.gpd --json
python -m work.horizon_clone extracted\FFFE07D1.gpd --xdbf-replace 5 --xdbf-source payload.bin --write edited.gpd
python -m work.horizon_clone extracted\FFFE07D1.gpd --xdbf-remove 5 --write without-entry.gpd
python -m work.horizon_clone extracted\FFFE07D1.gpd --xdbf-add-namespace 5 --xdbf-add-id 0x9000 --xdbf-add-source payload.bin --write with-entry.gpd
python -m work.horizon_clone extracted\FFFE07D1.gpd --xdbf-text 5 --xdbf-text-value "Edited label" --write edited-label.gpd
python -m work.horizon_clone C:\path\to\profile.con --xdbf-file FFFE07D1.gpd --xdbf-text 106 --xdbf-text-value "Edited label" --write edited-profile.con
python -m work.horizon_clone C:\path\to\profile.con --xdbf-file 4D53082D.gpd --achievement 12 --gamerscore 1000 --achievement-flags 1 --write edited-achievement.con
python -m work.horizon_clone C:\path\to\profile.con --xdbf-file FFFE07D1.gpd --xdbf-remove 106 --write edited-profile.con
python -m work.horizon_clone extracted\FFFE07D1.gpd --achievement 5 --gamerscore 1000 --achievement-flags 1 --write achievement.gpd
python -m work.horizon_app
```

For local fixture-backed testing, set `HORIZON_PROFILE_FIXTURE` to a profile/container path you control:

```powershell
$env:HORIZON_PROFILE_FIXTURE = 'C:\path\to\profile-fixture'
python -m work.horizon_clone $env:HORIZON_PROFILE_FIXTURE --output report.json
```

