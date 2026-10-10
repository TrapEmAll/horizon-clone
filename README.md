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
- Provides aggregate profile achievement counts, raw gamerscore totals, and
  explicitly unlabeled nonzero-flag counts through the library and
  `--profile-summary` CLI option.
- Exposes the same profile summary export from the desktop front end.
- Exposes read-only exports of the authenticated shared, Skyrim, Gears, Halo,
  legacy, and global catalogs from the desktop front end.
- Provides bulk embedded-GPD summaries with per-file entry counts, namespace
  distributions, text counts, and achievement counts through the library and
  `--xdbf-summary` CLI option.
- Exposes the same GPD summary export from the desktop front end.
- Edits observed namespace-5 XDBF UTF-16BE string entries with bounded repacking.
- Supports same-size raw XDBF entry replacement while preserving table layout.
- Repackages XDBF entries to different payload sizes within existing data
  capacity and can remove entries while rebuilding free-space metadata.
- Edits observed achievement payload fields: achievement ID, image ID,
  gamerscore, flags, and bounded UTF-16LE name changes.
- Provides a registry/plugin boundary for title-specific package editors.
- Provides a functional XDBF/GPD editor plugin API for inspection, entry
  replacement, bounded repacking, observed text edits, and achievement edits.
- Registers a read-only REA managed-surface editor for inspecting exported
  managed-members evidence through the same dispatch API.
- Exposes a complete XDBF payload surface (`--xdbf-surface`) with offsets,
  lengths, SHA-256 digests, and evidence-qualified text/achievement/opaque
  classification for future title-specific fixtures.
- Exposes the same XDBF payload surface export from the desktop front end.
- Exposes REA-observed Skyrim Shout, Perk, and Magic enum names and authenticated
  Constant-table numeric values; save offsets and mutation behavior remain
  unclaimed until fixture evidence establishes them.
- Exposes the retained REA-observed Gears of War 3 `EntryID` labels and
  authenticated Constant-table numeric values; save offsets remain unclaimed
  until fixture evidence establishes them.
- Exposes the 103 retained REA-observed Halo general-class type names; field
  layouts, save offsets, and mutation behavior remain unclaimed. It also
  exposes observed per-type field counts and an aggregate 1,102-method/
  140-property surface as structural metadata only, including the exact
  observed getter/setter property names.
- Exposes a focused REA-authenticated Halo field-type slice for `GameVariant`
  and selected options/traits classes; field names remain build-local and no
  save offsets are inferred.
- Exposes REA-observed shared catalog names for `ProfileLoadout` and
  `SaveEntryCategory`, including the authenticated Constant values for the
  latter; package offsets and mutation behavior remain unclaimed.
- Exposes seven additional REA-observed title catalogs (Dragon Ball Xenoverse,
  Code Veronica X, Devil May Cry, Ninja Gaiden 3, State of Decay, Castle
  Crashers, and Saints Row) with authenticated type/field names; enum values
  and mutation behavior remain unresolved. Their observed `i4` backing fields
  are reported separately from named members.
- Provides authenticated Constant-value resolvers and validators for the
  Skyrim enum families and Gears of War 3 `EntryID`; these validate metadata
  values only and do not infer save offsets.
- Exposes a collision-safe structural report for the largest authenticated
  global-namespace title rows (`--catalog global`), retaining duplicate CLR
  type names as separate metadata rows and explicitly withholding enum values
  and save offsets.
- Exposes the observed six-field `Horizon.ProfileData` member contract as
  typed metadata without claiming its opaque Account-file layout.
- Provides a `ProfileData` metadata-editor envelope with strict unsigned-64-bit,
  string, boolean, and hex-image validation; it remains metadata-only because
  the Account serializer was not present in authenticated REA evidence.
- Provides a legacy-catalog metadata-editor envelope for the seven observed
  title families, validating authenticated member names and signed-32-bit
  values without inventing enum assignments or save offsets.
- Exposes the same clean-room editor registry through `--editor-inspect`, so
  supported XDBF, ProfileData, Halo, Constant, legacy-catalog, managed-surface,
  and opaque Account inputs use one explicit dispatch path.
- Exposes declared metadata mutations through `--editor-edit-values` and
  `--editor-edit-output`; editors without an authenticated value-edit contract
  are rejected instead of being treated as mutable, and the CLI requires a
  distinct output path.
- Exposes detached development-signature verification through
  `--verify-detached-signature` for RSA-SHA256/SHA1 PKCS#1 v1.5 and a
  caller-supplied public key, including the JSON emitted by `--public-key`;
  Xbox signed-region inference and retail signing remain deliberately outside
  this boundary.
- Exposes the two REA-observed `Horizon.ProfileData` resource getters with
  unresolved `class:957` return-type identities; it does not infer image data
  or Account-file offsets from those declarations.
- Reports aggregate REA coverage for the observed Skyrim, Gears of War 3, and
  Halo editor families without publishing proprietary-derived member labels.
- Provides `NativeSaveBinding`, an explicit provider-only model of the
  recovered `RtsSaveDecrypt`/`RtsSaveEncrypt` signatures; it does not load
  `class3.dll` or infer the save-crypto protocol.
- Provides `AccountCodec`, an explicit bridge for opaque STFS `Account`
  payloads once an authorized class3-compatible provider and key are supplied;
  it does not store keys or claim Account serialization semantics.
- Provides `LzoBinding`, an explicit provider-only model of the four recovered
  LZO signatures, without loading `lzo.dll` or claiming codec semantics.
- Provides `LzoCodec`, a validated high-level compression/decompression bridge
  for explicit providers while preserving the observed variant names.
- Tracks the REA-observed managed-resource surface as 206 metadata records,
  205 embedded payloads, and one non-embedded unresolved record, separately
  from implementation claims.
- Exposes that resource-surface report through `--resource-surface` without
  copying or executing shipped resources.
- Queries exported REA resource inventories with `--resource-bundle` and an
  optional `--resource-pattern`, returning authenticated names, offsets,
  lengths, embedding state, and payload hashes without copying payloads.
- Exposes `--anti-analysis` as an evidence-only report of REA-observed
  debugger/obfuscation markers and guarded managed types; it does not execute,
  patch, disable, or bypass Horizon protections.
- Exposes the complete 54-row REA managed P/Invoke inventory through
  `--native-import-bundle`, including import scopes, names, calling metadata,
  and declaration-only verification state.
- Verifies the 4-byte length-prefixed managed-resource payload spans in the
  shipped executable with `--verify-resources`, currently matching 205 of 205
  embedded resources and reporting the one unresolved non-embedded record.
- Extracts printable UTF-16LE and ASCII strings with byte offsets.
- Emits a JSON report suitable for later parser fixtures.
- Replaces an existing STFS file with same-size bytes in place and rebuilds
  the complete STFS hash tree plus the metadata digest.
- Rebuilds and verifies level-0, level-1, and top-level STFS hash tables for
  allocations within the supported three-level range, while explicitly
  reporting that RSA package signing has not been checked.
- Provides a provider-oriented RSA PKCS#1 v1.5/SHA-256 signing boundary and
  SHA-256/SHA-1 detached verification primitives for authorized local test or
  development keys.
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
- Extracts the public RSA modulus/exponent from CON certificates through the
  library and `--public-key` CLI option; signed-region verification remains
  intentionally unclaimed.
- Exposes observed XDBF achievement editing from the desktop front end,
  including gamerscore, flags, and bounded name changes.
- Reads an exported REA managed-members evidence bundle and exposes a filtered
  observed Horizon type/field/method surface without loading or executing the
  inspected assembly (`--managed-surface`, with optional `--surface-pattern`).
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
compatible test provider is available. `--native-exports` reads the file-backed
PE export table without loading the DLL, allowing the supplied `class3.dll` and
`lzo.dll` surfaces to be compared to the authenticated names. REA also resolves the managed `Startup` caller for the runtime
checks and the `CheckString` caller for the user-string exports; the clone
does not load or invoke those DLLs implicitly.

`--native-contract` performs that comparison against the exact observed
`class3.dll`, `lzo.dll`, and `Horizon.dll` export contracts and reports missing
names without claiming native calling or algorithm semantics.

`--device-surface` reports the observed device-exploration members, including
device thumbnail properties and the `i8` `DeviceSize` property. Device
enumeration, FATX/USB behavior, and IOCTL semantics remain provider-boundary
items.

`--device-inventory` adds a read-only inventory of host-visible Windows logical
volumes and capacity. It does not claim Xbox FATX support or open a volume for
mutation.

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

