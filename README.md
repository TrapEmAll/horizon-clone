# Horizon-compatible clean-room prototype

This project is an independent, non-destructive inspector for Xbox 360
content containers. It is guided by static observations of an authorized
Horizon 2.9.0.0 installation, but contains no Horizon binaries, resources, or
copied implementation code.

## Current scope

- Recognizes the observed `CON ` content-container signature.
- Reports canonical FATX-facing profile paths with `--fatx-path`, including
  the authenticated profile filename, title ID, and content type.
- Reports size and SHA-256 fingerprint.
- Parses the STFS metadata header and file table for `CON`, `LIVE`, and `PIRS`.
- Lists entries and extracts files with path traversal protection.
- Parses extracted XDBF/GPD indexes and common string entries.
- Regression coverage parses all 67 GPD files plus the profile `.fit` XDBF
  payload in the supplied fixture, spanning the observed XDBF entries across
  namespaces 1 through 5.
- Regression coverage also exercises same-size XDBF replacement and reparsing
  across every supplied GPD without writing back to the fixture.
- Regression coverage replaces the opaque Account entry in memory, rebuilds
  the complete STFS hash tree, and verifies all hash levels afterward.
- Regression coverage exercises the achievement editor against all 2,339
  parsed achievement payloads in the supplied fixture.
- Provides a library API for enumerating parseable XDBF payloads embedded in STFS GPD files.
- Provides a normalized library API for enumerating observed achievements across embedded GPDs.
- Provides aggregate profile achievement counts, raw gamerscore totals, observed
  unlock-time coverage/bounds, and explicitly unlabeled nonzero-flag counts through the library and
  `--profile-summary` CLI option.
- Provides explicit raw achievement-flag mask operations across one XDBF payload
  through `mutate_xdbf_achievement_flags`; flag-bit meanings remain unlabeled.
- Applies the same explicit raw mask across every embedded GPD with
  `mutate_profile_achievement_flags` or the corresponding profile CLI options,
  preserving the STFS hash-tree rewrite path.
- Replaces exact observed namespace-5 XDBF text matches across embedded GPD/FIT
  files with `mutate_profile_xdbf_text` and the corresponding profile CLI options.
- Uses authenticated same-size STFS mutation for profile-wide edits and verifies
  general repack results by reading modified entries back before returning them.
- Exposes the same profile summary export from the desktop front end.
- The desktop front end exposes the canonical FATX path for the loaded
  container through “FATX path”.
- Exposes read-only exports of the authenticated shared, Skyrim, Gears, Halo,
  legacy, and global catalogs from the desktop front end.
- Provides bulk embedded-GPD/FIT summaries with per-file entry counts, namespace
  distributions, text counts, and achievement counts through the library and
  `--xdbf-summary` CLI option.
- Exposes the same GPD summary export from the desktop front end.
- The desktop front end can inspect registry-supported JSON editor artifacts
  and write explicit metadata edits to a separate output path.
- Edits observed namespace-5 XDBF UTF-16BE string entries with bounded repacking.
- Supports same-size raw XDBF entry replacement while preserving table layout.
- The desktop front end exposes an explicit, confirmation-gated in-place
  same-size STFS entry replacement; writes remain atomic and the container is
  reparsed afterward. The result is unsigned until an authorized signing step.
- It also exposes the corresponding confirmation-gated in-place capacity-aware
  repack action for entries whose replacement size differs.
- Entry removal is likewise available as a confirmation-gated in-place action,
  with the STFS hash tree rebuilt and the written container reparsed.
- In-place rename and move actions are also available for selected STFS entries;
  they require explicit confirmation, rebuild the hash tree, and reparse the
  overwritten container.
- Repackages XDBF entries to different payload sizes within existing data
  capacity and can remove entries while rebuilding free-space metadata.
- Edits observed achievement payload fields: achievement ID, image ID,
  gamerscore, flags, raw FILETIME/UTC unlock timestamp, and bounded UTF-16BE
  name changes.
- Provides a registry/plugin boundary for title-specific package editors.
- Exposes `--rea-feature-ledger`, a compact evidence-linked reconstruction
  ledger that keeps observed Horizon boundaries and unresolved parity questions
  explicit for subsequent REA passes.
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
- Exposes REA-authenticated decoded field types for 92 named Halo general
  classes (489 fields); field names remain build-local and no save offsets are
  inferred. Eleven unsupported signatures remain excluded rather than guessed.
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
- Supports the observed XeCrypt byte-reversed SHA-1 PKCS#1 signature encoding
  through `--signature-algorithm RSA-SHA1-XeCrypt-PKCS1v1.5` when the caller
  supplies exact signed and signature offsets; it does not infer package
  offsets or claim console validity.
- Provides `--verify-stfs-signature` for the observed CON package layout,
  reporting the actual verification result over bytes `0x22C..0x344` with the
  stored certificate key; a failed result is preserved as evidence rather than
  treated as an implementation success.
- Exposes the two REA-observed `Horizon.ProfileData` resource getters with
  unresolved `class:957` return-type identities; it does not infer image data
  or Account-file offsets from those declarations.
- Reports aggregate REA coverage for the observed Skyrim, Gears of War 3, and
  Halo editor families without publishing proprietary-derived member labels.
- Provides `NativeSaveBinding`, an explicit provider-only model of the
  recovered `RtsSaveDecrypt`/`RtsSaveEncrypt` signatures; it does not load
  `class3.dll` or infer the save-crypto protocol.
- The supplied x86 `Horizon.dll` has been smoke-tested through the explicit
  runtime bridge: `check-runtime` returns `true`; VM execution and user-string
  handles remain opt-in because their argument semantics are unresolved.
- Provides `AccountCodec`, an explicit bridge for opaque STFS `Account`
  payloads once an authorized class3-compatible provider and key are supplied;
  `encrypt_raw` preserves native status and the caller-sized output buffer;
  encryption length and Account serialization remain caller-resolved.
- Exposes the observed LZO boundary through `--lzo-operation`, including
  version queries and caller-selected LZO1X/LZO2A compression or decompression;
  output bytes can be written to an explicit path. The desktop front end
  exposes the same operation with explicit source and output dialogs.
- Provides an isolated `AccountRecord` body codec based on the public,
  Unlicense historical XProfile reference. It authenticates and round-trips the
  supplied 404-byte Account entry with a caller-supplied 16-byte key, but is
  labeled historical-reference rather than REA-recovered Horizon behavior and
  does not claim retail signing or console validity.
- Exposes `--historical-account-inspect` for authenticated, read-only Account
  field inspection with an explicit caller-supplied 16-byte key; secrets are
  returned only as field values in the caller's local JSON output and are not
  persisted by the clone.
- Supports explicit historical Account field mutation through
  `--historical-account-edit JSON --historical-account-key-hex KEY` together
  with `--write` or `--in-place`; the STFS hash tree is rebuilt, while the
  result remains explicitly unsigned and non-console-valid.
- Provides `AccountKeyProvider` integration for caller-owned key-vault or
  development-key services; keys are requested per operation and payload digest
  and are not persisted by the clone.
- Provides `CommandAccountKeyProvider` for an explicit absolute helper path;
  it exchanges one JSON request over stdin/stdout without shell invocation or
  local key storage.
- Supports explicit raw Account decryption through `--account-decrypt`, a
  caller-selected x86 `class3.dll`, and a nonpersistent key-vault helper;
  native crypto is never loaded implicitly.
- Supports the reverse raw-encryption flow with explicit output capacity and
  caller-known ciphertext length via `--account-encrypt`; the encrypted bytes
  can be passed to the existing `--replace Account` or `--in-place` path.
- Provides `LzoBinding`, an explicit provider-only model of the four recovered
  LZO signatures, without loading `lzo.dll` or claiming codec semantics.
- Provides `PowerShellLzoProvider`, an explicit x64-to-x86 bridge that invokes
  the supplied `lzo.dll` only through a caller-selected 32-bit PowerShell host.
- Verifies both observed codec families: `lzo1x` and `lzo2a`; the supplied
  `lzo2a` path round-trips with a 256 KiB caller-provided work buffer.
- Provides `PowerShellNativeSaveProvider`, an explicit x64-to-x86 bridge for
  the observed stdcall `class3.dll` save declarations; raw return and length
  values are preserved without inferring Account serialization.
- Provides `LzoCodec`, a validated high-level compression/decompression bridge
  for explicit providers while preserving the observed variant names.
- Exposes the authenticated Windows device boundary through `--device-ioctl`:
  one caller-selected IOCTL is forwarded over a read-only handle with input
  and output bytes represented as hex; FATX command values and safety
  semantics remain caller-resolved.
- Exposes the authenticated `Horizon.dll`/HVM runtime boundary through
  `--native-runtime-operation`, preserving raw runtime results and requiring
  an explicit DLL path and caller-supplied arguments.
- Runtime adapters enforce the observed x86 versus x64 image boundary; the
  supplied installation currently lacks `HVMRun64.dll`, so x64 operations fail
  explicitly until that authorized artifact is provided.
- Runtime CLI calls statically preflight the required export and image width
  before launching the explicit native provider.
- Tracks the REA-observed managed-resource surface as 206 metadata records,
  205 embedded payloads, and one non-embedded unresolved record, separately
  from implementation claims.
- Exposes that resource-surface report through `--resource-surface` without
  copying or executing shipped resources.
- Decodes standard .NET resource primitive, string, byte-array, and stream
  records from standalone `.resources` payloads while leaving user-defined
  values opaque and never instantiating them.
- Queries exported REA resource inventories with `--resource-bundle` and an
  optional `--resource-pattern`, returning authenticated names, offsets,
  lengths, embedding state, and payload hashes without copying payloads.
- Exposes `--anti-analysis` as an evidence-only report of REA-observed
  debugger/obfuscation markers and guarded managed types; it does not execute,
  patch, disable, or bypass Horizon protections.
- Exposes the same anti-analysis evidence report from the desktop front end;
  it remains read-only and non-executing.
- Exposes the complete 54-row REA managed P/Invoke inventory through
  `--native-import-bundle`, including import scopes, names, calling metadata,
  and declaration-only verification state.
- Exposes declared managed assembly dependencies through
  `--managed-references` with optional `--reference-pattern` filtering,
  retaining authenticated names, versions, and public-key-token metadata
  without loading or resolving dependencies.
- Exposes `--managed-artifact` for authenticated PE/CLI identity, assembly
  version, metadata/resource coverage, and dependency counts, preserving
  partial REA diagnostics instead of filling gaps by inference.
- Exposes `--native-installation DIRECTORY`, a read-only inventory of the
  observed `class3.dll`, `lzo.dll`, `Horizon.dll`, and `HVMRun64.dll` deployment
  contracts, including PE architecture and named exports; missing runtime
  helpers are reported as partial rather than silently emulated.
- Exposes joined type-centric managed editor schemas through
  `--managed-schema` and `--schema-pattern`, linking every matched observed
  type to its fields and methods without inferring save offsets or serializers.
- Adds opt-in `--schema-bodies` summaries for REA-observed method-body status,
  instruction counts, opcode counts, and IL digests.
- Supports `--schema-method-pattern` for focused `Read`/`Write`/`Save` method
  contract queries within matched managed editor types.
- Supports opt-in `--schema-field-accesses` to expose REA-observed field-access
  anchors and opcodes for matched managed types.
- Exposes `--managed-io-contract` for focused static `Read`/`Write`/`Load`/
  `Save` method contracts, including authenticated CIL anchors, field accesses,
  and call targets without inferring save offsets.
- Exposes `--managed-body-fidelity` to measure duplicate retained IL hashes and
  file offsets. This records when REA presents shared guard/throw bodies across
  title-editor members, preventing metadata stubs from being mistaken for
  serializer implementations.
- Adds conservative XDBF payload metadata to `--xdbf-surface`; observed PNG
  payloads expose format and dimensions without decoding or assigning title
  semantics.
- Provides `xdbf_achievement_image_links` to join authenticated achievement
  `image_id` values to same-file namespace-2 PNG entries, retaining missing
  references explicitly.
- Provides `xdbf_achievement_image_payload` for exact linked PNG retrieval,
  with explicit errors for missing or non-image references.
- The desktop front end can export the complete embedded achievement-image
  link inventory, including linked and missing-reference counts.
- The CLI exposes the same inventory through `--achievement-links-output`.
- The CLI and desktop front end can extract unique linked PNGs with
  `--extract-achievement-images DIR` or “Extract achievement images”.
- Verifies the 4-byte length-prefixed managed-resource payload spans in the
  shipped executable with `--verify-resources`, currently matching 205 of 205
  embedded resources and reporting the one unresolved non-embedded record.
- Extracts uniquely hash-verified embedded resource payloads with
  `--extract-resources DIR --resource-bundle BUNDLE`; unresolved or ambiguous
  spans are reported without writing unverified bytes.
- Labels extracted payloads with conservative non-executing magic
  classifications such as PNG, JPEG, GIF, BMP, ICO, WAV, ZIP, and .NET
  resources, and reports proven image dimensions without decoding or
  executing the asset.
- Parses standalone .NET `.resources` indexes with `--dotnet-resource-index`,
  exposing resource names, type names, authenticated byte spans, and hashes
  without deserializing resource values.
- Exposes the same managed-resource extraction flow from the desktop front end
  through an explicit executable, REA bundle, output directory, and optional
  resource-name filter.
- Exposes detached development signing for the currently loaded desktop
  artifact through an explicit caller label, private-key JSON, and signature
  output path.
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
- Provides `--sign-detached-signature` with a caller-supplied private-key JSON
  file for authorized development signing; private material is read only for
  the operation and is not included in reports.
- Provides `--sign-written-output` to sign the exact bytes emitted by a
  mutation through `--write` or `--in-place`, using the same explicit key and
  label requirements.
- Provides `--verify-embedded-signature` for caller-specified in-container
  signature and signed-region offsets; it deliberately does not infer Xbox
  package layout or claim console validity.
- Provides `--signature-compare OTHER` to compare two STFS images, report
  changed bytes outside stored signature regions, and identify whether the
  stored signature bytes were preserved; this is an integrity audit only.
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
- Groups that authenticated managed surface into queryable editor families with
  `--managed-editor-families` and optional `--family-pattern`, without inferring
  registration, save offsets, or serializers.
- Summarizes stable named title namespaces with `--managed-named-namespaces`,
  excluding obfuscated/compiler-generated names while retaining the evidence
  boundary for follow-on editor reconstruction.
- Reports REA-observed guarded methods with `--managed-guarded-methods`,
  identifying bodies containing a throw and no observed return opcode without
  executing or bypassing those methods.
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
- `--device-list DIRECTORY` provides a bounded, read-only listing of one
  host-visible directory with relative paths and basic entry metadata; paths
  are rejected when they escape the selected root.
The desktop front end exposes the same read-only inventory action.

`DeviceBinding` exposes the observed signed-64-bit `DeviceSize` property
through an explicit provider boundary; it never opens or enumerates a
physical device.

`WindowsDeviceIoProvider` and `DeviceIoBinding` expose the REA-observed
`CreateFile`/`DeviceIoControl` boundary for an explicitly supplied Windows
device path. The adapter requests no generic-write access, but IOCTL safety
semantics remain the caller's responsibility. FATX command codes, device
identity, and Xbox filesystem semantics remain unresolved.

The recovered DNG/HVM declarations are exposed through an explicit
`NativeRuntimeBinding` provider boundary. It never loads the original runtime
implicitly and leaves native argument semantics to the supplied provider.
`PowerShellNativeRuntimeProvider` adds an explicit path-bound bridge through a
matching Windows PowerShell host, preserving raw boolean/native-integer return
values without inferring the native handle or string protocol.

RSA signing remains behind an authorized signing-provider boundary. The
library supports detached signatures over caller-labeled development regions,
and can sign the observed CON package region with `--sign-stfs-package` when
the caller supplies an RSA private key whose modulus matches the package
certificate. This clean-room project does not contain private Xbox/Microsoft
signing keys and does not claim that a rewritten package is console-valid
under retail policy.

`--sign-written-package OUTPUT --private-key-json KEY` composes with
`--write` or `--in-place`: after each completed mutation, it signs the exact
CON bytes written to the mutation target and verifies the resulting package
signature into the separate output path.

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
python -m work.horizon_clone C:\path\to\profile.con --historical-account-inspect --historical-account-key-hex e1bc159c73b1eae9ab3170f3ad47ebf3
python -m work.horizon_clone C:\path\to\profile.con --historical-account-edit account-edit.json --historical-account-key-hex e1bc159c73b1eae9ab3170f3ad47ebf3 --write edited-profile.con
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
python -m work.horizon_clone C:\path\to\profile.con --xdbf-file 4D53082D.gpd --achievement 12 --gamerscore 1000 --achievement-flags 1 --achievement-unlock-utc 2024-12-18T00:52:13.512000Z --write edited-achievement.con
python -m work.horizon_clone C:\path\to\profile.con --xdbf-file FFFE07D1.gpd --xdbf-remove 106 --write edited-profile.con
python -m work.horizon_clone extracted\FFFE07D1.gpd --achievement 5 --gamerscore 1000 --achievement-flags 1 --write achievement.gpd
python -m work.horizon_app
```

For local fixture-backed testing, set `HORIZON_PROFILE_FIXTURE` to a profile/container path you control:

```powershell
$env:HORIZON_PROFILE_FIXTURE = 'C:\path\to\profile-fixture'
python -m work.horizon_clone $env:HORIZON_PROFILE_FIXTURE --output report.json
```

