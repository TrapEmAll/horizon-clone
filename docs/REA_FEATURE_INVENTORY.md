# REA feature inventory

This is a clean-room planning inventory derived from static metadata of the
authorized Horizon 2.9.0.0 artifact. It is not copied implementation code.

The inspected managed assembly contained 7,693 types and 37,401 methods. The
observed high-level areas include:

- profile metadata and profile editing;
- device exploration and save management;
- achievement and gamerscore views;
- Skyrim package-editor types;
- Gears of War 3 package-editor types;
- a large Halo variant/editor surface;
- save entries, content metadata, thumbnails, and game-specific models.

The current implementation covers the shared STFS/XDBF substrate, including
capacity-bounded mutation/repacking and complete three-level STFS hash-tree
rehashing/verification, plus a provider-oriented mutation/signing boundary.

The profile layer now aggregates the authenticated achievement fields across
all parseable embedded GPDs, exposing entry counts, raw gamerscore totals, and
nonzero flag counts. Flag-bit meanings are deliberately not inferred.

It also includes an evidence-only managed-surface exporter. Given the retained
JSON bundle produced by REA's `inspect_managed_members`, it reports the
authenticated artifact identity and can filter observed type, field, and method
records locally. This preserves build-local token identity and does not load or
execute Horizon.exe.
It does not yet claim parity for the game-specific editors above. Each editor
requires format fixtures and behavioral tests before it can be implemented
without guessing opaque fields.

The current title-specific increment publishes the observed Skyrim enum names
(`ShoutEnums`, `PerkEnums`, and `MagicEnums`) and an evidence-qualified summary:
all three use an observed `i4` backing field, with 27, 273, and 295 named
members respectively. A metadata-only Constant-table extractor recovered their
numeric values from the authenticated Horizon assembly; save-file offsets and
mutation behavior remain unresolved. The Gears `EntryID` catalog now likewise
records its observed declaring type, 1,139 named members, and 1,139
authenticated Constant-table values; save offsets remain unresolved.

The shared managed-member evidence also exposes `ProfileLoadout` with its
`All_Loadouts` member and `SaveEntryCategory` with observed audio, graphics,
controls, game, campaign, campaign-level, and unknown-category labels. The
authenticated Constant table recovers values 0 through 10 for
`SaveEntryCategory`; package offsets and mutation behavior remain unresolved.

The same Constant table recovers the global `XGearSlot` values (`Null=0`,
`Hat=10`, `Shirt=11`, `Boots=12`, `Pants=13`). These are metadata values, not
proof of a complete title save layout.

The retained member evidence identifies the six `Horizon.ProfileData` fields
(`FromDevice`, `XUID`, `Gamertag`, `Gamerpicture`, `ProfileId`, and `Favorite`)
and their managed types. The clone exposes that contract as metadata while
leaving the opaque Account-file serialization unresolved.

Field-access coverage is intentionally conservative: the retained static
member inventory observes only a `Favorite` field read for this type and does
not expose an Account serializer or field offsets. The clone therefore enforces
only the observed managed types and unsigned 64-bit ranges in its metadata
model; it does not pretend that this validates or rewrites the opaque Account
payload.

The retained evidence contains no managed `Account` type, Account serializer,
Account field layout, or Account-specific call edge. The supplied 404-byte
`Account` entry is therefore an opaque STFS payload; same-size replacement is
supported as a container operation, not as a reconstructed profile serializer.

`AccountCodec` now connects that opaque payload to the explicit class3 provider
boundary. It validates decrypt/encrypt buffer contracts and supports authorized
provider round trips, but does not interpret the decrypted Account layout or
persist key material.

The same evidence identifies two zero-argument `Horizon.ProfileData` resource
getters, `get_GoWJ_Thumb_New` and `get_GrayDot`, both returning unresolved
managed type `class:957`. They are exposed as declaration metadata only; no
bitmap format or Account-file relationship is inferred.


The shared STFS report also exposes public certificate descriptors, signature
byte digests, and all 16 license slots. A public-key probe against the supplied
fixture did not produce a valid PKCS#1 verification block from the apparent
modulus/signature fields, and REA did not authenticate the signed-region
protocol. The clone therefore deliberately does not guess a package-signature
layout, verify, or forge console signatures.

An additional retained-member audit found no authenticated Horizon-managed
STFS entry timestamp, creation-time, or file-attribute contract. The clone
therefore continues to expose the observed directory/name/size/block fields
without assigning semantics to the remaining file-table bytes.

REA's managed native-boundary inspection records 14 module references and 54
P/Invoke declarations. The most relevant editor boundaries are
`class3.dll`'s `RtsSaveEncrypt`/`RtsSaveDecrypt`, LZO compression imports,
device `CreateFile`/`DeviceIoControl`, and `Horizon.dll`/`HVMRun64.dll`
`DNG_Runtime`, `RunHVM`, and `GetUserString` imports. The clone exposes these
as a declaration-only native-surface report. Managed signatures are recovered
for the save-crypto, LZO, runtime, and user-string declarations, but parameter
semantics and native protocols are not inferred. The retained call-edge evidence does resolve the
obfuscated managed `Startup` method to both runtime checks and `CheckString`
to both user-string exports; it also shows `ZYXDNGuard` initializing LZO.

The member inventory also exposes a device-exploration surface: thumbnail
properties for `DeviceExplorer`, `FatxUSB_24`, `TestDrive`, and `TestDrive2`,
plus `get_DeviceSize`/`set_DeviceSize` with an `i8` value. These declarations
are now available through `--device-surface`; device enumeration, FATX/USB
behavior, and IOCTL semantics remain unresolved.

The clone now provides `--device-inventory` for the separately verifiable
read-only host-volume portion of this surface. It reports logical-drive type,
label, filesystem, serial, and capacity when Windows exposes them, while
keeping Xbox-specific FATX and IOCTL behavior unresolved.

`DeviceBinding` models the observed signed-64-bit `DeviceSize` getter/setter
behind an explicit provider. It does not enumerate devices, open USB/FATX
handles, or infer IOCTL semantics.

`NativeRuntimeBinding` provides the recovered `CheckRuntime`, `RunHVM`, and
`GetUserString` calls as an explicit provider boundary. No provider is bundled;
the binding refuses implicit DLL loading and preserves the unresolved native
argument semantics.

`NativeSaveBinding` now models the recovered `RtsSaveDecrypt` and
`RtsSaveEncrypt` buffer shapes, including the `u4&` output-length argument.
It requires an explicit caller-supplied provider, validates the observed
integer/buffer types, and does not load `class3.dll` or claim the native
algorithm, key format, or output semantics.

`LzoBinding` models the four recovered LZO declarations and their `i4&`
output-length argument. It requires an explicit provider and does not load
`lzo.dll` or claim that a particular provider reproduces Horizon's codec
configuration.

`LzoCodec` now adds a high-level validated buffer bridge over that binding. It
does not select a provider, infer work-memory requirements, or claim that an
arbitrary provider matches Horizon's compression configuration.

REA counted 7,693 managed types overall, including 3 Skyrim types, 1 Gears of
War 3 type, and 103 Halo general-class types. The clone exposes the retained
names through catalog-only APIs; they do not imply editor behavior or
package-format parity.

The retained metadata also contains seven additional catalog-only title
families: Dragon Ball Xenoverse (1 type), Code Veronica X (1), Devil May Cry
(1), Ninja Gaiden 3 (2), State of Decay (1), Castle Crashers (1), and Saints
Row (3). Together they contribute 10 types and 150 observed fields; their
authenticated field names are now exposed, but enum values, layouts, and
mutation behavior remain unresolved. REA observed an `i4` `value__` backing
field for each of these 10 types; the report separates that field from the
named-member counts.

The clone's `--resource-surface` inspection command reports 206 managed
resource metadata records: 205 embedded payloads and one non-embedded,
unresolved record. Resource names are largely obfuscated and the evidence only
establishes aggregate counts and payload digests; the clone does not copy,
execute, or assign those resources to UI features.

The retained Halo member evidence further counts 1,102 methods, 175 getter
methods, 168 setter methods, and 140 unique property names across the
general-class surface. 135 properties have both accessors; five are getter-only
(`c511c...`, `EngineVariant`, `Is_Currently_Custom`, `IsValid`, and `RealArray`).
The clone exposes these coverage counts and exact property names in the Halo
catalog report. Return types and the largest declaring-type groups are exposed
as metadata; save offsets and mutation behavior remain unresolved.

## Security observations

REA’s managed static evidence for the shipped executable records debugger and
IL-inspection-related metadata attributes and a `ZYXDNGuarder` type. These are
recorded as observations only. The reconstruction does not execute Horizon,
patch its protections, or implement anti-debugging bypasses.

The retained member evidence for the same SHA-256-bound executable identifies
three calls from the obfuscated `ZYXDNGuard` type to
`System.Reflection.Assembly.GetExecutingAssembly`. It does not, in the
available managed call-edge inventory, establish calls to
`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, or an equivalent debugger
API. Accordingly, the clone treats the guard as an anti-analysis observation,
not as a recovered editor feature or a behavior to reproduce.

