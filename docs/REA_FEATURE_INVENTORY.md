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
It does not yet claim parity for the game-specific editors above. Each editor
requires format fixtures and behavioral tests before it can be implemented
without guessing opaque fields.

The current title-specific increment publishes the observed Skyrim enum names
(`ShoutEnums`, `PerkEnums`, and `MagicEnums`). The retained REA metadata did
not expose their constant values or save-file offsets, so those remain explicit
unknowns rather than inferred mutations.

The shared managed-member evidence also exposes `ProfileLoadout` with its
`All_Loadouts` member and `SaveEntryCategory` with observed audio, graphics,
controls, game, campaign, campaign-level, and unknown-category labels. Their
numeric values and binary offsets remain unresolved for the same reason.

The retained member evidence identifies the six `Horizon.ProfileData` fields
(`FromDevice`, `XUID`, `Gamertag`, `Gamerpicture`, `ProfileId`, and `Favorite`)
and their managed types. The clone exposes that contract as metadata while
leaving the opaque Account-file serialization unresolved.


The shared STFS report also exposes public certificate descriptors, signature
byte digests, and all 16 license slots. It deliberately does not verify or
forge console signatures.

## Security observations

REA’s managed static evidence for the shipped executable records debugger and
IL-inspection-related metadata attributes and a `ZYXDNGuarder` type. These are
recorded as observations only. The reconstruction does not execute Horizon,
patch its protections, or implement anti-debugging bypasses.

