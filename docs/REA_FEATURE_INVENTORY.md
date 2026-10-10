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

