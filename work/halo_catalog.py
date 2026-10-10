"""Observed Halo general-class type names from REA metadata.

This catalog records stable managed type names only. It does not claim numeric
field layouts, save offsets, or title-specific mutation behavior.
"""

from __future__ import annotations

from collections.abc import Mapping


_HALO_GENERAL_CLASS_TYPES = (
    "GameVariant",
    "Halo4GameVariant",
    "HaloReachGameVariant",
    "GameEngineVariant",
    "MegaloEngineVariant",
    "Halo4MegaloEngineVariant",
    "HaloReachMegaloEngineVariant",
    "EngineBaseVariant",
    "Halo4EngineBaseVariant",
    "HaloReachEngineBaseVariant",
    "MegaloValueProperty",
    "MegaloValueTitle",
    "MegaloMenuTitle",
    "MegaloCollectionName",
    "StringTableInfo",
    "StringTableBuffer",
    "StringTableStringItem",
    "StringTable",
    "OptionalRealArrayInfo",
    "OptionalRealArray",
    "GameOptionsMisc",
    "Halo4GameOptionsMisc",
    "HaloReachGameOptionsMisc",
    "Halo4PrototypeOptions",
    "GameOptionsRepawning",
    "Halo4GameOptionsRespawning",
    "HaloReachGameOptionsRespawning",
    "Halo4GameOptionsPowerup",
    "Halo4GameOptionsPowerupSet",
    "Halo4GameOptionsTraits",
    "HaloReachGameOptionsPowerups",
    "Halo4RequisitionItem",
    "GameOptionsSingleTeamOptions",
    "Halo4GameOptionsSingleTeamOptions",
    "HaloReachGameOptionsSingleTeamOptions",
    "GameOptionsTeamOptions",
    "GameOptionsLoadout",
    "Halo4GameOptionsLoadout",
    "HaloReachGameOptionsLoadout",
    "GameOptionsLoadoutTier",
    "Halo4GameOptionsOrdnanceArea",
    "Halo4GameOptionsOrdnanceOptions",
    "MegaloVariable",
    "MegaloToken",
    "MegaloTokens",
    "MegaloVariableData",
    "MegaloVariableDataWithVar",
    "MegaloVariableDataNumeric",
    "MegaloVariableDataTimer",
    "MegaloVariableDataTeam",
    "MegaloVariableDataPlayer",
    "MegaloVariableDataObject",
    "IMegaloEngineDefinition",
    "MegaloVariantUserDefinedOptionValueElement",
    "MegaloVariantUserDefinedOptionValue",
    "MegaloVariantUserDefinedOption",
    "MegaloVariantExceptions",
    "MegaloVariantUnknownFloatArray",
    "Halo4MegaloVariantLoadout",
    "Halo4MegaloVariable",
    "Halo4MegaloToken",
    "Halo4MegaloTokens",
    "Halo4MegaloVariableDataNumeric",
    "Halo4MegaloVariableDataTeam",
    "Halo4MegaloVariableDataPlayer",
    "Halo4MegaloVariableDataObject",
    "MegaloVariableReach",
    "HaloReachMegaloTokenType",
    "HaloReachMegaloToken",
    "HaloReachMegaloTokens",
    "PlayerTraits",
    "Halo4PlayerTraits",
    "HaloReachPlayerTraits",
    "PlayerTraitsDamage",
    "Halo4PlayerTraitsDamage",
    "HaloReachPlayerTraitsDamage",
    "PlayerTraitsWeapons",
    "Halo4PlayerTraitsWeapons",
    "HaloReachPlayerTraitsWeapons",
    "PlayerTraitsMovement",
    "Halo4PlayerTraitsMovement",
    "HaloReachPlayerTraitsMovement",
    "Halo4PlayerTraitsAppearanceColor",
    "Halo4PlayerTraitsAppearanceModelVariant",
    "PlayerTraitsAppearance",
    "Halo4PlayerTraitsAppearance",
    "HaloReachPlayerTraitsAppearance",
    "PlayerTraitsSensors",
    "Halo4PlayerTraitsSensors",
    "HaloReachPlayerTraitsSensors",
    "MegaloVariantPlayerTraits",
    "HaloInterfaceLayout",
    "HaloInterfaceMegalo",
    "HaloInterfaceStrings",
    "HMegaloPageLink",
    "HMegaloValue",
    "HMegaloUserOption",
    "HMegaloUserOptions",
    "HMegaloOptionalReal",
    "HMegaloOptionalRealArray",
    "HMegaloColorValue",
    "HMegaloOptions",
    "HMegaloStrings",
)


def halo_general_class_types() -> tuple[str, ...]:
    return _HALO_GENERAL_CLASS_TYPES


_HALO_GENERAL_CLASS_FIELD_COUNTS = {
    "EngineBaseVariant": 10,
    "GameVariant": 3,
    "Halo4EngineBaseVariant": 21,
    "Halo4MegaloEngineVariant": 9,
    "HaloReachEngineBaseVariant": 6,
    "HaloReachMegaloEngineVariant": 8,
    "HMegaloOptions": 13,
    "HMegaloStrings": 18,
    "HMegaloColorValue": 9,
    "HMegaloPageLink": 7,
    "HMegaloValue": 18,
    "HMegaloOptionalReal": 8,
    "HMegaloOptionalRealArray": 7,
    "HMegaloUserOption": 8,
    "HMegaloUserOptions": 3,
    "HaloInterfaceLayout": 3,
    "HaloInterfaceMegalo": 2,
    "HaloInterfaceStrings": 1,
    "MegaloEngineVariant": 15,
    "GameOptionsLoadout": 1,
    "GameOptionsLoadoutTier": 1,
    "GameOptionsMisc": 7,
    "GameOptionsRepawning": 12,
    "GameOptionsSingleTeamOptions": 1,
    "GameOptionsTeamOptions": 3,
    "Halo4GameOptionsLoadout": 9,
    "Halo4GameOptionsMisc": 7,
    "Halo4GameOptionsOrdnanceArea": 16,
    "Halo4GameOptionsOrdnanceOptions": 22,
    "Halo4GameOptionsPowerup": 2,
    "Halo4GameOptionsPowerupSet": 2,
    "Halo4GameOptionsRespawning": 3,
    "Halo4GameOptionsSingleTeamOptions": 14,
    "Halo4GameOptionsTraits": 5,
    "Halo4MegaloToken": 1,
    "Halo4MegaloTokens": 3,
    "Halo4MegaloVariableDataNumeric": 1,
    "Halo4MegaloVariableDataObject": 1,
    "Halo4MegaloVariableDataPlayer": 1,
    "Halo4MegaloVariableDataTeam": 1,
    "Halo4MegaloVariantLoadout": 2,
    "Halo4PlayerTraitsAppearance": 8,
    "Halo4PlayerTraitsAppearanceColor": 4,
    "Halo4PlayerTraitsAppearanceModelVariant": 2,
    "Halo4PlayerTraitsDamage": 6,
    "Halo4PlayerTraitsMovement": 6,
    "Halo4PlayerTraitsSensors": 8,
    "Halo4PlayerTraitsWeapons": 16,
    "Halo4PrototypeOptions": 6,
    "Halo4RequisitionItem": 13,
    "HaloReachGameOptionsLoadout": 5,
    "HaloReachGameOptionsMisc": 2,
    "HaloReachGameOptionsPowerups": 10,
    "HaloReachGameOptionsRespawning": 1,
    "HaloReachGameOptionsSingleTeamOptions": 8,
    "HaloReachMegaloToken": 1,
    "HaloReachMegaloTokenType": 5,
    "HaloReachMegaloTokens": 3,
    "HaloReachPlayerTraitsAppearance": 2,
    "HaloReachPlayerTraitsDamage": 10,
    "HaloReachPlayerTraitsMovement": 5,
    "HaloReachPlayerTraitsSensors": 2,
    "HaloReachPlayerTraitsWeapons": 7,
    "MegaloToken": 1,
    "MegaloTokens": 4,
    "MegaloVariable": 4,
    "MegaloVariableDataNumeric": 1,
    "MegaloVariableDataObject": 1,
    "MegaloVariableDataPlayer": 1,
    "MegaloVariableDataTeam": 2,
    "MegaloVariableDataWithVar": 1,
    "MegaloVariantExceptions": 3,
    "MegaloVariantPlayerTraits": 6,
    "MegaloVariantUnknownFloatArray": 2,
    "MegaloVariantUserDefinedOption": 3,
    "MegaloVariantUserDefinedOptionValue": 6,
    "MegaloVariantUserDefinedOptionValueElement": 3,
    "PlayerTraits": 5,
    "PlayerTraitsAppearance": 3,
    "PlayerTraitsMovement": 1,
    "PlayerTraitsSensors": 1,
    "PlayerTraitsWeapons": 5,
    "MegaloCollectionName": 2,
    "MegaloMenuTitle": 1,
    "MegaloValueProperty": 2,
    "MegaloValueTitle": 1,
    "OptionalRealArray": 3,
    "OptionalRealArrayInfo": 6,
    "StringTable": 3,
    "StringTableBuffer": 6,
    "StringTableInfo": 5,
    "StringTableStringItem": 3,
}


def halo_general_class_field_counts() -> dict[str, int]:
    return dict(_HALO_GENERAL_CLASS_FIELD_COUNTS)


# Full decoded field-type projection retained directly from REA's managed
# metadata. REA decoded 489 fields across 92 named classes; the remaining
# observed classes had no decoded fields in this projection.
# Names and ``class:N`` identities are build-local; these are not save offsets.
_HALO_GENERAL_CLASS_FIELD_TYPES = {
  "EngineBaseVariant": {
    "c161901c49ffb6bce7f14e7b4df7344e6": "bool",
    "c19691439e92eb32f39128411a58c5904": "bool",
    "c1d74bc1db977cc829718fb3f3da6667f": "bool",
    "c1dd197ce967c8b9aaa2a8c1dad03f9cb": "bool",
    "c203f480da0991cc5f4b8cc74276b0a0f": "bool",
    "c2c93664df65fe1777f06d55903369638": "bool",
    "c3b207bff2552518a500c4434e3c0415f": "class:3112",
    "c49f280eae530dfde667800d5f403528a": "class:3456",
    "c693784662c589f7640635968c1d7e205": "u1",
    "c87701fa4ca39f77673c57efc8eb14050": "class:3128"
  },
  "GameOptionsLoadout": {
    "cf2f18013de0aa6933ee228e0253768cc": "i4"
  },
  "GameOptionsLoadoutTier": {
    "c892637d4d36afca4b586696fda87505b": "class:3176[]"
  },
  "GameOptionsMisc": {
    "c13ebb55f7d2e87fb7b5086229393615f": "bool",
    "c388d15697dde36977ee579c9fb4abdd5": "u1",
    "c66b46e90817726da52a73cc844fc808f": "u1",
    "c94670c5e8cf7db9453849cee7299c795": "u1",
    "c99eb7b250edba144f5da7e785fd4e1de": "bool",
    "cdfa90771c8db53edf11bb856a0d00eb0": "bool",
    "cf67d63092ec43388ac1d2b73c5c62c63": "bool"
  },
  "GameOptionsRepawning": {
    "c0146204c921003f3aa64f80993656254": "u1",
    "c13ebb55f7d2e87fb7b5086229393615f": "bool",
    "c183ae02fca9e75ec3df3df249079407f": "u1",
    "c62c6cf9ba74d6858ba0ad9f0f5a8f797": "u1",
    "c731e1decc4da38f8c4cd2e396d32b29d": "u1",
    "c831b819794bc0515360efc905399828e": "u1",
    "ccb41d710a601a125086650da03aaf1c9": "u1",
    "cd404245ced883f5a37b22707c3a4f0d1": "class:3312",
    "cd50217abd120842b80f6f01047cde6ea": "u1",
    "cda0909dddfac2ee20f7890af03c90cf2": "bool",
    "cdfa90771c8db53edf11bb856a0d00eb0": "bool",
    "cf67d63092ec43388ac1d2b73c5c62c63": "bool"
  },
  "GameOptionsSingleTeamOptions": {
    "c6240d9fbde014b413300d4308e62bf50": "class:3100"
  },
  "GameOptionsTeamOptions": {
    "c16cc5cf9e3b5592dc76dd6c63b64f746": "u1",
    "c1cd1f4ef580f7c70ae02751f3f255506": "class:3160[]",
    "cab30717b639e656b08084cf14e8bdf26": "u1"
  },
  "GameVariant": {
    "c7a62e9b2608ab1560f963117c637c401": "i4",
    "ce88aac0dcfe45cad4e217755bdd9365a": "string",
    "cfdc3d519a20a58cb100dd06a79fc138a": "class:3044"
  },
  "HMegaloColorValue": {
    "c03a3e9f354e5a727a0df368d4cbdabcf": "class:777",
    "c1fe927c68c0ad489f4313e4999c47084": "class:5560",
    "c436816eef76cb887b4d435761f454316": "class:3072",
    "c48276d611f314f014aacadabba70ffd1": "class:369",
    "c92eb0258cb0fd7d58f633d2f1fb072b5": "class:2369",
    "c982e8ca61e2945197f4fac4aaad2cf4a": "class:3404",
    "ccba7fa73d3f67c2169cd6ee071c9fe98": "class:473",
    "ccc4c30edc5a3be3bac335b027b365896": "class:161",
    "cd321dfeef87ee970cb89020630a30689": "class:3436"
  },
  "HMegaloOptionalReal": {
    "c03a3e9f354e5a727a0df368d4cbdabcf": "class:777",
    "c48276d611f314f014aacadabba70ffd1": "class:369",
    "c75900f4eef5969446aa1e79617fb3c90": "bool",
    "c7db2dce639e9ec411f13091bd5d8d1e0": "class:501",
    "c7f039d63c5f27cfc50c5e71964b38bfc": "class:3428",
    "c823ac5803f6193adecf3001db75a2cf6": "class:6088",
    "ccba7fa73d3f67c2169cd6ee071c9fe98": "class:473",
    "cee6b7443c12b7d874b8c33f1dec30dc0": "class:161"
  },
  "HMegaloOptionalRealArray": {
    "c03a3e9f354e5a727a0df368d4cbdabcf": "class:777",
    "c1fe927c68c0ad489f4313e4999c47084": "class:5560",
    "c436816eef76cb887b4d435761f454316": "class:3072",
    "c979b20a34503ea95fe808e1525666b55": "class:2365",
    "c982e8ca61e2945197f4fac4aaad2cf4a": "class:3404",
    "ccba7fa73d3f67c2169cd6ee071c9fe98": "class:473",
    "cd321dfeef87ee970cb89020630a30689": "class:3436"
  },
  "HMegaloOptions": {
    "c03a3e9f354e5a727a0df368d4cbdabcf": "class:777",
    "c1e3da8e4bf0bdc15d65b41947a7d8942": "class:3032",
    "c282fb99c2355a2db3e06fa191887bc40": "class:3396",
    "c2b7f4c9bf10944a5a38e9688cb838f24": "valuetype:3444",
    "c38ed19d6b8fba27db8752c1495ba6a0f": "class:125",
    "c6d9841228fbb50ccf237947f26a2eda0": "class:217",
    "c979b20a34503ea95fe808e1525666b55": "class:2365",
    "c982e8ca61e2945197f4fac4aaad2cf4a": "class:3404",
    "cafe5c7f4d7572bc2cf9179f3998a4181": "class:3400",
    "cbaec4757654f5c350deb2c64e22aa0f7": "class:113",
    "cd04846c379a4c5676b9fd70d3b4712c7": "class:2365",
    "cf479f3bdffe4580661de3acc53cb0b82": "class:2417"
  },
  "HMegaloPageLink": {
    "c03a3e9f354e5a727a0df368d4cbdabcf": "class:777",
    "c48276d611f314f014aacadabba70ffd1": "class:369",
    "c8db951cf9092e5b8539485be9cc2f9d4": "class:6188",
    "c9ef3e6a6e9ef2a785f59b57d58e5da10": "class:5556",
    "ca158290c76bf6dedd419feafbef3889a": "class:3436",
    "ccba7fa73d3f67c2169cd6ee071c9fe98": "class:473",
    "ce40a94846a93ea1f43d3e0854f3c98dc": "class:129"
  },
  "HMegaloStrings": {
    "c03a3e9f354e5a727a0df368d4cbdabcf": "class:777",
    "c0f57aede50944eb304796837eed4fc88": "class:369",
    "c1b8604d3773af4497d1d99ab70cde812": "class:129",
    "c1e3da8e4bf0bdc15d65b41947a7d8942": "class:3032",
    "c282fb99c2355a2db3e06fa191887bc40": "class:3396",
    "c33042fe5985cd9996e97aa3fd57706cf": "class:1953",
    "c3f106bdec57fbfccd9f5a70667095343": "class:369",
    "c48ee51cb94bc214ced563faf0e855536": "class:165",
    "c5faccd1ee1248ac730be957cf53b7a34": "class:209",
    "c8d023a211da434a3f776b705b79e0d74": "class:197",
    "c8d8a91a138043acd0e67a4e040029450": "class:369",
    "c982e8ca61e2945197f4fac4aaad2cf4a": "class:3404",
    "ca2a0d4c34a8b6f35b0338ba271672e3e": "class:129",
    "ca541f1b453a937e4cc106b66a21ba813": "valuetype:3444",
    "cacdf5412a3dd55fda99545fc0523dd3c": "class:165",
    "cafe5c7f4d7572bc2cf9179f3998a4181": "class:3400",
    "cb6d7251b0f37c859cfcc61e4152806c7": "class:1953"
  },
  "HMegaloUserOption": {
    "c03a3e9f354e5a727a0df368d4cbdabcf": "class:777",
    "c0aa1b3318cdf9ca342c7ad971e5609f4": "class:3252",
    "c19dd27b71a593a7c98b046a62aa1cd35": "class:3420",
    "c1e3da8e4bf0bdc15d65b41947a7d8942": "class:3032",
    "c48276d611f314f014aacadabba70ffd1": "class:369",
    "c906ba2080113a0cc13030fd1e5b28cba": "class:165",
    "cc9a81e7cf68109e3c00c9f81a3f05249": "class:517",
    "ccba7fa73d3f67c2169cd6ee071c9fe98": "class:473"
  },
  "HMegaloUserOptions": {
    "c03a3e9f354e5a727a0df368d4cbdabcf": "class:777",
    "c1e3da8e4bf0bdc15d65b41947a7d8942": "class:3032",
    "cd321dfeef87ee970cb89020630a30689": "class:3436"
  },
  "HMegaloValue": {
    "c03a3e9f354e5a727a0df368d4cbdabcf": "class:777",
    "c18f0deb914e902e9c17a2860b72207ab": "bool",
    "c1fe927c68c0ad489f4313e4999c47084": "class:5560",
    "c29c4ea844048134e383bf6daa9b631e3": "class:1889",
    "c358012b51951ad6de2b3e5a2ac36a486": "bool",
    "c436816eef76cb887b4d435761f454316": "class:3072",
    "c48276d611f314f014aacadabba70ffd1": "class:369",
    "c6e5fe922daf2948556d93042bd1bb02d": "class:165",
    "c75900f4eef5969446aa1e79617fb3c90": "bool",
    "c906ba2080113a0cc13030fd1e5b28cba": "class:165",
    "c982e8ca61e2945197f4fac4aaad2cf4a": "class:3404",
    "cbf86c5279abeb92bc9958bdb99835cce": "class:209",
    "cc9a81e7cf68109e3c00c9f81a3f05249": "class:517",
    "ccba7fa73d3f67c2169cd6ee071c9fe98": "class:473",
    "cd321dfeef87ee970cb89020630a30689": "class:3436",
    "cdf593a5b58825c7c7c7f2df95b5e4f27": "bool",
    "ce40a94846a93ea1f43d3e0854f3c98dc": "class:129",
    "cede85f7a9e52a90376831cc0b4352594": "class:501"
  },
  "Halo4EngineBaseVariant": {
    "c0ac0afc8f89b912e5b26aa42f374a9b3": "class:3172",
    "c0f39e25189d9138c2dea9e98f8ca20dc": "bool",
    "c111c6d791ea6f692daae444f5953d21c": "bool",
    "c16ba123387dda8e882644827650e4444": "bool",
    "c4810075e8115bf626acdf193dc5ce480": "bool",
    "c4828ce99b98f33384ed59b66bc254929": "i4",
    "c52c73d6db9c40968c18852c4f7509e4c": "bool",
    "c601ba19dbe4ba2c2ef7541c363262d27": "bool",
    "c79882ecdc8b414ce8353d604c3027d27": "bool",
    "c7e9496d8e5d57565dd3c47bc19d188ef": "class:3188[]",
    "c87da6b04210bc0b902c5dba5cb31ee54": "class:3148",
    "ca1153aa7afaa849d0f03183a54a770e9": "u4",
    "ca1c8acd4dc8e96c8f90f8a1c2036ae7b": "i4",
    "ca4e0f864223f380c90d10d9bce3e6dc9": "bool",
    "cc5c53522d80d059665d67e3b4253eee1": "bool",
    "cce552bdfcd52891efc4eda7dc4549ed2": "class:3196",
    "cd4659ed9c0335d72fc613453fa48239e": "bool",
    "cd8d890cd91a3acdfdf193f41466e6f89": "bool",
    "ce216990a54370df7ae25a3ec87842fa4": "class:3124",
    "cee5cf4c0df549d4805e35d67013ff370": "bool"
  },
  "Halo4GameOptionsLoadout": {
    "c1200466d0cd47a5afe532ca586b87ba3": "i1",
    "c1b93fa5435d31221fc0a492206e213cf": "i1",
    "c252d1a2dc805409dfc0d092fd51bc8ea": "bool",
    "c4504a009084e1a2c1dae532c718afc7c": "i1",
    "c4a5c925d9ae49b98cc935c503fcbab32": "u1",
    "c64d8f7df8e22e79e00e725bf12286ef3": "i1",
    "c745fd14a6cf1afd2358609d4a9758cbd": "i1",
    "c878f93400bb81f4f1fc853ab047cf148": "i1",
    "c904b7deda945a5a465c69f0bd26005ee": "i1"
  },
  "Halo4GameOptionsMisc": {
    "c25c0c6b5aff0305fe12d6c8f37d99d61": "u1",
    "c378acbf5bbfcb0f684ee0c79b6a1199a": "bool",
    "c4a3517c5d61b22390c186bbf0f52b3a0": "bool",
    "c819318087bb2c0268d67222922b9e179": "bool",
    "c928ae96207762f5a07ffd5a0795dcaf1": "bool",
    "c99cbc068b89d5175775a90580927676a": "u1",
    "ca5eb8b2399a9a8c5cf4d73c9926c9cf9": "bool"
  },
  "Halo4GameOptionsOrdnanceArea": {
    "c100ebb680d6c1ab1e325defea484e0ad": "string",
    "c262f87bff98255e62e8ccf1f4d3a68bf": "string",
    "c33688af273d443ea0845b19877a135b0": "r4",
    "c3de0341ec37596870a202beb9d602777": "r4",
    "c3ec5a818d4a769c53657eb7e314a6fc4": "string",
    "c54e389b4d5a2aceb447eed4b1b0b9a91": "r4",
    "c64876a9bb8181e9f4938bd1cb4de8e36": "r4",
    "c7f63a607feb3b65b48bb2739bb919dea": "string",
    "c8782ba2ca861c6383132f71d09acf571": "string",
    "c929e24749f97cfa6f606aa533fca306e": "r4",
    "c954d2a0f0fe8e280ffbc76aebadac1ab": "string",
    "cb457117a9881a9ff78b818c1b1f3aef6": "r4",
    "cc7861681bc3f27bc423dbe8a5d76277c": "r4",
    "cca67cfde421fe5c0dfb4f1f78879fa40": "string",
    "cec4eddc49f404c382e3c9f8a46f35a3b": "r4",
    "cf81b1f413d1f085021d3f7a218247af7": "string"
  },
  "Halo4GameOptionsOrdnanceOptions": {
    "c0792edafef66d2df51b7c4abd783ef97": "class:3192",
    "c10db75c6bef9016c2a3ef5246ae4de32": "class:3192",
    "c112952c5c5b2f9a23c3027c5ff6d1ec2": "string",
    "c1fb5ea0e0bd881395ca5413775296fdc": "bool",
    "c1fce552c6e023474f01d23af74894afa": "bool",
    "c2906ff24225941922a25e922e9f998a3": "string",
    "c32053c1ec9d4deecaab9333034109860": "string",
    "c3d8106e35d6acc02df3a82fa7f09a89f": "u1",
    "c406e126a81388a50f6375a2ba5c7cd15": "bool",
    "c40d6d08a69c87cdfffefcf9cd9b90729": "i2",
    "c6d5d6ca2df3169514df08136eba2718f": "i2",
    "c72399363af350b3b8a578aeaad6ae215": "r4",
    "c7ab36a0ce2b17c26ddec4195096ee68c": "class:3192",
    "c7e96aec25fc87eb574e48e2bef729a42": "i2",
    "c8134bfd2901e34a418dd1ee0f63ae094": "bool",
    "c88f6e1773464a87e9bd4e9303bd2a164": "r4",
    "c8f82a629b39ffb633d5bc7323e5d5b53": "i2",
    "ca302272cf8e8de820506f25755a3f388": "bool",
    "cb133ef51c3cc73e591abb797c25579f0": "string",
    "cb69e460fdba01091ca5c68e038e7f079": "i2",
    "cbeacc13818658f9b65dd4632feaefd68": "bool",
    "cea983c6b84790b1e36b99aaf9b82a79a": "class:3192"
  },
  "Halo4GameOptionsPowerup": {
    "ca35fc1529ac14a1537012348349ff4d0": "u1",
    "cd404245ced883f5a37b22707c3a4f0d1": "class:3312"
  },
  "Halo4GameOptionsPowerupSet": {
    "c45b4cc1bd2b312ac15b669cda28c6a61": "class:3140",
    "cffae239c447c460fdf279df2f111f7ad": "class:3140"
  },
  "Halo4GameOptionsRespawning": {
    "c77067ba6fa65dca76a5ea98cb35446d4": "bool",
    "c832d9843dd5970e0fbca0eed500ed769": "u1",
    "c95dc68d58a6d29c24412b7a74d28db25": "u1"
  },
  "Halo4GameOptionsSingleTeamOptions": {
    "c2313b9179b3e66056e977d9293fbcfcf": "u1",
    "c23cec914062acab9bfb69925a55ee627": "u4",
    "c23f31f4eff12b878c8bdacc7e4ff61c4": "u1",
    "c3f0b08485f8eef912ffaf05f8822579e": "u1",
    "c5d428eaf422967b93b1785b92c441a9e": "i4",
    "c8f7d8fed96a85cda24395ccd5a5265a9": "u4",
    "cab30717b639e656b08084cf14e8bdf26": "u1",
    "cbeec4900da94616212cdeee7b3e85e86": "u1",
    "cd1f6587b5285e58be3609d905c2852ac": "u1",
    "ce1de0a279ab0870687cb2a4e67c1a0ab": "u4",
    "ce47721b37e821ef2f3c23fe4e70380c5": "u1",
    "cec29c6bed460e8d5f35b92e8d7ec7e5f": "u1",
    "cf5d2ba80a4f22867d989a18cbb8c8833": "u1",
    "cf723491fadbda4371b91a41d7cdbd5bb": "u4"
  },
  "Halo4GameOptionsTraits": {
    "c2e5c1e86d31db9f3ec83104d8e16d43d": "i1",
    "ca15a52cb973e3019370d721da30c096a": "class:3144[]",
    "ce40b56a88df837020717012eeb0f304d": "class:3312",
    "cf01cdc4d2653ef3ee2b298bb582edf69": "i1",
    "cf51bfa396872d921aeeb011cd5cc0cee": "i1"
  },
  "Halo4MegaloEngineVariant": {
    "c0ae28ba9526371faf022f2f1b60fafd8": "bool",
    "c64587f0f841c95160cc1f1a5334ce653": "bool",
    "c7e114ee00f1bda8eede0dc470871635e": "i4[]",
    "c7e72960214e16ef5041298a6b2d917ad": "i4[]",
    "ca4061d9c1d9ce55c84363a36c31cfb08": "class:3100",
    "ccc5712a1ef0ff8428fcb7817e5bc0d86": "i4[]",
    "ce3dbc94bb08c177d2afeabaf7b87d992": "bool[]",
    "ceae918faf00667d836356ff308f2c9ce": "bool"
  },
  "Halo4MegaloToken": {
    "c4b8b4a31d8e1e9f12f033e02c62dae4a": "class:3268"
  },
  "Halo4MegaloTokens": {
    "c54bfb249d9b21f4727e8d95456f4d5b5": "class:3272",
    "c853e0b9e66dc563a4ed7fa9231863e58": "class:3272",
    "cbef14ce1995b9ff727eb81b60ff3caba": "class:3272"
  },
  "Halo4MegaloVariableDataNumeric": {
    "c13ebb55f7d2e87fb7b5086229393615f": "bool"
  },
  "Halo4MegaloVariableDataObject": {
    "c13ebb55f7d2e87fb7b5086229393615f": "bool"
  },
  "Halo4MegaloVariableDataPlayer": {
    "c13ebb55f7d2e87fb7b5086229393615f": "bool"
  },
  "Halo4MegaloVariableDataTeam": {
    "c13ebb55f7d2e87fb7b5086229393615f": "bool"
  },
  "Halo4MegaloVariantLoadout": {
    "c2ea1d2214050da769c20a215931fc665": "u1",
    "cd6ff3ed44855104edaf09ab65506164d": "class:3180"
  },
  "Halo4PlayerTraitsAppearance": {
    "c1929bc0ddd79a58e227ca02b2d72d80d": "u1",
    "c4341f89d61d3c346df1cc67a8dc985e3": "i4",
    "c43a6e04b7d8231813247e076417c2b6f": "u1",
    "c73f9ad3e7af2f8729f50931f5a1d614e": "class:3108",
    "c77efb7a822a3803c6f1fdd2e9e474e12": "i4",
    "cbeec4900da94616212cdeee7b3e85e86": "class:3360",
    "cc08362a2af27b7f01de8863c45d4de70": "class:3364",
    "ce47721b37e821ef2f3c23fe4e70380c5": "class:3360"
  },
  "Halo4PlayerTraitsAppearanceColor": {
    "c02055f6f6be5d7d493d8aa53c2abeb5b": "u1",
    "c38cfb42564b331fefbcddc3430af3ab3": "u1",
    "c474df060d72af617d9884fdd683af632": "u1",
    "c57da3ed5caabbaa0c58546099ea20a54": "bool"
  },
  "Halo4PlayerTraitsAppearanceModelVariant": {
    "c460b5b0695f23fc78153ee5ce7046f8d": "bool",
    "c8e43c30bf3129d04e9337248f2d5db9e": "i1"
  },
  "Halo4PlayerTraitsDamage": {
    "c1d75a1a2a7baf3a87d1a8b48a9e2a730": "u1",
    "c6faf3695bed02b1e23479bb0209d1b7b": "u1",
    "c73f9ad3e7af2f8729f50931f5a1d614e": "class:3108",
    "c9f11cc86f066adaed151634d707eb188": "u1",
    "cb01bff026439ddcfcfe7459444a1cd6e": "u1",
    "cdbe212a4ea6c4b0569c40de96c80d4a6": "u1"
  },
  "Halo4PlayerTraitsMovement": {
    "c0d2472ba0b915471021186aa8b9d64c3": "u1",
    "c73f9ad3e7af2f8729f50931f5a1d614e": "class:3108",
    "cb9d357db0f59bb45ac877b8c35f0b880": "u1",
    "cd9433389a658e48ad9a6162f91a82b5b": "u1",
    "ce6400309da7edd5f5b423e57162909d6": "u1",
    "cf161776f0a8e9dbb43b3bcca6c350609": "u1"
  },
  "Halo4PlayerTraitsSensors": {
    "c22d4044399ed9b01c9db16443f17bee2": "u1",
    "c444002c3f01802586b68762d39a2951d": "u1",
    "c4aa6841e92cf62dfffa1eac34c3e5e34": "u1",
    "c5559d663058f1d42fdd5990affca0342": "u1",
    "c73f9ad3e7af2f8729f50931f5a1d614e": "class:3108",
    "c85fce970d060c279a7c1475452aaeb6d": "u1",
    "cc0a56e8ea9cf1662b550c66b4471fa89": "u1",
    "cc6f403c7d9217dc81cace50069fecdcf": "u1"
  },
  "Halo4PlayerTraitsWeapons": {
    "c0345cf0a1c172bb75d26b9568cb6a7fd": "i1",
    "c04778752c608fd16846ba02bf8993d4b": "u1",
    "c1860d863b3e0c7c407f00cfcae79703c": "u1",
    "c1d74bc1db977cc829718fb3f3da6667f": "i1",
    "c38246536722914cb66943b06ce6b3350": "i1",
    "c40708ad8680929a477cdb1020e22f971": "u1",
    "c73f9ad3e7af2f8729f50931f5a1d614e": "class:3108",
    "c7c55dd1a08a519730bff163329a752bc": "u1",
    "c89e897ad7021eb480ff91c3e8f2b1422": "i1",
    "c8a04485b7cf2024666d80123e914ea91": "u1",
    "c9629f52a61da38fc3f4baea4bf864aca": "i1",
    "ca6ffb8169266bae08f694081cec5baa6": "u1",
    "cc37bdeb39e4dc11a19c1d07dd151e10b": "i1",
    "ced4556e35c5f363d8c53d736193fe0f6": "u1",
    "cf5cd068cd36e9069581d7123c72583c9": "i1",
    "cf9f8f95f0f5c81fc8d49dab723ee249a": "i1"
  },
  "Halo4PrototypeOptions": {
    "c2ca2643d9a89a742249230070acd3ad7": "u1",
    "c3b5418a612ccdc01d534d5b8013b47a8": "u1",
    "c75026eda28e9daf26449d85534e0799d": "u1",
    "c92b9b2e79b997f9b4eed911083042edb": "bool",
    "cf230dc8b6d1e595c7b6f8d415328cb87": "u1",
    "cf3ba7eacf1f4441a6d47f65238157878": "u1"
  },
  "Halo4RequisitionItem": {
    "c1b93fa5435d31221fc0a492206e213cf": "i4",
    "c2fab5e99859be3eee35ee4cfe6b4b992": "u4",
    "c32740bb17b9aa810610b4f75aac22520": "i4",
    "c42d2f4cfa97c9e7e613bb1d389a26a22": "u4",
    "c5fd0e38e87edb21135acacf450935c62": "i4",
    "c6d35352a7d8df0a8589a06f26b379866": "i4",
    "c708a06752f3d9a1b08690dfee7b549d2": "u4",
    "c7fa465b9b4b7e9e3728d640818bbfbdb": "bool",
    "c9ff85d014be96897929454107d7d49c5": "u4",
    "cb133ef51c3cc73e591abb797c25579f0": "u4",
    "cb67dc613f92292a42a9bca38b148fbae": "u1",
    "cb8cb323181bb20629fb609bf1f7ece96": "i4",
    "cdc66187a6bea62c1a9037e8b620fc9ee": "u1"
  },
  "HaloInterfaceLayout": {
    "c4902dc53a110aa496111f065a415e4fc": "string"
  },
  "HaloInterfaceMegalo": {
    "c4902dc53a110aa496111f065a415e4fc": "string"
  },
  "HaloInterfaceStrings": {
    "c4902dc53a110aa496111f065a415e4fc": "string"
  },
  "HaloReachEngineBaseVariant": {
    "c0ac0afc8f89b912e5b26aa42f374a9b3": "class:3172",
    "c16cc5cf9e3b5592dc76dd6c63b64f746": "u1",
    "c7e9496d8e5d57565dd3c47bc19d188ef": "class:3188[]",
    "cbd46af4a9f3858af9c127a480f1505b8": "bool",
    "cce7b32641050cabe87d685c6e279bd93": "u1",
    "cf7f043a2f9767b1bfbdbc0fc3477acef": "class:3152"
  },
  "HaloReachGameOptionsLoadout": {
    "c252d1a2dc805409dfc0d092fd51bc8ea": "bool",
    "c4504a009084e1a2c1dae532c718afc7c": "i1",
    "c4a5c925d9ae49b98cc935c503fcbab32": "u1",
    "c745fd14a6cf1afd2358609d4a9758cbd": "i1",
    "c878f93400bb81f4f1fc853ab047cf148": "i1"
  },
  "HaloReachGameOptionsMisc": {
    "c3d4eb35d9015d0dc13864d4adb34663b": "u1",
    "c7e02f569a18de7fa97eac47e9877bbf5": "u1"
  },
  "HaloReachGameOptionsPowerups": {
    "c084c4e4d1274024b0f6d744a2511acb7": "u1",
    "c0bc711a37b0a7b684119e357decd570a": "u1",
    "c568739ccd09d2ad0bed5ebe8c07cf802": "class:3312",
    "c7cb9ac1563d9b36aba1fe1970415f6a2": "class:3312",
    "c8616f7e6a0187c820be0d14047009803": "u1",
    "cd7f984cb2a0551694c1b8fade19c4a8b": "u1",
    "cdf4d348e9ec17faf455ac7e3f0efa988": "class:3312",
    "ce40b56a88df837020717012eeb0f304d": "class:3312",
    "ce9f279b7c2d3ecddf9ccefaa70dcdde1": "i1",
    "cfb0a71a58d88caafd086d61b9040948c": "i1"
  },
  "HaloReachGameOptionsRespawning": {
    "c95dc68d58a6d29c24412b7a74d28db25": "u1"
  },
  "HaloReachGameOptionsSingleTeamOptions": {
    "c048ad9ffb5e726adb3898e63ab904f53": "i4",
    "c2313b9179b3e66056e977d9293fbcfcf": "u1",
    "c53b1c23d924a2579b4ff5495cdee7c5f": "i4",
    "c5d428eaf422967b93b1785b92c441a9e": "i4",
    "c87300ef606c614e8825f941ae70a8b95": "class:3088",
    "cab30717b639e656b08084cf14e8bdf26": "u1",
    "cbd46af4a9f3858af9c127a480f1505b8": "i4",
    "cec29c6bed460e8d5f35b92e8d7ec7e5f": "u1"
  },
  "HaloReachMegaloEngineVariant": {
    "c0ae28ba9526371faf022f2f1b60fafd8": "bool",
    "c365de54f08e5253a9e48209cdf1b17ed": "i4",
    "c7e114ee00f1bda8eede0dc470871635e": "i4[]",
    "c7e72960214e16ef5041298a6b2d917ad": "i4[]",
    "cc1f6eb99875e69339ac4c310e06e3cdb": "i4",
    "ccc5712a1ef0ff8428fcb7817e5bc0d86": "i4[]",
    "ce3dbc94bb08c177d2afeabaf7b87d992": "bool[]",
    "ceae918faf00667d836356ff308f2c9ce": "bool"
  },
  "HaloReachMegaloToken": {
    "c4b8b4a31d8e1e9f12f033e02c62dae4a": "class:3296"
  },
  "HaloReachMegaloTokenType": {
    "c215cd2423173e152494954d2d006a17e": "valuetype:3300",
    "c2e75cf066c5b9e1976b82a0819175749": "valuetype:3300",
    "c3179b036eb0030f2741f2ce1a8ab01c3": "valuetype:3300",
    "c3656499c10368145d1b82dfeb019be63": "valuetype:3300",
    "cc6a9ac0e020240c48327bd6c837cedf4": "valuetype:3300",
    "value__": "i4"
  },
  "HaloReachMegaloTokens": {
    "c54bfb249d9b21f4727e8d95456f4d5b5": "class:3304",
    "c853e0b9e66dc563a4ed7fa9231863e58": "class:3304",
    "cbef14ce1995b9ff727eb81b60ff3caba": "class:3304"
  },
  "HaloReachPlayerTraitsAppearance": {
    "c1929bc0ddd79a58e227ca02b2d72d80d": "u1",
    "c45f9c696800dba6045b5543d93e53d86": "u1"
  },
  "HaloReachPlayerTraitsDamage": {
    "c09a0c4fdff50cd4c72918889a546d0d4": "u1",
    "c5791f0dc04dd197e03a9830ea9ca3dfd": "u1",
    "c70d9bbfcce6e70beb4e33cd2222b7ab3": "u1",
    "c81a6d296f20c13465b683b710bb32e67": "u1",
    "ca603bb6f260bb04551fc6c2b90218cc0": "u1",
    "cc3a7fa570a96a1eb837105b31f1a52cc": "u1",
    "ccfce2fa10a088e91803306dbfa2d68db": "u1",
    "cdb1f380e00c191b6e2a432a07c2bef3b": "u1",
    "cdf4bfcd8a2ebca1f212d13108175f2ea": "u1",
    "ce0c04c1efa068e8ddc487939b74209cc": "u1"
  },
  "HaloReachPlayerTraitsMovement": {
    "c06d6a93ff239f4a3f704aa511756a7db": "u1",
    "c1c0568effe7d9dcee9e296209a012abb": "u1",
    "c353be72d3c948a6914e2677a84dae375": "bool",
    "c5e804cb7b111eaa446ea8fb03284d99f": "i4",
    "cf25de4f056002f17d0848207c24fbe9c": "u1"
  },
  "HaloReachPlayerTraitsSensors": {
    "c06d6a93ff239f4a3f704aa511756a7db": "u1",
    "c14669918797b5ab907abeb73af018faf": "u1"
  },
  "HaloReachPlayerTraitsWeapons": {
    "c0345cf0a1c172bb75d26b9568cb6a7fd": "i1",
    "c0544df13b9f7000168297ed800bf7c1c": "u1",
    "c05489897dff1cc05623419b9303f11bc": "u1",
    "c2bcf450c5f0eb1cccdd276c2c3157740": "u1",
    "c7c55dd1a08a519730bff163329a752bc": "u1",
    "c9629f52a61da38fc3f4baea4bf864aca": "i1",
    "cf9f8f95f0f5c81fc8d49dab723ee249a": "i1"
  },
  "MegaloCollectionName": {
    "_name": "string",
    "_tagname": "string"
  },
  "MegaloEngineVariant": {
    "c099592bf9edde69ad3576505c2fee29f": "i4",
    "c3779937fdd97c2d9f3fe3d0e672bfb64": "class:3100",
    "c3b4a585851f5f475cd88993a6a619ef8": "class:3100",
    "c65afe417b6e7561f5882f307675ec238": "i2",
    "c70cc7125d0bda28b929f4a6c0d38b5ca": "i4",
    "c749d772ca90cd394946044402309b4e1": "class:3100",
    "c8e1760258d8fbd80bc466aa1151739f1": "class:3260",
    "c95145752479254548e3ec80d93dddb08": "class:3100",
    "c9b506ef11c218de6ab31d0779d17167e": "i4",
    "cb68644a478db1fcfac03522bbf7e87a2": "class:3060",
    "cc47feb222fd3b03805de0d5f3e2a293d": "i4",
    "ce8bf25c0ad7516f796f60ec01f6f86d2": "i4",
    "cf43c0f7472b658a39d5e7202f511df41": "class:3256"
  },
  "MegaloMenuTitle": {
    "_title": "string"
  },
  "MegaloToken": {
    "c015116b16f6955afa2cf247a92e9c25f": "u1"
  },
  "MegaloTokens": {
    "c1c70a1ec0ab3502dc5988b3ac1eda949": "i4",
    "c7db381331678025bfdfb61a414ae4d4c": "u4",
    "ce813a2145716211c96eafb90a5cfedb2": "u1",
    "cf33f6f012ed1fdc819e3c45745d2524c": "i4"
  },
  "MegaloValueProperty": {
    "c6fe2317a295aa9d46d24fb86f08aed50": "object",
    "cd5f2bb9cff45f969b944311871ed3ece": "class:1577"
  },
  "MegaloValueTitle": {
    "_title": "string"
  },
  "MegaloVariable": {
    "c07071cf67f55e8a58ed28202c7acb1a6": "i2",
    "c2000199c0299e4ecd86b2c1c4951f574": "i1",
    "c7a5c18b81d502d6f34759c117fb21f92": "i1",
    "cc6076c5fcf29a14bccc851099f992179": "i1"
  },
  "MegaloVariableDataNumeric": {
    "c1f432638441c33001dc6871397702c30": "u1"
  },
  "MegaloVariableDataObject": {
    "c1f432638441c33001dc6871397702c30": "u1"
  },
  "MegaloVariableDataPlayer": {
    "c1f432638441c33001dc6871397702c30": "u1"
  },
  "MegaloVariableDataTeam": {
    "c1f432638441c33001dc6871397702c30": "u1",
    "c3c0201c639a79c0f70a00e74d29a4b02": "i4"
  },
  "MegaloVariableDataWithVar": {
    "ce6ff302699959863400274b22b1c3aee": "class:3200"
  },
  "MegaloVariantExceptions": {
    "c5a6109cc03de2103cc1bc6d94b3abe2e": "i4",
    "ccddf8f5af6fc7e0be71194e11a52c08b": "i2[]",
    "cd2ff5bb6480a492b433251af59523499": "bool"
  },
  "MegaloVariantPlayerTraits": {
    "c205cf011c710632143fa167dfd4a2199": "bool",
    "c21845953b30afe04911cd60a50586780": "bool",
    "c5bfea9076e694c2b190bd0c4a9c12c8f": "valuetype:3444",
    "c74363cb9771792f639ef0ebfc237219d": "i1",
    "cd404245ced883f5a37b22707c3a4f0d1": "class:3312",
    "cf6756069f995d88fdb7ec329d33aee91": "i1"
  },
  "MegaloVariantUnknownFloatArray": {
    "c0aef7ef0e1fca9fe9897d07edcd3e8a0": "r4[]",
    "cec29c6bed460e8d5f35b92e8d7ec7e5f": "bool"
  },
  "MegaloVariantUserDefinedOption": {
    "c3c0201c639a79c0f70a00e74d29a4b02": "i4",
    "c738093c9d776a99e9cbb11b594475ea9": "i4",
    "c99ae0e81ee01711c2a7d271773effd21": "class:3248"
  },
  "MegaloVariantUserDefinedOptionValue": {
    "c07fd671da10c793d4b6b208ba0068500": "bool",
    "c2dc43885ceb34dd6e8e65a694abd8729": "i4",
    "c74363cb9771792f639ef0ebfc237219d": "i4",
    "c93a8c3f8edd48ad804f96c7c13bad913": "i4",
    "cf6756069f995d88fdb7ec329d33aee91": "i4"
  },
  "MegaloVariantUserDefinedOptionValueElement": {
    "c3c0201c639a79c0f70a00e74d29a4b02": "i4",
    "c74363cb9771792f639ef0ebfc237219d": "i4",
    "cf6756069f995d88fdb7ec329d33aee91": "i4"
  },
  "OptionalRealArray": {
    "c4d1a5dd460c23030b0c73cd6d6face9b": "class:3104",
    "c64b5a558e29bc8855030f8088ce2572b": "u4",
    "c7c42330ccecf679230bc4833186de710": "r4[]"
  },
  "OptionalRealArrayInfo": {
    "c3129703747def00d687a5e6dc1e21836": "bool",
    "c40d67488e55e09cff3677347621adfa7": "i4",
    "cb4110c04f0eab93ee58083394061ab4c": "r4",
    "cc92534a0ec7a6976ac5c1befcf53a3cc": "bool",
    "cde7f9b3ee15f0d234a2f8e076467574c": "i4",
    "ce835b47243cd6e9c09e77802c80ee428": "r4"
  },
  "PlayerTraits": {
    "c0f7280ba0a0abe4d50e2918693d0303b": "class:3348",
    "c28714ac23bef2bef32f24e0bc22cfb68": "class:3324",
    "ca8b0a9c4726be21b0f6e191997e4c665": "class:3380",
    "cec550511af721b0c7fa448533233a92a": "class:3368",
    "cf59e6df876992fdda73f8681309a6ee9": "class:3336"
  },
  "PlayerTraitsAppearance": {
    "c6afdc9b5bd23fb942e2e29b1fab3d306": "u1",
    "c8cb43fa6a8c6866f92c2de0efba6d450": "u1",
    "ca06c515312799cee093a7e488ad8e8ef": "u1"
  },
  "PlayerTraitsMovement": {
    "c3b1af06b60cb3bd31e42c2e930dc9d43": "u1"
  },
  "PlayerTraitsSensors": {
    "cd2c4b6ecd1929c71d457d9acfe7d722d": "u1"
  },
  "PlayerTraitsWeapons": {
    "c3485034e16add2a7c24dd72b94d5129b": "u1",
    "c49a7e284d8321ea5217bc1234ae9ff75": "u1",
    "c4a5c925d9ae49b98cc935c503fcbab32": "u1",
    "c8d9da36301400e49838e59e51f79e9c2": "u1",
    "ca52d22eafd368a7c4fd65fc6bf12d178": "u1"
  },
  "StringTable": {
    "c207be1e1eda7a8ca9d6a95396e356ad1": "class:3092",
    "c4d1a5dd460c23030b0c73cd6d6face9b": "class:3088"
  },
  "StringTableBuffer": {
    "c207be1e1eda7a8ca9d6a95396e356ad1": "u1[]",
    "c3ef08e987de796cc05bed9cd4a322bef": "class:3100",
    "c47f9fa7b294de2e80863052588f1c379": "i4",
    "c616626a8514a9c2ee2fd42436b07ac01": "u1[]",
    "c9b8395969c86faa2091fc4bc2e0895ca": "class:1477",
    "ce94e163b5814aa07d3cd00dc8831e35c": "bool"
  },
  "StringTableInfo": {
    "c153597b4377a02e647ca5bc82bfa08b1": "i4",
    "c208db3ce88a6752e737fc2e033dd02a1": "valuetype:3444",
    "c4478468b673b3dd343ef9887c7ab8a16": "i4",
    "c8cb297df83e796dbd5c305750f751f8d": "i4",
    "cbea1deeb4359ec8be25396bd02552c8c": "i4"
  },
  "StringTableStringItem": {
    "c0968258f016810a6d1db70e5bcb9831e": "i4[]",
    "c3ef08e987de796cc05bed9cd4a322bef": "class:3100",
    "cf2a3a2471299250d3824db3e0396b408": "string[]"
  }
}

def halo_general_class_field_types(type_name: str | None = None) -> dict[str, object]:
    """Return the selected REA-observed managed field-type slice."""

    if type_name is None:
        return {name: dict(fields) for name, fields in _HALO_GENERAL_CLASS_FIELD_TYPES.items()}
    if type_name not in _HALO_GENERAL_CLASS_FIELD_TYPES:
        raise KeyError(f"unknown observed Halo field-type slice: {type_name}")
    return dict(_HALO_GENERAL_CLASS_FIELD_TYPES[type_name])


def validate_halo_metadata_values(type_name: str, values: Mapping[str, object], *, require_all: bool = False) -> dict[str, object]:
    """Validate values against the authenticated REA field-type slice.

    This validates managed metadata only. It deliberately does not assign
    offsets, serialize bytes, or interpret ``class:N`` references.
    """

    field_types = halo_general_class_field_types(type_name)
    unknown = sorted(set(values) - set(field_types))
    if unknown:
        raise ValueError(f"unknown {type_name} fields: {', '.join(unknown)}")
    missing = sorted(set(field_types) - set(values)) if require_all else []
    if missing:
        raise ValueError(f"missing {type_name} fields: {', '.join(missing)}")
    result: dict[str, object] = {}
    for name, value in values.items():
        _validate_halo_field_value(type_name, name, field_types[name], value)
        result[name] = value
    return result


def _validate_halo_field_value(type_name: str, name: str, field_type: str, value: object) -> None:
    """Validate a decoded REA field signature without inventing wire layout."""

    if field_type == "bool":
        if not isinstance(value, bool):
            raise TypeError(f"{type_name}.{name} must be bool")
        return
    if field_type == "string":
        if not isinstance(value, str):
            raise TypeError(f"{type_name}.{name} must be string")
        return
    integer_limits = {
        "i1": (-0x80, 0x7F), "u1": (0, 0xFF),
        "i2": (-0x8000, 0x7FFF), "u2": (0, 0xFFFF),
        "i4": (-0x80000000, 0x7FFFFFFF), "u4": (0, 0xFFFFFFFF),
        "i8": (-0x8000000000000000, 0x7FFFFFFFFFFFFFFF),
        "u8": (0, 0xFFFFFFFFFFFFFFFF),
    }
    if field_type in integer_limits:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{type_name}.{name} must be integer")
        if not integer_limits[field_type][0] <= value <= integer_limits[field_type][1]:
            raise ValueError(f"{type_name}.{name} is outside {field_type} range")
        return
    if field_type in {"r4", "r8"}:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise TypeError(f"{type_name}.{name} must be real")
        return
    if field_type.endswith("[]"):
        if not isinstance(value, (list, tuple)):
            raise TypeError(f"{type_name}.{name} must be an array")
        element_type = field_type[:-2]
        for index, item in enumerate(value):
            _validate_halo_field_value(type_name, f"{name}[{index}]", element_type, item)
        return
    # REA identified these as managed references/value types, but did not
    # provide enough serialization evidence to validate their object shape.
    if field_type == "object" or field_type.startswith(("class:", "valuetype:")):
        return
    raise ValueError(f"unsupported decoded REA field type {field_type!r} for {type_name}.{name}")
def halo_general_class_method_summary() -> dict[str, object]:
    """Return aggregate method evidence retained for Halo general classes."""

    return {
        "method_count": 1102,
        "unique_getter_setter_property_count": 140,
        "getter_method_count": 175,
        "setter_method_count": 168,
        "properties_with_getter_and_setter": 135,
        "getter_only_properties": [
            "c511c78325de7a961851b2bb984e702ad",
            "EngineVariant",
            "Is_Currently_Custom",
            "IsValid",
            "RealArray",
        ],
        "setter_only_properties": [],
        "overloaded_method_names": [
            "EngineVariant", "EquipmentUsage", "Game", "GamertagVisible", "GameVariant",
            "GameVersion", "Header", "InitialEquipment", "InitialPrimaryWeapon",
            "InitialSecondaryWeapon", "InterfaceLayout", "InterfaceMegalo", "InterfaceStrings",
            "Modifiers", "OptionsContainer", "RealArray", "Value", "ValueInterface",
        ],
        "return_type_counts": {
            "void": 742,
            "u1": 65,
            "bool": 50,
            "string": 28,
            "i4": 23,
            "u1[]": 18,
            "i1": 14,
            "native-int": 8,
        },
        "top_declaring_types": {
            "Halo4GameOptionsSingleTeamOptions": 39,
            "Halo4PlayerTraitsWeapons": 35,
            "Halo4GameOptionsOrdnanceArea": 35,
            "MegaloEngineVariant": 32,
            "HaloReachGameOptionsPowerups": 31,
        },
        "status": "metadata-only",
    }


_HALO_GENERAL_CLASS_PROPERTY_NAMES = (
    "ActiveCamo", "Alpha", "Ammopack", "AssassinationImmunity", "Aura", "AuralEnhancement",
    "AutomaticMomentumUsage", "BattleAwareness", "BitStreamData", "Blue", "BodyMultiplier",
    "BodyRechargeRate", "c09521bc19ea8141a547e37f5ed091fcf", "c0bd6bd14a26ad3bf3602578abb7d2452",
    "c16498ca2febe71be8f33f39c992ceb3c", "c2402ce1daadcd3031f38cffd17d9aa89",
    "c26a570c4ca79e5839fa760938e283020", "c274f7e9c4a6b96d7aeef2e41f1ddee55",
    "c3ad596b08358facb5157a397df11a716", "c4436144cc0d60bc0e69a6a2fdc850d01",
    "c511c78325de7a961851b2bb984e702ad", "c535906cbcf536d6b661c9a9743cca796",
    "c9b9699e919cbfc2781159c8209a3b030", "ca46dfab5b362a9a26dee9c8473f56671",
    "ca61c05db915d9bb5f162b067cd3e1206", "cb314eada6ff4b8bbe789648d7190b724",
    "cc257b935fa49da7a1119f23015bea4d2", "cc99f7fb1d6d092545c67ed6d75ad30c4",
    "ce5a54ac5d994ca1ed85972740fe9301a", "ceb180ec35301e66ee1b7280bdfb47601",
    "cfa671c2ed611f7e9191c607e04fe820c", "ContentLength", "Creator", "DamageMod0", "DamageMod1",
    "DamageResistance", "DeathEffect", "Deathless", "DescriptionStringIndex", "DirectionalDamageIndicator",
    "DoubleJump", "EngineVariant", "Enum2", "EquipmentDrop", "EquipmentUsage",
    "EquipmentUsageExceptingAutoTurret", "ExplodeOnDeathMod", "FastTrackArmor", "Footer", "ForcedChangeColor",
    "Game", "Game_Version", "GamertagVisible", "GameVariant", "GameVersion", "GoofList", "Gravity", "Green",
    "Grenadier", "Has_Custom", "Has_Defaults", "Hash", "Header", "HeadshotImmunity", "ImmuneToAssassination",
    "ImmuneToHeadshots", "InfiniteAmmo", "InfiniteEquipment", "InitialEquipment", "InitialGrenadeCount",
    "InitialPrimaryWeapon", "InitialSecondaryWeapon", "InitialSupportUpgrade", "InitialTacticalPackage",
    "InterfaceLayout", "InterfaceMegalo", "InterfaceStrings", "IO", "Is_Currently_Custom", "IsUnused", "IsValid",
    "ItemAlignment", "ItemData", "Items", "ItemSignature", "ItemSize", "ItemVersion", "JumpHeight", "Label_Text",
    "LinkInterface", "LoopingEffect", "menuHistory", "MenuInterface", "ModelVariant", "Modifier", "Modifiers",
    "MotionTracker", "MotionTrackerRange", "MotionTrackerWhileZoomed", "NameStringIndex", "Nemesis",
    "OptionInformation", "OptionsContainer", "OrdnanceDisabled", "OrdnanceMarkersVisible", "Padding0", "ParentArray",
    "ParentOptions", "PowerupCancellation", "PrimaryColor", "RealArray", "RealValue", "RechargingGrenades", "Red",
    "RemainingData", "Resourceful", "SecondaryColor", "ShieldHUD", "ShieldMultiplier", "ShieldRechargeRate0",
    "ShieldRechargeRate1", "SilyList", "Speed", "SprintUsage", "Stealthy", "StringIdIndex", "ThreatView", "Traits",
    "Unknown0", "Unknown01", "Value", "Value_Type", "ValueInterface", "Vampirism", "VaultingEnabled", "VehicleUsage",
    "VisionMode", "Waypoint", "WeaponPickupAllowed", "WellEquipped",
)


def halo_general_class_property_names() -> tuple[str, ...]:
    """Return unique getter/setter property names observed by REA."""
    return _HALO_GENERAL_CLASS_PROPERTY_NAMES

