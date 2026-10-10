"""REA-observed device-exploration surface.

These are managed property declarations recovered from Horizon's metadata.
They identify UI/device concepts but do not establish USB enumeration,
filesystem, IOCTL, or thumbnail serialization behavior.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class DeviceMember:
    declaring_type: str
    name: str
    token: str
    return_type: str
    parameter_types: tuple[str, ...]


_MEMBERS = (
    DeviceMember("A.c481e7f09def65aded5645fc775214ae5", "get_Account_Thumb", "0x06000bc9", "class:957", ()),
    DeviceMember("A.c19f8a9b6dbfc214ef50f596f4e56345d", "get_DeviceExplorer_Thumb", "0x06000bfc", "class:957", ()),
    DeviceMember("A.c19f8a9b6dbfc214ef50f596f4e56345d", "get_FatxHDD_24", "0x06000c10", "class:957", ()),
    DeviceMember("A.c19f8a9b6dbfc214ef50f596f4e56345d", "get_FatxMU_24", "0x06000c11", "class:957", ()),
    DeviceMember("A.c19f8a9b6dbfc214ef50f596f4e56345d", "get_FatxUSB_24", "0x06000c12", "class:957", ()),
    DeviceMember("A.cfe87d2c16a6420298db515d0ecfcf31b", "get_TestDrive_Thumb", "0x06000cba", "class:957", ()),
    DeviceMember("A.cfe87d2c16a6420298db515d0ecfcf31b", "get_TestDrive2_Thumb", "0x06000cbb", "class:957", ()),
    DeviceMember("A.c0353b6b5ff8fecef988e28ba8b350fd5", "get_DeviceSize", "0x06000cf0", "i8", ()),
    DeviceMember("A.c0353b6b5ff8fecef988e28ba8b350fd5", "set_DeviceSize", "0x06000cf1", "void", ("i8",)),
)


def observed_device_members() -> tuple[DeviceMember, ...]:
    return _MEMBERS


def device_surface_report() -> dict[str, object]:
    return {
        "status": "metadata-only",
        "members": [asdict(item) for item in _MEMBERS],
        "unresolved": [
            "device enumeration and identity",
            "USB/FATX filesystem protocol",
            "device IOCTL values and semantics",
            "thumbnail resource serialization",
        ],
    }


