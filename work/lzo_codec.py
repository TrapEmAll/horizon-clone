"""High-level buffer wrapper around the explicit REA-observed LZO boundary."""

from __future__ import annotations

from dataclasses import dataclass

from .native_compression import Int32Ref, LzoBinding


@dataclass(frozen=True)
class LzoCodec:
    """Call an explicitly supplied LZO provider without loading ``lzo.dll``."""

    binding: LzoBinding

    def compress(self, variant: str, source: bytes, output_capacity: int, work_memory: bytes = b"") -> bytes:
        return self._run(True, variant, source, output_capacity, work_memory)

    def decompress(self, variant: str, source: bytes, output_capacity: int, work_memory: bytes = b"") -> bytes:
        return self._run(False, variant, source, output_capacity, work_memory)

    def _run(self, compress: bool, variant: str, source: bytes, output_capacity: int, work_memory: bytes) -> bytes:
        if not isinstance(source, bytes) or not isinstance(work_memory, bytes):
            raise TypeError("source and work_memory must be bytes")
        if not isinstance(output_capacity, int) or isinstance(output_capacity, bool) or output_capacity < 0:
            raise ValueError("output_capacity must be a non-negative integer")
        destination = bytearray(output_capacity)
        destination_length = Int32Ref(output_capacity)
        if compress:
            result = self.binding.compress(variant, source, len(source), destination, destination_length, work_memory)
        else:
            result = self.binding.decompress(variant, source, len(source), destination, destination_length, work_memory)
        if result < -0x80000000 or result > 0x7FFFFFFF:
            raise ValueError("LZO provider returned an invalid status")
        if not 0 <= destination_length.value <= len(destination):
            raise ValueError("LZO provider returned an invalid output length")
        return bytes(destination[: destination_length.value])

