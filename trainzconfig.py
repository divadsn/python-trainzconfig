import re
import struct

from pathlib import Path
from typing import Any, List, Union, Optional, TextIO
from typing_extensions import Self

__all__ = ["Kuid", "TrainzConfig"]


class Kuid:
    """
    A class representing a KUID (Kuid or Kuid2) used in Trainz.

    Attributes:
        user_id (int): The user ID part of the KUID.
        content_id (int): The content ID part of the KUID.
        version (int): The version number (only for Kuid2).
    """

    def __init__(self, user_id: int, content_id: int, version: int = 0):
        """
        Initializes a Kuid object.

        Args:
            user_id (int): The user ID part of the KUID.
            content_id (int): The content ID part of the KUID.
            version (int): The version number (only for Kuid2), must be between 0 and 127.

        Raises:
            ValueError: If the version is not between 0 and 127.
        """
        self.user_id = user_id
        self.content_id = content_id

        if not 0 <= version < 128:
            raise ValueError("Version must be between 0 and 127.")

        self.version = version

    def __repr__(self) -> str:
        """
        Returns a string representation of the Kuid object.

        Returns:
            str: The KUID string enclosed in angle brackets.
        """
        return f"<{str(self)}>"

    def __str__(self) -> str:
        """
        Returns the KUID as a string.

        Returns:
            str: The KUID in its string representation, either in kuid or kuid2 format.
        """
        return self.kuid2() if self.is_kuid2 else self.kuid()

    def __bytes__(self) -> bytes:
        """
        Returns the KUID as an 8-byte sequence.

        Returns:
            bytes: The byte sequence representing the KUID.
        """
        ubytes = struct.pack("<i", self.user_id)
        cbytes = struct.pack("<i", self.content_id)

        if self.is_kuid2 and 0 < self.version < 128 and self.user_id >= 0:
            ubytes = ubytes[:3] + bytes([ubytes[3] | (self.version << 1)])

        return ubytes + cbytes

    def __eq__(self, other: object) -> bool:
        """
        Compares two KUID objects for equality.

        Args:
            other (Kuid): Another KUID object to compare.

        Returns:
            bool: True if the KUIDs are equal, False otherwise.
        """
        if not isinstance(other, Kuid):
            return NotImplemented

        return self.user_id == other.user_id and self.content_id == other.content_id and self.version == other.version

    def __hash__(self) -> int:
        """
        Returns a hash value for the KUID.

        Returns:
            int: The hash value for the KUID.
        """
        return hash((self.user_id, self.content_id, self.version))

    def __reversed__(self) -> Self:
        """
        Returns a reversed KUID object.

        Returns:
            Kuid: A new Kuid object with the user ID and content ID swapped.
        """
        return Kuid(self.content_id, self.user_id, self.version)

    @property
    def is_kuid2(self) -> bool:
        """
        Determines if the KUID is in the kuid2 format.

        Returns:
            bool: True if the KUID is of type kuid2, False otherwise.
        """
        return self.user_id > 0 and self.version > 0

    def hex(self, *args, **kwargs) -> str:
        """
        Returns the hexadecimal representation of the KUID as an 8-byte string.

        Returns:
            str: The hex string representing the KUID, in uppercase.
        """
        return bytes(self).hex(*args, **kwargs).upper()

    def hash(self) -> str:
        """
        Returns the computed hash for this KUID in the format 'hash-xx'.

        Returns:
            str: The computed hash string for the KUID.
        """
        return f"hash-{Kuid.compute_hash(bytes(self)):02X}"

    def kuid(self) -> str:
        """
        Returns the KUID in 'kuid:<user_id>:<content_id>' format.

        Returns:
            str: The KUID string in the kuid format.
        """
        return f"kuid:{self.user_id}:{self.content_id}"

    def kuid2(self) -> str:
        """
        Returns the KUID in 'kuid2:<user_id>:<content_id>:<version>' format.

        Returns:
            str: The KUID string in the kuid2 format.
        """
        return f"kuid2:{self.user_id}:{self.content_id}:{self.version}"

    def local_path(self, trainz_path: Path) -> Path:
        """
        Returns the local path for the KUID in the Trainz installation.

        Args:
            trainz_path (Path): The path to the Trainz installation.

        Returns:
            Path: The local path for the KUID in the Trainz installation.
        """
        return trainz_path / "UserData" / "local" / self.hash() / str(self).replace(":", " ").replace("-", "_")

    @staticmethod
    def compute_hash(kuid_bytes: bytes) -> int:
        """
        Computes the hash value for a KUID byte sequence.

        Args:
            kuid_bytes (bytes): The byte sequence representing the KUID.

        Returns:
            int: The computed hash value for the KUID.
        """
        hash_val = 0x00

        for i in range(8):
            hash_val ^= kuid_bytes[i]

        if (kuid_bytes[3] & (1 << 0)) == 0:
            hash_val ^= kuid_bytes[3]

        return hash_val

    @classmethod
    def from_string(cls, kuid: str) -> Self:
        """
        Creates a Kuid object from a string representation of a KUID.

        Args:
            kuid (str): The string representation of the KUID.

        Returns:
            Kuid: The resulting Kuid object.

        Raises:
            ValueError: If the string representation is invalid.
        """
        if kuid.startswith("<") and kuid.endswith(">"):
            kuid = kuid[1:-1]

        if not re.match(r"^(?:kuid:-?\d+:\d+|kuid2:-?\d+:\d+:\d+)$", kuid, re.IGNORECASE):
            raise ValueError(f"Invalid KUID string: {kuid}")

        parts = kuid.split(":")[1:]
        user_id, content_id = map(int, parts[:2])
        version = 0

        if len(parts) == 3:
            version = int(parts[2])

        return cls(user_id, content_id, version)

    @classmethod
    def from_bytes(cls, kuid_bytes: bytes, reverse: bool = False) -> Self:
        """
        Creates a Kuid object from a byte sequence representing a KUID.

        Args:
            kuid_bytes (bytes): The byte sequence representing the KUID.
            reverse (bool): Whether the user ID and content ID should be swapped.

        Returns:
            Kuid: The resulting Kuid object.

        Raises:
            ValueError: If the byte sequence is not valid.
        """
        if len(kuid_bytes) != 8:
            raise ValueError("The byte sequence must be exactly 8 bytes long.")

        if reverse:
            kuid_bytes = kuid_bytes[4:] + kuid_bytes[:4]

        user_id = struct.unpack("<i", kuid_bytes[:4])[0]
        content_id = struct.unpack("<i", kuid_bytes[4:])[0]
        version = 0

        if kuid_bytes[3] & 0x01 == 0:
            user_id &= 0x00FFFFFF
            version = (kuid_bytes[3] >> 1) & 0x7F

        return cls(user_id, content_id, version)

    @classmethod
    def from_hex(cls, hex_kuid: str, reverse: bool = False) -> Self:
        """
        Creates a Kuid object from a hexadecimal representation of a KUID.

        Args:
            hex_kuid (str): The hex string representing the KUID.
            reverse (bool): Whether the user ID and content ID should be swapped.

        Returns:
            Kuid: The resulting Kuid object.

        Raises:
            ValueError: If the hex string is not valid.
        """
        try:
            kuid_bytes = bytes.fromhex(hex_kuid)
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {hex_kuid}") from e

        return cls.from_bytes(kuid_bytes, reverse)


class TrainzConfig:
    def __init__(self, filename: Path, encoding: str = "utf-8-sig"):
        self.config_data = {}

        if encoding == "auto":
            try:
                import chardet
                encoding = chardet.detect(open(filename, "rb").read())["encoding"]
            except ModuleNotFoundError as e:
                raise e

        self.load(filename, encoding)

    def load(self, filename: Path, encoding: str = "utf-8-sig"):
        path = []
        previous_key = None

        with open(filename, "r", encoding=encoding) as file_handle:
            for line in file_handle:
                line = line.strip()

                if not line or line.startswith(";"):
                    continue

                split_line = line.split(maxsplit=1)

                # Handle nested structures
                if len(split_line) == 1:
                    if split_line[0] == "{":
                        path.append(previous_key)
                    if split_line[0] == "}":
                        path.pop()
                    else:
                        previous_key = split_line[0]
                    continue

                key, value = split_line

                # Match different types of values
                if re.match(r'^".*"$', value):
                    value = value[1:-1]
                elif re.match(r'^<.*>$', value):
                    value = Kuid.from_string(value) if value.lower() != "<null>" else None
                elif re.match(r"^[-+]?([0-9]*[.])[0-9]+$", value):
                    value = float(value)
                elif re.match(r"^[-+]?\d+$", value):
                    value = int(value)
                elif "," in value:
                    value = self.parse_array(value)
                elif value.startswith('"') and not value.endswith('"'):
                    value = self.parse_multiline_string(file_handle, value)

                container = self.config_data

                for p in path:
                    if p not in container:
                        container[p] = {}

                    container = container[p]

                container[key] = value

    @staticmethod
    def parse_array(value: str) -> List[Union[int, float, str]]:
        array = []

        for item in map(str.strip, value.split(",")):
            if re.match(r"^[-+]?([0-9]*[.])[0-9]+$", item):
                item = float(item)
            elif re.match(r"^[-+]?\d+$", item):
                item = int(item)

            array.append(item)

        return array

    @staticmethod
    def parse_multiline_string(file_handle: TextIO, current_line: str) -> str:
        multi_line_value = current_line[1:]  # Skip the initial quote

        for line in file_handle:
            stripped_line = line.strip()

            if stripped_line.endswith('"'):
                multi_line_value += "\n" + stripped_line[:-1]  # Skip the closing quote
                break
            else:
                multi_line_value += "\n" + stripped_line

        return multi_line_value

    def get(self, path: str, default: Optional[Any] = None) -> Optional[Any]:
        path = path.split(".")
        container = self.config_data

        for p in path:
            if p not in container:
                return default

            container = container[p]

        return container

    def set(self, path: str, value: Any):
        path = path.split(".")
        container = self.config_data

        for p in path[:-1]:
            if p not in container:
                container[p] = {}

            container = container[p]

        container[path[-1]] = value

    @property
    def kuid(self) -> str:
        return self.config_data.get("kuid")

    @property
    def username(self) -> str:
        return self.config_data.get("username", self.config_data.get("name", self.config_data.get("asset-filename"))).replace("_", " ")

    def __len__(self):
        return len(self.config_data)

    def __getitem__(self, item):
        return self.config_data[item]

    def __setitem__(self, key, value):
        self.config_data[key] = value

    def __iter__(self):
        return iter(self.config_data)

    def __contains__(self, item):
        return item in self.config_data
