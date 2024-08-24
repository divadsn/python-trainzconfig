import re
import struct

__all__ = ["Kuid", "TrainzConfig"]


class Kuid:
    """
    A class representing a KUID (Kuid or Kuid2) used in Trainz.

    Attributes:
        author_id (int): The author ID part of the KUID.
        base_id (int): The base asset ID part of the KUID.
        version (int): The version number (only for Kuid2).
    """

    def __init__(self, value: str):
        """
        Initializes a Kuid object by parsing the given KUID string.

        Args:
            value (str): The KUID string, which can be in the kuid or kuid2 format.

        Raises:
            AssertionError: If the provided KUID string is not valid.
        """
        if value.startswith("<") and value.endswith(">"):
            value = value[1:-1]

        assert re.match(r"^(?:kuid:-?\d+:\d+|kuid2:-?\d+:\d+:\d+)$", value, re.IGNORECASE), f"Invalid KUID: {value}"
        parts = value.split(":")

        self.author_id = int(parts[1])
        self.base_id = int(parts[2])
        self.version = int(parts[3]) if len(parts) > 3 else 0

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
        ubytes = struct.pack('<I', self.author_id)
        cbytes = struct.pack('<I', self.base_id)

        if self.is_kuid2 and 0 < self.version < 128 and self.author_id >= 0:
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

        return self.author_id == other.author_id and self.base_id == other.base_id and self.version == other.version

    def __hash__(self) -> int:
        """
        Returns a hash value for the KUID.

        Returns:
            int: The hash value for the KUID.
        """
        return hash((self.author_id, self.base_id, self.version))

    @property
    def is_kuid2(self) -> bool:
        """
        Determines if the KUID is in the kuid2 format.

        Returns:
            bool: True if the KUID is of type kuid2, False otherwise.
        """
        return self.version > 0

    def hex(self) -> str:
        """
        Returns the hexadecimal representation of the KUID as an 8-byte string.

        Returns:
            str: The hex string representing the KUID, in uppercase.
        """
        return bytes(self).hex().upper()

    def hash(self) -> str:
        """
        Returns the computed hash for this KUID in the format 'hash-xx'.

        Returns:
            str: The computed hash string for the KUID.
        """
        def compute_hash(kuid_bytes):
            hash_val = 0x00

            for i in range(8):
                hash_val ^= kuid_bytes[i]

            if (kuid_bytes[3] & (1 << 0)) == 0:
                hash_val ^= kuid_bytes[3]

            return hash_val

        # Compute and return the hash as a byte
        return f"hash-{compute_hash(bytes(self)):02X}"
    
    def kuid(self) -> str:
        """
        Returns the KUID in 'kuid:<author_id>:<base_id>' format.

        Returns:
            str: The KUID string in the kuid format.
        """
        return f"kuid:{self.author_id}:{self.base_id}"

    def kuid2(self) -> str:
        """
        Returns the KUID in 'kuid2:<author_id>:<base_id>:<version>' format.

        Returns:
            str: The KUID string in the kuid2 format.
        """
        return f"kuid2:{self.author_id}:{self.base_id}:{self.version}"


class TrainzConfig:
    def __init__(self, filename, encoding="utf-8-sig"):
        self.config_data = {}

        path = []
        previous_key = None

        if encoding == "auto":
            try:
                import chardet
                encoding = chardet.detect(open(filename, "rb").read())["encoding"]
            except ModuleNotFoundError as e:
                raise e

        with open(filename, "r", encoding=encoding) as f:
            for line in f.readlines():
                line = line.strip()

                if not line or line.startswith(";"):
                    continue

                split_line = line.split(maxsplit=1)

                if len(split_line) == 1:
                    if split_line[0] == "{":
                        path.append(previous_key)
                    if split_line[0] == "}":
                        path.pop()
                    else:
                        previous_key = split_line[0]
                    continue

                key = split_line[0]
                value = split_line[1]

                if re.match(r'^".*"$', value):
                    value = value[1:-1]
                elif re.match(r'^<.*>$', value):
                    value = Kuid(value)
                elif re.match(r"^[-+]?([0-9]*[.])[0-9]+$", value):
                    value = float(value)
                elif re.match(r"^[-+]?\d+$", value):
                    value = int(value)
                elif "," in value:
                    value = value.split(",")

                container = self.config_data

                for p in path:
                    if p not in container:
                        container[p] = {}

                    container = container[p]

                container[key] = value

    def get(self, path, default=None):
        path = path.split(".")
        container = self.config_data

        for p in path:
            if p not in container:
                return default

            container = container[p]

        return container

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
