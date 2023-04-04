#!/usr/bin/env python3

import enum
import hashlib
import re
import struct
import uuid
from typing import Tuple

# ########################################
# utilities
# ########################################


def nullterm8(buffer: bytes) -> str:
    """
    convert byte buffers with null terminated UTF-8 C strings to python strings
    """
    return buffer.decode("utf-8").split("\x00")[0]


def nullterm16(buffer: bytes) -> str:
    """
    convert byte buffers with null terminated UTF-16 C strings to python strings
    """
    return buffer.decode("utf-16").split("\u0000")[0]


# ########################################
# Enumeration of all event types
# ########################################


class Event(enum.IntEnum):
    """
    All UEFI event log events (an enumeration)
    TCG PC Client Platform Firmware Profile Spec, v1.05 Rev 22, Table 14, page 91.
    """

    EV_PREBOOT_CERT = 0x0
    EV_POST_CODE = 0x1
    EV_UNUSED = 0x2
    EV_NO_ACTION = 0x3
    EV_SEPARATOR = 0x4
    EV_ACTION = 0x5
    EV_EVENT_TAG = 0x6
    EV_S_CRTM_CONTENTS = 0x7
    EV_S_CRTM_VERSION = 0x8
    EV_CPU_MICROCODE = 0x9
    EV_PLATFORM_CONFIG_FLAGS = 0xA
    EV_TABLE_OF_DEVICES = 0xB
    EV_COMPACT_HASH = 0xC
    EV_IPL = 0xD
    EV_IPL_PARTITION_DATA = 0xE
    EV_NONHOST_CODE = 0xF
    EV_NONHOST_CONFIG = 0x10
    EV_NONHOST_INFO = 0x11
    EV_OMIT_BOOT_DEVICE_EVENTS = 0x12
    EV_EFI_EVENT_BASE = 0x80000000
    EV_EFI_VARIABLE_DRIVER_CONFIG = EV_EFI_EVENT_BASE + 0x1
    EV_EFI_VARIABLE_BOOT = EV_EFI_EVENT_BASE + 0x2
    EV_EFI_BOOT_SERVICES_APPLICATION = EV_EFI_EVENT_BASE + 0x3
    EV_EFI_BOOT_SERVICES_DRIVER = EV_EFI_EVENT_BASE + 0x4
    EV_EFI_RUNTIME_SERVICES_DRIVER = EV_EFI_EVENT_BASE + 0x5
    EV_EFI_GPT_EVENT = EV_EFI_EVENT_BASE + 0x6
    EV_EFI_ACTION = EV_EFI_EVENT_BASE + 0x7
    EV_EFI_PLATFORM_FIRMWARE_BLOB = EV_EFI_EVENT_BASE + 0x8
    EV_EFI_HANDOFF_TABLES = EV_EFI_EVENT_BASE + 0x9
    EV_EFI_PLATFORM_FIRMWARE_BLOB2 = EV_EFI_EVENT_BASE + 0xA
    EV_EFI_HANDOFF_TABLES2 = EV_EFI_EVENT_BASE + 0xB
    EV_EFI_VARIABLE_BOOT2 = EV_EFI_EVENT_BASE + 0xC
    EV_EFI_VARIABLE_AUTHORITY = EV_EFI_EVENT_BASE + 0xE0

    EV_UNKNOWN = 0xFFFFFFFF


# ########################################
# Event digests
# ########################################


class Digest(enum.IntEnum):
    """
    TPM2_ALG_<digesttype> from TCG algorithm registry
    NOTE The overlap with python's hashlib is low, but
    it apparently covers most use cases ...
    """

    sha1 = 4
    sha256 = 11
    sha384 = 12
    sha512 = 13
    sha3_224 = 0x27
    sha3_256 = 0x28
    sha3_512 = 0x29


class EfiEventDigest:
    """
    Event digests
    TCG PC Client platform firmware profile, TPML_DIGEST_VALUES, Section 10.2.2
    """

    hashalgmap = {
        Digest.sha1: hashlib.sha1,
        Digest.sha256: hashlib.sha256,
        Digest.sha384: hashlib.sha384,
        Digest.sha512: hashlib.sha512,
    }

    def __init__(self, algid: Digest, buffer: bytes, idx: int):
        """
        constructor for a digest
        """
        self.algid = algid
        assert self.algid in EfiEventDigest.hashalgmap
        self.hashalg = EfiEventDigest.hashalgmap[self.algid]()
        self.digest_size = self.hashalg.digest_size
        self.digest = buffer[idx : idx + self.digest_size]

    def to_json(self):
        """
        JSON converter -- we use this function on every non-natively
        jsonifiable type that requires translation to JSON
        """
        return {"AlgorithmId": self.algid.name, "Digest": self.digest.hex()}

    @staticmethod
    def parselist(digestcount: int, buffer: bytes, idx: int) -> Tuple[dict, int]:
        """
        ----------------------------------------
        parse a list of digests in the event log
        ----------------------------------------
        inputs:
          digestcount: how many digests to parse
          idx: index in the buffer we are parsing
          buffer: input buffer we are parsing
        outputs:
          digests: list of parsed digests
          idx: index of first unparsed byte in buffer
        """

        digests = {}
        for _ in range(0, digestcount):
            (algid,) = struct.unpack("<H", buffer[idx : idx + 2])
            digest = EfiEventDigest(Digest(algid), buffer, idx + 2)
            digests[algid] = digest
            idx += 2 + digest.digest_size
        return digests, idx


# ########################################
# EFI event classes
# ########################################


class GenericEvent:
    """
    # ########################################
    # base class for all EFI events.
    # ########################################
    # GenericEvent is the superclass of all Events
    # parsed by this code. A parsed Event ends up
    # being a GenericEvent type if there is no specialized
    # parser to further interpret it.
    # ########################################
    # * Each Event type has a constructor, which parses the input
    #   buffer. The constructor is used when there is no doubt about
    #   what should be parsed and how it should be interpreted.
    # * However, the main parser entry point is the parse class method.
    #   This method peeks into the input buffer and makes decisions
    #   about what object the buffer should be parsed into, then invokes
    #   the appropriate constructor for that type.
    #   Examples of decision points include checking EFI variable names,
    #   e.g. "BootOrder" is handled differently from "Boot0001".
    # * Each Event class has a "validate" method used in
    #   testing its internal consistency (not really available for all
    #   event types, so in those cases testing returns "true")
    # * Each Event class has a "to_json" method to convert it into
    #   data structures accepted by the JSON pickler
    #   (i.e. dictionaries, lists, strings)
    #
    # NOTE on JSON output of raw events. tpm2_eventlog limits raw event
    # output to 1024 characters when there is no intelligent processing
    # done on it.  We follow suit for reasons of compatibility -- and
    # because no one in their right mind will process a 6kB raw string in
    # JSON/hex.
    """

    def __init__(
        self, eventheader: Tuple[int, int, dict, int, int], buffer: bytes, idx: int
    ):
        self.evpcr = eventheader[1]
        self.digests = eventheader[2]
        self.evsize = eventheader[3]
        self.evidx = eventheader[4]
        assert (
            len(buffer) >= idx + self.evsize
        ), f"Event log truncated, GenericEvent, evt.idx = {self.evidx}"
        self.evbuf = buffer[idx : idx + self.evsize]

        try:
            self.evtype = Event(eventheader[0])
        except Exception as _:
            self.evtype = Event.EV_UNKNOWN

    @classmethod
    def parse(
        cls, eventheader: Tuple[int, int, dict, int, int], buffer: bytes, idx: int
    ):
        return cls(eventheader, buffer, idx)

    # pylint: disable=no-self-use
    def validate(self) -> Tuple[bool, bool, str]:
        """
        validate returns:
        boolean: True if the validation is vacuous (the event is not self-validating).
             False otherwise.
             For vacuous validations the second and third return values will always be "True" and an empty string.
        boolean: True if validation passed; False otherwise.
             For passed validations the third return value will always be an empty string.
        string:  A reason why validation failed. For human consumption, as a debugging help.
        """
        return True, True, ""

    def to_json(self):
        return {
            "EventType": self.evtype.name,
            "EventNum": self.evidx,
            "PCRIndex": self.evpcr,
            "EventSize": self.evsize,
            "DigestCount": len(self.digests),
            "Digests": list(self.digests.values()),
            "Event": self.evbuf[:1024].hex(),
        }


class ValidatedEvent(GenericEvent):
    """
    Events that can be validated by CONTENT_MATCHES_DIGEST
    (TCG Guidance on Integrity Measurements and Event Log Processing, V1, Rev 0.118, 12/15/2021, Section 7.2.5.1)
    EV_S_CRTM_VERSION EV_EFI_VARIABLE_DRIVER_CONFIG EV_SEPARATOR EV_EFI_GPT_EVENT EV_EFI_VARIABLE_BOOT
    """

    def validate(self) -> Tuple[bool, bool, str]:
        for algid, refdigest in self.digests.items():
            calchash1 = EfiEventDigest.hashalgmap[algid](self.evbuf).digest()
            if refdigest != calchash1:
                return False, False, str(self.evtype.name)
        return False, True, ""


class PostCodeEvent(GenericEvent):
    """
    EV_POST_CODE -- interpreted as a string or else as a blob base/length pair
    """

    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        if self.evsize == 16:
            (self.blobBase, self.blobLength) = struct.unpack(
                "<QQ", buffer[idx : idx + 16]
            )
        else:
            self.blobBase = None
            self.blobLength = None

    def to_json(self) -> dict:
        if self.blobBase is not None:
            evt = {"BlobBase": self.blobBase, "BlobLength": self.blobLength}
        else:
            evt = self.evbuf.decode("utf-8")
        return {**super().to_json(), "Event": evt}


class FirmwareBlobEvent(GenericEvent):
    """
    Firmware blob measurement (old and new)
    EV_EFI_PLATFORM_FIRMWARE_BLOB EV_EFI_PLATFORM_FIRMWARE_BLOB2
    """

    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        (self.base, self.length) = struct.unpack("<QQ", buffer[idx : idx + 16])

    def to_json(self) -> dict:
        return {
            **super().to_json(),
            "Event": {"BlobBase": self.base, "BlobLength": self.length},
        }


class EfiIPLEvent(GenericEvent):
    """
    EV_IPL: Used during initial program load.
    ---
    Differs from generic events in that the body of the
    event is a zero terminated UTF-8 string describing
    what is being loaded.

    NOTE we choose to not carry the terminating zero as part of the JSON output.
    """

    def to_json(self) -> dict:
        return {**super().to_json(), "Event": {"String": nullterm8(self.evbuf[:-1])}}


class SpecIdEvent(GenericEvent):
    """
    This is the first event in the log, and it gets a lot of
    special processing. It does not have a type in the enumeration
    of event types.
    """

    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        (
            self.signature,
            self.platformClass,
            self.specVersionMinor,
            self.specVersionMajor,
            self.specErrata,
            self.uintnSize,
            self.numberOfAlgorithms,
        ) = struct.unpack("<16sIBBBBI", buffer[idx + 0 : idx + 28])
        idx += 28
        self.alglist = []
        for x in range(0, self.numberOfAlgorithms):
            (algid, digsize) = struct.unpack("<HH", buffer[idx : idx + 4])
            idx += 4
            self.alglist.append(
                {
                    f"Algorithm[{x}]": None,
                    "algorithmId": Digest(algid).name,
                    "digestSize": digsize,
                }
            )
        (self.vendorInfoSize,) = struct.unpack("<I", buffer[idx : idx + 4])
        self.vendorInfo = buffer[idx + 4 : idx + 4 + self.vendorInfoSize]

    def to_json(self):
        j = super().to_json()
        del j["DigestCount"]
        del j["Digests"]
        del j["Event"]
        j["Digest"] = self.digests[Digest.sha1].digest.hex()
        j["SpecID"] = [
            {
                "Signature": nullterm8(self.signature),
                "platformClass": self.platformClass,
                "specVersionMinor": self.specVersionMinor,
                "specVersionMajor": self.specVersionMajor,
                "specErrata": self.specErrata,
                "uintnSize": self.uintnSize,
                "vendorInfoSize": self.vendorInfoSize,
                "numberOfAlgorithms": self.numberOfAlgorithms,
                "Algorithms": self.alglist,
            }
        ]
        if self.vendorInfoSize > 0:
            j["SpecID"][0]["vendorInfo"] = self.vendorInfo.decode("utf-8")
        return j


class EfiVarEvent(ValidatedEvent):
    """
    EV_EFI_VARIABLE_DRIVER_CONFIG: EfiVarEvent is used to cover multiple
    types of EFI variable measurements.
    """

    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        self.guid = uuid.UUID(bytes_le=buffer[idx : idx + 16])
        self.gg = buffer[idx : idx + 16]
        (self.namelen, self.datalen) = struct.unpack("<QQ", buffer[idx + 16 : idx + 32])
        self.name = buffer[idx + 32 : idx + 32 + 2 * self.namelen]
        self.data = buffer[
            idx + 32 + 2 * self.namelen : idx + 32 + 2 * self.namelen + self.datalen
        ]

    @classmethod
    def parse(cls, eventheader: Tuple, buffer: bytes, idx: int):
        """
        EFI variables are handled differently by tpm2_eventlog
        based on their names or whether they contain booleans.
        Best discriminator for boolean values is whether the
        data length is 1.

        Secure boot related variables get special handling.
        """
        (namelen, datalen) = struct.unpack("<QQ", buffer[idx + 16 : idx + 32])
        name = buffer[idx + 32 : idx + 32 + 2 * namelen].decode("utf-16")
        if datalen == 1:
            return EfiVarBooleanEvent(eventheader, buffer, idx)
        if name in ["PK", "KEK", "db", "dbx"]:
            return EfiSignatureListEvent(eventheader, buffer, idx)
        return EfiVarEvent(eventheader, buffer, idx)

    def to_json(self) -> dict:
        return {
            **super().to_json(),
            "Event": {
                "UnicodeName": self.name.decode("utf-16"),
                "UnicodeNameLength": self.namelen,
                "VariableDataLength": self.datalen,
                "VariableName": str(self.guid),
                "VariableData": self.data.hex(),
            },
        }


class EfiVarAuthEvent(EfiVarEvent):
    """
    EFI variable authority event (EV_EFI_VARIABLE_AUTHORITY).
    Contains a single signature, a boolean or a string.
    Booleans are easy to find (datalen==1)
    It is unclear what general rule decides between strings and signatures,
    so the current implementation decides based on variable names.
    """

    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        self.sigdata = EfiSignatureData(self.data, self.datalen, 0)

    @classmethod
    def parse(cls, eventheader: Tuple, buffer: bytes, idx: int):
        (namelen, datalen) = struct.unpack("<QQ", buffer[idx + 16 : idx + 32])
        name = buffer[idx + 32 : idx + 32 + 2 * namelen].decode("utf-16")
        if datalen == 1:
            return EfiVarBooleanEvent(eventheader, buffer, idx)
        if name == "MokList":
            return EfiVarHexEvent(eventheader, buffer, idx)
        if name == "SbatLevel":
            return EfiVarStringEvent(eventheader, buffer, idx)
        return EfiVarAuthEvent(eventheader, buffer, idx)

    def to_json(self) -> dict:
        j = super().to_json()
        j["Event"]["VariableData"] = [self.sigdata]
        return j

    # signature data are not subject to validation.
    def validate(self) -> Tuple[bool, bool, str]:
        return True, True, ""


class EfiVarBooleanEvent(EfiVarEvent):
    """
    Boolean EFI variable.
    """

    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        (self.enabled,) = struct.unpack("<?", self.data[:1])

    def to_json(self) -> dict:
        j = super().to_json()
        j["Event"]["VariableData"] = {"Enabled": "Yes" if self.enabled else "No"}
        return j


class EfiVarStringEvent(EfiVarEvent):
    """
    String EFI variable.
    """

    def to_json(self) -> dict:
        j = super().to_json()
        j["Event"]["VariableData"] = {"String": self.data.decode("utf-8")}
        return j


class EfiVarHexEvent(EfiVarEvent):
    """
    EFI variable encoded as a hexadecimal string
    """

    def to_json(self) -> dict:
        j = super().to_json()
        j["Event"]["VariableData"] = self.data.hex()
        return j


class EfiVarBootEvent(EfiVarEvent):
    """
    EFI variable describing a boot entry
    EFI_LOAD_OPTION, https://dox.ipxe.org/UefiSpec_8h_source.html, line 2069
    """

    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        (self.attributes, self.filepathlistlength) = struct.unpack(
            "<IH", self.data[0:6]
        )
        # description UTF-16 string: from byte 6 to the first pair of zeroes
        desclen = 0
        while self.data[desclen + 6 : desclen + 8] != bytes([0, 0]):
            desclen += 2
        self.description = self.data[6 : 6 + desclen]
        # dev path: from the end of the description string to the end of data
        devpathlen = (self.datalen - 8 - desclen) * 2 + 1
        self.devicePath = self.data[8 + desclen : 8 + desclen + devpathlen].hex()

    @classmethod
    def parse(cls, eventheader: Tuple, buffer: bytes, idx: int):
        (namelen,) = struct.unpack("<Q", buffer[idx + 16 : idx + 24])
        name = buffer[idx + 32 : idx + 32 + 2 * namelen].decode("utf-16")
        if name == "BootOrder":
            return EfiVarBootOrderEvent(eventheader, buffer, idx)
        if re.compile("^Boot[0-9a-fA-F]{4}$").search(name):
            return EfiVarBootEvent(eventheader, buffer, idx)
        return EfiVarEvent(eventheader, buffer, idx)

    def validate(self) -> Tuple[bool, bool, str]:
        """
        The published digest of this event can match either the entire
        event buffer or just the data portion (without the name).
        I have not found any documentation about this choice -- I imagine
        it is left to UEFI BIOS implementers. So we accept either.
        """
        for algid, refdigest in self.digests.items():
            calchash1 = EfiEventDigest.hashalgmap[algid](self.evbuf).digest()
            calchash2 = EfiEventDigest.hashalgmap[algid](self.data).digest()
            if refdigest not in (calchash1, calchash2):
                return False, False, str(self.name.decode("utf-16"))
        return False, True, ""

    def to_json(self) -> dict:
        j = super().to_json()
        j["Event"]["VariableData"] = {
            "Enabled": "Yes" if (self.attributes & 1) == 1 else "No",
            "FilePathListLength": self.filepathlistlength,
            "Description": self.description.decode("utf-16"),
            "DevicePath": self.devicePath,
        }
        return j


class EfiVarBootOrderEvent(EfiVarEvent):
    """
    EFI event describing the BIOS boot order.
    """

    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        assert (self.datalen % 2) == 0
        self.bootorder = struct.unpack(f"<{self.datalen//2}H", self.data)

    def to_json(self) -> dict:
        j = super().to_json()
        j["Event"]["VariableData"] = [f"Boot{b:04x}" for b in self.bootorder]
        return j

    # the published digest can match the entire event buffer or just the data portion (without the name).
    def validate(self) -> Tuple[bool, bool, str]:
        for algid, refdigest in self.digests.items():
            calchash1 = EfiEventDigest.hashalgmap[algid](self.evbuf).digest()
            calchash2 = EfiEventDigest.hashalgmap[algid](self.data).digest()
            if refdigest not in (calchash1, calchash2):
                return False, False, str(self.name.decode("utf-16"))
        return False, True, ""


class EfiSignatureListEvent(EfiVarEvent):
    """
    EFI signature event: an EFI variable event for secure boot variables.
    """

    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        idx2 = 0
        self.varlist = []
        while idx2 < self.datalen:
            var = EfiSignatureList(self.data, idx2)
            idx2 += var.listsize
            self.varlist.append(var)

    def to_json(self) -> dict:
        j = super().to_json()
        if len(self.varlist) == 0:
            j["Event"]["VariableData"] = None
        else:
            j["Event"]["VariableData"] = self.varlist
        return j


class EfiSignatureList:
    """
    A list of EFI signatures (UEFI Spec 2.88 Section 32.4.1, EFI_SIGNATURE_LIST)
    """

    def __init__(self, buffer, idx):
        self.sigtype = uuid.UUID(bytes_le=buffer[idx : idx + 16])
        (self.listsize, self.hsize, self.sigsize) = struct.unpack(
            "<III", buffer[idx + 16 : idx + 28]
        )
        idx2 = 28 + self.hsize
        self.keys = []
        while idx2 < self.listsize:
            key = EfiSignatureData(buffer, self.sigsize, idx + idx2)
            self.keys.append(key)
            idx2 += self.sigsize

    def to_json(self) -> dict:
        return {
            "SignatureType": str(self.sigtype),
            "SignatureHeaderSize": self.hsize,
            "SignatureListSize": self.listsize,
            "SignatureSize": self.sigsize,
            "Keys": self.keys,
        }


class EfiSignatureData:
    """
    A single EFI signature
    UEFI Spec 2.88 Section 32.4.1, EFI_SIGNATURE_DATA
    """

    def __init__(self, buffer: bytes, sigsize, idx):
        assert (
            len(buffer) >= 16
        ), f"EFI signature truncated, expected 16, found {len(buffer)} bytes"
        self.owner = uuid.UUID(bytes_le=buffer[idx : idx + 16])
        self.sigdata = buffer[idx + 16 : idx + sigsize]

    def to_json(self) -> dict:
        return {"SignatureOwner": str(self.owner), "SignatureData": self.sigdata.hex()}


class EfiActionEvent(GenericEvent):
    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        self.event = buffer[idx : idx + self.evsize]

    def to_json(self) -> dict:
        return {**super().to_json(), "Event": self.event.decode("utf-8")}


class EfiGPTEvent(ValidatedEvent):
    """
    EFI GPT event (a GPT partition table description event)
    """

    class GPTPartHeader:
        """
        Embedded class: GPT Partition header, UEFI Spec version 2.88 Errata B Section 5.3.2 Table 21
        """

        def __init__(self, buffer, idx):
            (
                self.signature,
                self.revision,
                self.headerSize,
                self.headerCRC32,
                _,
                self.MyLBA,
                self.alternateLBA,
                self.firstUsableLBA,
                self.lastUsableLBA,
                guidbytes,
                self.partitionEntryLBA,
                self.numPartitionEntries,
                self.sizeOfPartitionEntry,
                self.partitionEntryArrayCRC,
            ) = struct.unpack("<8sIIIIQQQQ16sQIII", buffer[idx : idx + 92])
            self.diskGuid = uuid.UUID(bytes_le=guidbytes)

        def to_json(self) -> dict:
            return {
                "Signature": self.signature.decode("utf-8"),
                "Revision": self.revision,
                "HeaderSize": self.headerSize,
                "HeaderCRC32": self.headerCRC32,
                "MyLBA": self.MyLBA,
                "AlternateLBA": self.alternateLBA,
                "FirstUsableLBA": self.firstUsableLBA,
                "LastUsableLBA": self.lastUsableLBA,
                "DiskGUID": str(self.diskGuid),
                "PartitionEntryLBA": self.partitionEntryLBA,
                "NumberOfPartitionEntry": self.numPartitionEntries,
                "SizeOfPartitionEntry": self.sizeOfPartitionEntry,
                "PartitionEntryArrayCRC32": self.partitionEntryArrayCRC,
            }

    class GPTPartEntry:
        """
        Embedded class: GPT Partition entry, UEFI Spec version 2.88 Errata B Section 5.3.3 Table 22
        """

        def __init__(self, buffer, idx):
            self.partitionTypeGUID = uuid.UUID(bytes_le=buffer[idx : idx + 16])
            self.uniquePartitionGUID = uuid.UUID(bytes_le=buffer[idx + 16 : idx + 32])
            (
                self.startingLBA,
                self.endingLBA,
                self.attributes,
                self.partitionName,
            ) = struct.unpack("<QQQ72s", buffer[idx + 32 : idx + 128])

        def to_json(self) -> dict:
            return {
                "PartitionTypeGUID": str(self.partitionTypeGUID),
                "UniquePartitionGUID": str(self.uniquePartitionGUID),
                "Attributes": self.attributes,
                "StartingLBA": self.startingLBA,
                "EndingLBA": self.endingLBA,
                "PartitionName": nullterm16(self.partitionName),
            }

    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        self.gptheader = self.GPTPartHeader(buffer, idx)
        idx += self.gptheader.headerSize
        (self.numparts,) = struct.unpack("<Q", buffer[idx : idx + 8])
        idx += 8
        self.partitions = []
        for _ in range(0, self.numparts):
            self.partitions.append(self.GPTPartEntry(buffer, idx))
            idx += self.gptheader.sizeOfPartitionEntry

    def to_json(self) -> dict:
        return {
            **super().to_json(),
            "Event": {
                "Header": self.gptheader.to_json(),
                "NumberOfPartitions": self.numparts,
                "Partitions": self.partitions,
            },
        }


# ########################################
# Event type: uefi image load
# TCG PC Client platform firmware profile, UEFI_IMAGE_LOAD_EVENT, Section 10.2.3
# ########################################


class UefiImageLoadEvent(GenericEvent):
    def __init__(self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        (
            self.addrinmem,
            self.lengthinmem,
            self.linktimeaddr,
            self.lengthofdevpath,
        ) = struct.unpack("<QQQQ", buffer[idx : idx + 32])

        self.devpathlen = self.evsize - 32
        self.devpath = buffer[idx + 32 : idx + 32 + self.devpathlen].hex()

    def to_json(self) -> dict:
        j = super().to_json()
        j["Event"] = {
            "ImageLocationInMemory": self.addrinmem,
            "ImageLengthInMemory": self.lengthinmem,
            "ImageLinkTimeAddress": self.linktimeaddr,
            "LengthOfDevicePath": self.lengthofdevpath,
            "DevicePath": str(self.devpath),
        }
        return j


# ########################################
# Event Log parser
# ########################################


class EventLog(list):
    """
    EventLog is really a list of EfiGenericEvent objects.
    Ref: TCG PC Client Specific Implementation Specification for Conventional BIOS
    """

    def __init__(self, buffer: bytes, buflen: int):
        """
        The constructor, when invoked on a buffer, performs the parsing
        """
        list.__init__(self)
        self.buflen = buflen
        evt, idx = EventLog.parse_1stevent(buffer, 0)
        self.append(evt)
        evidx = 1
        while idx < buflen:
            evt, idx = EventLog.parse_event(evidx, buffer, idx)
            self.append(evt)
            evidx += 1

    @staticmethod
    def parse_1stevent(buffer: bytes, idx: int) -> Tuple[GenericEvent, int]:
        """
        parser for 1st event
        TCG PC client platform firmware profile spec, structure: TCG_PCClientPCREvent, Section 10.2.1
        """
        (evpcr, evtype, digestbuf, evsize) = struct.unpack(
            "<II20sI", buffer[idx : idx + 32]
        )
        digests = {4: EfiEventDigest(Digest(4), digestbuf, 0)}
        evt = SpecIdEvent((evtype, evpcr, digests, evsize, 0), buffer, idx + 32)
        return (evt, idx + 32 + evsize)

    @staticmethod
    def parse_event(evidx: int, buffer: bytes, idx: int) -> Tuple[GenericEvent, int]:
        """
        parser for all other events
        TCG PC client platform firmware profile spec, structure: TCG_PCR_EVENT2, Section 10.2.2
        """
        (evpcr, evtype, digestcount) = struct.unpack("<III", buffer[idx : idx + 12])
        digests, idx = EfiEventDigest.parselist(digestcount, buffer, idx + 12)
        (evsize,) = struct.unpack("<I", buffer[idx : idx + 4])
        evt = EventLog.Handler(evtype)(
            (evtype, evpcr, digests, evsize, evidx), buffer, idx + 4
        )
        return (evt, idx + 4 + evsize)

    @staticmethod
    def Handler(evtype: int):
        """
        figure out which Event constructor to call depending on event type
        """
        EventHandlers = {
            Event.EV_POST_CODE: PostCodeEvent.parse,
            Event.EV_SEPARATOR: ValidatedEvent.parse,
            Event.EV_EFI_ACTION: EfiActionEvent.parse,
            Event.EV_EFI_GPT_EVENT: EfiGPTEvent.parse,
            Event.EV_IPL: EfiIPLEvent.parse,
            Event.EV_EFI_VARIABLE_DRIVER_CONFIG: EfiVarEvent.parse,
            Event.EV_EFI_VARIABLE_BOOT: EfiVarBootEvent.parse,
            Event.EV_EFI_BOOT_SERVICES_DRIVER: UefiImageLoadEvent.parse,
            Event.EV_EFI_BOOT_SERVICES_APPLICATION: UefiImageLoadEvent.parse,
            Event.EV_EFI_RUNTIME_SERVICES_DRIVER: UefiImageLoadEvent.parse,
            Event.EV_EFI_PLATFORM_FIRMWARE_BLOB: FirmwareBlobEvent.parse,
            Event.EV_EFI_PLATFORM_FIRMWARE_BLOB2: FirmwareBlobEvent.parse,
            Event.EV_EFI_VARIABLE_BOOT2: EfiVarBootEvent.parse,
            Event.EV_EFI_VARIABLE_AUTHORITY: EfiVarAuthEvent.parse,
            Event.EV_S_CRTM_VERSION: ValidatedEvent.parse,
        }
        try:
            return EventHandlers[Event(evtype)]
        except Exception as _:
            return GenericEvent.parse

    def pcrs(self) -> dict:
        """
        calculate the expected PCR values
        """
        algid = Digest.sha1
        d0 = EfiEventDigest.hashalgmap[algid]()
        pcrs = {}
        for event in self:
            if event.evtype == 3:
                continue  # do not measure NoAction events
            pcridx = event.evpcr
            oldpcr = pcrs[pcridx] if pcridx in pcrs else bytes(d0.digest_size)
            extdata = event.digests[algid].digest
            newpcr = EfiEventDigest.hashalgmap[algid](oldpcr + extdata).digest()
            pcrs[pcridx] = newpcr
        return pcrs

    def validate(self) -> list[list[Tuple]]:
        """
        run validation on all events
        returns a triplet of lists
        in the first list are all events that are vacuously valid (no self-validation)
        in the second list are all events that have passed validation
        in the third list are all events that have failed validation

        THIS IS PROBABLY TEMPORARY. It is a useful debugging tool, but the production use
        will most likely demand a single boolean answer (passed/failed)
        """
        pass_list = []
        fail_list = []
        vac_list = []
        for evt in self:
            vacuous, passed, why = evt.validate()
            if vacuous:
                vac_list.append((evt.evidx, evt.evtype.name, type(evt)))
            elif passed:
                pass_list.append((evt.evidx, evt.evtype.name, type(evt)))
            else:
                fail_list.append((evt.evidx, evt.evtype.name, type(evt), why))
        return [vac_list, pass_list, fail_list]
