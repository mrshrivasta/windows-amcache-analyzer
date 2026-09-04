"""
hive_builder.py — Windows Amcache Analyzer test support

Real, from-scratch construction of a minimal-but-genuinely-valid Windows
Registry (REGF) hive file, built by hand with `struct` following the public
REGF/HBIN/NK/VK binary cell format. This is NOT a mock: the bytes produced
here are a real registry hive that python-registry's `Registry.Registry()`
actually opens and actually walks through its real NK/VK cell-parsing code
path — exactly like it would for a real Amcache.hve pulled off a real
Windows system.

Layout produced:
    REGF header (0x1000 bytes)
    one HBIN block containing, bottom-up:
        - VK records + their out-of-line RegSZ data cells for each value
        - a ValuesList cell per key that has values
        - leaf NK records (Amcache entry subkeys)
        - "lf" subkey-list cells
        - "Root" and "InventoryApplicationFile" NK records
        - the hive root NK record (flagged is_root)
"""
import struct


def _pad8(data):
    pad = (-len(data)) % 8
    return data + b"\x00" * pad


class HiveBuilder:
    def __init__(self):
        self._cells = bytearray()  # raw bytes of the single HBIN's cell area

    # HBIN pointer fields (NK/VK subkey/value/data offsets) are relative to
    # the START of the first HBIN block, which is 0x20 bytes BEFORE the cell
    # area (0x20 = size of the HBIN block header itself).
    HBIN_HEADER_SIZE = 0x20

    def add_cell(self, payload):
        """Real-append one HBINCell (4-byte negative-size prefix + payload,
        8-byte aligned) to the hive's cell area. Returns the offset of this
        cell relative to the start of the first HBIN (i.e. what NK/VK
        pointer fields expect)."""
        payload = _pad8(payload)
        total_size = 4 + len(payload)
        local_offset = len(self._cells)
        # Allocated cells store size as a NEGATIVE signed dword.
        self._cells += struct.pack("<i", -total_size)
        self._cells += payload
        return local_offset + self.HBIN_HEADER_SIZE

    def add_vk(self, name, data_type, data_bytes):
        """Real-build a VK record + its out-of-line data cell. Returns the
        VK record's cell offset (relative to first HBIN)."""
        name_bytes = name.encode("windows-1252")
        if data_bytes is None:
            data_bytes = b""

        if len(data_bytes) == 0:
            data_offset_field = 0
            data_length = 0x80000000  # inline / empty, per raw_data_length() high bit
        else:
            data_cell_offset = self.add_cell(data_bytes)
            data_offset_field = data_cell_offset
            data_length = len(data_bytes)

        vk = b"vk"
        vk += struct.pack("<H", len(name_bytes))       # 0x2  name length
        vk += struct.pack("<I", data_length)            # 0x4  data length
        vk += struct.pack("<I", data_offset_field)       # 0x8  data offset
        vk += struct.pack("<I", data_type)               # 0xC  data type
        vk += struct.pack("<H", 0x0001)                  # 0x10 flags: bit0 = ascii name
        vk += struct.pack("<H", 0)                        # 0x12 spare
        vk += name_bytes                                   # 0x14 name
        return self.add_cell(vk)

    def add_values_list(self, vk_offsets):
        payload = b"".join(struct.pack("<I", off) for off in vk_offsets)
        return self.add_cell(payload)

    def add_nk(self, name, is_root=False, subkey_list_offset=None,
               subkey_count=0, values_list_offset=None, values_count=0):
        name_bytes = name.encode("windows-1252")
        flags = 0x0020  # ascii name
        if is_root:
            flags |= 0x0004

        nk = b"nk"
        nk += struct.pack("<H", flags)                          # 0x2
        nk += struct.pack("<Q", 0)                                # 0x4  timestamp
        nk += struct.pack("<I", 0)                                 # 0xC  spare/access bits
        nk += struct.pack("<I", 0)                                  # 0x10 parent offset (unused by our nav)
        nk += struct.pack("<I", subkey_count)                        # 0x14 subkey count
        nk += struct.pack("<I", 0)                                    # 0x18 volatile subkey count
        nk += struct.pack("<I", subkey_list_offset or 0)                # 0x1C subkey list offset
        nk += struct.pack("<I", 0xFFFFFFFF)                               # 0x20 volatile subkey list offset
        nk += struct.pack("<I", values_count)                              # 0x24 values count
        nk += struct.pack("<I", values_list_offset or 0)                    # 0x28 values list offset
        nk += struct.pack("<I", 0)                                           # 0x2C sk offset
        nk += struct.pack("<I", 0)                                            # 0x30 classname offset
        nk += b"\x00" * 20                                                     # 0x34..0x47 max-length stats
        nk += struct.pack("<H", len(name_bytes))                                # 0x48 name length
        nk += struct.pack("<H", 0)                                               # 0x4A classname length
        nk += name_bytes                                                          # 0x4C name
        return self.add_cell(nk)

    def add_subkey_list(self, nk_offsets):
        payload = b"lf"
        payload += struct.pack("<H", len(nk_offsets))
        for off in nk_offsets:
            payload += struct.pack("<I", off)
            payload += b"\x00\x00\x00\x00"  # 4-byte name-hint hash, unused by parser
        return self.add_cell(payload)

    def build_key(self, name, values=None, subkeys=None, is_root=False):
        """Real-build one NK record with real VK children and/or real NK
        subkey children already built (offsets known), wiring up its
        ValuesList / subkey "lf" list as needed. `values` is a list of
        (name, data_type, data_bytes). `subkeys` is a list of already-built
        NK cell offsets. Returns this key's own NK cell offset."""
        values = values or []
        subkeys = subkeys or []

        values_list_offset = None
        if values:
            vk_offsets = [self.add_vk(n, t, d) for (n, t, d) in values]
            values_list_offset = self.add_values_list(vk_offsets)

        subkey_list_offset = None
        if subkeys:
            subkey_list_offset = self.add_subkey_list(subkeys)

        return self.add_nk(
            name,
            is_root=is_root,
            subkey_list_offset=subkey_list_offset,
            subkey_count=len(subkeys),
            values_list_offset=values_list_offset,
            values_count=len(values),
        )

    def finalize(self, root_offset, hive_name="Amcache.hve"):
        """Real-assemble the finished REGF header + single HBIN block into a
        complete, byte-accurate hive file body."""
        cell_area = bytes(self._cells)
        # HBIN block header (0x20 bytes) + cell area, padded to a 0x1000 multiple.
        hbin_body = cell_area
        hbin_total = 0x20 + len(hbin_body)
        pad_to = ((hbin_total + 0xFFF) // 0x1000) * 0x1000
        hbin_body += b"\x00" * (pad_to - hbin_total)
        hbin_size = 0x20 + len(hbin_body)

        hbin_header = b"hbin"
        hbin_header += struct.pack("<I", 0)          # offset of this hbin rel. to first hbin
        hbin_header += struct.pack("<I", hbin_size)   # offset/size of next hbin (== this hbin's size)
        hbin_header += b"\x00" * 20                     # timestamp + spare, unused by parser (pads header to 0x20)

        hbin_block = hbin_header + hbin_body

        # REGF base block (first 0x1000 bytes of the file)
        header = bytearray(0x1000)
        header[0x0:0x4] = b"regf"
        struct.pack_into("<I", header, 0x4, 1)          # sequence1
        struct.pack_into("<I", header, 0x8, 1)          # sequence2
        struct.pack_into("<Q", header, 0xC, 0)           # last modified timestamp
        struct.pack_into("<I", header, 0x14, 1)           # major version
        struct.pack_into("<I", header, 0x18, 5)             # minor version
        struct.pack_into("<I", header, 0x1C, 0)               # file type = primary
        struct.pack_into("<I", header, 0x20, 1)                 # file format
        struct.pack_into("<I", header, 0x24, root_offset)         # root key offset (rel. to first hbin)
        struct.pack_into("<I", header, 0x28, hbin_size)             # hbins_size
        struct.pack_into("<I", header, 0x2C, 1)                      # clustering factor
        name_bytes = hive_name.encode("utf-16le")[:64]
        header[0x30:0x30 + len(name_bytes)] = name_bytes

        # Checksum: XOR of all dwords from 0x0 to 0x1FB inclusive.
        xsum = 0
        for i in range(0, 0x1FC, 4):
            xsum ^= struct.unpack_from("<I", header, i)[0]
        xsum &= 0xFFFFFFFF
        if xsum == 0:
            xsum = 1
        elif xsum == 0xFFFFFFFF:
            xsum = 0xFFFFFFFE
        struct.pack_into("<I", header, 0x1FC, xsum)

        return bytes(header) + hbin_block


REG_SZ = 0x0001


def build_amcache_hive(out_path, entries, legacy_entries=None, hive_name="Amcache.hve"):
    """Real-build a full Amcache-shaped hive file on disk at out_path.

    entries: list of dicts with keys among:
        name, path, publisher, product_name, size, link_date, sha1, program_id
      -> written under Root\\InventoryApplicationFile\\<name>

    legacy_entries: same shape, written under Root\\File\\<volguid>\\<name>
      to exercise the Windows 8/8.1 legacy layout fallback.
    """
    hb = HiveBuilder()

    def _entry_values(e):
        vals = []
        if e.get("path") is not None:
            vals.append(("LowerCaseLongPath", REG_SZ, e["path"].encode("utf-16le")))
        if e.get("publisher") is not None:
            vals.append(("Publisher", REG_SZ, e["publisher"].encode("utf-16le")))
        if e.get("product_name") is not None:
            vals.append(("ProductName", REG_SZ, e["product_name"].encode("utf-16le")))
        if e.get("link_date") is not None:
            vals.append(("LinkDate", REG_SZ, e["link_date"].encode("utf-16le")))
        if e.get("sha1") is not None:
            vals.append(("FileId", REG_SZ, e["sha1"].encode("utf-16le")))
        if e.get("program_id") is not None:
            vals.append(("ProgramId", REG_SZ, e["program_id"].encode("utf-16le")))
        return vals

    iaf_subkey_offsets = []
    for idx, entry in enumerate(entries):
        key_name = entry.get("name", "%04d" % idx)
        off = hb.build_key(key_name, values=_entry_values(entry))
        iaf_subkey_offsets.append(off)
    iaf_offset = hb.build_key("InventoryApplicationFile", subkeys=iaf_subkey_offsets)

    root_subkeys = [iaf_offset]

    if legacy_entries:
        legacy_subkey_offsets = []
        for idx, entry in enumerate(legacy_entries):
            key_name = entry.get("name", "%04d" % idx)
            off = hb.build_key(key_name, values=_entry_values(entry))
            legacy_subkey_offsets.append(off)
        volume_offset = hb.build_key("{00000000-0000-0000-0000-000000000000}", subkeys=legacy_subkey_offsets)
        file_offset = hb.build_key("File", subkeys=[volume_offset])
        root_subkeys.append(file_offset)

    root_of_amcache_offset = hb.build_key("Root", subkeys=root_subkeys)
    hive_root_offset = hb.build_key("HiveRoot", subkeys=[root_of_amcache_offset], is_root=True)

    data = hb.finalize(hive_root_offset, hive_name=hive_name)
    with open(out_path, "wb") as fh:
        fh.write(data)
    return out_path
