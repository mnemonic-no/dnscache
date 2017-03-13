# ISC License
#
# Copyright (c) 2017, mnemonic AS <opensource@mnemonic.no>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""This module attempts to extract the DNS cache from a Windows image

@author:        Geir Skjotskift
@license:       ISC License
@contact:       opensource@mnemonic.no

DEPENDENCIES:
    construct (pdbparse dependency)
    pdbparse
    pefile
    requests
    cabextract (system utility)

REFERENCES:
    [1] Cohen, M. (2014). The Windows User mode heap and the DNS resolver cache.
        Retrieved from:
          http://www.rekall-forensic.com/posts/2014-12-20-usermode-heap.html
    [2] Cohen, M. (2014). Source code for Module rekall.plugins.windows.dns
        Retrieved from:
          http://www.rekall-forensic.com/epydocs/rekall.plugins.windows.dns-pysrc.html
    [3] Pulley, C. (2013). Source code for Module symbols.py (volatility community plugins)
        Retrieved from:
          https://github.com/carlpulley/volatility/blob/master/symbols.py
    [4] Ligh, M., Case, A., Levy, J. & Walters, A. (2014). The Art of Memory Forensics.
    [5] Levy, J. (2015). dns cache plugin #201 (Volatility Issiues)
        Retrieved from:
          https://github.com/volatilityfoundation/volatility/issues/201

DEBUG:
    NameError: name 'ULInt32' is not defined #31
    --------------------------------------------
    $ pip install construct==2.5.5-reupload
    Retrieved from:
      https://github.com/moyix/pdbparse/issues/31
"""

import os
import pefile
import pdbparse
import pdbparse.peinfo
import shutil
import subprocess
import sys
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32 as win32

candownload = False
try:
    import requests
    candownload = True
except ImportError:
    self.logverbose("Missing python library requests. You need to manually provide .PDB file")



dnstypes = {
        '_DNS_RECORD' : [ None, {
            'pNext'       : [ 0x00, ['pointer', ['_DNS_RECORD']]],
            'pName'       : [ 0x08, ['pointer', ['unsigned short']]],
            'wType'       : [ 0x10, ['unsigned short']],
            'wDataLength' : [ 0x12, ['unsigned short']],
            'dwFlags'     : [ 0x14, ['unsigned long']],
            'dwTTL'       : [ 0x18, ['unsigned long']],
            'Data'        : [ 0x20, ['unsigned long']], # this can be various size, depends on datalength
            } ],
        }

WinXPx86_DNS_TYPES = {
        '_DNS_RECORD' : [ None, {
            'pNext'       : [ 0x00, ['pointer', ['_DNS_RECORD']]],
            'pName'       : [ 0x04, ['pointer', ['unsigned short']]],
            'wType'       : [ 0x08, ['unsigned short']],
            'wDataLength' : [ 0x0a, ['unsigned short']],
            'dwFlags'     : [ 0x0c, ['unsigned long']],
            'dwTTL'       : [ 0x10, ['unsigned long']],
            'Data'        : [ 0x18, ['unsigned long']],
            } ],
        }

dns_hashtable_entry = {
        '_DNS_HASHTABLE_ENTRY' : [ 0x1c, {
            'List'   : [ 0x00, ['pointer', ['_LIST_ENTRY']]],
            'Name'   : [ 0x08, ['pointer', ['_UNICODE_STRING']]],
            'Record' : [ 0x18, ['pointer', ['_DNS_RECORD']]],
            }]
        }

win10_dns_hashtable_entry = {
        '_DNS_HASHTABLE_ENTRY' : [ 0x5c, {
            'List'   : [ 0x08, ['pointer', ['_LIST_ENTRY']]],
            'Name'   : [ 0x38, ['pointer', ['_LARGE_UNICODE_STRING']]],
            'Record' : [ 0x58, ['pointer', ['_DNS_RECORD']]],
            }]
        }

WinXPx86_dns_hashtable_entry = {
        '_DNS_HASHTABLE_ENTRY' : [ None, {
            'List'   : [ 0x00, ['pointer', ['_LIST_ENTRY']]],
            'Name'   : [ 0x04, ['pointer', ['_UNICODE_STRING']]],
            'Record' : [ 0x10, ['pointer', ['_DNS_RECRD']]],
            }]
        }



class DNSHastableTypesWindows10_and_2016_10(obj.ProfileModification):

    conditions = {'os'   : lambda x: x == 'windows',
                  'major': lambda x: x == 10,
                  }

    def modification(self, profile):

        profile.vtypes.update(dnstypes)
        profile.vtypes.update(win10_dns_hashtable_entry)


class DNSHastableTypesWindows10_and_2016(obj.ProfileModification):

    conditions = {'os'   : lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4,
                  }

    def modification(self, profile):

        profile.vtypes.update(dnstypes)
        profile.vtypes.update(win10_dns_hashtable_entry)


class DNSHastableTypesWindows81_2012R2(obj.ProfileModification):

    conditions = {'os'   : lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 3,
                  }

    def modification(self, profile):

        profile.vtypes.update(dnstypes)
        profile.vtypes.update(win10_dns_hashtable_entry)


class DNSHastableTypesWindows8_2012(obj.ProfileModification):

    conditions = {'os'   : lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 2,
                  }

    def modification(self, profile):

        profile.vtypes.update(dnstypes)
        profile.vtypes.update(win10_dns_hashtable_entry)


class DNSHastableTypesWindows7_2008R2(obj.ProfileModification):

    conditions = {'os'   : lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  }

    def modification(self, profile):

        profile.vtypes.update(dnstypes)
        profile.vtypes.update(win10_dns_hashtable_entry)


class DNSHastableTypesWindowsVista_2008(obj.ProfileModification):

    conditions = {'os'   : lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  }

    def modification(self, profile):

        profile.vtypes.update(dnstypes)
        profile.vtypes.update(win10_dns_hashtable_entry)


class DNSHastableTypesOld(obj.ProfileModification):

    conditions = {'os'   : lambda x: x == 'windows',
                  'major': lambda x: x <= 5,
                  'memory_model': lambda x: x == '64bit',
                  }

    def modification(self, profile):

        profile.vtypes.update(dnstypes)
        profile.vtypes.update(dns_hashtable_entry)


class DNSHastableTypesOldx86(obj.ProfileModification):

    conditions = {'os'   : lambda x: x == 'windows',
                  'major': lambda x: x <= 5,
                  'memory_model': lambda x: x == '32bit',
                  }

    def modification(self, profile):

        profile.vtypes.update(WinXPx86_DNS_TYPES)
        profile.vtypes.update(WinXPx86_dns_hashtable_entry)


class DNSCache(common.AbstractWindowsCommand):
    """Volatility plugin to extract the Windows DNS cache

    Options:
    --proxy_server=PROXY_SERVER
                        Use this proxy to download .PDB file
    -D DUMP_DIR, --dump_dir=DUMP_DIR
                        Dump directory for .PDB file
    --symbols=http://msdl.microsoft.com/download/symbols
                        Server to download .PDB file from
    --pdb_file=PDB_FILE
                        Allows you to download the .PDB file off system and
                        provide the reference on the command line
    --cabextract=cabextract
                        Provide path to the cabextract system utility
    --dll_file=DLL_FILE
                        Provide dnsrslvr.dll from the file system.
    """

    meta_info = {}
    meta_info['author']    = 'Geir Skjotskift'
    meta_info['copyright'] = 'Copyright (c) 2017, mnemonic AS'
    meta_info['contact']   = 'opensource@mnemonic.no'
    meta_info['license']   = 'ISC License'
    meta_info['url']       = 'https://mnemonic.no'

    def __init__(self, config, *args, **kwargs):

        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option('PROXY_SERVER',  default = None,
                          help = 'Use this proxy to download .PDB file',
                          action = 'store')
        config.add_option('DUMP_DIR', short_option = 'D', default = None,
                          help = 'Dump directory for .PDB file',
                          action = 'store')
        config.add_option("SYMBOLS", default="http://msdl.microsoft.com/download/symbols",
                          help = "Server to download .PDB file from", action = 'store')
        config.add_option("PDB_FILE", default = None,
                          help = "Allows you to download the .PDB file off system and provide the reference on the command line",
                          action = "store")
        config.add_option("CABEXTRACT", default = "cabextract",
                          help = "Provide path to the cabextract system utility",
                          action = "store")
        config.add_option("DLL_FILE", default="", help = "Provide dnsrslvr.dll from the file system",
                          action = "store")

        if self._config.VERBOSE:
            self.logverbose = debug.info
        self.cache_found = False
        self.pid = 0
        self.dllname = ""

    def logverbose(self, msg):
        if self._config.VERBOSE:
            debug.info(msg)

    def _find_dns_resolver(self, ps_list):

        for proc in ps_list:
            for mod in proc.get_load_modules():
                if mod.m("BaseDllName") == "dnsrslvr.dll":
                    yield proc, mod

    def _is_valid_debug_dir(self, debug_dir, image_base, addr_space):
        if debug_dir == None:
            self.logverbose("debug_dir is None")
            return False

        if debug_dir.AddressOfRawData == 0:
            self.logverbose("debug_dir == 0")
            return False

        if not addr_space.is_valid_address(image_base + debug_dir.AddressOfRawData):
            self.logverbose("Invalid address: {0:#x}".format(image_base + debug_dir.AddressOfRawData))
            return False

        if not addr_space.is_valid_address(image_base + debug_dir.AddressOfRawData + debug_dir.SizeOfData - 1):
            self.logverbose("Debug data outside valid address space: {0:#x}".format(image_base + debug_dir.AddressOfRawData + debug_dir.SizeOfData - 1))
            return False

        return True

    def _get_debug_symbols(self, addr_space, mod):

        image_base = mod.DllBase
        debug_dir = mod.get_debug_directory()

        if not self._is_valid_debug_dir(debug_dir, image_base, addr_space):
            self.logverbose("Invalid debug dir {0:#x} {1:#x}".format(debug_dir.v(), image_base.v()))
            return None, None

        self.logverbose("Found debug_dir: {0:#x}, image_base: {1:#x}".format(debug_dir.v(), image_base.v()))
        debug_data = addr_space.zread(image_base + debug_dir.AddressOfRawData, debug_dir.SizeOfData)
        if debug_data[:4] == 'RSDS':
            return pdbparse.peinfo.get_rsds(debug_data)

        self.logverbose("Found no RSDS")
        return None, None

    def _download_pdb_file(self, guid, filename):

        if self._config.PDB_FILE:
            return self._config.PDB_FILE

        archive = filename[:-1] + "_"
        url = "{0}/{1}/{2}/{3}".format(self._config.SYMBOLS, filename, guid, archive)

        self.logverbose("Download URL .PDB file: {0}".format(url))

        if not candownload:
            self.logverbose("Manually provide the above resource with the --pdb-file option")
            return

        proxies = None
        if self._config.PROXY_SERVER:
            proxies = {
                    'http': self._config.PROXY_SERVER,
                    'https': self._config.PROXY_SERVER
                    }

        resp = requests.get(url, proxies=proxies, stream=True)

        if resp.status_code != 200:
            self.logverbose("Unable to download {0} (response code: {1})".format(url, resp.status_code))
            return

        archive_path = os.path.join(self._config.DUMP_DIR, archive)

        with open(archive_path, "wb") as af:
            shutil.copyfileobj(resp.raw, af)

        subprocess.call([self._config.CABEXTRACT, archive_path, "-d", self._config.DUMP_DIR])

        return os.path.join(self._config.DUMP_DIR, filename)

    def _get_pdb_filename(self):
        if self._config.PDB_FILE:
            return self._config.PDB_FILE
        if self._config.DUMP_DIR:
            return os.path.join(self._config.DUMP_DIR, "dnsrslvr.pdb")
        raise NoPDBFileException("Unable to provide PDB file name.")

    def _hash_info(self, pdbfile, imgbase=0):

        def _sym_name(sym):
            try:
                return sym.name
            except AttributeError:
                return ""

        pdb_file_name = self._get_pdb_filename()
        self.logverbose("Using PDB file: {0}".format(pdb_file_name))
        pdb = pdbparse.parse(self._get_pdb_filename())
        try:
            sects = pdb.STREAM_SECT_HDR_ORIG.sections
            omap = pdb.STREAM_OMAP_FROM_SRC
        except AttributeError as err:
            # In this case there is no OMAP, so we use the given section
            # headers and use the identity function for omap.remap
            sects = pdb.STREAM_SECT_HDR.sections
            omap = DummyOmap()


        g_HashTable_p = 0
        g_HashTableSize_p = 0
        g_CacheHeap_p = 0

        for sym in pdb.STREAM_GSYM.globals:
            if _sym_name(sym).endswith("g_HashTable"):
                off = sym.offset
                virt_base = sects[sym.segment-1].VirtualAddress
                g_HashTable_p = imgbase+omap.remap(off+virt_base)
            if _sym_name(sym).endswith("g_HashTableSize"):
                off = sym.offset
                virt_base = sects[sym.segment-1].VirtualAddress
                g_HashTableSize_p = imgbase+omap.remap(off+virt_base)
            if _sym_name(sym).endswith("g_CacheHeap"):
                off = sym.offset
                virt_base = sects[sym.segment-1].VirtualAddress
                g_CacheHeap_p = imgbase+omap.remap(off+virt_base)

        return g_HashTable_p, g_HashTableSize_p, g_CacheHeap_p

    def calculate(self):

        address_space = utils.load_as(self._config)

        metadata = address_space.profile.metadata
        version = (metadata.get("major", 0), metadata.get("minor", 0), metadata.get("memory_model", ""))
        self.logverbose("major, minor, memory_model: {0}".format(version))

        ps_list = win32.tasks.pslist(address_space)

        for proc, mod in self._find_dns_resolver(ps_list):


            self.logverbose("Found PID: {0} Dll: {1}".format(proc.UniqueProcessId, str(mod.m("FullDllName"))))
            self.pid = proc.UniqueProcessId
            self.dllname = str(mod.m("FullDllName"))

            proc_as = proc.get_process_address_space()

            if self._config.DLL_FILE: # User provide the dll file
                guid, pdb = extract_rsds(self._config.DLL_FILE)
            else: # search for the debug symbols in dll memory map
                guid, pdb = self._get_debug_symbols(proc_as, mod)

            if not guid:
                self.logverbose("No Debug symbols found")
                continue
            pdb_file = self._download_pdb_file(guid, pdb)
            self.logverbose("Using PDB: {0}".format(pdb_file))

            image_base_address = int(proc.Peb.m("ImageBaseAddress"))
            g_HashTable_offset, g_HashTableSize_offset, g_CacheHeap_offset = self._hash_info(pdb_file, mod.DllBase)
            self.logverbose("DllBase:                {0:#x}".format(mod.DllBase))
            self.logverbose("Offset g_CacheHeap:     {0:#x}".format(g_CacheHeap_offset))
            self.logverbose("Offset g_HashTable:     {0:#x}".format(g_HashTable_offset))

            g_HashTableSize = obj.Object('unsigned int', offset = g_HashTableSize_offset, vm = proc_as)

            self.logverbose("g_HashTableSize:        {0:#x}".format(g_HashTableSize))

            g_CacheHeap_p = obj.Object("Pointer", offset = g_CacheHeap_offset, vm = proc_as)
            g_HashTable_p = obj.Object("Pointer", offset = g_HashTable_offset, vm = proc_as)

            self.logverbose("g_CacheHeap_p:          {0:#x}".format(g_CacheHeap_p.v()))
            self.logverbose("g_HashTable_p:          {0:#x}".format(g_HashTable_p.v()))

            dnscache = obj.Object("Array", targetType="Pointer", count = g_HashTableSize + 1, offset = g_HashTable_p, vm = proc_as)
            for p in dnscache:
                entry = obj.Object("_DNS_HASHTABLE_ENTRY", offset = p, vm = proc_as)
                if entry.Name:
                    self.cache_found = True
                    yield entry.v(), memstring(offset = entry.Name, vm = proc_as), "HASH", "{0:#x}".format(entry.Record.v()), ""
                    record = obj.Object("_DNS_RECORD", offset = entry.Record.v(), vm = proc_as)
                    runaway_count = 0
                    while True:
                        if record.wType == DNSType["A"]:
                            yield record.v(), str(memstring(offset = record.pName, vm = proc_as)), "A", str(IPv4DWORD(record.Data)), record.dwTTL
                        elif PTR_DATA.has_key(record.wType.v()): # all types where data is a pointer to a string
                            yield record.v(), str(memstring(offset = record.pName, vm = proc_as)), PTR_DATA[record.wType.v()], dnspstr(record=record, vm = proc_as), record.dwTTL
                        elif record.wType == DNSType["ALL"]:
                            yield record.v(), str(memstring(offset = record.pName, vm = proc_as)), "ALL", dnspstr(record = record, vm = proc_as), record.dwTTL
                        elif record.wType == DNSType["AAAA"]:
                            yield record.v(), str(memstring(offset = record.pName, vm = proc_as)), "AAAA", memipv6(offset = record.Data.obj_offset, vm = proc_as), record.dwTTL
                        else:
                            val = val_to_type(record.wType)
                            if val != "UNKNOWN": # Try to print old hashes with overwrites.
                                yield record.v(), str(memstring(offset = record.pName, vm = proc_as)), val, "(catch all, value not interpreted)", record.dwTTL

                        if not record.pNext or runaway_count > 100:
                            break
                        runaway_count += 1
                        record = obj.Object("_DNS_RECORD", offset = record.pNext, vm = proc_as)

    def render_text(self, outfd, data):

        if self._config.DUMP_DIR == None and self._config.PDB_FILE == None:
            debug.error("Please specify a dump directory (--dump_dir)")

        self.table_header(outfd, [("Offset",  '#018x'),
            ('Name', '<64'),
            ('TTL',  '>8'),
            ('Type', '<6'),
            ('Value', '')])

        for offset, name, recordtype, value, ttl in data:
            self.table_row(outfd, offset, name, ttl, recordtype, value)

        outfd.write("-------------------------\n")
        outfd.write("PID: {0}, DLL: {1}\n".format(self.pid, self.dllname))
        if not self.cache_found:
            outfd.write("No cache found. dnsrslvr.dll paged?\n")


class IPv4DWORD(object):
    """IPv4DWORD is a wrapper object for a DWORD (uint32) representing)
    an IP version 4 address. The original value is stored in the value
    attribute, but it will be represented as a string in human readable
    form"""

    def __init__(self, value):
        """Constructor taking a DWORD as argument"""

        self.value = value

    def _IPv4FromDWORD(self):
        """_IPv4FromDWORD takes converst the DWORD representation
        into a human readble IPv4 form"""

        a = self.value & 0xff
        b = (self.value & 0xff00) >> 8
        c = (self.value & 0xff0000) >> 16
        d = (self.value & 0xff000000) >> 24
        return "%d.%d.%d.%d" % (a,b,c,d)

    def __str__(self):
        return self._IPv4FromDWORD()


# DNS type Enumeration
DNSPType = {
    "QUESTION": 0,
    "ANSWER": 1,
    "AUTHORITY": 2,
    "ADDITIONAL": 3
}

def val_to_type(value):
    for key,val in DNSType.items():
        if value == val:
            return key
    return "UNKNOWN"

PTR_DATA = {
        0x0002: "NS",
        0x0003: "MD",
        0x0004: "MF",
        0x0005: "CNAME",
        0x0007: "MB",
        0x0008: "MG",
        0x0009: "MR",
        0x000c: "PTR",
        0x0021: "SRV",
        0x0027: "DNAME",
        }

# DNS Record Type Enumeration
DNSType = {
    "A": 0x0001,
    "NS": 0x0002,
    "MD": 0x0003,
    "MF": 0x0004,
    "CNAME": 0x0005,
    "SOA": 0x0006,
    "MB": 0x0007,
    "MG": 0x0008,
    "MR": 0x0009,
    "NULL": 0x000a,
    "WKS": 0x000b,
    "PTR": 0x000c,
    "HINFO": 0x000d,
    "MINFO": 0x000e,
    "MX": 0x000f,
    "TEXT": 0x0010,
    "RP": 0x0011,
    "AFSDB": 0x0012,
    "X25": 0x0013,
    "ISDN": 0x0014,
    "RT": 0x0015,
    "NSAP": 0x0016,
    "NSAPPTR": 0x0017,
    "SIG": 0x0018,
    "KEY": 0x0019,
    "PX": 0x001a,
    "GPOS": 0x001b,
    "AAAA": 0x001c,
    "LOC": 0x001d,
    "NXT": 0x001e,
    "EID": 0x001f,
    "NIMLOC": 0x0020,
    "SRV": 0x0021,
    "ATMA": 0x0022,
    "NAPTR": 0x0023,
    "KX": 0x0024,
    "CERT": 0x0025,
    "A6": 0x0026,
    "DNAME": 0x0027,
    "SINK": 0x0028,
    "OPT": 0x0029,
    "UINFO": 0x0064,
    "UID": 0x0065,
    "GID": 0x0066,
    "UNSPEC": 0x0067,
    "ADDRS": 0x00f8,
    "TKEY": 0x00f9,
    "TSIG": 0x00fa,
    "IXFR": 0x00fb,
    "AXFR": 0x00fc,
    "MAILB": 0x00fd,
    "MAILA": 0x00fe,
    "ALL": 0x00ff,
    "ANY": 0x00ff
}

def memstring(offset = 0, vm = None):
    if not offset or not vm:
        return ""
    return str(obj.Object("String", offset = offset, vm = vm, encoding = 'utf16', length = 0x7FFF))


def dnspstr(record = None, vm = None):
    if not record or not vm:
        return "dnspstr: None"
    offset = record.Data.obj_offset
    pstr = obj.Object('Pointer', offset = offset, vm = vm)
    return memstring(pstr, vm)


def memipv6(offset = 0, vm = None):
    mstr = ""
    data = vm.zread(offset, 16)
    for i, c in enumerate(data):
        if i > 0 and i % 2 == 0:
            mstr += ":"
        mstr += "{0:02x}".format(ord(c))
    return mstr

class DummyOmap(object):
    def remap(self, addr):
	return addr

class NoPDBFileException(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)


def find_pe_debug_directory(pe):
    # find debug directory
    for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if d.name == "IMAGE_DIRECTORY_ENTRY_DEBUG": break

    if not d or d.name != "IMAGE_DIRECTORY_ENTRY_DEBUG":
        print("Debug directory not found!")
        return None, None

    debug_directories = pe.parse_debug_directory(d.VirtualAddress, d.Size)
    for debug_directory in debug_directories:
        if debug_directory.struct.Type == DEBUG_TYPE["IMAGE_DEBUG_TYPE_CODEVIEW"]:
            return debug_directory.struct.PointerToRawData, debug_directory.struct.SizeOfData

    return None, None


def extract_rsds(filename):
    pe = pefile.PE(filename)

    d = None

    file_offset, segment_size = find_pe_debug_directory(pe)
    dataf = open(filename, "rb")
    dataf.seek(file_offset)
    rsds = dataf.read(segment_size)
    pe.close()
    dataf.close()

    return  pdbparse.peinfo.get_rsds(rsds)


DEBUG_TYPE = {
        "IMAGE_DEBUG_TYPE_UNKNOWN"   : 0,
        "IMAGE_DEBUG_TYPE_COFF"      : 1,
        "IMAGE_DEBUG_TYPE_CODEVIEW"  : 2,
        "IMAGE_DEBUG_TYPE_FPO"       : 3,
        "IMAGE_DEBUG_TYPE_MISC"      : 4,
        "IMAGE_DEBUG_TYPE_EXCEPTION" : 5,
        "IMAGE_DEBUG_TYPE_FIXUP"     : 6,
        "IMAGE_DEBUG_TYPE_BORLAND"   : 9,
        }
