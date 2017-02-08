# Copyright (c) 2017, mnemonic AS <geir@mnemonic.no>
#
#  Permission is hereby granted, free of charge, to any person obtaining a
#  copy of this software and associated documentation files (the "Software"),
#  to deal in the Software without restriction, including without limitation
#  the rights to use, copy, modify, merge, publish, distribute, sublicense,
#  and/or sell copies of the Software, and to permit persons to whom the
#  Software is furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
#  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE

"""This module attempts to extract the DNS cache from a Windows image

@author:        Geir Skjotskift
@license:       ISC License
@contact:       geir@mnemonic.no

DEPENDENCIES:
    construct (pdbparse dependency)
    pdbparse
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
"""

import os
import pdbparse
import pdbparse.peinfo
import shutil
import subprocess
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
    debug.info("Missing python library requests. You need to manually provide .PDB file")

dnstypes = {
        '_DNS_RECORD_FLAGS' : [ 4, {
            'Section'         : [ 0, ['BitField', dict(start_bit = 0, end_bit = 2)]],
            'Delete'          : [ 0, ['BitField', dict(start_bit = 2, end_bit = 3)]],
            'CharSet'         : [ 0, ['BitField', dict(start_bit = 3, end_bit = 5)]],
            'Unused'          : [ 0, ['BitField', dict(start_bit = 5, end_bit = 8)]],
            'Reserved'        : [ 0, ['BitField', dict(start_bit = 8, end_bit = 32)]],
            } ],

        '_DNS_RECORD' : [ None, {
            'pNext'       : [ 0x00, ['pointer', ['_DNS_RECORD']]],
            'pName'       : [ 0x04, ['pointer', ['unsigned short']]],
            'wType'       : [ 0x08, ['unsigned short']],
            'wDataLength' : [ 0x0a, ['unsigned short']],
            'Flags'       : [ 0x0c, ['_DNS_RECORD_FLAGS']],
            'dwTtl'       : [ 0x10, ['unsigned long']],
            'dwReserved'  : [ 0x14, ['unsigned long']],
            'Data'        : [ 0x18, ['unsigned long']], # this can be various size, depends on datalength
            } ]
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

    """

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

    def _find_dns_resolver(self, ps_list):

        for proc in ps_list:
            for mod in proc.get_load_modules():
                if mod.m("BaseDllName") == "dnsrslvr.dll":
                    yield proc, mod

    def _is_valid_debug_dir(self, debug_dir, image_base, addr_space):
        if debug_dir == None:
            return False

        if debug_dir.AddressOfRawData == 0:
            return False

        if not addr_space.is_valid_address(image_base + debug_dir.AddressOfRawData):
            return False

        if not addr_space.is_valid_address(image_base + debug_dir.AddressOfRawData + debug_dir.SizeOfData - 1):
            return False

        return True

    def _get_debug_symbols(self, addr_space, mod):

        image_base = mod.DllBase
        debug_dir = mod.get_debug_directory()

        if not self._is_valid_debug_dir(debug_dir, image_base, addr_space):
            debug.info("Invalid debug dir {0:#x} {1:#x} {2:#x}".format(debug_dir.v(), image_base.v(), addr_space.v()))
            return

        debug.info("Found debug_dir: {0:#x}, image_base: {1:#x}".format(debug_dir.v(), image_base.v()))
        debug_data = addr_space.zread(image_base + debug_dir.AddressOfRawData, debug_dir.SizeOfData)
        if debug_data[:4] == 'RSDS':
            return pdbparse.peinfo.get_rsds(debug_data)

        debug.info("Found no RSDS")

    def _download_pdb_file(self, guid, filename):

        if self._config.PDB_FILE:
            return self._config.PDB_FILE

        archive = filename[:-1] + "_"
        url = "{0}/{1}/{2}/{3}".format(self._config.SYMBOLS, filename, guid, archive)

        debug.info("Download URL .PDB file: {0}".format(url))

        if not candownload:
            debug.info("Manually provide the above resource with the --pdb-file option")
            return

        proxies = None
        if self._config.PROXY_SERVER:
            proxies = {
                    'http': self._config.PROXY_SERVER,
                    'https': self._config.PROXY_SERVER
                    }

        resp = requests.get(url, proxies=proxies, stream=True)

        if resp.status_code != 200:
            debug.info("Unable to download {0} (response code: {1})".format(url, resp.get_code()))
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
        debug.info("Using PDB file: {0}".format(pdb_file_name))
        pdb = pdbparse.parse(self._get_pdb_filename())
        sects = pdb.STREAM_SECT_HDR_ORIG.sections
        omap = pdb.STREAM_OMAP_FROM_SRC

        g_HashTable_p = 0
        g_HashTableSize_p = 0
        g_CacheHeap_p = 0

        for sym in pdb.STREAM_GSYM.globals:
            if _sym_name(sym) == "g_HashTable":
                off = sym.offset
                virt_base = sects[sym.segment-1].VirtualAddress
                g_HashTable_p = imgbase+omap.remap(off+virt_base)
            if _sym_name(sym) == "g_HashTableSize":
                off = sym.offset
                virt_base = sects[sym.segment-1].VirtualAddress
                g_HashTableSize_p = imgbase+omap.remap(off+virt_base)
                debug.info("Found hashtable size: {0}".format(off))
            if _sym_name(sym) == "g_CacheHeap":
                off = sym.offset
                virt_base = sects[sym.segment-1].VirtualAddress
                g_CacheHeap_p = imgbase+omap.remap(off+virt_base)

        return g_HashTable_p, g_HashTableSize_p, g_CacheHeap_p

    def calculate(self):

        address_space = utils.load_as(self._config)
        ps_list = win32.tasks.pslist(address_space)
        address_space.profile.add_types(dnstypes)
        address_space.profile.add_types(win10_dns_hashtable_entry)

        for proc, mod in self._find_dns_resolver(ps_list):

            debug.info("Found PID: {0} Dll: {1}".format(proc.UniqueProcessId, str(mod.m("FullDllName"))))

            proc_as = proc.get_process_address_space()
            guid, pdb = self._get_debug_symbols(proc_as, mod)
            pdb_file = self._download_pdb_file(guid, pdb)
            debug.info("Using PDB: {0}".format(pdb_file))

            image_base_address = int(proc.Peb.m("ImageBaseAddress"))
            g_HashTable_offset, g_HashTableSize_offset, g_CacheHeap_offset = self._hash_info(pdb_file, mod.DllBase)
            debug.info("DllBase:         {0:#x}".format(mod.DllBase))
            debug.info("Offset g_CacheHeap:     {0:#x}".format(g_CacheHeap_offset))
            debug.info("Offset g_HashTable:     {0:#x}".format(g_HashTable_offset))

            g_HashTableSize = obj.Object('unsigned int', offset = g_HashTableSize_offset, vm = proc_as)

            debug.info("g_HashTableSize: {0:#x}".format(g_HashTableSize))

            g_CacheHeap_p = obj.Object("Pointer", offset = g_CacheHeap_offset, vm = proc_as)
            g_HashTable_p = obj.Object("Pointer", offset = g_HashTable_offset, vm = proc_as)

            debug.info("g_CacheHeap_p: {0:#x}".format(g_CacheHeap_p.v()))
            debug.info("g_HashTable_p: {0:#x}".format(g_HashTable_p.v()))

            dnscache = obj.Object("Array", targetType="Pointer", count = g_HashTableSize + 1, offset = g_HashTable_p, vm = proc_as)
            lastNull = False
            c = 0
            for p in dnscache:
                if p == 0 and not lastNull:
                    print "{0:#x}".format(p)
                    lastNull = True
                elif p == 0 and lastNull:
                    c += 1
                else:
                    print "*", c
                    c = 0
                    lastNull = False
                    print "{0:#x}".format(p)
                entry = obj.Object("_DNS_HASHTABLE_ENTRY", offset = p, vm = proc_as)
                if entry.Name:
                    #cache_name = obj.Object("_LONG_UNICODE_STRING", offset = entry.Name.v(), vm = proc_as)
                    print "{0:#x} : {1}".format(entry.Name, memstring(entry.Name))

            yield guid, pdb

    def render_text(self, outfd, data):

        if self._config.DUMP_DIR == None and self._config.PDB_FILE == None:
            debug.error("Please specify a dump directory (--dump_dir)")

        outfd.write("DEBUG!***\n")
        for guid, pdb in data:
            outfd.write("DEBUG -- GUID: {0}, PDB: {1}\n".format(guid, pdb))


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

# DNS Record Type Enumeration
DNSType = {
    "A": 0x0001,
    "NS_TYPE_NS": 0x0002,
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

def memstring(addr):
    mstr = ""
    while True:
        w = proc_as.read(addr, 2)
        if w == "\x00\x00": return mstr
        mstr += w
        addr += 2


class NoPDBFileException(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
