#!/usr/bin/env python

import sys
import pefile
import pdbparse
import pdbparse.peinfo

def find_debug_directory(pe):
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

    file_offset, segment_size = find_debug_directory(pe)
    dataf = open(filename, "rb")
    dataf.seek(file_offset)
    rsds = dataf.read(segment_size)
    pe.close()
    dataf.close()

    return  pdbparse.peinfo.get_rsds(rsds)

def main(filename):

    guid, pdb = extract_rsds(filename)

    print "GUID/Age: {0}".format(guid)
    print "PDB     : {0}".format(pdb)

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

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: {0} PEFILENAME".format(sys.argv[0]))
        sys.exit(1)
    main(sys.argv[1])
