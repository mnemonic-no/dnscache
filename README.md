dnscache
=========

dnscache is a plugin for the [Volatility Memory Forensics Platform](http://www.volatilityfoundation.org/) to extract the Windows DNS Resolver Cache.

The plugin will try to download the .pdb file from microsoft for the dnsrslvr.dll. This behavior can be avoided by providing the file your self.

## Usage

<pre>
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
</pre>

The plugin will provide more information if the volatility --verbose flag is set (among other things, this will output the download link for the .pdb file if the dnsrslvr.dll is not paged)

`% vol.py --verbose dnscache -D dump/`

## Installation

`% python setup.py install`

## Requirements

* construct (pdbparse dependency) (Feb. 12 2017, see BUGS.md)
* pdbparse
* requests
* cabextract (system utility)

## Known issues

See the BUGS.md file.

## Contributing

See the CONTRIBUTING.md file.

## Credits

REFERENCES:
1. Cohen, M. (2014). The Windows User mode heap and the DNS resolver cache.
   Retrieved from:
     http://www.rekall-forensic.com/posts/2014-12-20-usermode-heap.html
2. Cohen, M. (2014). Source code for Module rekall.plugins.windows.dns
   Retrieved from:
     http://www.rekall-forensic.com/epydocs/rekall.plugins.windows.dns-pysrc.html
3. Pulley, C. (2013). Source code for Module symbols.py (volatility community plugins)
   Retrieved from:
     https://github.com/carlpulley/volatility/blob/master/symbols.py
4. Ligh, M., Case, A., Levy, J. & Walters, A. (2014). The Art of Memory Forensics.
5. Levy, J. (2015). dns cache plugin #201 (Volatility Issiues)
   Retrieved from:
     https://github.com/volatilityfoundation/volatility/issues/201

## License

dnscache is released under the ISC License. See the bundled LICENSE file for
details.
