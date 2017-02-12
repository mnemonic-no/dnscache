Known Issues
=========

This file contains known issues with the dnscache plugin.

## NameError: name 'ULInt32' is not defined #31

The constructs library has had a large rewrite in the 2.8 release [Issue 31](https://github.com/moyix/pdbparse/issues/31). The developer of pdbparse will try and address this at some point in time, but suggests installing an older version of construct for the time being.

```bash
$ pip install construct==2.5.5-reupload
```

## No cache found. dnsrslvr.dll paged?

This is not a *bug* but a result of the DNS file being paged to disk. This happens quite often in my test cases. The solution is either to provide the pagefile to or to aquire the dnsrslvr.dll from disk and manually finding the GUID/age and .pdb file path and download the file from microsoft and provide it with the --pdf_file= option.
