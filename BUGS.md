Known Issues
=========

This file contains known issues with the dnscache plugin.

## NameError: name 'ULInt32' is not defined #31

The constructs library has had a large rewrite in the 2.8 release [Issue 31](https://github.com/moyix/pdbparse/issues/31). The developer of pdbparse will try and address this at some point in time, but suggests installing an older version of construct for the time being.

```bash
$ pip install construct==2.5.5-reupload
```

## No cache found. dnsrslvr.dll paged?

This is not a *bug* but a result of the dll being paged to disk. This happens quite often in my test cases. The solution may be to aquire the dnsrslvr.dll from disk providing this to the plugin with --dll_file=FILENAME .. If you are lucky; the pointer to the cache is still in memory.
