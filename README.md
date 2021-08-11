# Post-binwalk analysis

## TODO BACKLOG (LOCKED)
[ ] Add more types (device, directory, file -> datafile) 
[ ] Change Node IDs to be the full path
[ ] Edges should show _dependencies_ not _calls_ which may imply alternative edge directions.
[ ] Fix exporting the graph
[ ] Debug and validate output
[ ] Output in a relevant format for PandaLog (aka protobuf)
[ ] Switch to shell parser (Architecture Frog)
[ ] Embed or use EMBA data (Architecture Frog)

#### The not-getting-done backlog
[ ] Deal with hard-coded assumptions (busybox -> init -> inittab -> init)
[ ] Add option to write symbol info for all init binaries (separate application to decoreate filesystem.csv) 
[ ] Refactor internally - startCollections (systemd, systemv, initdict) should be a list with keys to the "files" hash table
[ ] Make another tool to build missing file dependency graph (Edge labels are the actual line in the script)
* Notes: If I could redo this, it'd be nice to set filters and callbacks to process files
[ ] Use full paths for all nodes? (Deobfuscates circular edges, makes it a true DAG)

## Notes
* Anything related to multi-arch binaries may not return valid symbol info from read-elf

## DONE
[x] Output logs to a file in the "-l logs" directory
[x] Decorate graph with "file metadata" in filesystem.csv
   [x] Color nodes by type [file=black, ELF=red, script=blue, link=pink] 
   [x] Color edges to show symlinks [red] 
[x] Write symbol data for all leaf nodes (processes) in the init graph
[x] Finish adding "processed" tag to InitCollections
[x] Discover *NEEDED* libraries (may not find versions) 
[x] Building filesystem.csv should be a separate application (nope)
[x] FIX Preinit missing from scripts (re.match() vs re.search()) 
[x] DEBUG: Complete graphs (no missing links)
[x] DEBUG Why are there edgeless binaries in the graph? (No parent, no child)
[x] DEBUG No edges to self (turns out it was a symlink from /etc/init to /sbin/init)
[x] Merge init and systemv
[x] Establish hierarchies ( init -> inittab -> init -> subfunctions
[x] Mount points
[x] Ignore comments
[x] Find binaries affiliated with path -> new regex
[x] log referenced but missing files in hash table
[x] Store in a log folder
[x] Get more data from binaries (objdump -T, readelf -sym, ldd)

#### ***WHAT IS THE POINT***

To enable dynamic analysis, specifically fuzzing.
Which means, getting inputs to code, coverage, crash/error reporting, instrumentation 

#### Why not `pstree` after boot?

Because there are firmware we may never run completely. 

## InitProcessGraph.py

Simple application that searches a binwalk extracted firmware filesystem and
makes a graph of the initial processes. It should give us a simple way to visualize
the boot process. There'd be a better way to get this tied into firmware.

### Dependencies

* [binwalk](https://github.com/ReFirmLabs/binwalk/blob/master/INSTALL.md)
* [firmadyne extractor](https://github.com/firmadyne/extractor.git)
* [python-magic 0.4.22](https://pypi.org/project/python-magic/)
* [pygraphviz](https://pypi.org/project/graphviz/)
* [networkx](https://pypi.org/project/networkx/)

### Citrics:
* What can we learn to rehost better (STATICLLY)?
* What can we learn to find vulnerabilities (STATICALLY)?

### Rehosting barriers
* Filesystem or no?
* Architecture (ARM/x86/etc)
* Operating System Layer (we need a kernel)
    * What type? (Type 1: Linux kernel version? External modules?)
    * Kernel command line parameters
* QEMU requires a matching machine (Architecture, Devices, etc)
    * Do you need dlock devices (for SD Cards)?
    * Do you need other devices?
    * BIG QUESTION: Of the QEMU machines available, why is one better than another?
    * BIG QUESTION: What can we get out of the image to tell us which one is preferred?
* Device Drivers and Missing Peripherals? It's asking for a peripheral that is missing.
    * Can you dig into a device driver and find which device (aka `/dev/`)
    * Strings on the whole d*mn thing
    * Find a dtb.
    * BTW run strings on everything
* Terminals (--no-graphic and other terminal issues)

-- It boot run at this point --
* User-land static analysis 
* Inittab
* Networking 
    * How do you know which ports its using?
    * We make a lot of assumptions... (Heuristics everywhere)
    * Can we find this statically? Where in the kernel + filesystem can we infer this info?  

-- 

* Can we point someone to an interesting binary for analysis? 
* Define interesting?
    * Emulation breakers. When you're running it, it breaks?
        * Bad Ioctl calls, Missing files, missing devices, etc
    * Dependency Binaries
        * Calls to bad libraries and bad versions (are they present?)

# TODO:
* Re
* Finish building the hierarchy
* Run File on all files / file forensics
    * Determine what tools/arch for further analysis
    * 
* The harder work is derving the *relationships* between each file
* Embed Bootchart?
* Check Firmadyne [nothing big here]
* Can we find out "where" a firmware gets its memory to boot
    * Look for anything with /dev or /proc
* Is there any way to extract out port information? 
    * Look for open ports, socets, 

# Feedback
* Think Libraries/Dependencies! 
    * You should know the libraries of every binary within the firmware.
* Citics -adjacent -> Wants to go through and collect as much info on a firmware as possible
    Firmware -> libraries 
    libraries + CVE database -> Report
* What's the value? How would you use this to find vulnerabilities?
* Set graphs to directed
* Annotate an order (use orderedDicts)
* Look for common files and setups
  -> BusyBox
  -> Standard Linux Build
* Find unique files
* Careful for Lib files -> Imports and exports -> readelf
* Consider hashing across filesystems
* Binary parsing will be the big note -> linking it to the 
