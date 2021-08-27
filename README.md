# InitAnalysis

```
usage: __init__.py [-h] [-v] [--trim] [-q] [-x EXCLUDE [EXCLUDE ...]]
                   [-i INCLUDE [INCLUDE ...]] [-d DOT] [-g GRAPHML]
                   [-l LOGDIR]
                   firmware

Graphing and Static Recon tool for Linux's SystemV

positional arguments:
  firmware              target firmware's root directory

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         display verbosity
  --trim                remove functions with no edges from the output tree
  -q, --quiet           output nothing other than graphs
  -x EXCLUDE [EXCLUDE ...], --exclude EXCLUDE [EXCLUDE ...]
                        exclude files when searching for binaries
  -i INCLUDE [INCLUDE ...], --include INCLUDE [INCLUDE ...]
                        whitelist directories when searching for init binaries
  -d DOT, --dot DOT     output dep graph to dot file
  -g GRAPHML, --graphml GRAPHML
                        output dep graph to graphml file
  -l LOGDIR, --logdir LOGDIR
                        log directory for various output
```

The goal is to quickly gather reconnaissasnce information about a given firmware's SystemV 
Initialization process. In addition, there may be several libraries and dependencies built into it.
This project was designed to be included into the [EMBA](https://github.com/e-m-b-a/emba) project.

#### Why not `pstree` after boot?

Because there are firmware we may never run completely. 

## Notes
* Anything related to multi-arch binaries may not return valid symbol info from read-elf

# Output 

## The Report

## The Graph

Simple application that searches a binwalk extracted firmware filesystem and
makes a graph of the initial processes. It should give us a simple way to visualize
the boot process. There'd be a better way to get this tied into firmware.

### Dependencies

* [binwalk](https://github.com/ReFirmLabs/binwalk/blob/master/INSTALL.md)
* [firmadyne extractor](https://github.com/firmadyne/extractor.git)
* [python-magic 0.4.22](https://pypi.org/project/python-magic/)
* [pygraphviz](https://pypi.org/project/graphviz/)
* [networkx](https://pypi.org/project/networkx/)




