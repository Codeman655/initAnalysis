# InitAnalysis

```
usage: __main__.py [-h] [-v] [--trim] [-q] [-x EXCLUDE [EXCLUDE ...]]
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

The goal is to quickly gather reconnaissance information about a given firmware's SystemV 
Initialization process. In addition, there may be several libraries and dependencies built into it.
This project was designed to be included into the [EMBA](https://github.com/e-m-b-a/emba) project.

# Installation

Simply install all dependencies:

`pip install -r requirements.txt`

Then perform a simple install:

`python3 setup.py install`

Then execute the command as a pthon module:

`python3 -m initAnalysis --help`


## Why not `pstree` after boot?

Because there are firmware that may never run completely. In many cases, getting the firmware to be completely rehosted is
extremely difficult. This is a simple measure to identify critical files to the firmware's init process.

# Output 

## The Report

When the process is finished, you'll get a quick report of the 

```
============================= Init Service Report =============================
Found init: ./sbin/init
Assumed service startup graph:
 > init: ELF
 | > inittab: file
 | | > rc.sysinit: script
 | | | > mscfg: file
 | | | > mount: ELF
 | | | > proc: directory
 | | | > alignment: missing
 | | | > echo: symlink
```

## The Graph

The embedded NetworkX graph can be exported to `dot` or `graphml` output formats, via the `-d` and `-g` options respectively.

### Dependencies

* [binwalk](https://github.com/ReFirmLabs/binwalk/blob/master/INSTALL.md)
* [firmadyne extractor](https://github.com/firmadyne/extractor.git)
* [python-magic 0.4.22](https://pypi.org/project/python-magic/)
* [pygraphviz](https://pypi.org/project/graphviz/)
* [networkx](https://pypi.org/project/networkx/)




