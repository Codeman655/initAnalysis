#!/usr/bin/env python3


# ************************************
# System V Grapher
# The chain of events is as follows:
# 
#  * The kernel looks in several places for init and runs the first one it finds
#  * init runs /etc/rc.d/rc.sysinit
#  * rc.sysinit does a bunch of necessary things and then runs rc.serial (if it exists)
#  * init runs all the scripts for the default runlevel.
#  * init runs rc.local 
# 
# SystemV source: https://www.linux.co.cr/distributions/review/1997/red-hat-5.0/doc081.html
# written by: craigca@ornl.gov
# ************************************

import sys,os,argparse,stat,subprocess,copy
import logging
import csv
import pprint 
import re

import magic
import networkx as nx

# Global params
parser = argparse.ArgumentParser(description="post binwalk firmware analysis")
parser.add_argument("-v", "--verbose", action='store_true', help="display verbosity")
#parser.add_argument("-e", "--elfinfo", action='store_true', help="Record symbols/libraries for *all* ELF binaries")
parser.add_argument(      "--trim", action='store_true', help="remove functions with no edges from the output tree")
parser.add_argument("-q", "--quiet", action='store_true', help="output nothing other than graphs")
parser.add_argument("-s", "--symbols", action='store_true', help="dumps ELF dynamic symbol data into the log folder")
parser.add_argument("-x", "--exclude", default=list(), type=list, nargs='+', help="exclude files when searching for binaries")
parser.add_argument("-i", "--include", default=list(), type=list, nargs='+', help="whitelist directories when searching for init binaries")
parser.add_argument("-d", "--dot", default="", help="output dep graph to dot file")
parser.add_argument("-g", "--graphml", default="", help="output dep graph to graphml file")
parser.add_argument("-l", "--logdir", default="./", help="log directory for various output")
parser.add_argument("filesystem", metavar="firmware", help="target firmware's root directory")

# For white/blacklisting
reserved_keywords=["case",
 "do",
 "done",
 "elif",
 "else",
 "esac",
 "fi",
 "for",
 "function",
 "if",
 "in",
 "select",
 "then",
 "time",
 "until",
 "while",
 "set",
 "try",
 "with",
 "class",
 "except"] 
init_whitelist_dirs = [ "init.d", "rcS.d", "rc.local" ]
blacklist = ['/proc', '/sys', '/dev'] 

args = parser.parse_args()

# create file handler which logs debug messages
if args.quiet:
    logging.disable(logging.CRITICAL)
elif args.verbose:
    logging.basicConfig(level=logging.DEBUG)
    fh = logging.FileHandler(os.path.join(args.logdir, 'debug.log'), mode='w+')
    fh.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(fh)
else:
    logging.basicConfig(level=logging.INFO)


# Firmware Class ################################################
#################################################################
#################################################################
#################################################################

class Firmware:
    "class to store all relevant meta-data about aforementioned firmware"
    def __init__(self, args):
        self.G = nx.DiGraph(name=args.filesystem.strip("/"))
        self.directory = args.filesystem
        self.blacklist = list(args.exclude) + blacklist
        self.signatures = []
        self.firmware = ""
        self.files = {}
        self.missing = {}
        self.systemv = {}
        self.systemd = {}
        self.mountpoints = {}
        self.binlist = []
        self.fs_type=""
        self.arch=""
        self.scanForInitFiles(args.filesystem)

    def statFile(self, entry):
        """
        statFile
        args: entry - the path to the file
        
        returns a dictionary of the following:
        path - the full path from the given starting directory
        basename - basename for the file
        perm - octal permissions
        processed - gone through the scandirs process at least once
        magic - magic data for each file
        """
        m_data = magic.from_file(entry.path)
        return {"path": entry.path,
                    "basename":os.path.basename(entry.name),
                    "perms":oct(os.stat(entry.path).st_mode)[-3:],
                    "processed":False,
                    "magic":m_data}

    def statDir(self, basepath):
        """
        For some reason, only called for init collections
        """
        ret = {}
        try:
            with os.scandir(basepath) as entries:
                for entry in entries:
                    entry_path = os.path.join(basepath, entry.name)
                    if entry.is_file():
                        m_data = magic.from_file(entry_path)
                        #TODO These should be a class
                        #logging.debug(f"Adding {entry_path} to init collection")
                        self.files[entry.path] = {"path": entry.path,
                                "basename":os.path.basename(entry.name),
                                "perms":oct(entry.stat().st_mode)[-3:], 
                                "processed":False,
                                "magic":m_data}
                        #catch the big fields related to init 
                        if entry.path.endswith("/rc") or entry.path.endswith("/rc.sysinit"):
                            ret[entry.path] = {"path": entry.path,
                                "parent":"init", # this is pre-emptive. I haven't found init yet
                                "basename":os.path.basename(entry.name),
                                "perms":oct(entry.stat().st_mode)[-3:],
                                "processed":False,
                                "magic":m_data}
                        elif "/rc." in entry.path:
                            ret[entry.path] = {"path": entry.path,
                                "parent":"rc.sysinit", # this is pre-emptive. Belongs to rc or rc.sysinit
                                "basename":os.path.basename(entry.name),
                                "perms":oct(entry.stat().st_mode)[-3:],
                                "processed":False,
                                "magic":m_data}
                        else:
                            ret[entry.path] = {"path": entry.path,
                                "parent":"init", # this is pre-emptive. I haven't found init yet
                                "basename":os.path.basename(entry.name),
                                "perms":oct(entry.stat().st_mode)[-3:],
                                "processed":False,
                                "magic":m_data}
        except OSError:
            pass
        return ret

    def ELFDependencyWriter(self, v):
        """
        Writes the symbol table and dynamic section to a unique file
        Arguments: StatFile Entry {path, basename, prems, magic}
        """
        global args
        if "dynamically linked" in v["magic"]:
            logging.info(f"ELF file found is dynamically linked: {v['path']}")
            libs= {}
            symfile = os.path.join(args.logdir,v["basename"] + "_symbols.log")
            with open(symfile, 'w') as symoutfile:
                logging.info(f"Writing syminfo to {symfile}")
                subprocess.call("readelf -s " + v["path"],\
                        shell=True,\
                        stdout=symoutfile)
            libfile = os.path.join(args.logdir,v["basename"] + "_libs.log")
            with open(symfile, 'w') as liboutfile:
                logging.info(f"Writing needed libraries to {libfile}")
                stdout = subprocess.call("readelf -d " + v["path"],\
                        shell=True,\
                        stdout=liboutfile)

    def scanForInitFiles(self, basepath):
        """
        Recursive function to search filesystems for init functions
        Fills elements of the class with relevant filesystem data

        SystemV Seach Paths
        * Anything with "init" -> inittab/, /sbin/init, busybox -> init
        * /etc/rc.*

        SystemD Search Paths for unit files

        # SystemD Units
        /etc/systemd/system.control/*
        /run/systemd/system.control/*
        /run/systemd/transient/*
        /run/systemd/generator.early/*
        /etc/systemd/system/*
        /etc/systemd/system.attached/*
        /run/systemd/system/*
        /run/systemd/system.attached/*
        /run/systemd/generator/*

        ... # USER UNITS
        /USR/LIB/SYSTEMD/SYSTEM/*
        /RUN/SYSTEMD/GENERATOR.LATE/*
        ~/.CONFIG/SYSTEMD/USER.CONTROL/*
        ~/.CONFIG/SYSTEMD/USER/*
        /usr/lib/systemd/user/*

        """
        global args
        global init_whitelist_dirs
        init_whitelist_dirs.extend(args.include)

        try:
            with os.scandir(basepath) as entries:
                for entry in entries:
                    # Build the path
                    entry_path = os.path.join(basepath,entry.name)
                    # If in the blacklist, just move on
                    if entry.name in self.blacklist:
                        continue
                    # If we've already hit this file before
                    if entry_path in self.files:
                        continue
                    # Check if an established init file
                    if entry.is_file():
                        self.files[entry_path] = self.statFile(entry) #add file path to global list
                        if re.search(r"init",entry.name) or re.match(r"rc.*", entry.name):
                            logging.debug(f"init-related file: \"{entry_path}\"")
                            self.systemv[entry_path] = self.statFile(entry)
                    #Not a file
                    elif entry.is_dir() and not entry.is_symlink():
                        logging.debug(f"checking out directory: {entry_path}")
                        if entry.name in init_whitelist_dirs or re.match("rc.*",entry.name):
                            # Record binaries related to systemv init
                            logging.debug(f"init dir found: {entry_path}!")
                            self.systemv.update(self.statDir(entry_path))
                        elif entry.name == "systemd":
                            # Record binares related to systemd
                            logging.debug(f"systemd found: {entry_path}!")
                            self.systemd.update(self.statDir(entry_path))
                        else:
                            # Recurse into this directory
                            self.scanForInitFiles(entry_path)
        except OSError:
            logging.debug(f"Can't open this file: {entry}")
            pass

    def scriptSearch(self, initFile, initNodes):
        """
        This function searches recursively for paths or binaries located in init functions for graphing
        Arguments:
        initFile -> the file entry from the self.systemv, systemd, or init dictionaries
        initNodes -> map for recrusive use later
        """

        global reserved_keywords

        #TODO set a hierarchy in recursive searches. each found path needs a parent

        # Incoming from startupCollection, out as new map
        path = initFile["path"]
        magicData = initFile["magic"]
        pathRegex = re.compile(r"((?:/[\w-]+)*(?:/[\w\.-]+))\s")
        commentRegex = re.compile(r"[\s*]*#")
        keywordRegex = re.compile(r"\s*(\w+)")
        mountsInFile = []
        # Short circuit self-references 
        if path in initNodes or initFile["processed"] == True:
            # Decoreate with ELF data?
            logging.debug(f"already scanned {path}...")
            return

        # Because this is recursive, we don't know if the file is a script
        if "script" in magicData or "ASCII text" in magicData:
            logging.debug(f"Searching {path} script for other binaries")
            initFile["children"] = []
            with open(path, 'r') as fp:
                order=0
                # For each line in the open file
                for line in fp:
                    #if comment, skip this line
                    if commentRegex.match(line):
                        continue
                    #if a keyword that might be an executable in PATH
                    match = keywordRegex.match(line)
                    if match != None and match[0].strip() not in reserved_keywords:
                        binInQuestion = match[0].strip()

                        # Is the keyword "mount or umount?"
                        if "mount" in binInQuestion:
                            # There may up to 2 paths
                            matches = pathRegex.findall(line)
                            logging.info(f"found mount command: {line}")
                            # Just record the line for now
                            # Let continue to parse the following paths in the mount command
                            mountsInFile.append( line )

                        # Check if keyword matches a found file
                        fileRecordEntry = self.getFileRecord(binInQuestion)
                        if fileRecordEntry == None:
                            self.missing[binInQuestion] = {"file":binInQuestion,"calledby":path}
                            logging.info(f"binary '{binInQuestion}' referenced but not in filesystem")
                            #we still must scan this line for a path
                        else:
                            fileRecordPath = fileRecordEntry["path"]
                            # The binary in question must match a path/to(/binary)
                            logging.debug(f" {order}-th call to binary: {binInQuestion}")
                            # append to original init file in startupColleciton
                            # The order in which they are appended is the order in which they were discovered
                            initFile["children"].append(copy.deepcopy(fileRecordEntry))

                            # Prepare child for recursive search
                            if fileRecordPath not in initNodes:
                                logging.debug(f"Deep Copy {fileRecordPath} into initnodes")
                                initNodes[fileRecordPath] = copy.deepcopy(fileRecordEntry) #Copy! Do not reference
                                self.parseInitElf(initNodes[fileRecordPath])
                                initNodes[fileRecordPath]["processed"] = True
                            else:
                                logging.debug(f"{fileRecordPath} already in initnodes")
                            order += 1 

                    # If a path to a binary or another script 
                    for foundPath in pathRegex.findall(line):
                        # Check found path against the global list of files
                        foundPath = foundPath.strip()
                        found = False
                        fileRecordEntry = self.getFileRecord(foundPath)
                        if fileRecordEntry == None:
                            self.missing[foundPath] = {"file":foundPath,"calledby":path}
                            logging.info(f"path '{foundPath}' referenced but not in filesystem. Marked as missing child.")
                            # Generate a missing file record for this strange file
                            missingFileRecord = { "path": foundPath,
                                    "basename":os.path.basename(foundPath),
                                    "perms":'000',
                                    "processed":True, #No need to search for this
                                    "magic":"missing"}
                            initFile["children"].append(missingFileRecord)
                        else:
                            # The foundRecord path must match the given path we have.
                            fileRecordPath = fileRecordEntry["path"] # this is redundant. 
                            if fileRecordPath.endswith(foundPath): # This is not OS agnostic
                                #If they match, append to the list of children
                                logging.debug(f" {order}-th call to file: {foundPath}")
                                # append to original init file in startupColleciton
                                initFile["children"].append(copy.deepcopy(fileRecordEntry))

                                # Prepare child for recursive search
                                if fileRecordPath not in initNodes:
                                    logging.debug(f"Deep Copy {fileRecordPath} into initnodes from found path")
                                    #Copy! Do not pass-by-reference
                                    initNodes[fileRecordPath] = copy.deepcopy(fileRecordEntry)

                                    #elf or script 
                                    # Set processed (as scriptSearch was run on this file)
                                    #if elf, will print libraries in log
                                    self.parseInitElf(initNodes[fileRecordPath])
                                    #if script, will traverse
                                    self.scriptSearch(initNodes[fileRecordPath], initNodes)
                                    initNodes[fileRecordPath]["processed"] = True
                                order += 1
        if mountsInFile:
            self.mountpoints[path] = mountsInFile

    def parseInitElf(self, fileRecord):
        """
        Uses regexes to decorate the init collections
        Args: fileRecord - the systemv record of the file in question
        """
        if args.symbols and "ELF" in fileRecord["magic"]:
            if "dynamically linked" in fileRecord["magic"]:
                logging.info(f"ELF file found is dynamically linked: {fileRecord['path']}")
            else:
                logging.info(f"ELF file found: {fileRecord['path']}")
            libs= {}
            symfile = os.path.join(args.logdir,fileRecord["basename"] + "_symbols.log")
            try:
                with open(symfile, 'w') as symoutfile:
                    logging.info(f"Writing syminfo to {symfile}")
                    subprocess.call("readelf -s " + fileRecord["path"],\
                            shell=True,\
                            stdout=symoutfile)
                libfile = os.path.join(args.logdir,fileRecord["basename"] + "_libs.log")
                with open(symfile, 'w') as liboutfile:
                    logging.info(f"Writing needed libraries to {libfile}")
                    stdout = subprocess.call("readelf -d " + fileRecord["path"],\
                            shell=True,\
                            stdout=liboutfile)
            except IOError:
                print("I/O error")

    def parseInitTab(self, fileRecord):
        """
        Uses regexes to decorate the init collections
        Args: fileRecord - the systemv record of the file in question
        """
        init_file = fileRecord["path"]
        fileRecord["children"] = []
        fileRecord["parent"] = "init" # Hard Coded because I am *DUMB*
        with open(init_file, "r") as fp:
            order=0
            for line in fp:
                # Parse each line in inittab for 
                for match in re.findall(r"^[^#](?:.*:)+-?((?:/[\w.-]+)+)\s?", line):
                    #Check found path against the global list of files
                    found = False
                    #Loop through all files in the filesystem
                    for filepath in self.files.keys():
                        if match in filepath:
                            #If they match, append to the list of children of inittab
                            childFileRecord = self.getFileRecord(match)
                            assert(childFileRecord), f"child record not found for file {match}"
                            fileRecord["children"].append(childFileRecord)
                            logging.info(f" {order}-th call to binary: {match}")
                            order += 1
                            found = True
                            break
                    # if not, report and move on
                    if not found:
                        logging.info(f"path '{match}' not found in filesystem")

    def processInitCollection(self, d):
        """
        This function is full of heuristics.
        I'd love to formalize this into something coherent

        args:
        Self: the calling class
        D: could have a better name, it's the init dictionary in use {systemd, systemv}

        """
        #TODO: If I were to do this again, I'd have a list of filenames or 
        #      regexes and callback functions to process each file
        initnodes = {}
        for k,v in d.items(): # Immediately iterate to subitems
            #If it's already been processed, skip
            if v["processed"] == True:
                continue

            # TODO Refactor the inittab work into a function
            if v["path"].endswith("inittab"):
                self.parseInitTab(v)

            elif "ELF" in v["magic"]:
                self.parseInitElf(v)

            elif "symbolic link" in v["magic"]:
                # Consider replacing or relabeling the symbolic link 
                # Consider not setting parents, its relabeled when the graph is produced
                match = re.search(r"symbolic link to (.*)$", v["magic"])
                linked_file = match.group(1)
                linked_basename  = os.path.basename(linked_file)
                #v['parent'] = { "path":linked_basename, "basename": linked_basename, "magic": v["magic"] }
                logging.debug(f"Setting symbolic link (link -> realpath): {linked_basename} => {v['path']}")
            # If we don't know, pass to script searcher
            else: 
                # Recurse and add your children to the filesystem init graph
                self.scriptSearch(v,initnodes)
            v["processed"] = True

        # Discovered files should be processed into init
        # Rerun this function if there are unprocessed files
        d.update(initnodes)
        if not self.allProcessed(d):
            self.processInitCollection(d)
        return initnodes

    def getFileRecord(self,basepath):
        """
        it's a lazy searcher to return something from the 
        local file dictionary, if the paths aren't perfect
        """

        #clean the input
        basepath = basepath.strip(' /')
        try: 
            # If the basepath == full path
            return self.files[basepath]
        except KeyError: 
            # If the basepath is a substring of the full path
            for key,value in self.files.items():
                #print(f"does {key} == /{basepath}?")
                if key.endswith("/" + basepath):
                #    print(f"returning record for {basepath}")
                    return value #short ciruit
        # if neither is true
        logging.debug(f"getFileRecord: couldn't find {basepath}")
        return None

    def allProcessed(self, initnodes):
        flag = True
        for k,v in initnodes.items():
            if v["processed"] == False:
                flag = False
                break
        return flag

    def listbins(self):
        print("Found binaries:")
        pprint.pprint(self.binlist)

    def listinit(self):
        if self.systemv: 
            print("systemv:")
            print(self.systemv)
        if self.systemd: 
            print("systemd:")
            print(self.systemd)
        return

    def genEdgeColor(self, process, mtype):
        if process in self.missing:
            return "red"
        #if  "link" in mtype:
            #return "pink"
        else:
            return "black"

    def genMagicShorthand(self, magic):
        shorthand = ""
        if "ELF" in magic:
            return "ELF"
        elif "symbolic link" in magic:
            return "symlink"
        elif "script" in magic:
            return "script"
        elif "missing" in magic:
            return "missing"
        else:
            return "file"

    def genNodeLabel(self, basename, magic):
        labelname=basename
        if "symbolic link" in magic:
          match = re.search("symbolic link to (.*)", magic)
          if match:
              labelname = labelname + " ==> " + match.group(1)
        return labelname

    def genNodeColor(self, magic):
        if "missing" in magic:
            return "gray"
        if "ELF" in magic:
            return "red"
        elif "symbolic link" in magic:
            return "pink"
        elif "script" in magic:
            return "blue"
        else:
            return "black"

    def genNodeID(self, fileRecord, parent_path):
        uid = parent_path
        path=fileRecord["path"]
        magic = fileRecord["magic"]
        if not "script" in magic: 
            return f"{hash(uid)}:{fileRecord['path']}"
        return path

    def buildGraph(self):
        global args

        #Create the graph
        G = self.G
        #For each startup dictionary
        # for each process in the startup list
        init_index=0
        observed = set()
        for process, attrs in self.systemv.items():
            # Hacky checklist to avoid repeats
            if process in observed: 
                continue
            else:
                observed.add(process)
            process_basename = attrs["basename"]
            process_magic = attrs["magic"]
            node_label = self.genNodeLabel(process_basename, process_magic)
            magic_shorthand = self.genMagicShorthand(process_magic)
            node_color = self.genNodeColor(process_magic)
            G.add_node(process, label=node_label, order=init_index, color=node_color, node_path=process, type=magic_shorthand)
            logging.debug(f"process: {process}:")
            #Increase index
            init_index +=1 

            #adding children
            if "children" not in attrs:
                logging.debug("no children")
            else:
                for index in range(len(attrs["children"])):
                    """
                    fileRecord = type(childRecord)
                    """
                    childRecord = attrs["children"][index]
                    child_order = index
                    child_path  = childRecord["path"]
                    observed.add(child_path)

                    logging.debug(f" {process_basename} has child process {childRecord['path']}")

                    # Add child node 
                    child_basename = os.path.basename(childRecord["path"])
                    child_id = self.genNodeID(childRecord, process) #Produce unique name for leaf nodes common one for scripts/dirs/files
                    edge_color = self.genEdgeColor(childRecord["path"], childRecord["magic"])
                    node_color = self.genNodeColor(childRecord["magic"])
                    node_label = self.genNodeLabel(child_basename, childRecord["magic"])
                    magic_shorthand = self.genMagicShorthand(childRecord["magic"])
                    edge_label = str(index)

                    #Skip self-referencing 
                    if child_path == process:
                        continue
                    G.add_node(child_id, label=node_label, order=index, color=node_color, node_path=child_path, type=magic_shorthand)
                    G.add_edge(process, child_id, color=edge_color, label=edge_label)

            if "parent" in attrs:
                #TODO: Why is the only parent: init?
                assert(attrs["parent"] != ""), "parent of {process_basename} is still empty"
                logging.debug(f" {process_basename} has parent process {attrs['parent']}")
                parentRecord = self.getFileRecord(attrs["parent"])
                # if this is null, we haven't found the parent in the filesystem
                assert(parentRecord != None), f"{attrs['parent']} is NULL and not in the filesystem"
                node_color = self.genNodeColor(parentRecord["magic"])
                magic_shorthand = self.genMagicShorthand(parentRecord["magic"])
                edge_color = self.genEdgeColor(process_basename, magic_shorthand)

                # init is an assumed binary
                G.add_edge(parentRecord["path"], attrs["path"], color=edge_color)
        #Trim the tree 
        if args.trim:
            G.remove_nodes_from(list(nx.isolates(G)))
    #END
# END Firmware class

# Utility Functions #############################################
#################################################################
#################################################################
#################################################################
#################################################################


def printDoD(d, depth):
    if isinstance(d, dict):
        for key,value in d.items():
            if isinstance(value, dict):
                print(f"{' '*depth}{key}")
                printDoD(value, depth+5)
            else:
                print(f"{' '*depth}{key}:{value}")
    return

def print_dir(basepath):
    """
    recursive function to search post-binwalked filesystems
    """
    try:
        with os.scandir(basepath) as entries:
            for entry in entries:
                entry_path = os.path.join(basepath,entry.name)
                if entry.is_dir() and not entry.is_symlink():
                    print(f"dir: \"{entry_path}\"")
                    print_dir(entry_path)
                else:
                    print(f"file: \"{entry_path}\"")
    except OSError:
        pass

def findInDir(basepath):
    """
    recurise function to search and stat a single file in a given directory
    """
    ret = False
    try:
        with os.scandir(basepath, filename) as entries:
            for entry in entries:
                entry_path = os.path.join(basepath,entry.name) 
                if entry_name == filename:
                    return True
                elif entry.is_dir():
                    ret = findInDir(entry_path,filename)
        return ret
    except OSError:
        pass

def write_missingfiles_csv(F, outfile):
    global args
    csv_file = outfile
    csv_columns = [ "file", "calledby"]
    print(f"\nWriting {csv_file} ...")
    try:
        with open(csv_file, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for k,v in F.missing.items():
                writer.writerow(v)
    except IOError:
        print("I/O error")

def write_file_csv(F, outfile):
    global args
    csv_file = outfile
    csv_columns = [ "path", "basename", "perms", "processed", "magic"]
    print(f"\nWriting {csv_file} ...")
    if args.verbose:
        for i in list(F.files.keys())[0:10]:
            logging.debug(F.files[i])
    try:
        with open(csv_file, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for k,v in F.files.items():
                writer.writerow(v)
    except IOError:
        print("I/O error")

def printdict(d,tabspace=0):
    space=' '*(tabspace*5)
    print(space+'{')
    for key,value in d.items():
        if isinstance(value, dict):
            print(f"{space}{key}:")
            printdict(value,tabspace+1)
        else:
            print(f"{space}{key}: {value}")
    print(space+'}')

def extractPath(s):
    return re.match(r"((?:/[\w-]+)*(?:/[\w-]+))\s", s)

    
# Main Function #################################################
#################################################################
#################################################################
#################################################################
#################################################################

def main(args):
    # Construct the firmware class (enumerates the firmware's root dir)
    logging.info("Reading the filesystem...")
    F = Firmware(args)

    # Processing the collection of init-related files
    logging.info("Processing/Searching for init files...")
    F.processInitCollection(F.systemv)

    # Build the graph
    logging.info("Building the graph...")
    F.buildGraph()

    if not args.dot == "":
        logging.info(f"Writing dot file {args.dot}...")
        nx.nx_agraph.write_dot(F.G,args.dot)
    if not args.graphml == "":
        logging.info(f"Writing graphml file {args.graphml}...")
        nx.write_graphml(F.G, args.graphml)
    if not args.quiet:
        write_file_csv(F, os.path.join(args.logdir, "filesystem.csv"))
        write_missingfiles_csv(F, os.path.join(args.logdir, "missingfiles.csv"))
        print()

if __name__ == "__main__":
    main(args)
