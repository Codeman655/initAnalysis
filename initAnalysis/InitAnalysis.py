import sys,os,stat,subprocess,copy
import logging
import csv
import pprint 
import re
import magic

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


# FileRecord Class #############################################
#################################################################
#################################################################
#################################################################
class FileRecord:
    #defaults
    path=""
    basename=""
    perms=""
    processed=False
    magic=""
    parent=""
    meta={}
    children=[]

    def __init__(self, entry):
        if isinstance(entry, dict):
            self.path = entry["path"]
            self.basename = entry["basename"]
            self.perms = entry["perms"]
            self.processed = entry["processed"]
            self.magic = entry["magic"]
            self.parent = entry["parent"]
            self.meta = entry["meta"]
            self.children = entry["children"]

        elif isinstance(entry, os.DirEntry):
            self.path = entry.path
            self.basename = os.path.basename(entry.name)
            self.perms = oct(os.stat(entry.path).st_mode)[-3:]
            self.processed = False
            self.magic = magic.from_file(entry.path)
            self.parent = ""
            self.meta = {}
            self.children=[]
        else:
            #I should throw an error
            logging.info("FileRecord init with bad info: None Returned")
            return None


# InitAnalysis Class ############################################
#################################################################
#################################################################
#################################################################

class InitAnalysis:
    "class to store all relevant meta-data about aforementioned firmware"
    def __init__(self, args):
        self.args = args # local copy for later
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
        return FileRecord(entry)

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
                        # Add to the global files record
                        logging.debug(f"Adding {entry_path} to init collection")
                        self.files[entry.path] = FileRecord(entry)

                        #catch the big fields related to init 
                        if entry.path.endswith("/rc") or entry.path.endswith("/rc.sysinit"):
                            # this is pre-emptive. I haven't found init yet
                            fr = FileRecord(entry)
                            fr.parent = "init"
                            ret[entry.path] = fr

                        elif "/rc." in entry.path:
                            # this is pre-emptive. Belongs to rc or rc.sysinit
                            fr = FileRecord(entry)
                            fr.parent="rc.sysinit"
                            ret[entry.path] = fr
                        else:
                            # just a file in an rc or whitelisted directory
                            ret[entry.path] = FileRecord(entry)
        except OSError:
            pass
        return ret

    def ELFDependencyWriter(self, fr):
        """
        Writes the symbol table and dynamic section to a unique file
        Arguments: StatFile Entry {path, basename, prems, magic}
        """
        if "dynamically linked" in fr.magic:
            logging.info(f"ELF file found is dynamically linked: {fr.path}")
            libs= {}
            symfile = os.path.join(self.args.logdir, fr.basename + "_symbols.log")
            with open(symfile, 'w') as symoutfile:
                logging.info(f"Writing syminfo to {symfile}")
                subprocess.call("readelf -s " + fr.path,\
                        shell=True,\
                        stdout=symoutfile)
            libfile = os.path.join(self.args.logdir, fr.basename + "_libs.log")
            with open(symfile, 'w') as liboutfile:
                logging.info(f"Writing needed libraries to {libfile}")
                stdout = subprocess.call("readelf -d " + fr.path ,\
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
        global init_whitelist_dirs
        init_whitelist_dirs.extend(self.args.include)

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
        path = initFile.path
        magicData = initFile.magic
        pathRegex = re.compile(r"((?:/[\w-]+)*(?:/[\w\.-]+))\s")
        commentRegex = re.compile(r"[\s*]*#")
        keywordRegex = re.compile(r"\s*(\w+)")
        mountsInFile = []

        # Short circuit self-references 
        if path in initNodes or initFile.processed == True:
            # Decoreate with ELF data?
            logging.debug(f"already scanned {path}...")
            return

        # Because this is recursive, we don't know if the file is a script
        if "script" in magicData or "ASCII text" in magicData:
            logging.debug(f"Searching {path} script for other binaries")
            initFile.children = []
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
                            fileRecordPath = fileRecordEntry.path
                            # The binary in question must match a path/to(/binary)
                            logging.debug(f" {order}-th call to binary: {binInQuestion}")
                            # append to original init file in startupColleciton
                            # The order in which they are appended is the order in which they were discovered
                            initFile.children.append(copy.deepcopy(fileRecordEntry))

                            # Prepare child for recursive search
                            if fileRecordPath not in initNodes:
                                logging.debug(f"Deep Copy {fileRecordPath} into initnodes")
                                initNodes[fileRecordPath] = copy.deepcopy(fileRecordEntry) #Copy! Do not reference
                                self.parseInitElf(initNodes[fileRecordPath])
                                initNodes[fileRecordPath].processed = True
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
                            missingFileRecord = FileRecord( {"path":foundPath, 
                                    "basename":os.path.basename(foundPath),
                                    "perms":'000',
                                    "processed":True,
                                    "magic":"missing",
                                    "meta":{},
                                    "parent":[],
                                    "children":[]
                                    })
                            initFile.children.append(missingFileRecord)
                        else:
                            # The foundRecord path must match the given path we have.
                            fileRecordPath = fileRecordEntry.path # this is redundant. 
                            if fileRecordPath.endswith(foundPath): # This is not OS agnostic
                                #If they match, append to the list of children
                                logging.debug(f" {order}-th call to file: {foundPath}")
                                # append to original init file in startupColleciton
                                initFile.children.append(copy.deepcopy(fileRecordEntry))

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
                                    initNodes[fileRecordPath].processed = True
                                order += 1
        if mountsInFile:
            self.mountpoints[path] = mountsInFile

    def parseInitElf(self, fileRecord):
        """
        Uses regexes to decorate the init collections
        Args: fileRecord - the systemv record of the file in question
        """
        if self.args.symbols and "ELF" in fileRecord["magic"]:
            if "dynamically linked" in fileRecord["magic"]:
                logging.info(f"ELF file found is dynamically linked: {fileRecord['path']}")
            else:
                logging.info(f"ELF file found: {fileRecord['path']}")
            libs= {}
            symfile = os.path.join(self.args.logdir,fileRecord["basename"] + "_symbols.log")
            try:
                with open(symfile, 'w') as symoutfile:
                    logging.info(f"Writing syminfo to {symfile}")
                    subprocess.call("readelf -s " + fileRecord["path"],\
                            shell=True,\
                            stdout=symoutfile)
                libfile = os.path.join(self.args.logdir,fileRecord["basename"] + "_libs.log")
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
        init_file = fileRecord.path
        fileRecord.parent = "init"
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
                            fileRecord.children.append(childFileRecord)
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
        for path, fr in d.items(): # Extract the file and fileRecord Object
            #If it's already been processed, skip
            if fr.processed == True:
                continue

            # TODO Refactor the inittab work into a function
            if fr.path.endswith("inittab"):
                self.parseInitTab(fr)

            elif "ELF" in fr.magic:
                self.parseInitElf(fr)

            elif "symbolic link" in fr.magic:
                # Consider replacing or relabeling the symbolic link 
                # Consider not setting parents, its relabeled when the graph is produced
                match = re.search(r"symbolic link to (.*)$", fr.magic)
                linked_file = match.group(1)
                linked_basename  = os.path.basename(linked_file)
                logging.debug(f"Setting symbolic link (link -> realpath): {linked_basename} => {fr.path}")
            # If we don't know, pass to script searcher
            else: 
                # Recurse and add your children to the filesystem init graph
                self.scriptSearch(fr,initnodes)
            fr.processed = True

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
            for path,fileRecord in self.files.items():
                #print(f"does {key} == /{basepath}?")
                if path.endswith("/" + basepath):
                #    print(f"returning record for {basepath}")
                    return fileRecord #short ciruit
        # if neither is true
        logging.debug(f"getFileRecord: couldn't find {basepath}")
        return None

    def allProcessed(self, initnodes):
        flag = True
        for path,fr in initnodes.items():
            if fr.processed == False:
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
