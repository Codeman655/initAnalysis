#!/usr/bin/env python3


# ************************************
# InitAnalysis Graph Tool
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

from InitAnalysis import * #InitAnalysis and FileRecord classes

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

# Graphing Functions ############################################
#################################################################
#################################################################
#################################################################
#################################################################

def genEdgeColor(process, IA):
    if process in IA.missing:
        return "red"
    #if  "link" in mtype:
        #return "pink"
    else:
        return "black"

def genMagicShorthand( magic):
    shorthand = ""
    if "ELF" in magic:
        return "ELF"
    elif "symbolic link" in magic:
        return "symlink"
    elif "script" in magic:
        return "script"
    elif "missing" in magic:
        return "missing"
    elif "directory" in magic:
        return "directory"
    else:
        return "file"

def genNodeLabel( basename, magic):
    labelname=basename
    if "symbolic link" in magic:
      match = re.search("symbolic link to (.*)", magic)
      if match:
          labelname = labelname + " ==> " + match.group(1)
    return labelname

def genNodeColor( magic):
    if "missing" in magic:
        return "gray"
    if "ELF" in magic:
        return "red"
    elif "symbolic link" in magic:
        return "pink"
    elif "script" in magic:
        return "blue"
    else: #files and directories
        return "black"

def genNodeID(fileRecord, parent_path):
    uid = hash(parent_path)
    path = fileRecord.path
    magic = fileRecord.magic
    if not "script" or "directory" in magic: 
        return f"{uid}:{path}"
    return path

def buildGraph(G, IA, args):
    """
    G = Networx Graph
    IA = InitAnalysis Firmware Class
    args = command line args
    """

    #For each startup dictionary
    # for each process in the startup list
    init_index=0
    observed = set()
    for process, fileRecord in IA.systemv.items():
        # Hacky checklist to avoid repeats
        if process in observed: 
            continue
        else:
            observed.add(process)
        process_basename = fileRecord.basename 
        process_magic = fileRecord.magic 
        node_label = genNodeLabel(process_basename, process_magic)
        magic_shorthand = genMagicShorthand(process_magic)
        node_color = genNodeColor(process_magic)
        G.add_node(process, label=node_label, order=init_index, color=node_color, node_path=process, type=magic_shorthand)
        logging.debug(f"process: {process}:")
        #Increase index
        init_index +=1 

        #adding children
        if not fileRecord.children: 
            logging.debug("no children")
        else:
            for index in range(len(fileRecord.children)):
                """
                fileRecord = type(childRecord)
                """
                childRecord = fileRecord.children[index]
                child_order = index
                child_path  = childRecord.path 
                observed.add(child_path)

                logging.debug(f" {process_basename} has child process {child_path}")

                # Add child node 
                #Produce unique name for leaf nodes common one for scripts/dirs/files
                child_basename = os.path.basename(child_path)
                child_id = genNodeID(childRecord, process) 
                edge_color = genEdgeColor(childRecord.path , IA)
                node_color = genNodeColor(childRecord.magic )
                node_label = genNodeLabel(child_basename, childRecord.magic )
                magic_shorthand = genMagicShorthand(childRecord.magic )
                edge_label = str(index)

                #Skip IA-referencing 
                if child_path == process:
                    continue
                G.add_node(child_id, label=node_label, order=index, color=node_color, node_path=child_path, type=magic_shorthand)
                G.add_edge(process, child_id, color=edge_color, label=edge_label)

        if fileRecord.parent:
            #TODO: Why is the only parent: init?
            logging.debug(f" {process_basename} has parent process {fileRecord.parent}")
            parentRecord = IA.getFileRecord(fileRecord.parent )

            # if this is null, we haven't found the parent in the filesystem
            assert(parentRecord != None), f"{fileRecord.parent} is NULL and not in the filesystem"
            node_color = genNodeColor(parentRecord.magic )
            magic_shorthand = genMagicShorthand(parentRecord.magic )
            edge_color = genEdgeColor(process_basename, IA)

            # init is an assumed binary
            G.add_edge(parentRecord.path , fileRecord.path , color=edge_color)
    #Trim the tree 
    if args.trim:
        G.remove_nodes_from(list(nx.isolates(G)))
    #END
# END initAnalysis class


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

def write_missingfiles_csv(IA, outfile):
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

def write_file_csv(IA, outfile):
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
    IA = InitAnalysis(args)

    printdict(IA.systemv)

    # Processing the collection of init-related files
    logging.info("Processing/Searching for init files...")
    IA.processInitCollection(IA.systemv)

    # Build the graph
    logging.info("Building the graph...")
    G = nx.DiGraph(name=args.filesystem.strip("/"))
    buildGraph(G, IA, args)

    if not args.dot == "":
        logging.info(f"Writing dot file {args.dot}...")
        nx.nx_agraph.write_dot(G,args.dot)
    if not args.graphml == "":
        logging.info(f"Writing graphml file {args.graphml}...")
        nx.write_graphml(G, args.graphml)
    if not args.quiet:
        #write_file_csv(IA, os.path.join(args.logdir, "filesystem.csv"))
        #write_missingfiles_csv(IA, os.path.join(args.logdir, "missingfiles.csv"))
        print("fileRecords don't support new objects")

if __name__ == "__main__":
    main(args)
