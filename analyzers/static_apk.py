#!/usr/bin/env python

import time
import logging
import shutil
#import sunburnt
import uuid
#import processing
import subprocess
import ConfigParser
#import gamin
import re
import time
import json
import urllib
import datetime
import argparse
#import sunburnt
import solr
import fcntl
import os, sys
from contextlib import contextmanager
import time
import tempfile
import hashlib
import zipfile


if sys.getdefaultencoding() != 'utf-8':
    reload(sys)
    sys.setdefaultencoding('utf-8')
#
# set path  PATH=$PATH:`pwd`/tools/dex2jar-0.0.9.9; export PATH
# and PATH=`pwd`/tools
#
os.environ["PATH"] =  "%s:%s/tools:%s/tools/dex2jar-0.0.9.9" % (os.environ["PATH"], os.path.abspath(os.path.dirname(__file__)), os.path.abspath(os.path.dirname(__file__)))

FORMAT = '%(asctime)-15s  %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('detector')
logger.setLevel(logging.INFO)
#logger.info("Started")


def hashdata(data, hasher):
    hasher.update(data)
    return hasher.hexdigest()

def hashfile(filename, hasher, blocksize=65536):
    afile = open(filename, 'r')
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.hexdigest()


@contextmanager
def file_lock(lock_file):
    if os.path.exists(lock_file):
        logger.info( 'Script is locked with %s' % lock_file)
        sys.exit(-1)
    else:
        open(lock_file, 'w').write("1")
        try:
            yield
        finally:
            os.remove(lock_file)

def check_urls(data):
# extend later
    urls = re.findall(r'href=[\'"]?([^\'" >]+)', data)
    return urls


def analyze_content(path, doc, temp):
    if (not doc.has_key("urls")):
        doc["urls"] = []
    if (not doc.has_key("features")):
        doc["features"] = []
    if (not doc.has_key("services")):
        doc["services"] = []
    if (not doc.has_key("classes")):
        doc["classes"] = []
    if (not doc.has_key("intents")):
        doc["intents"] = []
    if (not doc.has_key("receivers")):
        doc["receivers"] = []
    if (not doc.has_key("api_calls")):
        doc["api_calls"] = []


    z = zipfile.ZipFile(path)
    for n in z.namelist():
        d = z.read(n)
        cksum  = hashdata(d, hashlib.md5())
        if (not doc.has_key("files_md5")):
            doc["files_md5"] = []
        doc["files_md5"].append("%s:%s" %(n, cksum))
        urlz = check_urls(d)
        if len(urlz) != 0:
            doc["urls"].append(urlz)

        if n == "classes.dex":
            doc["dex_md5"] = cksum
            doc["dex_sha1"] = hashdata(d, hashlib.sha1())
            doc["dex_sha256"] = hashdata(d, hashlib.sha256())
            z.extract(n, temp)
            s =subprocess.check_output(["d2j-dex2jar.sh", "%s/classes.dex"% (temp), "-o", "%s/classes_dex2jar.jar"%(temp)], shell=False)
            zjar = zipfile.ZipFile("%s/classes_dex2jar.jar" % (temp))
            doc["classes"] = zjar.namelist()
            os.mkdir("%s/smali" % (temp))
            s =subprocess.check_output(["baksmali", "-o%s/smali"% (temp), "%s/classes.dex" % (temp)], shell=False)
    return doc



def analyze_aapt(path, doc):
    s_aaptout = subprocess.check_output(["aapt", "d", "badging", path], shell=False)
    l =  s_aaptout.split('\n')
    for line in l:
        logger.info(line)
        p = line.split(':')
        if (p[0] == 'application'):
            r = re.search("label='([^']+).*", p[1])
            doc["name"] = r.group(1)
        if (p[0] == 'sdkVersion'):
            doc["sdk_version"] = p[1][1:len(p[1]) - 1]
        if (p[0] == 'targetSdkVersion'):
            doc["target_sdk_version"] = p[1][1:len(p[1]) - 1]

        if (p[0] == 'uses-permission'):
            if (not doc.has_key("permissions")):
                doc["permissions"]= []
            doc["permissions"].append(p[1][1:len(p[1]) - 1])

        if (p[0] == 'uses-feature'):
            if (not doc.has_key("features")):
                doc["features"]= []
            doc["features"].append(p[1][1:len(p[1]) - 1])


        if (p[0] == 'package'):
            r = re.search("name='(.*)'\s+versionCode='(.*)'\s+versionName='(.*)'", p[1])
            doc["package_name"] = r.group(1)
            doc["version_code"] = r.group(2)
            doc["version_name"] = r.group(3)
        if (line.find("launchable activity") != -1):
            r = re.search("launchable activity name='(.*)'label='(.*)'", line)
            doc["launch_class"] = r.group(1)
            doc["launch_class_label"] = r.group(2)

    return doc




def process_file(path):
    logger.info("processing %s" %(path))
    t = tempfile.mkstemp()
    os.close(t[0])
    logfile = t[1]
    # isfile path and event 8
    #s_out = subprocess.check_output(["./tools/extractAPK", "%s" %(path), logfile], shell=False)
    doc = {}
    doc["id"] =  str(uuid.uuid4())
    doc["analysis_start"] = datetime.datetime.utcnow()
    doc["md5"] = hashfile(path, hashlib.md5())
    doc["sha1"] = hashfile(path, hashlib.sha1())
    doc["sha256"] = hashfile(path, hashlib.sha256())
    try:
        tempdir = "/tmp/CMA/%s" % doc["id"]
        doc = analyze_aapt(path, doc)

        os.mkdir(tempdir)
        doc = analyze_content(path, doc, tempdir)
        #s_out = subprocess.check_output(["./tools/apktool d ", "%s" %(path)], shell=False)


        doc["analysis_end"] = datetime.datetime.utcnow()
        shutil.rmtree(tempdir)
        return doc

    except Exception, e:
        logger.info(e)
        doc["error_msg"] = e
        doc["error"] = True
        doc["error_time"] = datetime.datetime.utcnow()
        doc["error_apk_path"] = path
        return doc


def main():
    parser = argparse.ArgumentParser(description = 'Run scan on apk file')
    parser.add_argument('filename',  metavar='filename', nargs='+', help='apk file name')

    args = parser.parse_args()
    for f in args.filename:
        with file_lock('/tmp/.apk.script.lock'):
            logger.info("Aquired lock")
        rez = process_file(f)
        print rez




if __name__ == "__main__":
    main()




