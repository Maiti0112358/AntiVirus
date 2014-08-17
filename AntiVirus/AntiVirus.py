
# Script Name: AntiVirus.py
# Description: Scans files for predefined virus signatures
#              and detects.
# Created By:  Eeran Maiti 11334191.
# Date:        24 January 2014.
import os
import hashlib
import glob
import errno

def antiVirus():
    # path is the path of the directory
    path = 'D:/uni-goettingen/Intro to computer security/Exercise/exercise 9/*.*'
    # vX are the signatures of the viruses I am trying to detect
    v1 = '0cc97b8570c43856500652b88cb9debc6aff5781'
    v2 = 'a045a63e83c0bda0a608f60754ec8cee46c68a0e'
    v3 = '7d12ebad134fb044b76a11ca85c4c688b859b1f8'
    v4 = 'a35fbe4bc5d607f2da88b05353fd8f476840815d'
    v5 = 'dbe76064aed80bf9bd837fb9faf337c90ebfae19'
    v6 = '64a51e91bf3e4032f891e40a868242648841867e'
    # This is supposedly meant to recursively fetch all files in all folders in directory.
    files = glob.glob(path) 
    # Open all the files in read mode
    for name in files: 
        try:
            with open(name, 'rb') as f: 
                print ("Scanning file %s", name)
                try:
                    sig = hashlib.sha1(f.read()).hexdigest()
                    print (sig)
                except:
                    print ("Error to calcualate hash.")
                if any(sig == vsig for vsig in (v1, v2, v3, v4, v5, v6)):
                    # When detected, show alert
                    print ('Alert! Virus detected in file: ',name)
                    # Delete the virus file
                    try:
                        #os.remove(name)
                        print("Virus has been removed!")
                    except OSError as e:  ## if failed, report it back to the user ##
                        f.close()
                        print ("Error: %s - %s." % (e.filename,e.strerror))
                        raise
            f.close()
        except IOError as exc:
            if exc.errno != errno.EISDIR: # Do not fail if a directory is found, just ignore it.
                f.close()
                raise # Propagate other kinds of IOError.
# Call function for virus detection
antiVirus()
