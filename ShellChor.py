#!/usr//bin/env python

# The MIT License (MIT)

# Copyright (c) 2014 Muhammad Adeel

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import os,urllib2,re,sys

def banner():
    print '''
 _____ _          _ _ _____ _                
/  ___| |        | | /  __ \ |               
\ `--.| |__   ___| | | /  \/ |__   ___  _ __ 
 `--. \ '_ \ / _ \ | | |   | '_ \ / _ \| '__|
/\__/ / | | |  __/ | | \__/\ | | | (_) | |   
\____/|_| |_|\___|_|_|\____/_| |_|\___/|_|   
==========================================
Author:  Muhammad Adeel aka Stoker
Mail:    Chaudhary1337@gmail.com
Blog:    http://urdusecurity.blogspot.com
Version: 1.0
==========================================\n'''

def ShellChor():
    global host
    global var_host
    Malicious = []
    found = []
    redirect = []
    with open('Shells.txt', 'r') as hell:
        lines = hell.readlines()
        for line in lines:
            try:
                var_host = host + line
                pre_req = urllib2.Request(var_host)
                pre_req.add_unredirected_header('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6')
                pre_req.add_unredirected_header('Referer', 'http://www.google.com/')
                req = urllib2.urlopen(pre_req)
                response = req.read()
                if req.getcode() == 200:
                    print "[+] URL could be intresting => {0}".format(req.geturl())
                    Malicious.append(var_host + str(len(response)))
                else:
                    print "[!] Redirecting => {0}".format(var_host)
                    redirect.append(var_host)
            except urllib2.HTTPError, err:
                if err.code == 401:
                    print "[+] URL Could be intretsing => {0}".format(var_host)
                    found.append(var_host)
                elif err.code == 404:
                    print "[!] URL Not Found => {0}".format(var_host)
                elif err.code == 503:
                    print "[!] Redirecting => {0}".format(var_host)
                else:
                    print "[-] Unknown Response"
        print "\n -- Printing Results -- \n"
        if Malicious:
            print "++++\tPossible Malicious Files Found\t++++"
            for Malx in Malicious:
                print "[*] => {0}".format(Malx)
            print "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
        if found:
            print "++++\tPossible Shells Found\t++++"
            for fx in found:
                print "[*] => {0}".format(fx)
            print "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
        if redirect:
            print "++++\tInvalid WebResponse\t++++"
            for Rx in redirect:
                print "[*] => {0}".format(Rx)
            print "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"

def GetInput():
    global host
    host = raw_input('\nEnter URL >> ')
    print "========================================================"
    print "#       Please Wait Unitll We Scan the Site            #"
    print "========================================================"
    if host.endswith("/"):
        pass
    else:
        host = host + "/"
    if re.match('((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)',host):
        pass
    else:
        GetInput()

if __name__ == '__main__':
    try:
        banner()
        GetInput()
        ShellChor();
    except KeyboardInterrupt, e:
        print "[-] {0}".format(e)
        pass
    except Exception as e:
        print "[-] Error, {0}".format(e)
