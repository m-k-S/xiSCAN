# 
# xiSCAN - Max Aalto - Updated 8/18/2015 1:01 AM HST - Nonfunctional
# Basic domain information scanner
# Utilizes Eyewitness Triage Tool, written by Chris Truncer - https://github.com/ChrisTruncer/EyeWitness
#
#
# Dependencies:
# shodan, PyQt4, SIP, pyvirtualdisplay, selenium, netaddr, fuzzywuzzy, Levenshtein, Firefox (Create pip script to download?)
# TO DO:
# Move into separate files and import for neater code
# Better argument parsing
# Account for domain DNS distribution
# Combine output into single html file, to be opened upon scan completion
# Redirect output files into a separate directory

import signal, datetime, sys, os, optparse, thread, threading, httplib
import urllib2, socket, shodan, webbrowser, glob, shutil, time
from modules import objects
from modules import selenium_module
from modules.helpers import create_folders_css
from modules.helpers import default_creds_category
from modules.helpers import do_jitter
from modules.helpers import get_ua_values
from modules.helpers import target_creator
from modules.helpers import title_screen
from modules.helpers import open_file_input
from modules.helpers import resolve_host
from modules.reporting import create_table_head
from modules.reporting import create_web_index_head
try:
    from pyvirtualdisplay import Display
    from PyQt4 import QtGui
    from PyQt4.QtCore import QTimer
except ImportError:
    print "Certain dependencies not installed - please download and try again."
    sys.exit("Exiting scanner.")

# Target domain/IP
args1 = str(sys.argv[1])
target = socket.gethostbyname(args1)

# Grabbing local time and using it to organize output files
scantime = datetime.datetime.now()
filename = "Scan on " + args1 + " at " + scantime.strftime("%Y-%m-%d %H:%M") + ".txt"

print "--------------------------------------------------------------------"
print "Scanning " + args1 + " at " + scantime.strftime("%Y-%m-%d %H:%M") + "."
print "--------------------------------------------------------------------"

# Writing output file
output = open(filename, 'w+')

def shodan_scan(url, f):
    
    print "Pulling info from shodan.io..."
    # Shodan API 
    SHODAN_API_KEY = "NHEtA05p8soXE9vZ0wrI2y0R3u6YE3RN"
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        host = api.host(url)
    except shodan.APIError, e:
        print "Error: %s." % e
        
    # Parsing and writing info from Shodan scan
    f.write('[DOMAIN INFO]\n')
    f.write('Organization: '+host.get('org', 'n/a')+'\n')
    f.write('ISP: '+host.get('isp', 'n/a')+'\n')
    f.write('Operating System: '+str(host.get('os', 'n/a'))+'\n')
    f.write('Coordinates: '+str(host.get('latitude', 'n/a')) + ' N, ' + str(host.get('longitude', 'n/a')) + ' E\n')
    f.write('Country: '+host.get('country_name', 'n/a')+'\n')
    f.write('City: '+host.get('city', 'n/a')+'\n')
    f.write('AS#: '+host.get('asn', 'n/a')+'\n\n\n')
    #f.write('Ports: '+str(host.get('ports', 'n/a'))+'\n')
    
    

# Screenshot scan with server header info
class HeadRequest(urllib2.Request):
    def get_method(self):
        return "HEAD"
    
def eyewitnessscan(url):
    display = None
    create_driver = selenium_module.create_driver
    capture_host = selenium_module.capture_host
    http_object = objects.HTTPTableObject()
    http_object.remote_system = url.single
    http_object.set_paths(url.d, None)
    date = scantime.strftime('%m/%d/%Y')
    time = scantime.strftime('%H/%M/%S')
    web_index_head = create_web_index_head(date, time)
    
    print 'Attempting to screenshot: {0}'.format(http_object.remote_system)
    driver = create_driver(url)
    result, driver = capture_host(url, http_object, driver)
    result = default_creds_category(result)
    if url.resolve:
        result.resolved = resolve_host(result.remote_system)
    driver.quit()
  
    if display is not None:
        display.stop()
    html = result.create_table_html()
    with open(os.path.join(url.d, 'Screenshot scan of ' + url.single + ' at ' + scantime + '.html'), 'w') as f:
        f.write(web_index_head)
        f.write(create_table_head())
        f.write(html)
        f.write("</table><br>")

def headerscan(url, f):
    request = HeadRequest("http://www."+url) # Fix this argument parsing 
    print "Grabbing headers..."
    try: 
        response = urllib2.urlopen(request)
        response_headers = response.info()
        f.write("[HEADER]\n"+str(response_headers)+'\n\n\n')
    except urllib2.HTTPError, e:
        print "Error: %s." % e
        sys.exit("Exiting scanner.")
        
    
# Simple TCP port scan with banner grabbing
def portconnection(url, p, f):
    print "Scanning ports..."
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((url, p))
        f.write("[TCP]\nPort %d: Open\n" % p)
        connection.send("hi\r\n".encode("utf-8"))
        
        b = connection.recv(100).decode("utf-8").strip("\n")
        f.write("[BANNER]\n" + b + '\n\n\n')
        connection.shutdown(socket.SHUT_RDWR)
        connection.close()
    except Exception, e:
        print "Error: %s." % e
        sys.exit("Exiting scanner.")

def portscan(url, f):
    port = 80
    portconnection(url, port, f)
# Fix port scan loop - timeout error?? Could be my computer.
#    while port < 64445:
#        portconnection(url, port, f)
#        port = port + 1
	
class eyewitness_args():
    all_protocols=False
    createtargets=None
    cycle=None
    d=os.getcwd()+'/reports/'
    difference=50
    f=None
    h=False
    headless=False
    jitter=0
    log_file_path=os.getcwd()+'/reports/'
    no_dns=False
    no_prompt=False
    proxy_ip=None
    proxy_port=None
    rdp=False
    resolve=False
    results=25
    resume=None
    show_selenium=False
    single=args1
    t=7
    threads=10
    ua_init=False
    user_agent=None
    vnc=False
    web=True
eyewitness_namespace = eyewitness_args()
shodan_scan(target, output)
#sscan(args1, output)
eyewitnessscan(eyewitness_args)
portscan(target, output)


endscantime = datetime.datetime.now()
totaltime = endscantime - scantime 
print "Scan completed in " + str(totaltime) + "."
    
    
# Storing all banners from Shodan *Unnecessary*
#banners = []
#for item in host['data']:
#     banners.append("""
#                       Port: %s
#                      Banner: %s
#
#                    """ % (item['port'], item['data']))

