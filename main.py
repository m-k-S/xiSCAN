# 
# xiSCAN - Max Aalto - Updated 8/18/2015 1:01 AM HST - Nonfunctional
# Basic domain information scanner
# Utilizes Eyewitness Triage Tool, written by Chris Truncer - https://github.com/ChrisTruncer/EyeWitness
#
#
# Dependencies:
# shodan, PyQt4, SIP, pyvirtualdisplay, selenium, netaddr, fuzzywuzzy, Levenshtein, Firefox, python-nmap (Create pip script to download?)
# TO DO:
# Move into separate files and import for neater code
# Better argument parsing
# Utilize Shodan DNS resolving
# Shodan API Key as input
# Iterate port scan over all discovered hosts
# Combine output into single html file, to be opened upon scan completion
# Redirect output files into a separate directory

import signal, datetime, sys, os, optparse, thread, threading, httplib
import urllib2, socket, webbrowser, glob, shutil, time
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
    import shodan
    import nmap
except ImportError:
    print "Certain dependencies not installed - please download and try again."
    sys.exit("Exiting scanner.")

print "-------------------------------------------------------------------"
print "|                            xiSCAN 0.4                           |"
print "-------------------------------------------------------------------"
    
# Target domain/IP
try:
    args1 = str(sys.argv[1])
    target = socket.gethostbyname(args1)
except socket.gaierror, e:
    print "Invalid domain."
    sys.exit("Exiting scanner.")



# Grabbing local time and using it to organize output files
scantime = datetime.datetime.now()
filename = "Scan on " + args1 + " at " + scantime.strftime("%Y-%m-%d %H:%M") + ".txt"

print "Scanning " + args1 + " at " + scantime.strftime("%Y-%m-%d %H:%M") + "."
print "-------------------------------------------------------------------"

# Writing output file
output = open(filename, 'w+')

def shodan_scan(url, f):
    
    print "Pulling info from shodan.io..."
    # Shodan API 
    SHODAN_API_KEY = "NHEtA05p8soXE9vZ0wrI2y0R3u6YE3RN"
    # In final version, use an input function (SHODAN_API_KEY = input("Enter Shodan API Key:"))
    api = shodan.Shodan(SHODAN_API_KEY)
    
    # DNS Resolving (finding all IPs associated with a domain) - unsure if this is possible within Shodan
    #dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + args1 *change this* + '&key=' + SHODAN_API_KEY
    #res = requests.get(dnsResolve)
    #hostIPs = resolved.json()[target]
    
    try:
        host = api.host(url)
    except shodan.APIError, e:
        print "Shodan Error: %s." % e
        sys.exit("Exiting scanner.")
        
    # Parsing and writing info from Shodan scan
    f.write('[DOMAIN INFO]\n')
    f.write('Organization: '+host.get('org', 'n/a')+'\n')
    f.write('ISP: '+host.get('isp', 'n/a')+'\n')
    f.write('Operating System: '+str(host.get('os', 'n/a'))+'\n')
    f.write('Coordinates: '+str(host.get('latitude', 'n/a')) + ' N, ' + str(host.get('longitude', 'n/a')) + ' E\n')
    f.write('Country: '+host.get('country_name', 'n/a')+'\n')
    f.write('City: '+host.get('city', 'n/a')+'\n')
    f.write('AS#: '+host.get('asn', 'n/a')+'\n\n\n')
    
    

# Screenshot scan with server header info
class HeadRequest(urllib2.Request):
    def get_method(self):
        return "HEAD"
    
def eyewitnessscan(url):
    # Iterate this over all the IPs given by the Shodan scan
    display = None
    create_driver = selenium_module.create_driver
    capture_host = selenium_module.capture_host
    http_object = objects.HTTPTableObject()
    http_object.remote_system = url.single
    http_object.set_paths(url.d, None)
    date = scantime.strftime('%m/%d/%Y')
    time = scantime.strftime('%H/%M/%S')
    web_index_head = create_web_index_head(date, time)
    
    print 'Attempting to screenshot: {0}...'.format(http_object.remote_system)
    driver = create_driver(url)
    result, driver = capture_host(url, http_object, driver)
    result = default_creds_category(result)
    if url.resolve:
        result.resolved = resolve_host(result.remote_system)
    driver.quit()
  
    if display is not None:
        display.stop()
    html = result.create_table_html()
    with open(os.path.join(url.d, 'Screenshot scan of ' + url.single + ' at ' + scantime.strftime("%Y-%m-%d %H:%M") + '.html'), 'w') as f:
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
        
    
# Simple TCP port scan using python-nmap
def portscan(url, f):
    print "Scanning TCP ports 1 through 1080..."
    nm = nmap.PortScanner()
    nm.scan(url, '1-1080')
    lport = nm[url]['tcp'].keys()
    lport.sort()
    f.write('[PORTS]\n')
    for port in lport:
        f.write('Port: %s\tState : %s\n' % (port, nm[url]['tcp'][port]['state']))

	
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
headerscan(args1, output)
eyewitnessscan(eyewitness_args)
portscan(target, output)


endscantime = datetime.datetime.now()
totaltime = endscantime - scantime 
print "Scan completed in " + str(totaltime) + "."
print "Exiting scanner."
    
    