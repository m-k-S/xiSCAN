# 
# xiSCAN - Max Aalto
# Basic domain information scanner
# Dependencies:
# shodan, PyQt4, SIP (create pip script to download?)
# TO DO:
# Move into separate files and import for neater code
# Better argument parsing
# Account for domain DNS distribution
# Combine output into single html file, to be opened upon scan completion
# Redirect output files into a separate directory

import signal, datetime, sys, os, optparse, thread, threading
import urllib2, socket, shodan
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from PyQt4.QtWebKit import *

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
    
def pageload(r):
    if not r:
        print "Screenshot load error."
        sys.exit("Exiting scanner.")
    webpage.setViewportSize(webpage.mainFrame().contentsSize())
    image = QImage(webpage.viewportSize(), QImage.Format_ARGB32)
    painter = QPainter(image)
    webpage.mainFrame().render(painter)
    painter.end()
    image.save("Screenshot of " + args1 + " at " + scantime.strftime("%Y-%m-%d %H:%M") + ".png")

def sscan(url, f):
    request = HeadRequest("http://www."+url) # Fix this argument parsing 
    print "Taking screenshot and grabbing headers..."
    try: 
        response = urllib2.urlopen(request)
        response_headers = response.info()
        f.write("[HEADER]\n"+str(response_headers)+'\n\n\n')
    except urllib2.HTTPError, e:
        print "Error: %s." % e
        sys.exit("Exiting scanner.")
    app = QApplication(sys.argv)
    page = QWebPage()
    page.connect(page, SIGNAL("loadFinished(bool)"), pageload)
    page.mainFrame().load(QUrl(args1))
        
    
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
	
    
    
shodan_scan(target, output)
sscan(args1, output)
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

