# 
# xiSCAN - Max Aalto
# Basic domain information scanner
#

import socket, datetime, sys, os, optparse, thread, threading, shodan

# Target domain/IP
args1 = str(sys.argv[1])
target = socket.gethostbyname(args1)

# Grabbing local time and using it to organize output files
scantime = datetime.datetime.now()
filename = "Scan on " + args1 + " at " + scantime.strftime("%Y-%m-%d %H:%M") + ".txt"

# Writing output file
output = open(filename, 'w+')

# Shodan API 
SHODAN_API_KEY = "NHEtA05p8soXE9vZ0wrI2y0R3u6YE3RN"
api = shodan.Shodan(SHODAN_API_KEY)
host = api.host(target)

# Parsing and writing info from Shodan scan
output.write('DOMAIN INFO:\n')
output.write('Organization: '+host.get('org', 'n/a')+'\n')
output.write('ISP: '+host.get('isp', 'n/a')+'\n')
output.write('Operating System: '+str(host.get('os', 'n/a'))+'\n')
output.write('Coordinates: '+str(host.get('latitude', 'n/a')) + ' N, ' + str(host.get('longitude', 'n/a')) + ' E\n')
output.write('Country: '+host.get('country_name', 'n/a')+'\n')
output.write('City: '+host.get('city', 'n/a')+'\n')
output.write('AS#: '+host.get('asn', 'n/a')+'\n')
output.write('Ports: '+str(host.get('ports', 'n/a'))+'\n')



# Storing all banners from Shodan
#banners = []
#for item in host['data']:
#     banners.append("""
#                       Port: %s
#                       Banner: %s
#
#                    """ % (item['port'], item['data'])

    
