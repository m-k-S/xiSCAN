# xiSCAN - Max Aalto
Domain fingerprinting tool

Designed to run on Kali Linux

SETUP:

  1. Install dependencies
  2. Unzip directory

USAGE: 

python main.py <domain name>

  Note that argument parsing functionality is very limited - domain name must be given as one subdomain of one
  top-level domain (ie: google.com). xiSCAN should pull all subdomains of a scanned domain via Shodan for more
  comprehensive results.

DEPENDENCIES:

To run xiSCAN, one must first install:
  1. py-shodan
  2. PyQt 4.11.4 (and consequently sip)
  3. pyvirtualdisplay
  4. selenium
  5. netaddr
  6. fuzzywuzzy
  7. py-Levenshtein
  8. Firefox/Iceweasel
  9. python-nmap

I recommend installing pip first as all of these modules are easily downloaded via pip.
