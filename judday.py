import Queue
from threading import Thread
import csv
import math
from mpu6050 import mpu6050
from time import sleep
import requests
import json
from requests import get
import time
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from commands import getoutput, getstatusoutput
import json as simplejson
import csv
import textwrap
import urllib2
import grp
import sys
import os
import time
from sys import argv
from time import sleep
import re
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

__version__ = "0.1.23"

# A Google Maps Geolocation API key is required, get it yours here:
# https://developers.google.com/maps/documentation/geolocation/intro
API_KEY = os.environ.get('GOOGLE_API_KEY') or 'YOUR_KEY'

# Alexander Mylnikov API
# https://www.mylnikov.org/archives/1170
# Too many gateway time-out (HTTP error 504)

# TODO support the WiGLE API
# https://wigle.net/

# TODO check the cool display of iSniff-GPS
# https://raw.githubusercontent.com/hubert3/iSniff-GPS/master/iSniff_GPS_Apple_WLOC_screenshot.jpg

# TODO check http://www.minigps.net/cellsearch.html
# TODO check if there is another API from Open Street Map ?


def get_scriptpath():
    pathname = os.path.dirname(sys.argv[0])
    fullpath = os.path.abspath(pathname)

    if not fullpath.endswith('/'):
        fullpath += '/'

    return fullpath


def prettify_json(json_data):
    if args.json_prettify:
        return '\n'.join([l.rstrip() for l in simplejson.dumps(json_data, sort_keys=True, indent=4*' ').splitlines()])
    else:
        return simplejson.dumps(json_data)


def create_overview(api_result, map_type, filename='Wifi_geolocation.html', filepath=get_scriptpath()):
    """ROADMAP   displays the default road map view
       SATELLITE displays Google Earth satellite images
       HYBRID    displays a mixture of normal and satellite views
                (this is the default map type)
       TERRAIN   displays a physical map based on terrain information"""

    html = """<!DOCTYPE html>
    <html>
        <head>
            <meta name="viewport" content="initial-scale=1.0, user-scalable=no" />
            <meta http-equiv="content-type" content="text/html; charset=UTF-8"/>

            <style type="text/css">
                html, body {
                    height: 100%;
                    margin: 0;
                    padding: 0;
                }

                #map_canvas {
                    height: 100%;
                }

                @media print {
                    html, body {
                        height: auto;
                    }

                    #map_canvas {
                        height: 650px;
                    }
                }
            </style>

            <title>Geolocation</title>
            <script type="text/javascript" src="http://maps.googleapis.com/maps/api/js?sensor=false"></script>
            <script type="text/javascript">
                function initialize() {
                    var mapOptions = {
                        zoom: 18,
                        center: new
                        google.maps.LatLng("""+str(api_result['location']['lat'])+", "+str(api_result['location']['lng'])+"""),
                        mapTypeId: google.maps.MapTypeId."""+map_type+"""

                    };

                    var map = new google.maps.Map(document.getElementById("map_canvas"), mapOptions);

                    // Construct the accuracy circle.
                    var accuracyOptions = {
                        strokeColor: "#000000",
                        strokeOpacity: 0.8,
                        strokeWeight: 2,
                        fillColor: "#000000",
                        fillOpacity: 0.35,
                        map: map,
                        center: mapOptions.center,
                        radius: """+str(api_result["accuracy"])+"""
                    };
                    var accuracyCircle = new google.maps.Circle(accuracyOptions);

                    var contentString = '<div>'+
                        '<p><b>Wi-Fi geolocation</b><br>'+
                        'Latitude : """+str(api_result['location']['lat'])+"""<br>'+
                        'Longitude : """+str(api_result['location']['lng'])+"""<br>'+
                        'Accuracy : """+str(api_result['accuracy'])+"""</p>'+
                        '</div>';

                    var infoWindow = new google.maps.InfoWindow({
                        content: contentString
                    });

                    var marker = new google.maps.Marker({
                        position: mapOptions.center,
                        map: map
                    });

                    google.maps.event.addListener(accuracyCircle, 'click', function() {
                        infoWindow.open(map,marker);
                    });

                    google.maps.event.addListener(marker, 'click', function() {
                        infoWindow.open(map,marker);
                    });
                }
            </script>
        </head>
        <body onload="initialize()">
            <div id="map_canvas"></div>
        </body>
    </html>"""

    # TODO parameters for output file path / name modification
    with open(filepath+filename, 'wb') as overview:
        overview.write(html)

    if args.verbose:
        print filepath + filename

    # Keep the owners
    scriptpath = get_scriptpath()
    script_uid = os.stat(scriptpath+sys.argv[0]).st_uid
    script_gid = os.stat(scriptpath+sys.argv[0]).st_gid
    overview_uid = os.stat(filepath+filename).st_uid
    overview_gid = os.stat(filepath+filename).st_gid
    if overview_uid != script_uid or overview_gid != script_gid:
        os.chown(filepath+filename, script_uid, script_gid)


def get_signal_strengths(wifi_scan_method):
    wifi_data = []

    # GNU/Linux
    if wifi_scan_method is 'iw':
        iw_command = 'iw dev %s scan' % (args.wifi_interface)
        iw_scan_status, iw_scan_result = getstatusoutput(iw_command)

        if iw_scan_status != 0:
            print "[!] Unable to scan for Wi-Fi networks !"
            print "Used command: '%s'" % iw_command
            print "Result:\n" + '\n'.join(iw_scan_result.split('\n')[:10])
            if len(iw_scan_result.split('\n')) > 10:
				print "[...]"
            exit(1)
        else:
            parsing_result = re.compile("BSS ([\w\d\:]+).*\n.*\n.*\n.*\n.*\n\tsignal: ([-\d]+)", re.MULTILINE).findall(iw_scan_result)

            wifi_data = [(bss[0].replace(':', '-'), int(bss[1])) for bss in parsing_result]

    # Mac OS X
    elif wifi_scan_method is 'airport':
        address_match = '([a-fA-F0-9]{1,2}[:|\-]?){6}'  # TODO useless ?
        airport_xml_cmd = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport --scan -x'
        airport_scan_status, airport_scan_xml = getstatusoutput(airport_xml_cmd)

        if airport_scan_status != 0:
            print "[!] Unable to scan for Wi-Fi networks !"
            print "Used command: '%s'" % airport_xml_cmd
            print "Result:\n" + '\n'.join(airport_scan_xml.split('\n')[:10])
            if len(airport_scan_xml.split('\n')) > 10:
				print "[...]"
            exit(1)
        else:
            root = ET.fromstring(airport_scan_xml)
            networks = root.getchildren()[0]

            wifi_data = [(network.find("string").text, abs(int(network.findall("integer")[7].text))) for network in networks]

    # OpenBSD
    elif wifi_scan_method is 'ifconfig':
        ifconfig_cmd = 'ifconfig %s scan' % (args.wifi_interface)
        ifconfig_scan_status, ifconfig_scan_result = getstatusoutput(ifconfig_cmd)

        if ifconfig_scan_status != 0:
            print "[!] Unable to scan for Wi-Fi networks !"
            print "Used command: '%s'" % ifconfig_cmd
            print "Result:\n" + '\n'.join(ifconfig_scan_result.split('\n')[:10])
            if len(ifconfig_scan_result.split('\n')) > 10:
				print "[...]"
            exit(1)
        else:
            parsing_result = re.compile("nwid\s+[\w-]+\s+chan\s+\d+\s+bssid\s+([\w\d\:]+)\s+([-\d]+)dBm", re.MULTILINE).findall(ifconfig_scan_result)

            wifi_data = [(bss[0].replace(':', '-'), int(bss[1])) for bss in parsing_result]

    return wifi_data


def check_prerequisites():
    # Moved arguments check and parsing to get_arguments()

    # Do something/nothing here for different kind of systems
    if sys.platform.startswith(('linux', 'netbsd', 'freebsd', 'openbsd')) or sys.platform == 'darwin':
        wifi_scan_method = None
        perm_cmd = None

        # Do something specific to GNU/Linux
        if sys.platform.startswith('linux'):
            # If not launched with root permissions
            if os.geteuid() != 0:
                # First try with 'sudo'
                which_sudo_status, which_sudo_result = getstatusoutput('which sudo')
                # If 'sudo' is installed and current user in 'sudo' group
                if which_sudo_status is 0:
                    # Like in the ubuntu default sudo configuration
                    # "Members of the admin group may gain root privileges"
                    # "Allow members of group sudo to execute any command"
                    current_user_groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
                    if 'sudo' in current_user_groups or \
                       'admin' in current_user_groups:
                        perm_cmd = 'sudo --preserve-env'
                    #etc_sudoers_status, etc_sudoers_result = getstatusoutput('sudo cat /etc/sudoers')
                    # If 'sudo' is configured for the current user
                    #if etc_sudoers_status is 0:
                        #perm_cmd = 'sudo'
                # If not 'sudo'
                if perm_cmd is None:
                    # Check other methods for getting permissions
                    for su_gui_cmd in ['gksu', 'kdesu', 'ktsuss', 'beesu', 'su -c', '']:
                        which_cmd_status, which_cmd_result = getstatusoutput('which '+su_gui_cmd.split()[0])
                        # If one is found, keep it in 'su_gui_cmd' var
                        if which_cmd_status is 0:
                            break
                    # If 'su_gui_cmd' var is not empty, we have one !
                    if su_gui_cmd:
                        perm_cmd = su_gui_cmd
                    else:
                        print "Error: this script need to be run as root !"
                        exit(1)
            #else:
                #print "[+] Current user is '%s'" % os.environ.get('USER')

            # Command available to ask permissions
            if perm_cmd:
                # Restart as root
                #print "[+] This script need to be run as root, current user is '%s'" % os.environ.get('USER')
                if args.verbose:
                    print "[+] Using '" + perm_cmd.split()[0] + "' for asking permissions"
                if perm_cmd is 'sudo --preserve-env':
                    #print perm_cmd.split()[0], perm_cmd.split() + [
                    #          ' '.join(['./' + sys.argv[0].lstrip('./')])
                    #      ] + sys.argv[1:]
                    os.execvp(perm_cmd.split()[0], perm_cmd.split() + [
                                  ' '.join(['./' + sys.argv[0].lstrip('./')])
                              ] + sys.argv[1:])
                else:
                    #print perm_cmd.split()[0], perm_cmd.split() + [
                    #          ' '.join(['./' + sys.argv[0].lstrip('./')] + sys.argv[1:])
                    #      ]
                    os.execvp(perm_cmd.split()[0], perm_cmd.split() + [
                                  ' '.join(['./' + sys.argv[0].lstrip('./')] + sys.argv[1:])
                              ])

            which_iw_status, which_iw_result = getstatusoutput('which iw')
            if which_iw_status != 0:
                print "Missing dependency: 'iw' is needed\n" + \
                      "    iw - tool for configuring Linux wireless devices"
                if 'ubuntu' in getoutput('uname -a').lower():
                    print "    > sudo apt-get install iw"
                # TODO for other distro, see with /etc/*release files ?
                elif 'gentoo' in getoutput('cat /etc/*release').lower():
                    print "    > su -c 'emerge -av net-wireless/iw'"
                exit(1)
            else:
                wifi_scan_method = 'iw'

        # Do something specific to Mac OS X
        elif sys.platform == 'darwin':
            aiport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
            if not os.path.exists(aiport_path):
                print "Missing dependency:\n" + \
                      "    airport - tool for configuring Apple wireless devices from Terminal.app"
                exit(1)
            else:
                wifi_scan_method = 'airport'

        # Do something specific to OpenBSD
        # TODO test with NetBSD and FreeBSD
        elif sys.platform.startswith(('netbsd', 'freebsd', 'openbsd')):
            # See: http://man.openbsd.org/su.1

            # If the optional shell arguments are provided on the command line, they are passed to the login shell
            # of the target login. This allows it to pass arbitrary commands via the -c option as understood by most
            # shells. Note that -c usually expects a single argument only; you have to quote it when passing multiple
            # words.

            # If group 0 (normally "wheel") has users listed then only those users can su to "root". It is not
            # sufficient to change a user's /etc/passwd entry to add them to the "wheel" group; they must explicitly
            # be listed in /etc/group. If no one is in the "wheel" group, it is ignored, and anyone who knows the root
            # password is permitted to su to "root".

            # If not launched with root permissions
            if os.geteuid() != 0:
                # Try with 'su -c' if current user in 'wheel' group
                # Like in the OpenBSD default su configuration
                # "If group 0 (normally "wheel") has users listed then only those users can su to "root"."
                # "If no one is in the "wheel" group, it is ignored [...]"
                current_user_groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
                if 'wheel' in current_user_groups:
                    perm_cmd = 'su -c'
                else:
                    # TODO "If no one is in the "wheel" group, it is ignored [...]" ?
                    print "Error: this script need to be run as root !"
                    exit(1)

            wifi_scan_method = 'ifconfig'

    else:
        # All other systems - or exception for non-supported system
        # Like 'win32'...
        # TODO is 'cygwin' could be found on Mac OS X operation systems ?
        print "Error: unsupported operating system..." + \
              "\nMicrosoft Windows operating systems are not currently supported, missing Wi-Fi cli tool / library." + \
              "\nIf you use a Mac OS X operating system, the detected plateform could have been 'cygwin'," + \
              "\nplease let us know so we can publish a correction with your help !"
        exit(1)

    return wifi_scan_method


class MyParser(ArgumentParser):
    def error(self, message):
        sys.stderr.write('erreur: %s\n\n' % message)
        #self.print_help()
        self.print_usage()
        sys.exit(2)


def get_arguments(argv=None):
    """Command line options."""

    if argv is not None:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = 'v%s' % __version__
    program_version_message = '%%(prog)s %s' % program_version
    #program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    #program_copyright = 'Copyright (c) 2017  Julien Deudon (initbrain)'

    program_license = '''sdfjsjdfisj'''

    parser = MyParser(description=program_license,
                      formatter_class=RawDescriptionHelpFormatter,
                      epilog=textwrap.dedent('''\
                          additional informations:
                            ROADMAP   displays the default road map view
                            SATELLITE displays Google Earth satellite images
                            HYBRID    displays a mixture of normal and satellite views
                                      (this is the default map type)
                            TERRAIN   displays a physical map based on terrain information'''))

    #parser.add_argument('-V', '--version', action='version', version=program_version_message)
    #parser.add_argument('-L', '--license', action='version', version=detailed_license,
    #                    help='show program\'s license details and exit')
    parser.add_argument('-v', '--verbose', action="store_true",
                        help='enable verbose messages',
                        default=False)
    parser.add_argument('-k', '--api-key', action="store", dest="api_key",
                        help='Google Maps Geolocation API key (could be hardcoded)',
                        default=None)
    parser.add_argument('-p', '--json-prettify', action="store_true",
                        help='prettify JSON output',
                        default=False)
    parser.add_argument('-o', '--with-overview', action="store_true",
                        help='accuracy overview file generation',
                        default=False)
    parser.add_argument('-m', '--map-type', choices=['ROADMAP', 'SATELLITE', 'HYBRID', 'TERRAIN'],
                        help='accuracy overview map type',
                        default='HYBRID')
    parser.add_argument('-i', action="store", dest="wifi_interface", help='specify Wi-Fi scan interface', default='wlan0')
    parser.add_argument('--demo', action="store_true", help='demo mode - West Norwood (London)', default='False')
    # Because using Mac OS X don't require to specify a Wi-Fi interface
    '''if sys.platform == 'darwin':
        parser.add_argument('--demo', action="store_true", help='demo mode - West Norwood (London)', default=False)
    else:
        required_parser = parser.add_argument_group('required arguments')
        required_parser = required_parser.add_mutually_exclusive_group(required=True)
        required_parser.add_argument('-i', action="store", dest="wifi_interface", help='specify Wi-Fi scan interface', default='wlp2s0')
        #required_parser.add_argument('--demo', action="store_true", help='demo mode - West Norwood (London)', default='False')'''

    return parser.parse_args()

import math
global lat1,lon1,ti
def get_distance(la1,lo1,flag,time):
	global lat1
	global lon1
	speed=0
	global ti
	if flag == 0:		
		lat1=la1
		lon1=lo1
		ti=time
	else:		
		lat2=la1
		lon2=lo1
		R=6371000                               # radius of Earth in meters
		phi_1=math.radians(lat1)
		phi_2=math.radians(lat2)

		delta_phi=math.radians(lat2-lat1)
		delta_lambda=math.radians(lon2-lon1)

		a=math.sin(delta_phi/2.0)**2+\
		math.cos(phi_1)*math.cos(phi_2)*\
		math.sin(delta_lambda/2.0)**2
		c=2*math.atan2(math.sqrt(a),math.sqrt(1-a))
		speed= (R*c*3600)/(time*1000)
		print ("Speed (km/h)=", speed)
		ti=ti+time
                row=[]
		row.append(ti)
                row.append(speed)
                

                with open('speed.csv','a') as newFile:
                        newFileWriter =  csv.writer(newFile)
                        newFileWriter.writerow(row)
		lat1=lat2
		lon1 = lon2
        return speed
	


def foo(bar):
        
    
    sensor = mpu6050(0x68)
    print(" waiting for the sensor to callibrate...")
    sleep(2)
    vo=0
    vl=0
    count = 0
    avg=0
    rate=5
    th_1=1.5
    th_2=2.26
    th_3=3.07
    sp_1=30
    sp_2=20
    sp_3=10
    sp_0=40
    readings = [];
    while True:
    	accel_data = sensor.get_accel_data()
    	gyro_data = sensor.get_gyro_data()
    #temp = sensor.get_temp()
   	print("Accelerometer data")
    	print("x: " + str(accel_data['x']))
    	print("y: " + str(accel_data['y']))
    	print("z: " + str(accel_data['z']))
    	accel_data['z']=accel_data['z']-2.65
    	accel_data['x']=accel_data['x']-0.31
    	accel_data['y']=accel_data['y']-0.16
    	ax_value = str(accel_data['x'])
    	ay_value = str(accel_data['y'])
    	az_value = str(accel_data['z'])
    	#accel_data['z']=accel_data['z']-2.65
    	#stunt
    	s1=-8.9
    	if ((-5.6 < accel_data['z']) and ((-8.5> accel_data['y'] >-11.6) or (8.5< accel_data['y'] < 11) or (-11.6 < accel_data['x'] < -8.5) or  (8.5 < accel_data['x'] < 11.6))):
        	print("/////////////////////////////////////////////////////////Accident Detected////////////////////////////////////////////////")
        	return 3

        #sharp turn
    	if ((3.1<accel_data['x']) or (-3.1>accel_data['x'] )):
        	print("/////////////////////////////////RASH DRIVING////////////////////////////////////////////////")
        	return 4
	sleep(1)

def moo(bar):
    
    start_time = time.time()
    count=1
    end_time=0
    flag = 0
    speed=0
    while True:
	    
		# your code

	    args = get_arguments()
	    #print(args[0])
	    #print(args[1])

	    # Parameter for demo mode set to False by default via get_arguments()
	    '''if args.demo:
		# TODO parameter for displaying messages or not
		# --verbose command line argument see get_arguments()
		if args.verbose:
		    print "[+] Scanning nearby Wi-Fi networks (demo)"

		# Demo - West Norwood (London)
		wifi_data = [
		    ('00-fe-f4-25-ee-30', -40),
		    ('02-fe-f4-25-ee-30', -44),
		    ('12-fe-f4-25-ee-30', -44),
		    ('00-26-5a-7e-0d-02', -60),
		    ('90-01-3b-30-04-29', -60),
		    ('2c-b0-5d-bd-db-4a', -50)
		]'''
	    if True:
		# Checking permissions, operating system and software dependencies
		wifi_scan_method = check_prerequisites()

		if args.verbose:
		    print "[+] Scanning nearby Wi-Fi networks..."
		wifi_data = get_signal_strengths(wifi_scan_method)
		# TODO check if the amount of detected Wi-Fi access points is good enough to call the API
		
	    if args.verbose:
		print "[+] Generating the HTML request"
	    location_request = {
		'considerIp': False,
		'wifiAccessPoints':[
		    {
		        "macAddress": mac,
		        "signalStrength": signal
		    } for mac, signal in wifi_data]
	    }

	    if args.verbose:
		print prettify_json(location_request)

	    # Check for missing API_KEY
	    #if args.api_key:
	    API_KEY = 'AIzaSyAtd5tCCCQQLO4kedpqbx9WZXxP9VfKbkc'
	    if not API_KEY or API_KEY is 'YOUR_KEY':
		print "Error: a Google Maps Geolocation API key is required, get it yours here:\n" + \
		      "https://developers.google.com/maps/documentation/geolocation/intro"
		exit(1)
	    else:
		json_data = simplejson.JSONEncoder().encode(location_request)
		http_request = urllib2.Request('https://www.googleapis.com/geolocation/v1/geolocate?key=' + API_KEY)
		http_request.add_header('Content-Type', 'application/json')

		if args.verbose:
		    print "[+] Sending the request to Google"
		# TODO internet connection error handling ?







		try:
			api_result = simplejson.loads(urllib2.urlopen(http_request, json_data).read())
	                #print ("api result is ",api_result)
			if args.verbose:
			    print "[+] Result"

			# Print JSON results
			print prettify_json(api_result)
			a=api_result['location']['lat']
			b=api_result['location']['lng']
			if flag ==0:	
				speed=get_distance(a,b,flag,end_time)
				flag = 1
				if speed>40:
                                	return speed

			else:
				speed=get_distance(a,b,flag,end_time)
                                print("main")
                                print(speed)
                                if bar == 'accident' and speed<5:
                                    bar == 'acc'
                                    stat='2'
                                    mobno='9424963915'
                                    send_loc = 'http://localhost:8089//smart-helmet/send?status='+stat+'&lat='+str(a)+'&long='+str(b)+'&mobile='+mobno

            #https://www.google.com/maps/search/?api=1&query=<lat>,<lon>
                                    response = requests.get(send_loc)
                                    print response.content
				if speed>40:
	                                return speed
			if args.verbose:
			    print "[+] Google Maps link"
			    print 'https://www.google.com/maps?q=%f,%f' % (api_result['location']['lat'], api_result['location']['lng'])
			    

			    	
	                    
	                    		
			end_time = time.time()-start_time
			start_time=time.time()
                        print ("Ende time:")
                        print(end_time)
	                
	                
			# --with-overview argument set to False by default via get_arguments()
			if args.with_overview: 
			    if args.verbose:
			        print "[+] Accuracy overview"
			    create_overview(api_result, args.map_type)
                        count+=1
		        sleep(10)
		except urllib2.HTTPError,e:
			print e.fp.read()
    if speed>40:
    	return speed()

from multiprocessing.pool import ThreadPool
from multiprocessing import Process

if __name__ == '__main__':
    accel=0
    que = Queue.Queue()
    poo = Queue.Queue()
    args = get_arguments()
    t = Thread(target=lambda q, arg1: q.put(foo(arg1)), args=(que, 'world!'))
    y = Thread(target=lambda q, arg1: q.put(moo(arg1)), args=(poo, 'worlvlkjgld!'))
    #pool = ThreadPool(processes=2)
    #async_result = pool.apply_async(foo()) # tuple of args for foo

    # do some other stuff in the main process
    print("Thread Started")
    #speed = async_result.get()  # get the return value from your function.   
    #async_result = pool.apply_async(moo()) # tuple of args for foo

    # do some other stuff in the main process
    y.start()
    #y.join()	
    #accel = async_result.get()  # get the return value from your function. 
    #while accel!=3:
    print("Accelerometer thread")
    t.start()
    #y.start()
    t.join()
    accel = que.get()
    print accel
    #y.join()
    #result = poo.get()
    #print result
    #moo()
    if (accel==1 or accel==2 or accel==4):
            	stat = 1
		lat = '12.84356'
        	lon = '77.66323'
        	stat='1'
        	mobno='9424963915'
        	send_loc = 'http://localhost:8089//smart-helmet/send?status='+stat+'&lat='+lat+'&long='+lon+'&mobile='+mobno

        #https://www.google.com/maps/search/?api=1&query=<lat>,<lon>
        	response = requests.get(send_loc)
        	print response.content
    elif (accel == 3):
            stat = 2  
    sleep(1)
    y.join()
    z = Thread(target=lambda q, arg1: q.put(moo(arg1)), args=(poo, 'accident'))
    z.start()
    z.join()
    result = poo.get()

