import requests
import logging
import xml.etree.cElementTree as ET
from datetime import datetime
from pygtail import Pygtail
from time import sleep

def send_uid(user, ip):
    apikey = 'insert api key here as string'
    payload = ('<uid-message>'
               '<version>1.0</version>'
               '<type>update</type>'
               '<payload>'
               '<login>'
               '<entry name="{0}" ip="{1}"/>'
               '</login>'
               '</payload>'
               '</uid-message>'
               .format(user, ip))
    url = 'https://palo alto mgmt ip address here/api/?type=user-id&cmd='
    post_request = url + payload
    data = {'key': apikey}
    r = requests.post(post_request, data=data, verify=False)
    logging.info('A record was send to palo alto, user={0}, ip={1}'.format(user, ip))
    sleep(0.001)

def uid_update(data):
    root = ET.fromstring(data)
    #break if the data type in log is not a user login
    for element in root.findall('Fully-Qualifed-User-Name'):
        ou = element.text
    #check if it was a user or computer that auth'd with radius
        if ou[:23] == 'UNION.EDU/Domain Users/':
            for element in root.findall('SAM-Account-Name'):
                user = element.text
            for element in root.findall('Client-IP-Address'):
                ip = element.text
            send_uid(user, ip)

def run_loop(now):
    logging.basicConfig(filename ='C:\\rad_uid\\log{0}.log'.format(now), level=logging.DEBUG)
    radius_log = 'C:\\Windows\\System32\\LogFiles\\IN{0}.log'.format(str(now))
    #while date hasn't changed; once it changes we will need a new now variable
    #to look in the current days radius log
    logging.info('Starting program')
    while datetime.now().strftime('%y%m%d') == now:
        for line in Pygtail(radius_log):
            #skip error lines
            if line[:3] != '0x3':
                try:
                    uid_update(line)
                except:
                    logging.warning('There was an error parsing the radius log.')
            else:
                logging.info('A bad line was found in the radius log.')
    else:
        now = datetime.now().strftime('%y%m%d')
        run_loop(now)

def main():
    #get current date
    now = datetime.now().strftime('%y%m%d')
    run_loop(now)

main()
