'''
MIT License

Copyright (c) 2022 Sturzbecher

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.



Note: 
This is code that I have created for personal use and maybe an assessment project. 

I also want to stress that installing AnyDesk like any remote desktop software 
can open up your system to allow anyone to take full control of it. 
If you do not know how to lock down AnyDesk's permissions and/or DMZ a VM then   
I strongly suggest you do not setup a HoneyPot.

Also Note: 
The default MQTT server configured is a free open public server, anyone see the 
messages that this script publishes to that server. 

To monitor MQTT messages, Use a application like MQTT Lens
https://chrome.google.com/webstore/detail/mqttlens/hemojaaeigabkbcookmlgmdigohjobjm?hl=en

Then add the server "test.mosquitto.org"

Then Subscribe to "test/BGR_dev/AD_honeypot/<HOSTNAME>/#"       Replace <HOSTNAME> with the hostname of the system running this script     



'''





# report abuse url https://anydesk.com/en/contact/general
# AnyDesk have not responded to any of my scammer reports yet. Maybe they just don't care 


# example data we are interested in (example from real Amazon scammer that called me)
# info 2022-05-05 01:38:27.181       back   3668   3660                   app.backend_session - Incoming session request: AMAZON COSTUMER SERVICES (602780917)
# ^ Has Aliase as well as remote client ID  

# info 2022-05-05 01:38:27.193       back   3668   3660                   app.backend_session - Remote OS: Windows, Connection flags: direct scam paid 3 
# ^ can see that is from a Windows Desktop, not sure what "direct scam paid 3" means, my free accounts reports just "paid"  

# info 2022-04-29 05:04:45.849       back   2060   2584                   app.backend_session - Remote version: 7.0.7
# info 2022-04-29 05:25:14.750       back    992   3852                   app.backend_session - The socket was closed remotely.
# info 2022-04-29 05:25:14.750       back    992   4324                   app.backend_session - The user has requested a connection quit. 

# C:\ProgramData\AnyDesk\system.conf = Anydesk main config, 
# Should add function to check settings in this file are safe (relatively). I have found permissions have been known to reset back to defaults.  Local AnyDesk ID is stored in here too


import time
import os
import sys
import platform
import random
import paho.mqtt.client as mqtt
uname = platform.uname()                    # Used to get system information like Hostname

# ----- Settings -----
logPath = "\\\\192.168.1.107\\core\\Users\\remote\\AppData\\Roaming\\AnyDesk\\ad.trace"     # Path to log file to monitor, remember to escape the back slashes 
#logPath = "C:\\Users\\remote\\AppData\\Roaming\\AnyDesk\\ad.trace"                         # example of local path 

clientName = uname.node  # "HoneyPot2"      # use HOSTNAME, can hardcode to a string but if running on a few HoneyPot VMs it is easier to just use the hostnames
MQTTBroker = "test.mosquitto.org" # "mqtt.eclipseprojects.io"       # which MQTT server to use, both are free public open, recommend using a private server if you have the option 
MQTTbaseTopic = "test/BGR_dev/AD_honeypot/" + clientName + "/"
# ----- Settings -----



# Tail the log file
def tail(filename):
    filename.seek(0, os.SEEK_END)           # Move to end of file, comment out this line to test with a exiting file data instead of only with new log data               
    try:
        while True:                         # start infinite loop
            line = filename.readline()      # read last line of file
            if not line:                    # sleep if file hasn't been updated
                time.sleep(0.2)             # 200ms sleep 
                continue
            yield line                      # return line
    except OSError:                         # error opening file, may not exist or can not access for some other reason
        print("\33[91mError opening trace file\33[0m")
        sys.exit() 



def checkLine(line):
    remoteID = 0
    if line.find("Incoming session request:") >1:
        remoteID=line[-11:-2]                                           # This is just the AnyDesk ID who is trying to connet to us
        remoteID_full = line[line.find('Incoming session request:'):-1]
        print(f"Incoming session request: {remoteID_full}")             # this also prints the remote Alias 
        print(f"AnyDesk ID: {remoteID}")
        client.publish(MQTTbaseTopic + "remoteID", remoteID)            # Pub just the ID number 
        client.publish(MQTTbaseTopic + "FullremoteID", remoteID_full)   # Pub the full ID string with Aliase        

    if line.find("Remote OS:") >1:
        remoteOS = line[line.find('Remote OS:'):-1]
        print(f"Incomming connection desktop {remoteOS}")
        client.publish(MQTTbaseTopic + "remoteOS", remoteOS)            # Pub the remote OS string
    
    if line.find("Remote version:") >1:
        remoteVer = line[line.find('Remote version:'):-1]
        print(f"Incomming connection version {remoteVer}")       
        client.publish(MQTTbaseTopic + "remoteVersion", remoteVer)      # Pub the remote version string

    if line.find("The socket was closed remotely") >1:
        print(f"Incomming connection socket was closed remotely")

    return


# main function
if __name__ == '__main__':
    logfile = open(logPath,"r")                                         # Open the trace file
    loglines = tail(logfile)                                            # tail the trace log file
    client = mqtt.Client("AD_Honeypot_"+ clientName + "_"+ random.randint(1111, 9999))       # Client name needs to be unique 
    client.connect(MQTTBroker)                                          
    client.publish(MQTTbaseTopic + "state", "boot")
    
    for line in loglines:
        #print(line)                                                    # used for debug, dumps the log lines to the console as they come in  
        checkLine(line)

