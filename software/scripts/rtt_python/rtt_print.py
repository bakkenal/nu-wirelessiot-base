#! /usr/bin/env python3

import subprocess
import telnetlib
import time

PORT=42477

# Open JLinkExe connection
jlink_cmd = "JLinkExe -device nrf52840_xxaa -if swd -speed 4000 -RTTTelnetPort {} -AutoConnect 1".format(PORT)
subprocess.Popen(jlink_cmd.split(' '))

# Wait until it is ready
time.sleep(1)

# Open Telnet to RTT port and start printing data
telnet = telnetlib.Telnet(host="localhost", port=PORT, timeout=1)
while True:
    rx_data = telnet.read_very_eager()
    if rx_data:
        print(rx_data)

