from netmiko import ConnectHandler
from netmiko import ssh_exception
from network import textfsm
import os
import auth
import IPValidation

# TODO - Add spanning tree recognition to potential uplinks
# TODO - Add comments for how branch and branchinspection functions work
# TODO - Use device exceptions if cannot connect to device | What scenarios could this stop the application?
# TODO - Add input for device exclusion to not add as potential root branches
# TODO - Add LLDP support
# TODO - Check CDP formatting for multiple devices
# TODO - Add support for devices that don't support "section" output modifier
# TODO - Add NXOS support
# TODO - Add multi-user support
# TODO - Add SNMP get support for parsing CDP or LLDP info
# TODO - Add multi-vendor support
# TODO - Use similar branching framework for finding connected interface given an ip address branching from router

# Clears reference files on fresh run
for mgmtfile in os.listdir('MGMT'):
    if mgmtfile.__contains__('.txt'):
        os.remove(f'MGMT/{mgmtfile}')
for cdpfile in os.listdir('CDP'):
    if cdpfile.__contains__('.txt'):
        os.remove(f'CDP/{cdpfile}')
for rfile in os.listdir('ROOT'):
    if rfile.__contains__('.txt'):
        os.remove(f'ROOT/{rfile}')

# Global variables used in functions | See comments in functions for usage
legacydownlinkcount = 0
downlinkcount = 0
coredeviceip = ''
rootdeviceip = ''
root = ''
user = ''
passw = ''


# Function used to parse core device
def core(coreipaddress):
    # Parsed CDP Neighbor Info file
    cdp = open(f'CDP/rootcdp.txt', 'w+')
    # Device ip list to use for first branch function SSH loop
    mgmt = open(f'MGMT/rootdevicelist.txt', 'w+')
    global user
    global passw
    global downlinkcount
    global legacydownlinkcount
    # Sets legacydownlink count for downlink count to possible later be increased and checked if downlinkcount is >
    legacydownlinkcount = downlinkcount
    device = {
        'device_type': 'cisco_ios',
        'ip': coreipaddress,
        'username': user,
        'password': passw
    }
    try:
        ssh = ConnectHandler(**device)
        hostname = ssh.send_command('show run | i hostname').replace('hostname ', '').split('\n')[0]
        # Defines global "root" as core device hostname to be used by first branch functions' file creation
        global root
        root = hostname
        # Gets raw CDP Neighbor output filter with output modifier to include the sections defined
        cdpinforaw = ssh.send_command('sh cdp nei det | sec Device ID|Platform|Interface|Management address')
        # Gets total CDP Neighbor Count from raw CDP cmd output and cleans up output
        cdpcount = cdpinforaw.count('Device ID: ')
        cdpinfo = cdpinforaw.replace('Management address(es): \n  ', '')

        # Splits raw CDP Neighbor output into liat individual neighbors and does the following:
        # Parses data for each individual neighbor and outputs data to files
        # Outputs non-uplink cdp neighbor infomation to CDP file
        # Outputs non-uplink cdp neighbor mgmt ip to mgmt file if mgmt ip exists for neighbor
        cdpsplit = cdpinfo.split('\nD')
        for cdpnum in range(0, cdpcount):
            # Fixing formatting from split
            if cdpsplit[cdpnum].startswith('e'):
                cdpsplitraw = cdpsplit[cdpnum].replace('evice ID', 'Device ID')
            else:
                cdpsplitraw = cdpsplit[cdpnum]
            # Parse if Router, Switch, or WAP
            if 'Router' or 'Switch' or 'Trans-Bridge' in cdpsplitraw:
                cdplinecount = cdpsplitraw.count('\n') + 1
                cdpnsplit = cdpsplitraw.split('\n')
                # Defines variables for cdp entries so later if statements say they might not exist
                devicename = ''
                deviceplatform = ''
                devicetype = ''
                localint = ''
                neighborint = ''
                neighborip = ''

                # Parses all lines of CDP entry
                for cdpline in range(0, cdplinecount):
                    # Defines device hostname
                    if cdpnsplit[cdpline].__contains__('Device ID: '):
                        devicename = cdpnsplit[cdpline].replace('Device ID: ', '')
                    # Defines device type and platform
                    elif cdpnsplit[cdpline].__contains__('Platform: '):
                        platlinesplit = cdpnsplit[cdpline].split(' ,  ')
                        deviceplatform = platlinesplit[0].replace('Platform: ', '')
                        devicetyperaw = platlinesplit[1].replace('Capabilities: ', '')
                        # Defines device types based on capabilities listed on CDP entry info
                        if devicetyperaw.__contains__('Router') and devicetyperaw.__contains__('Switch'):
                            devicetype = 'L3_Switch'
                        elif devicetyperaw.__contains__('Router'):
                            devicetype = 'Router'
                        elif devicetyperaw.__contains__('Switch'):
                            devicetype = 'L2_Switch'
                        elif devicetyperaw.__contains__('Trans-Bridge'):
                            devicetype = 'WirelessAP'
                        else:
                            devicetype = 'Other'
                    # Defines local and neighbor interface
                    elif cdpnsplit[cdpline].__contains__('Interface: '):
                        intsplit = cdpnsplit[cdpline].split(',  ')
                        localint = intsplit[0].replace('Interface: ', '')
                        neighborint = intsplit[1].replace('Port ID (outgoing port): ', '')
                    elif cdpnsplit[cdpline].__contains__('IP address: '):
                        neighborip = cdpnsplit[cdpline].replace('IP address: ', '')
                # Excludes neighborip from cdp output if line count is 3 so previous cdp neighbor ip isn't reused
                if cdplinecount == 3:
                    cdp.write(f'{devicename} {deviceplatform} {devicetype} {localint} {neighborint}\n')
                else:
                    cdp.write(
                        f'{devicename} {deviceplatform} {devicetype} {localint} {neighborint} {neighborip}\n')

                    # If CDP Neighbor is any device type listed, outputs to mgmt ip list used in first branch function
                    if devicetype == 'L3_Switch' or 'L2_Switch' or 'Router':
                        mgmt.write(f'{neighborip}\n')

    except ssh_exception.NetmikoAuthenticationException:
        print()
    except ssh_exception.NetMikoTimeoutException:
        print()
    cdp.close()
    mgmt.close()


# Function used to parse manageable branch devices
def branch(mgmtaddresslist):
    devicecheck = open(mgmtaddresslist).read()
    devicelist = open(mgmtaddresslist)
    global user
    global passw
    global coredeviceip
    global rootdeviceip
    global downlinkcount
    global legacydownlinkcount
    legacydownlinkcount = downlinkcount
    for alldevices in devicelist:
        downlink = False
        alldevices = alldevices.strip()
        device = {
            'device_type': 'cisco_ios',
            'ip': alldevices,
            'username': user,
            'password': passw
        }
        try:
            ssh = ConnectHandler(**device)
            hostname = ssh.send_command('show run | i hostname').replace('hostname ', '').split('\n')[0]
            print(hostname)
            cdpinforaw = ssh.send_command('sh cdp nei det | sec Device ID|Platform|Interface|Management address')
            cdpcount = cdpinforaw.count('Device ID: ')
            cdpinfo = cdpinforaw.replace('Management address(es): \n  ', '')

            # Split RAW CDP Neighbor Data info crucial data
            cdpsplit = cdpinfo.split('\nD')
            for cdpnum in range(0, cdpcount):
                # Fixing formatting from split
                if cdpsplit[cdpnum].startswith('e'):
                    cdpsplitraw = cdpsplit[cdpnum].replace('evice ID', 'Device ID')
                else:
                    cdpsplitraw = cdpsplit[cdpnum]
                # Parse if Router, Switch, or WAP
                if 'Router' or 'Switch' or 'Trans-Bridge' in cdpsplitraw:
                    cdplinecount = cdpsplitraw.count('\n') + 1
                    cdpnsplit = cdpsplitraw.split('\n')

                    # Parses all lines of CDP entry
                    # Defines variables for cdp entries
                    devicename = ''
                    deviceplatform = ''
                    devicetype = ''
                    localint = ''
                    neighborint = ''
                    neighborip = ''
                    for cdpline in range(0, cdplinecount):
                        # Defines device hostname
                        if cdpnsplit[cdpline].__contains__('Device ID: '):
                            devicename = cdpnsplit[cdpline].replace('Device ID: ', '')
                        # Defines device type and platform
                        elif cdpnsplit[cdpline].__contains__('Platform: '):
                            platlinesplit = cdpnsplit[cdpline].split(' ,  ')
                            deviceplatform = platlinesplit[0].replace('Platform: ', '')
                            devicetyperaw = platlinesplit[1].replace('Capabilities: ', '')
                            # Defines device types based on capabilities listed on CDP entry info
                            if devicetyperaw.__contains__('Router') and devicetyperaw.__contains__('Switch'):
                                devicetype = 'L3_Switch'
                            elif devicetyperaw.__contains__('Router'):
                                devicetype = 'Router'
                            elif devicetyperaw.__contains__('Switch'):
                                devicetype = 'L2_Switch'
                            elif devicetyperaw.__contains__('Trans-Bridge'):
                                devicetype = 'WirelessAP'
                            else:
                                devicetype = 'Other'
                        # Defines local and neighbor interface
                        elif cdpnsplit[cdpline].__contains__('Interface: '):
                            intsplit = cdpnsplit[cdpline].split(',  ')
                            localint = intsplit[0].replace('Interface: ', '')
                            neighborint = intsplit[1].replace('Port ID (outgoing port): ', '')
                        elif cdpnsplit[cdpline].__contains__('IP address: '):
                            # print(cdpnsplit[cdpline])
                            neighborip = cdpnsplit[cdpline].replace('IP address: ', '')
                    # Excludes neighborip if line count is 3 so previous cdp neighbor ip isn't reused
                    global root
                    if cdplinecount == 3:
                        cdp = open(f'CDP/devicecdp_{root}_{hostname}.txt', 'a+')
                        cdp.write(f'{devicename} {deviceplatform} {devicetype} {localint} {neighborint}\n')
                        cdp.close()
                    if devicecheck.__contains__(neighborip) or coredeviceip.__contains__(neighborip) \
                            or rootdeviceip.__contains__(neighborip):
                        continue
                    else:
                        cdp = open(f'CDP/devicecdp_{root}_{hostname}.txt', 'a+')
                        cdp.write(
                            f'{devicename} {deviceplatform} {devicetype} {localint} {neighborint} {neighborip}\n')
                        cdp.close()
                        if devicetype == 'L3_Switch' or 'L2_Switch' or 'Router':
                            mgmt = open(f'MGMT/devicelist_{hostname}.txt', 'a+')
                            mgmt.write(f'{neighborip}\n')
                            mgmt.close()
                            downlinkcount += 1
                            downlink = True

            # Checks if there are manageable downlinks on this particular device
            # If so, then it adds this particular device's info to root list
            if downlink is True:
                rootfile = open('ROOT/roots.txt', 'a+')
                rootfile.write(f'{hostname} {alldevices}\n')
        except ssh_exception.NetmikoAuthenticationException:
            print(f'Failed to connect to {alldevices}')
            # f.write(f'{alldevices}\n')
        except ssh_exception.NetMikoTimeoutException:
            print(f'Failed to connect to {alldevices}')
            # f.write(f'{alldevices}\n')
    devicelist.close()


# Bring it all together now
def branchinspection(coreipaddress, username, password):
    global user
    global passw
    global root
    global coredeviceip
    global rootdeviceip
    global downlinkcount
    global legacydownlinkcount
    user = username
    passw = password
    coredeviceip = coreipaddress
    # SSH to Core and makes list of CDP Neighbors on root and available MGMT IP Addresses
    core(coreipaddress)
    # SSH to devices with MGMT IP addresses connected to root, then makes individual CDP and MGMT IP lists
    branch('MGMT/rootdevicelist.txt')
    while downlinkcount > legacydownlinkcount:
        rootdevices = open('ROOT/roots.txt')
        for rootdevice in rootdevices:
            rootdevicesplit = rootdevice.split(' ')
            rootdevice = rootdevicesplit[0].strip()
            rootdeviceip = rootdevicesplit[1].strip()
            root = rootdevice
            branch(f'MGMT/devicelist_{rootdevice}.txt')


branchinspection('10.10.10.3', 'admin', 'admin')
