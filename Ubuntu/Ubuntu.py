import commands, os, re

from XSConsoleLog import *

class Util:
    #NOTE: not a good way
    #@classmethod
    #def GetIfAddr(cls, ifname):
    #    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #    # 0x8915 means SIOCGIFADDR
    #    inet = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))
    #    return socket.inet_ntoa(inet[20:24])

    @classmethod
    def GetIfAddr(cls, ifname):
        ifaddr = ""
        cmd = "ifconfig %s | awk -F\"[: ]+\" '/inet addr/{print $4}'" % ifname
        (status, output) = commands.getstatusoutput(cmd)
        if status == 0:
            ifaddr = output.strip()
        return ifaddr

    @classmethod
    def GetIfNetmask(cls, ifname):
        netmask = ""
        cmd = "ifconfig %s | awk -F\"[: ]+\" '/Mask/{print $8}'" % ifname
        (status, output) = commands.getstatusoutput(cmd)
        if status == 0:
            netmask = output.strip()
        return netmask

    @classmethod
    def GetIfGateway(cls, ifname):
        gateway = ""
        routeRE = re.compile(r'([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+UG\s+\d+\s+\d+\s+\d+\s+' + ifname,
                re.IGNORECASE)
        routes = commands.getoutput("route -n").split("\n")
        for line in routes:
            match = routeRE.match(line)
            if match:
                gateway = match.group(2).strip()
                break
        return gateway

    @classmethod
    def GetIfMacaddr(cls, ifname):
        macaddr = ""
        cmd = "ifconfig %s | awk -F\"[ ]+\" '/HWaddr/{print $5}'" % ifname
        (status, output) = commands.getstatusoutput(cmd)
        if status == 0:
            macaddr = output.strip()
        return macaddr

    @classmethod
    def GetIfConfigmode(cls, ifname):
        configmode = "UNKNOWN"
        try:
            f = open("/etc/network/interfaces", "r")
            for line in f.readlines():
                ifaceRE = re.compile(r'iface\s+' + ifname + "\s+inet\s+(.*)$", re.IGNORECASE)
                match = ifaceRE.match(line)
                if match:
                    configmode = match.group(1).strip().upper()
        finally:
            f.close()
        return configmode

    @classmethod
    def GetHostName(cls):
        hostname = "UNKNOWN"
        (status, output) = commands.getstatusoutput("hostname -f") # FQDN
        if status == 0:
            hostname = output.strip()
        return hostname

    @classmethod
    def GetNICMetric(cls, ifname):
        vendor = "UNKNOWN"
        pciname = "UNKNOWN"
        carrier = False
        try:
            pci_dev_path = os.readlink("/sys/class/net/%s/device" % ifname)
            pci_bus_id = ":".join(pci_dev_path.split(":")[-2:])
            (status, output) = commands.getstatusoutput("lspci -mm -s %s" % pci_bus_id)
            if status == 0:
                pciRE = re.compile(".*\s\"(.*)\"\s\"(.*)\"\s\"(.*)\"\s.*\s\"(.*)\"")
                match = pciRE.match(output.strip())
                if match:
                    vendor = match.group(2)
                    pciname = match.group(3)
                    
            (status, output) = commands.getstatusoutput("cat /sys/class/net/%s/carrier" % ifname)
            if status == 0:
                if output.strip() == "1":
                    carrier = True

        except Exception, e:
            pass
        return (vendor, pciname, carrier)

class Ubuntu:
    @classmethod
    def FullVersion(cls):
        # ['Distributor ID', '\tUbuntu']
        # ['Description', '\tUbuntu 12.04.1 LTS']
        # ['Release', '\t12.04']
        # ['Codename', '\tprecise']

        brand = ""
        version = ""
        release = ""
        codename = ""

        (status, output) = commands.getstatusoutput("lsb_release -a")
        if status == 0:
            for line in output.split("\n"):
                releaseinfo = line.split(":")
                if releaseinfo[0].strip() == "Distributor ID":
                    brand = releaseinfo[1].strip()
                elif releaseinfo[0].strip() == "Release":
                    release = releaseinfo[1].strip()
                elif releaseinfo[0].strip() == "Codename":
                    codename = releaseinfo[1].strip()
            version = codename + " " + release

        return (brand, version)

    @classmethod
    def GetSystemPifs(cls):
        pifs = []
        if os.path.exists("/sys/class/net"):
            for inf in os.listdir("/sys/class/net"):
                if (inf != "lo"):
                    ipaddr = Util.GetIfAddr(inf)
                    managementpif = False
                    if ipaddr != "":
                        managementpif = True

                    netmask = Util.GetIfNetmask(inf)
                    gateway = Util.GetIfGateway(inf)
                    macaddr = Util.GetIfMacaddr(inf)
                    configmode = Util.GetIfConfigmode(inf)
                    vendor, pciname, carrier = Util.GetNICMetric(inf)

                    pifs.append({
                        "device": inf,
                        "management": managementpif,
                        "ipaddr": ipaddr,
                        "netmask": netmask,
                        "gateway": gateway,
                        "macaddr": macaddr,
                        "configmode": configmode,
                        "metrics": {
                            "vendor_name": vendor,
                            "device_name": pciname,
			    "carrier": carrier
                        }
                    })
        return pifs

    @classmethod
    def UpdateNetConf(cls, conf):
        ifname = conf['device']
        configmode = conf['configmode']
        try:
            f = open("/etc/network/interfaces", 'r')
            lines = f.readlines()
            f.close()

            # remove old config
            startIfConf = -1
            endIfConf = -1
            numOfLine = -1
            ifconfRE = re.compile("^auto.*%s" % ifname)
            ifautoRE = re.compile("^auto")
            for line in lines:
                numOfLine = numOfLine + 1

                if not line.startswith('#'):
                    if ifconfRE.match(line) != None:
                        startIfConf = numOfLine
                        continue

                if startIfConf != -1:
                    if ifautoRE.match(line) != None:
                        endIfConf = numOfLine
                        break

            if endIfConf == -1:
                endIfConf = numOfLine + 1

            for num in range(startIfConf, endIfConf):
                del lines[startIfConf]

            # append new config
            lines.append("auto %s\n" % ifname)
            if configmode.lower() == "static":
                lines.append("iface %s inet static\n" % ifname)
                lines.append("address %s\n" % conf['ipaddr'])
                lines.append("netmask %s\n" % conf['netmask'])
                lines.append('gateway %s\n' % conf['gateway'])
            else:
                lines.append("iface %s inet dhcp\n" % ifname)

            f = open("/etc/network/interfaces", 'w')
            for line in lines:
                f.write(line)
            f.close()

        except Exception, e:
            raise

    @classmethod
    def GetHostName(cls):
        return Util.GetHostName()

    @classmethod
    def GetServiceName(cls, orig_name):
        real_name = orig_name
        if orig_name == "ntpd":
            real_name = "ntp"
        return real_name
