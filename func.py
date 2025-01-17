import re
import netifaces as ni
import subprocess
from flask import flash
from main import firewall_conf

def execute_command(command):
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        flash(f"Error executing command: {e}")
        return False
    return True


def check_forward_rule(external_iface, internal_iface):
    try:
        result = subprocess.run(
            ["sudo", "iptables", "-L", "FORWARD", "-v", "-n"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"Error iptables: {result.stderr}")
            return False
        rules = result.stdout
        for line in rules.splitlines():
            if external_iface in line and internal_iface in line:
                return True
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False


def get_interface_ip(interface_name):
    if ni.AF_INET in ni.ifaddresses(interface_name):
        return ni.ifaddresses(interface_name)[ni.AF_INET][0]['addr']
    else:
        return None

def get_network_interfaces():
    interfaces = ni.interfaces()
    return interfaces

def remove_iptables_rules(external_iface, internal_iface, local_ip, service_port, current_port):
    external_ip = get_interface_ip(external_iface)
    internal_ip = get_interface_ip(internal_iface)

    if not external_ip or not internal_ip:
        return

    commands = [
        f"sudo iptables -t nat -D PREROUTING -d {external_ip} -p tcp --dport {current_port} -j DNAT --to-destination {local_ip}:{service_port}",
        f"sudo iptables -t nat -D POSTROUTING -d {local_ip} -p tcp --dport {service_port} -j SNAT --to-source {internal_ip}",
        f"sudo iptables-save >{firewall_conf}"
    ]

    for command in commands:
        execute_command(command)

def is_valid_ip(ip):
    pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if not pattern.match(ip):
        return False

    octets = ip.split('.')
    for octet in octets:
        if int(octet) > 255:
            return False

    return True