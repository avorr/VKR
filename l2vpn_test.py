#!/usr/bin/python3.7
import paramiko
import time
import getpass
import sys
import re

hostname = input('Hostname/ip: ')
secret = getpass.getpass('Password: ')   
stdout_data =None; stderr = None; mac_add = None; mac_add = None; mpls_l2 = None; mpls_l2_deyail = None; 
neighbor_str = None; Listneighbor = None; neighbor_str_cdp = None; Listneighbor_lsp1 = None;
 
def ssh_try_except(command):
        try: 
                #Login
                client = paramiko.Transport((hostname, 22))
                client.connect( username = getpass.getuser(), password = secret)
                session = client.open_channel(kind='session')
                List = []
                #Command
                session.exec_command(command)
                while True:

                        if session.recv_ready():
                                List.append(session.recv(4096))
                        if session.recv_stderr_ready():
                                List.append(session.recv_stderr(4096))
                        if session.exit_status_ready():
                                break        
        except paramiko.ssh_exception.AuthenticationException as e:
                print(str(e))
        except paramiko.ssh_exception.SSHException as e: 
                print(str(e))
        except EOFError as e:
                print(str(e))
        return List
        session.close()
        client.close()

stdout_data = ssh_try_except( str('sh vlan brief'))
time.sleep(0.5)
print(stdout_data)
out_str=''.join(map(str, stdout_data))
print(out_str)
show_int_desc=out_str.replace('\\r\\n', '\n').replace(out_str[0], '').replace(out_str[-1], '').strip()  
print(show_int_desc)
interface = input('Interface: ')
mpls_l2 = ssh_try_except( str("sh mpls l2transport vc interface " + str(interface) + ' | i ST')) 
mpls_l2_str=''.join(map(str, mpls_l2))
ip_nexthop = r'(?:\d{1,3}\.)+(?:\d{1,3})'
ipsearch = re.findall(ip_nexthop, mpls_l2_str)
ip=''.join(ipsearch)
print(ip)
mpls_l2_detail = ssh_try_except(str("sh mpls l2transport vc interface " + str(interface) +  ' destination ' + str(ip) + " detail"))
mpls_l2_detail_str_d=''.join(map(str, mpls_l2_detail))
mpls_l2_detail_str=mpls_l2_detail_str_d.replace(mpls_l2_detail_str_d[1], '')
print(mpls_l2_detail_str)
vlvlan=''.join(re.findall(r'Vl[1-4]\d+', mpls_l2_detail_str))
label_rem = ''.join(re.findall(r'{\d+}', mpls_l2_detail_str))
label_remote =''.join(re.findall(r'\d+', label_rem))
next_hop_ipint=''.join(re.findall(r'[N-n]e\w+ [H-h]o\w+\W+ \d+\.\d+\.\d+\.\d+', mpls_l2_detail_str))
next_hop_int =''.join(re.findall(r'(\d+(\.\d+){3})', next_hop_ipint))
print(next_hop_int)
print(label_remote)
vlan =''.join(re.findall(r'[1-4]\d+', vlvlan))
print(vlan)      
mac_add = ssh_try_except("sh mac-address-table " + 'vlan ' + str(vlan))
mac_a=''.join(map(str, mac_add))
mac_str=mac_a.replace(mac_a[1], '')
mac =''.join(re.findall(r'[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+', mac_str))
mac_int = re.search(r'([T,F,G,B][A-Za-z]\d\/\d\/\d\/\d+(.\d+)?)|(BE\d+(.\d+)?)|([T,G,F,B][a-z]\d\/\d+)', mac_str).group()
print(type(mac_str))
print(mac_int)
print(mac)

def ssh_neighbor(neighbor, comm_neigh):
        try:
                #Login
                client = paramiko.Transport((neighbor, 22))
                client.connect( username = getpass.getuser(), password = secret)
                session = client.open_channel(kind='session')
                Listneighbor = []
                session.exec_command(comm_neigh)
                while True:
                        if session.recv_ready():
                                Listneighbor.append(session.recv(4096))
                        if session.recv_stderr_ready():
                                Listneighbor.append(session.recv_stderr(4096))
                        if session.exit_status_ready():
                                break
        except paramiko.ssh_exception.AuthenticationException as e:
                print(str(e))
        except paramiko.ssh_exception.SSHException as e:
                print(str(e))
        except EOFError as e:
                print(str(e))
        return Listneighbor
neighbor_cdp = ssh_try_except("sh cdp neighbors  "  + str(mac_int))
neighbor_strr = ''.join(map(str, neighbor_cdp))
neighbor_str = neighbor_strr.replace(neighbor_strr[1], '')
neighbor = re.search(r'[A-Z0-9]+\-[1-5]\-ASR9\d+', neighbor_str).group()
print(neighbor)
Listneighbor = ssh_neighbor(neighbor, 'sh ip int brief lo0')
iploopneighbor = ''.join(map(str, Listneighbor))
iploopback = re.findall(r'\d+\.\d+\.\d+\.\d+', iploopneighbor) 
print(iploopback)
iploop=''.join(iploopback)
stat_int_lsp = []; iploopcsg = []
while iploopback != ipsearch: 
        try:
                client = paramiko.Transport((iploop, 22))
                client.connect( username = getpass.getuser(), password = secret)
                session = client.open_channel(kind='session')
                Listneighbor_lsp = []
                session.exec_command('sh ip inter brief')
                while True:
                        if session.recv_ready():
                                Listneighbor_lsp.append(session.recv(4096))
                        if session.recv_stderr_ready():
                                Listneighbor_lsp.append(session.recv_stderr(4096))
                        if session.exit_status_ready():
                                break
        except paramiko.ssh_exception.AuthenticationException as e:
                print(str(e))
        except paramiko.ssh_exception.SSHException as e:
                print(str(e))
        except EOFError as e:
                print(str(e))
        neighbor_cdp_lsp = ssh_neighbor(iploop, "sh cdp neighbors  "  + str(mac_int))
        stat_int = ''.join(ssh_neighbor(iploop, "sh inter  "  + str(mac_int) + ' | begin (30 sec|5 sec)'))
        stat_int_lsp.append(stat_int)
        neighbor_strr_lsp = ''.join(map(str, neighbor_cdp_lsp))
        neighbor_str_lsp = neighbor_strr_lsp.replace(neighbor_strr_lsp[1], '')
        neighbor = re.search(r'[A-Z0-9]+\-[1-5]\-ASR[0-9]+', neighbor_str_lsp).group()
        Listneighbor_lsp1 = ssh_neighbor(neighbor, 'sh ip int brief lo0')
        iploopneighbor_lsp = ''.join(map(str, Listneighbor_lsp1))
        iploopback_lsp = re.findall(r'\d+\.\d+\.\d+\.\d+', iploopneighbor_lsp)
        iploop=''.join(iploopback_lsp)
        iploopcsg.append(iploop)
        print(iploop)
for i,n in zip(iploopcsc, stat_int_lsp):
    print(iploopcsg[i], stat_int_lsp[n])
session.close()
client.close()