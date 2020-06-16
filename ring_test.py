#!/usr/bin/python3.7
def f():    
    import re
    import time
    import getpass
    import paramiko
    import seaborn as sns
    import networkx as nx
    import matplotlib.pyplot as plt
    from concurrent.futures import ThreadPoolExecutor, as_completed
    sns.set()
    G=nx.Graph()    
    
    hostname_or_ip = input('Hostname/ip: ').strip().encode('latin1').decode('ascii')
    secret = getpass.getpass('Password: ').strip().encode('latin1')
    
    def once_command(command:str, hostname_def):
        try:
            sshtransport = paramiko.Transport((hostname_def, 22))
            sshtransport.connect( username = getpass.getuser(), password = secret)
            session = sshtransport.open_channel(kind='session')
            List = []                
            session.exec_command(str(command))
            while True:
                if session.recv_ready():
                    List.append(session.recv(5000).decode('ascii'))
                if session.recv_stderr_ready():
                    List.append(session.recv_stderr(5000).decode('ascii'))
                if session.exit_status_ready():
                    break
            return List
        except paramiko.ssh_exception.AuthenticationException as e:
            print(str(e))
        except paramiko.ssh_exception.SSHException as e:
            print(str(e))
        except EOFError as e:
            print(str(e))
        session.close()
        sshtransport.close()
    
    def some_commands_ASR900(commands:str, hostname_def:str):    
        sshshell = paramiko.SSHClient()
        sshshell.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sshshell.connect(
                hostname=hostname_def,
                username=getpass.getuser(),
                password=secret,
                look_for_keys=False,
                allow_agent=False)
        try:
            with sshshell.invoke_shell() as ssh:
                ssh.settimeout(1)
                ssh.send('tclsh\n')
                time.sleep(1)
                ssh.send(str(commands)+"\n")
                time.sleep(1)
                complete_stdoutlist = []
                complete_stdout = ''
                while True:
                    try:
                        incomplete_stdout = ssh.recv(5000).decode('ascii')
                    except paramiko.ssh_exception.socket.timeout:
                        break
                    complete_stdout += incomplete_stdout
                    if len(re.findall(r'More-- $', incomplete_stdout)) > 0:
                        ssh.send(' ')
            return(complete_stdout)
        except paramiko.ssh_exception.AuthenticationException as e:
            print(str(e))
        except paramiko.ssh_exception.SSHException as e:
            print(str(e))
        except EOFError as e:
            print(str(e))
    
    def some_commands_ASR9K(hostname_def, *commandsASR9K):    
        sshshell = paramiko.SSHClient()
        sshshell.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sshshell.connect(
            hostname=str(hostname_def),
            username=getpass.getuser(),
            password=secret,
            look_for_keys=False,
            allow_agent=False)
        try:
            with sshshell.invoke_shell() as ssh:
                ssh.settimeout(1)
                for commandASR9K in commandsASR9K:
                    ssh.send(str(commandASR9K)+'\n')
                    time.sleep(1)
                complete_stdout = ''
                while True:
                    try:
                        incomplete_stdout = ssh.recv(5000).decode('ascii')
                    except paramiko.ssh_exception.socket.timeout:
                        break
                    complete_stdout += incomplete_stdout
                    if len(re.findall(r'More-- $', incomplete_stdout)) > 0:
                        ssh.send(' ')
            return(complete_stdout)
        except paramiko.ssh_exception.AuthenticationException as e:
            print(str(e))
        except paramiko.ssh_exception.SSHException as e:
            print(str(e))
        except EOFError as e:
            print(str(e))
            
    def ASR900ring(commands:str, hostname_def):       
        sshshell = paramiko.SSHClient()
        sshshell.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sshshell.connect(
            hostname=hostname_def,
            username=getpass.getuser(),
            password=secret,
            look_for_keys=False,
            allow_agent=False)
        try:
            with sshshell.invoke_shell() as ssh:
                ssh.settimeout(0.1)
                ssh.send('tclsh\n')
                time.sleep(0.2)
                ssh.send(str(commands)+"\n")
                time.sleep(3)
                complete_stdout = ''
                while True:
                    try:
                        complete_stdout = ssh.recv(5000).decode('ascii')
                        stroutput = re.search(r'.+input+(.*\n+){5}', complete_stdout).group()
                    except paramiko.ssh_exception.socket.timeout:
                        break
            return [hostname_def, stroutput]
        except paramiko.ssh_exception.AuthenticationException as e:
            print(str(e))
        except paramiko.ssh_exception.SSHException as e:
            print(str(e))
        except EOFError as e:
            print(str(e))            
        
    def findlocalBGPneighbor(hostname_or_ip1):
        findAGN = None
        findAGN = once_command("show ip bgp summary | begin Neighbor", hostname_or_ip1)
        findAGNstr = ''.join(map(str, findAGN))
        findAGNip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', findAGNstr) 

        if len(findAGNip) == 2:
            localAGNneighbor = None
            localAGNneighbor = some_commands_ASR9K(findAGNip[0], " sh cdp neig det | i Dev", ' sh run int lo0')
            findbgpipASR900 = re.findall(r'([A-Za-z0-9._-]+\-[1-5]-ASR9\d{2})\.nw', localAGNneighbor)

            AGNipneighbor = None   
            findAGNipnei = ['None']
            while (len(set(findAGNip)&set(findAGNipnei)) != 2):
                for num_of_asr900 in findbgpipASR900:
                    AGNipneighbor = once_command("sh ip bgp sum | b Neig", num_of_asr900)
                    AGNipneighborstr = ''.join(map(str, AGNipneighbor))
                    findAGNipnei = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', AGNipneighborstr)

        elif len(findAGNip) == 1:
            localAGNneighbor = None
            localAGNneighbor = some_commands_ASR9K(findAGNip[0], " sh cdp neigh det | i Dev", ' sh run int lo')
            findbgpipASR900 = re.findall(r'([A-Za-z0-9._-]+\-[1-5]-ASR9\d{2})\.nw', localAGNneighbor)         
            AGNipneighbor = None; findAGNipnei = ['None']
            while findAGNip != findAGNipnei:
                for num_of_asr900 in findbgpipASR900:
                    AGNipneighbor = once_command("show ip bgp summary | begin Neighbor", num_of_asr900)
                    AGNipneighborstr = ''.join(map(str, AGNipneighbor))
                    findAGNipnei = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', AGNipneighborstr)
            
    def startscript(iphop):
        infoASRbgp = None; ipasr = None; bgptime = None
        infoASRbgp = once_command("s ip bgp sum | b Ne", iphop)
        ipasr = once_command("s ru in lo0 | b add", iphop)        
        searchipAGNbgp = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "".join(infoASRbgp))
        ipasrlo0 = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "".join(ipasr)).group()
        bgptime = re.findall(r'\d+w+\d+d|\d+:\d+:\d+', "".join(infoASRbgp))
        sshshell = paramiko.SSHClient()
        sshshell.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sshshell.connect(
                hostname=searchipAGNbgp[0],
                username=getpass.getuser(),
                password=secret,
                look_for_keys=False,
                allow_agent=False)
        try:
                with sshshell.invoke_shell() as ssh:
                        ssh.settimeout(1)
                        time.sleep(1)
                        ssh.send(f' sh mpls ldp forwa {ipasrlo0}/32 | b --\n')
                        time.sleep(1)
                        complete_stdout = ssh.recv(5000).decode('ascii')
                        time.sleep(1)
                        findFirstInt = re.findall(r'[TtGgFfEe]+\w+[0-2/]+[^.]+', complete_stdout)
                        findintAGN = ''.join(findFirstInt)                               
                        ssh.send(f' sh cdp ne de {findintAGN} | i Dev\n')
                        time.sleep(1.5)
                        ssh.send(f' sh cdp ne {findintAGN} | i Te\n')
                        time.sleep(1.5)
                        outputAGN = []
                        outputAGN.append(ssh.recv(500).decode('ascii'))
                        nameof1AGN = re.search(r'[$:]+([A-Za-z0-9/._]+-[1-3]-ASR[9016]{4})', ''.join(outputAGN)).group(1)
                        nexthop = ''.join(re.findall(r'([^\s]+ASR9\d{1,2}).nw', ''.join(outputAGN)))
                        findintCSG = re.findall(r'[T]+\w+[0-2/]+\d+.[^/S|]', ''.join(outputAGN))                       
        except paramiko.ssh_exception.AuthenticationException as e:
                print(str(e))
        except paramiko.ssh_exception.SSHException as e:
                print(str(e))
        except EOFError as e:
                print(str(e))    
        ringASR = []; ringCSG = []; ringint = []; ringint2 = []; infointlist = []; infointlist2 = []
        ringCSG.append(nameof1AGN)
        ringCSG.append(nexthop)
        ringint.append(findintCSG[-1].strip())
        ringint2.append(findintAGN)
        infoint = ''.join(once_command(f'show interfaces {findintAGN} | begin 30 sec', searchipAGNbgp[0]))
        infointlist.append(infoint)
        iploopbackcsg = 10
        
        while iploopbackcsg != searchipAGNbgp[1]:
            infoCsg = []
            ringcsglist = infoCsg.append(some_commands_ASR900('s run int lo0;s cdp n | b De', nexthop))
            ringcsg = ''.join(infoCsg)
            iploopbackcsg = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ringcsg).group()
            nexthopall = re.findall(r'(.*)\.nw.', ringcsg)
            nexthop = ''.join(set(nexthopall)-set(ringCSG))                                        
            reg_exp = rf"{nexthop}" + r'.+\s+([T]+\w+\s+\d+/+\d+(/+\d+)?).*([T].+)'
            intring2 = re.search(reg_exp, ringcsg).group(1)
            intring = re.search(reg_exp, ringcsg).group(3)                 
            ringint.append(intring[0:-1])
            ringint2.append(intring2)
            ringCSG.append(nexthop)
            if str(9001) in ringCSG[-1] or str(9006) in ringCSG[-1] or str(9010) in ringCSG[-1]:
                break
        if len(ringCSG)%2 ==0:
            for i,n in zip(ringCSG, range(len(ringCSG)//2)):
                if ringCSG.index(i) < len(ringCSG)//2:
                    G.add_node(i, pos=(n,((len(ringCSG)//2)**2-n**2)**0.5))

            for a,b in zip(ringCSG[::-1], range(len(ringCSG)//2)):
                if ringCSG.index(a) >= len(ringCSG)//2:
                    G.add_node(a, pos=(b,-((len(ringCSG)//2)**2-b**2)**0.5))

            for i,n,m,k in zip(range(len(ringCSG)), range(1, len(ringCSG)), ringint, ringint2):
                if i <= len(ringint)//2:
                    G.add_edge(ringCSG[i], ringCSG[n],interfaces=k+'--'+m, relation='neighbor')
                else:
                    G.add_edge(ringCSG[i], ringCSG[n],interfaces=m+'--'+k, relation='neighbor')
        else:
            for i,n in zip(ringCSG, range(len(ringCSG)//2+1)):
                if ringCSG.index(i) < len(ringCSG)//2:
                    G.add_node(i, pos=(n,((len(ringCSG)//2)**2-n**2)**0.5))

            for a,b in zip(ringCSG[::-1], range(len(ringCSG)//2+1)):
                if ringCSG.index(a) >= len(ringCSG)//2:
                    G.add_node(a, pos=(b,-((len(ringCSG)//2)**2-b**2)**0.5))

            for i,n,m,k in zip(range(len(ringCSG)), range(1, len(ringCSG)), ringint, ringint2):
                G.add_edge(ringCSG[i], ringCSG[n],interfaces=m+'--'+k, relation='neighbor')

            for i,n,m,k in zip(range(len(ringCSG)), range(1, len(ringCSG)), ringint, ringint2):
                if i < len(ringint)//2:
                    G.add_edge(ringCSG[i], ringCSG[n],interfaces=k+'--'+m, relation='neighbor')
                else:
                    G.add_edge(ringCSG[i], ringCSG[n],interfaces=m+'--'+k, relation='neighbor')
       
        G.add_edge(ringCSG[ringCSG.index(hostname_or_ip)], ringCSG[0],interfaces=bgptime[0], relation='ibgp')
        G.add_edge(ringCSG[ringCSG.index(hostname_or_ip)], ringCSG[-1],interfaces=bgptime[1], relation='ibgp')
        
        pos=nx.get_node_attributes(G, 'pos')
        labels = nx.get_edge_attributes(G, 'interfaces')
        relation = nx.get_edge_attributes(G, 'relation')
        ref = {'neighbor': 'blue', 'linkdown': 'red', 'ibgp': 'red'}
        nx.draw_networkx(G, pos, edge_color=[ref[x] for x in relation.values()])
        nx.draw_networkx_edge_labels(G,pos,edge_labels=labels)

        ringCSG.pop(0); ringCSG.pop(-1); ringint.pop(-1); ringint2.pop(0)
        
        with ThreadPoolExecutor(max_workers=len(ringCSG)) as executor:
            futures = []
            results = []
            for asr, asrint in zip(ringCSG, ringint):
                futures.append(executor.submit(ASR900ring, f'sh int {asrint} | i (bits|errors);sh int tra | i {asrint[4:]}', asr))
            for f in as_completed(futures):         
                a = f.result()        
                results.insert(ringCSG.index(a[0]), a[1])
                     
            for host,intasr,result in zip(ringCSG, ringint, results):
                print(host)
                print(intasr)
                print(result)           
 
    sshshellhostname = paramiko.SSHClient()
    sshshellhostname.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sshshellhostname.connect(
        hostname=hostname_or_ip,
        username=getpass.getuser(),
        password=secret,
        look_for_keys=False,
        allow_agent=False)
    try:
        sshhost=sshshellhostname.invoke_shell()
        sshhost.settimeout(0.1)
        sshhost.send(' show running-config interface loopback 0\n')
        time.sleep(1.5)
        List1 = []
        List1.append(sshhost.recv(300).decode('ascii'))
    except paramiko.ssh_exception.AuthenticationException as e:
        print(str(e))
    except paramiko.ssh_exception.SSHException as e:
        print(str(e))
    except EOFError as e:
        print(str(e))
    liststr1 = ''.join(List1)    
    searchasr = re.findall(r'[A-Za-z0-9._-]+\-[1-5]-ASR9\d+', liststr1)
    searchiplo0 = re.search(r'(\d{1,3}[\.]){3}\d{1,3}', liststr1).group()
    
    if str(9010) in searchasr[0] or str(9001) in searchasr[0] or str(9006) in searchasr[0]:        
        neighborASR9K = None	
        neighborASR9K = once_command("show cdp neighbor detail | include Device", hostname_or_ip)
        cdpneighborASR9K = ''.join(map(str, neighborASR9K))
        cdpneighborASR9Kstr = cdpneighborASR9K.replace('\\r\\n', "\n").replace(cdpneighborASR9K[0], '').replace(cdpneighborASR9K[-1], '').strip()
        cdpASR900 = re.findall(r'([A-Za-z0-9.]+\-[1-5]-ASR9\d{2})\.nw', cdpneighborASR9Kstr)
        neighbor900 = []
        for num_of_asr, lineASR in enumerate(cdpASR900,1):
            print(str(num_of_asr)+str(')'),str(lineASR))
            neighbor900.append(str(lineASR))
        neighbor900asr = input('Number of router: ')
        print(neighbor900[int(neighbor900asr)-1])
        startscript(neighbor900[int(neighbor900asr)-1])
 
    else:	
        startscript(searchiplo0)