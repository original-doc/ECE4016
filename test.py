import socket
from dnslib import *

class dnserver:
    def __init__(self):
        self.ip = "127.0.0.1"
        self.port = 1234
        self.cache = {}
        self.flag = 1
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.ip, self.port))

    def listen_q(self):
        while(1):
            query, clientaddr = self.sock.recvfrom(4096)
            """ print("query: ")
            print(query)
            print("clientaddr: ")
            print(clientaddr) """
            data = DNSRecord.parse(query)
            """ print(data)
            print(data.q.qname) """
            if data.q.qname in self.cache:
                ans = self.cache[data.q.qname]
                ans.header.id = data.header.id
                pack_a = ans.pack()
                self.sock.sendto(pack_a, clientaddr)
            else:
                if self.flag == 0:
                    self.ask_pulicdns(data, clientaddr)
                elif self.flag == 1:
                    self.ask_dns(data, clientaddr)
            #self.sock.sendto(query, clientaddr)

    def update_cache(self, qname, response):
        self.cache[qname] = response

    
    def ask_pulicdns(self, data, clientaddr):
        public_dns = [
            "119.29.29.29",#tencent
            "8.8.8.8",#google
            "223.5.5.5",#aliyun
            "180.76.76.76",#baidu
        ]

        a_dns = public_dns[1]
        '''
        qname = data.q.qname
        a_q = DNSRecord.question(qname, qtype="A")
        aa_q = a_q.send(a_dns)
        res = DNSRecord.parse(aa_q)
        '''
        qname = data.q.qname
        test = data.send(a_dns)
        ans = DNSRecord.parse(test)
        self.update_cache(qname, ans)
        print(ans)
        self.sock.sendto(test, clientaddr)
    
    def extract_add_RR(self, source, dest):
        for rr in source.rr:
            rtype = rr.rtype
            ttl = rr.ttl
            rdata = str(rr.rdata.label)
            #print("rr: _", type(rr), rr, "rtype:__", type(rtype), rtype, "ttl:__",type(ttl), ttl, "rdata:__", type(rdata), rdata)
            #newRR = RR(domain, rtype, cname, ttl)
            dest.add_answer(rr)


    def handlecname(self, cname, data, clientaddr,pre_response):
        signaltop = False
        root_server = [
            '198.41.0.4',#A.root
            '192.228.79.201',#B.root
            '192.33.4.12',#C.root
            '128.8.10.90',#D.root
            '192.203.230.10',#E.root
            '192.5.5.241',#F.root
            '192.112.36.4',#G.root
            '128.63.2.53',#H.root
            '192.36.148.17',#I.root
            '192.58.128.30',#J.root
            '193.0.14.129',#K.root
            '198.32.64.12',#L.root
            '202.12.27.33',#M.root
        ]

        domain = ""
        a_dns = root_server[2]
        qname = cname
        list_qname = str(qname).split('.')
        list_qname.reverse()
        list_qname.remove('')
        #print(list_qname)
        for i in range(len(list_qname)):             
            list_qname[i] = list_qname[i] + "."
        
        #print(list_qname)
        server_passby = []
        for i in list_qname:
            server_passby.append(a_dns)
            domain = i + domain
            print("-----------------")
            print("domain in qery: ", domain)
            print("-----------------")
            request = DNSRecord.question(domain, qtype="NS")
            rr = request.send(a_dns)
            response = DNSRecord.parse(rr)
            print(response)
            for rr in response.auth:
                try:
                    tmp = rr.rdata.label
                except:
                    tmp = rr.rdata
                #print("rrlabel: _______", tmp)

                judge = str(tmp).count("ns1."+list_qname[-2])
                #print("ns1."+list_qname[-2])
                if judge:
                    #print("judged packet:_____________", response)
                    a_dns = rr.rdata.__str__()
                    for rr in response.ar:
                        if str(rr).count(a_dns):
                            a_dns = str(rr.rdata)
                    #print("A_DNS: ", a_dns)
                    #temp = DNSRecord.question(data.q.qname, qtype="A")
                    temp = DNSRecord.question(cname, qtype="A")
                    #print("CNAME: _______", cname)
                    rr = temp.send(a_dns)
                    response = DNSRecord.parse(rr)
                    response.header.id = data.header.id
                    signaltop = True
        
                    print(response)
                    response.add_answer()
                    #data.add_answer(response.a[0])
                    #pack_d = data.pack()
                    pack_r = response.pack()
                    #print(pack_r)
                    #self.sock.sendto(pack_d, clientaddr)
                    #self.update_cache(data.q.qname, data)

                    ans = DNSRecord.question(data.q.qname, qtype="A")
                    ans.header.id = data.header.id
                    ans.rr = response.rr
                    ans.auth = response.auth
                    ans.ar = response.ar
                    pre_domain = pre_response.q.qname
                    self.extract_add_RR(pre_response, ans)
                    pa = ans.pack()
                    self.sock.sendto(pa, clientaddr)
                    self.update_cache(data.q.qname, ans)

                    #self.sock.sendto(pack_r, clientaddr)
                    #self.update_cache(data.q.qname, response)
                    print("The servers pass-by during iterative query for cname: ")
                    for i in range(len(server_passby)):
                        print(server_passby[i])
                    break
            if signaltop:
                break
            if (len(response.auth) >= 1):
                a_dns = response.auth[0].rdata.__str__()#for the next dns server to do iterative query
                try:
                    server_passby.append(response.ar[0].rdata.__str__())
                except:
                    pass
            else:
                '''
                if (domain == qname):
                    a = DNSRecord.question(domain, qtype="A")
                    rr = a.send(a_dns)
                    response = DNSRecord.parse(rr)
                    a_dns = str(response.rr[0].rdata)


                if any(rr.rdata.label == QTYPE.SOA for rr in response.rr):
                    a_dns = rr.rdata.label
                    
                    temp = DNSRecord.question(data.q.qname, qtype="A")
                    rr = temp.send(a_dns)
                    response = DNSRecord.parse(rr)
                    print("SOA: ___________________")
                    print(response)
                    break
                else:
                    continue
                '''
                break
            #print(a_dns)
        '''
        changename = DNSRecord.question(data.q.qname, qtype="A")
        changename.add_answer(response.rr)
        changename.header.id = data.header.id
        pack_c = changename.pack()
        '''
        #print(response)
        response.header.id = data.header.id
        
        print(response)
        pack_r = response.pack()
        #print(pack_r)
        self.sock.sendto(pack_r, clientaddr)
        self.update_cache(data.q.qname, response)
        print("The servers pass-by during iterative query for cname: ")
        for i in range(len(server_passby)):
            print(server_passby[i])


    def ask_dns(self, data, clientaddr):
        root_server = [
            '198.41.0.4',#A.root
            '192.228.79.201',#B.root
            '192.33.4.12',#C.root
            '128.8.10.90',#D.root
            '192.203.230.10',#E.root
            '192.5.5.241',#F.root
            '192.112.36.4',#G.root
            '128.63.2.53',#H.root
            '192.36.148.17',#I.root
            '192.58.128.30',#J.root
            '193.0.14.129',#K.root
            '198.32.64.12',#L.root
            '202.12.27.33',#M.root
        ]

        domain = ""
        a_dns = root_server[2]
        qname = data.q.qname
        list_qname = str(qname).split('.')
        list_qname.reverse()
        list_qname.remove('')
        #print(list_qname)
        for i in range(len(list_qname)):             
            list_qname[i] = list_qname[i] + "."
        
        #print(list_qname)
        server_passby = []
        for i in list_qname:
            server_passby.append(a_dns)#name of server passby
            domain = i + domain
            print("-----------------")
            print("domain in qery: ", domain)
            print("-----------------")
            if (domain == qname):
                
                a = DNSRecord.question(domain, qtype="A")
                rr = a.send(a_dns)
                response = DNSRecord.parse(rr)
                for rr in response.rr:
                    if (rr.rtype == QTYPE.CNAME):
                        cname = str(rr.rdata.label)
                        #print("rr.rdata:________", rr.rdata)
                        #print("_____response.ar_____")
                        #print(response.rr)
                        self.handlecname(cname, data, clientaddr, response)
                        break
                #print("ask A:___", response)
                a_dns = str(response.rr[0].rdata)
                break

            request = DNSRecord.question(domain, qtype="NS")
            rr = request.send(a_dns)
            response = DNSRecord.parse(rr)
            print(response)
            if (len(response.auth) >= 1):
                a_dns = response.auth[0].rdata.__str__()#for the next dns server to do iterative query
                try:
                    server_passby.append(response.ar[0].rdata.__str__())#ip of the server passby
                except:
                    pass
            else:
                if (domain == qname):
                    #if (response.get_a is None):
                        for rr in response.rr:
                            if (rr.rtype == QTYPE.CNAME):
                                cname = str(rr.rdata.label)
                                self.handlecname(cname, data, clientaddr, response)
                                break
                    

                        
                        a = DNSRecord.question(domain, qtype="A")
                        rr = a.send(a_dns)
                        response = DNSRecord.parse(rr)
                        #print("ask A:___", response)
                        a_dns = str(response.rr[0].rdata)
                        break
                else:
                    continue
                break
            #print(a_dns)

        print(response)
        response.header.id = data.header.id
        
        #print(response)
        pack_r = response.pack()
        #print(pack_r)
        self.sock.sendto(pack_r, clientaddr)
        self.update_cache(qname, response)
        print("The servers pass-by during iterative query: ")
        for i in range(len(server_passby)):
            print(server_passby[i])
            




        

def main():
    #print(1)
    dns = dnserver()
    #print(0)
    print("Local DNS server starts: ")
    dns.listen_q()


""" if __name__ == "__main__ ":
    main() """

main()
    