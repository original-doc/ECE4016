import socket
from dnslib import *

class dnserver:
    def __init__(self):
        self.ip = "127.0.0.1"
        self.port = 1234
        self.cache = {}
        self.flag = 0
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
                if self.flag == 1:
                    self.ask_pulicdns(data, clientaddr)
                elif self.flag == 0:
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

    def handlecname(self, cname, data, clientaddr):
        root_server = [
            '198.41.0.4'#A.root
        ]

        domain = ""
        a_dns = root_server[0]
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
            #print(domain)
            request = DNSRecord.question(domain, qtype="NS")
            rr = request.send(a_dns)
            response = DNSRecord.parse(rr)
            print(response)
            if (len(response.auth) >= 1):
                a_dns = response.auth[0].rdata.__str__()#for the next dns server to do iterative query
            else:
                if (domain == qname):
                    a = DNSRecord.question(domain, qtype="A")
                    rr = a.send(a_dns)
                    response = DNSRecord.parse(rr)
                    a_dns = str(response.rr[0].rdata)

                else:
                    continue
                break
            #print(a_dns)
        changename = DNSRecord.question(data.q.qname, qtype="A")
        changename.add_answer(response.rr[0])
        changename.header.id = data.header.id
        pack_c = changename.pack()
        #print(response)
        #response.header.id = data.header.id
        
        #print(response)
        #pack_r = response.pack()
        #print(pack_r)
        self.sock.sendto(pack_c, clientaddr)
        self.update_cache(data.q.qname, changename)
        print("The servers pass-by during iterative query for cname: ")
        for i in range(len(server_passby)):
            print(server_passby[i])


    def ask_dns(self, data, clientaddr):
        root_server = [
            '198.41.0.4'#A.root
        ]

        domain = ""
        a_dns = root_server[0]
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
            server_passby.append(a_dns)
            domain = i + domain
            #print(domain)
            request = DNSRecord.question(domain, qtype="NS")
            rr = request.send(a_dns)
            response = DNSRecord.parse(rr)
            #print(response)
            if (len(response.auth) >= 1):
                a_dns = response.auth[0].rdata.__str__()#for the next dns server to do iterative query
            else:
                if (domain == qname):
                    #if (response.get_a is None):
                        for rr in response.rr:
                            if (rr.rtype == QTYPE.CNAME):
                                cname = rr.rdata.label
                                self.handlecname(cname, data, clientaddr)
                                break
                    

                        else:
                            a = DNSRecord.question(domain, qtype="A")
                            rr = a.send(a_dns)
                            response = DNSRecord.parse(rr)
                            a_dns = str(response.rr[0].rdata)
                            break
                else:
                    continue
                break
            #print(a_dns)

        #print(response)
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
    print(1)
    dns = dnserver()
    print(0)
    dns.listen_q()


""" if __name__ == "__main__ ":
    main() """

main()
    
