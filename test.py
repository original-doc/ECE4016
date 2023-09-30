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
            #self.ask_pulicdns(data, clientaddr)
            self.ask_dns(data, clientaddr)
            #self.sock.sendto(query, clientaddr)
    
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

        test = data.send(a_dns)
        ans = DNSRecord.parse(test)
        print(ans)
        self.sock.sendto(test, clientaddr)

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
        print(list_qname)
        for i in range(len(list_qname)):             
            list_qname[i] = list_qname[i] + "."
        
        print(list_qname)
        for i in list_qname:
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
                    a_dns = str(response.rr[0].rdata)
                else:
                    continue
                break
            print(a_dns)

        print(response)
        response.header.id = data.header.id
        
        print(response)
        pack_r = response.pack()
        print(pack_r)
        self.sock.sendto(pack_r, clientaddr)

        #root_dns
        #TLD_dns
        #Auth_dns


        

def main():
    print(1)
    dns = dnserver()
    print(0)
    dns.listen_q()


""" if __name__ == "__main__ ":
    main() """

main()
    
