import socket
from dnslib import *

'''
def send2dns(q_data, dest,port=53,tcp=False,timeout=None,ipv6=False):#changed from dnslib.DNSRecord.send()
        """
            Send packet to nameserver and return response
        """
        data = q_data.pack()
        if ipv6:
            inet = socket.AF_INET6
        else:
            inet = socket.AF_INET
        try:
            sock = None
            if tcp:
                if len(data) > 65535:
                     raise ValueError("Packet length too long: %d" % len(data))
                data = struct.pack("!H",len(data)) + data
                sock = socket.socket(inet,socket.SOCK_STREAM)
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.connect((dest,port))
                sock.sendall(data)
                response = sock.recv(8192)
                length = struct.unpack("!H",bytes(response[:2]))[0]
                while len(response) - 2 < length:
                    response += sock.recv(8192)
                response = response[2:]
            else:
                sock = socket.socket(inet,socket.SOCK_DGRAM)
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.sendto(q_data.pack(),(dest,port))
                response,server = sock.recvfrom(8192)
        finally:
            if (sock is not None):
                sock.close()

        return response,server
'''
class DNSserver:
    def __init__(self, ip = '127.0.0.1', port = 1234):
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.ip, self.port))
        self.sock.listen()
        self.cache = {}
        self.flag = 1

    def listen_query(self):
        while True:
            data, cilent_addr = self.sock.recvfrom(8192)
            q_data = DNSRecord.parse(data)
            q_data.header.set_rd(0)
            data = DNSRecord.pack(q_data)

            if q_data.q.qname in self.cache:
                ans = self.cache[q_data.q.qname]
                self.send_query(ans, cilent_addr)
            else:
                response = self.update_cache(q_data)
                self.send_query(response, cilent_addr)
            

    def send_query(self, data, addr):
        self.sock.sendto(data, addr)

    
    def update_cache(self, q_data):
        qname = q_data.q.qname
        list_qname = qname.split('.')
        list_qname.reverse()
        for i in range(len(list_qname)):
            list_qname[i] = list_qname[i] + "."
        if (self.flag == 1):
            response = self.ask_dns(self, list_qname, q_data)
        else:
            response = self.ask_publiccdns(self, q_data)
        
        self.cache[q_data.q.qname] = response.pack

        return response
        
    def ask_dns(self, list_qname, q_data, ):
        root_DNS_servers=[
        ["A.root-servers.net",'198.41.0.4'],
        ["B.root-servers.net",'192.228.79.201'],
        ["C.root-servers.net",'192.33.4.12'],
        ["D.root-servers.net",'128.8.10.90'],
        ["E.root-servers.net",'192.203.230.10'],
        ["F.root-servers.net",'192.5.5.241'],
        ["G.root-servers.net",'192.112.36.4'],
        ["H.root-servers.net",'128.63.2.53'],
        ["I.root-servers.net",'192.36.148.17'],
        ["J.root-servers.net",'192.58.128.30'],
        ["K.root-servers.net",'193.0.14.129'],
        ["L.root-servers.net",'198.32.64.12'],
        ["M.root-servers.net",'202.12.27.33'],
        ]   

        domain = ""
        a_dns = "A.root-servers.net"
        response = None
        for i in list_qname:
            domain = i + domain
            request = DNSRecord.question(domain, qtype="NS")
            rr = request.send(request,a_dns)
            response = DNSRecord.parse(rr)
            a_dns.auth[0].rdata.__str__()#for the next dns server to do iterative query
        domain = str(response.rr[0].rdata)
        r = DNSRecord.question(domain, qtype="A")
        rr = r.send(a_dns)
        response1 = DNSRecord.parse(rr)

        list_response = response1.rr
        for i in list_response:
            response.rr.append(i)

        response.header.id = q_data.header.id
        response.header.ra = 1
        response.q.qtype = 1 #typeA

        response.auth = []
        response.ar = []

        return response

    def ask_publiccdns(self, q_data):
        public_dns = [
            "119.29.29.29",#tencent
            "8.8.8.8",#google
            "223.5.5.5",#aliyun
            "180.76.76.76",#baidu
        ]

        a_dns = public_dns[0]
        qname = q_data.q.qname
        r = DNSRecord.question(qname, qtype="A")
        rr = r.send(a_dns)
        response1 = DNSRecord.parse(rr)

        return response1
    
if __name__ == "__main__":
    dns = DNSserver()
    dns.listen_query()
        

    




