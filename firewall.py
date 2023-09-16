import socket 
import struct

def main():
    #Create a socket to capture network traffic 
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    #DEfine a list of allowed IP addressed
    allowed_ips = ["192.168.1.100", "192.168.1.101"]
    
    while True:
        raw_data, _ = s.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        
        #Filter only IPv4 packets
        if eth_proto == 8:
            version, header_length, ttl, proto,src, target, data = ipv4_packet(data)
            
            #Filter packets based on source IP
            
            src_ip = socket.inet_ntoa(src)
            if src_ip in allowed_ips:
                print(f"Allowed packet from {src_ip}")
            
            else:
                print(f"Blocked packet from {src_ip}")
                
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto),data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, src, target, data[header_length:]

if __name__ == '__main__':
    main()