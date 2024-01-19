import socket
import struct
import threading
import time
import netifaces


LIMIT_S = 500
LIMIT = 500
local_ip = None
mac_address = None

class IPAddressInfo:
    def __init__(self, ip):
        self.ip = ip
        self.count = 0
        self.notification_sent = False
        self.start_time = time.time()

    def increment_count(self):
        self.count += 1

    def reset_count(self):
        self.count = 0
        self.notification_sent = False
        self.start_time = time.time()

    def time_elapsed(self):
        return time.time() - self.start_time

http_requests = {} # Dicionário para armazenar a contagem de solicitações HTTP por IP
syn_counters = {} # Dicionário para armazenar os contadores de pacotes SYN por IP

lock = threading.Lock()# Bloqueio para gerenciar o acesso ao dicionário de contadores

# Dicionário para armazenar as contagens de outros tipos de pacotes
packet_counts = {
    "ARP Request": 0,
    "ARP Reply": 0,
    "IPv4": 0,
    "ICMP": 0,
    "IPv6": 0,
    "TCP": 0,
    "UDP": 0
}

def process_ipv4(data):
    packet_counts["IPv4"] += 1
    (data, src, target, proto) = ipv4_packet(data)
    print("IPv4 -> IP:", src)  # Print the source IP address
    if proto == 1:
        packet_counts["ICMP"] += 1
        print("    ICMP (IPv4):")
    elif proto == 6:
        packet_counts["TCP"] += 1
        print("    TCP (IPv4):")
        if local_ip == target:
            tcp_data = tcp_segment(data)
            if tcp_data:
                src_port, dest_port, flags = tcp_data
                if flags & 0x02:  # Verifica a flag SYN
                    process_syn_packet(src)
            handle_packet(data, src)
    elif proto == 17:
        packet_counts["UDP"] += 1
        print("    UDP (IPv4):")
        #udp_datagram(data)


def process_arp(data):
    hardware_type, protocol_type, hardware_size, protocol_size, opcode, data = arp_packet(data)
    if opcode == 1:
        packet_counts["ARP Request"] += 1
        print("ARP Request -> MAC:", get_mac_addr(data[8:14]), "IP:", socket.inet_ntoa(data[14:18]))
    elif opcode == 2:
        packet_counts["ARP Reply"] += 1
        print("ARP Reply -> MAC:", get_mac_addr(data[8:14]), "IP:", socket.inet_ntoa(data[14:18]))

def process_ipv6(data):
    packet_counts["IPv6"] += 1
    (data, src, target, next_header) = ipv6_packet(data)
    print("IPv6 -> IP:", src)  # Print the source IP address
    if next_header == 6:
        packet_counts["TCP (IPv6)"] += 1
        if local_ip == target:
            tcp_data = tcp_segment(data)
            print("    TCP (IPv6):")
            if tcp_data:
                src_port, dest_port, flags = tcp_data
                if flags & 0x02:  # Verifica a flag SYN
                    process_syn_packet(src)
            handle_packet(data, src)
    elif next_header == 17:
        packet_counts["UDP (IPv6)"] += 1
        #udp_datagram(data)
        print("    UDP (IPv6):")

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    _, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    # Convertendo os endereços IP de bytes para strings legíveis
    src_ip = socket.inet_ntoa(src)
    target_ip = socket.inet_ntoa(target)

    return data[header_length:], src_ip, target_ip, proto
            
def arp_packet(data):
    hardware_type, protocol_type, hardware_size, protocol_size, opcode = struct.unpack('! H H B B H', data[:8])
    return hardware_type, protocol_type, hardware_size, protocol_size, opcode, data[8:]

def tcp_segment(data):
    try:
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flags = offset_reserved_flags & 0x01FF
        return src_port, dest_port, flags
    except struct.error:
        return None

def udp_datagram(data):
    if len(data) > 8:
        src_port, dest_port, size = struct.unpack('! H H 2x', data[:8])
    else:
        print("Data is too short to unpack")
    #return data[8:]  # Return data after UDP header
    return None

def ipv6_packet(data):
    # Desempacotando o cabeçalho do IPv6
    # Estrutura: 4 bytes para version/traffic class/flow label, 2 bytes para payload length,
    # 1 byte para next header, 1 byte para hop limit, 16 bytes para endereço de origem (src),
    # e 16 bytes para endereço de destino (target).
    version_traffic_class_flow_label, payload_length, next_header, hop_limit, src, target = struct.unpack('! 4s H B B 16s 16s', data[:40])
    # Convertendo os endereços de bytes para strings legíveis
    src_addr = socket.inet_ntop(socket.AF_INET6, src)
    target_addr = socket.inet_ntop(socket.AF_INET6, target)
    # Retorna os dados após o cabeçalho IPv6
    return data[40:], src_addr, target_addr, next_header


# Control variable to track if notification has been sent within the last ten seconds
notification_sent = False

def process_syn_packet(src):
    with lock:
        if src not in syn_counters:
            syn_counters[src] = IPAddressInfo(src)
            # Inicie um timer para zerar a contagem após 10 segundos
            threading.Timer(10, syn_counters[src].reset_count).start()
        syn_counters[src].increment_count()
        # Se o número de pacotes SYN de um IP for maior que um certo limite em 10 segundos, imprima uma mensagem
        if syn_counters[src].count > LIMIT_S and not syn_counters[src].notification_sent:
            print("****************************************************")
            print(f'ALERTA: Possível ataque SYN Flood detectado de {src} ')
            print("****************************************************")
            syn_counters[src].notification_sent = True
            
def handle_packet(packet, src_ip):
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20]) # Desempacote o cabeçalho IP (os primeiros 20 bytes)
    ip_header_length = (ip_header[0] & 0x0F) * 4 # O tamanho do cabeçalho IP é determinado pelo byte IHL
    tcp_header = packet[ip_header_length:ip_header_length+20] # O cabeçalho TCP começa após o cabeçalho IP
    tcp_header = struct.unpack('!HHLLBBHHH', tcp_header) # Desempacote o cabeçalho TCP (os primeiros 20 bytes)
    source_port, dest_port = tcp_header[0], tcp_header[1] # As portas de origem e destino estão nas duas primeiras posições
    payload = packet[ip_header_length+20:] # A carga útil começa após o cabeçalho TCP
    if dest_port == 80 or dest_port == 443: # Verifique se a porta de destino é 80 (HTTP) ou 443 (HTTPS)
        # A primeira linha da carga útil deve conter o método HTTP
        if payload.startswith(b'GET') or payload.startswith(b'POST'):
            print('HTTP request')
            update_http_requests(src_ip)

def update_http_requests(ip):
    with lock:
        if ip not in http_requests:
            http_requests[ip] = IPAddressInfo(ip)
            # Inicie um timer para zerar a contagem após 10 segundos
            threading.Timer(10, http_requests[ip].reset_count).start()
        http_requests[ip].increment_count()
        # Se o número de solicitações HTTP de um IP for menor que 500 em 10 segundos, imprima uma mensagem
        if http_requests[ip].count > LIMIT and not http_requests[ip].notification_sent:
            print("****************************************************")
            print(f'ALERTA: Possível ataque DoS HTTP detectado de {ip} ')
            print("****************************************************")
            http_requests[ip].notification_sent = True

def reset_counter(ip_addr):
    with lock:
        syn_counters[ip_addr] = 0

def main():
    print("Iniciando o sniffer...")
    print("Pressione Ctrl+C para finalizar o sniffer.")

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))# Cria um socket raw
    # Obtém o nome da interface de rede padrão (ex: 'eth0', 'wlan0')
    gateways = netifaces.gateways()
    if netifaces.AF_INET in gateways['default']:
        default_interface = gateways['default'][netifaces.AF_INET][1]
        print(default_interface)
    else:
        default_interface = 'eth3' #se tiver problemas mude isso

    print(default_interface)
    conn.bind((default_interface, 0))# Associa o socket à interface de rede (por exemplo, 'eth0', 'wlan0')

    # Obtém o endereço de IP do Host
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print("IP do Host:", local_ip)
    # Obtém o endereço MAC da interface de rede
    addr = netifaces.ifaddresses(default_interface)
    mac_address = addr[netifaces.AF_LINK][0]['addr']
    print("MAC da interface de rede:", mac_address)

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:14])
            dest_mac = get_mac_addr(dest_mac)
            src_mac = get_mac_addr(src_mac)
            #eth_proto = socket.htons(eth_proto)
            data = raw_data[14:]
            print("MAC de destino:", dest_mac, "MAC de origem:", src_mac, "Protocolo:", eth_proto)
            #print("\nEthernet Frame: ")
            # Processamento de pacotes
            if eth_proto == 0x0800:  # IPv4
                #print("    IPv4:")
                process_ipv4(data)
            elif eth_proto == 0x0806:  # ARP
                #print("    ARP:")
                process_arp(data)
            elif eth_proto == 0x86DD:  # IPv6
                #print("    IPv6:")
                process_ipv6(data)

    except KeyboardInterrupt:
        print("\nEstatísticas de captura de pacotes:")
        for packet_type, count in packet_counts.items():
            print(f"{packet_type}: {count}")

if __name__ == "__main__":
    main()
