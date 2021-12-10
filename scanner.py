import socket
import struct
import random
import time
import select
import sys
import binascii
import netifaces
import os


ICMP_ECHO_REPLY_TYPE = 0
ICMP_DESTINATION_UNREACHABLE_TYPE = 3
ICMP_SOURCE_QUENCH_TYPE = 4
ICMP_REDIRECT_MESSAGE_TYPE = 5
ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ROUTER_ADVERTISEMENT_TYPE = 9
ICMP_ROUTER_SOLICITATION_TYPE=10
ICMP_TIME_EXCEEDED_TYPE = 11
ICMP_PARAMETER_PROBLEM_TYPE = 12


# resolving the ip address of current device which is conntected to internet, since devices can contain multiple ip 
def get_internet_connected_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address


# get the ip of device refering to itself
def get_local_ip():
    localaddres = socket.gethostbyname(socket.gethostname())
    return localaddres


# returning the network address of an ip given its mask
def get_net_ip(ip:str, netmask:str):
    ip_parts = ip.split('.')
    mask_parts = netmask.split('.')
    parts = []
    for i in range(0,4):
        parts.append(str(int(ip_parts[i]) & int(mask_parts[i])))
    return ".".join(parts)


# this method return what ip of our device should be used for connectecing to dest_ip
def get_src_ip_connected_to_dest_ip(dest_ip):
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        res = netifaces.ifaddresses(interface)
        try:
            ip = res[2][0]["addr"]
            netmask = res[2][0]["netmask"]
            src_network = get_net_ip(ip,netmask)
            dest_network = get_net_ip(dest_ip,netmask)
            if src_network == net_ip:
                return ip
        except:
            pass
    return get_internet_connected_ip()



def checksum(source_string):
    # I'm not too confident that this is right but testing seems to
    # suggest that it gives the same answers as in_cksum in ping.c.
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff  # Necessary?
        count = count + 2
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff  # Necessary?
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


#  ping functions
def create_echo_request_packet(id):
    """Create a new echo request packet based on the given "id"."""
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST_TYPE, 0, 0, id, 1)
    data = 192 * 'Q'
    data_bytes = bytearray(data,'ascii')
    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data_bytes)
    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST_TYPE, 0,
                         socket.htons(my_checksum), id, 1)
    return header + data_bytes


def receive_ping(my_socket, packet_id, time_sent, timeout):
    # Receive the ping from the socket.
    time_left = timeout
    while True:
        ready = select.select([my_socket], [], [], time_left)
        if ready[0] == []:  # Timeout
            return
        time_received = time.time()
        rec_packet, addr = my_socket.recvfrom(1024)
        ip_header = rec_packet[0:20]
        icmp_header = rec_packet[20:28]
        # the ! in the pack format string means network order
        # H:    C Type : unsigned short 	Python type :integer 	Standard size:2
        # h:    C Type : short 	            Python type :integer 	Standard size:2
        # L:    C Type : unsigned long 	    Python type :integer 	Standard size:4
        # l:    C Type : long 	            Python type :integer 	Standard size:4
        # B:    C Type : unsigned char   	Python type :integer 	Standard size:1
        # s: 	C Type : char[] 	        Python type :bytes
        type, code, checksum, p_id, sequence = struct.unpack(
            'bbHHh', icmp_header)

        if p_id == packet_id:
            return time_received - time_sent

        time_left -= time_received - time_sent
        if time_left <= 0:
            return


def do_one_ping(dest_ip, timeout=5):
    """
        Sends one ping to the given "dest_addr" which can be an ip or hostname.
        "timeout" can be any integer or float except negatives and zero.
        Returns either the delay (in seconds) or None on timeout and an invalid
        address, respectively.
        """
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as e:
        print('Exception in creating socket for icmp scan while scanning '+ dest_ip + ", error : " + str(e) )
        raise  # raise the original error

    # Maximum for an unsigned short int c object counts to 65535 so
    # we have to sure that our packet id is not greater than that.
    packet_id = int((id(timeout) * random.random()) % 65535)
    packet = create_echo_request_packet(packet_id)
    while packet:
        # The icmp protocol does not use a port, but the function
        # below expects it, so we just give it a dummy port.
        sent = my_socket.sendto(packet, (dest_ip, 1))
        packet = packet[sent:]
    delay = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    if delay != None:
        print('response for icmp scan of ' + dest_ip + ' was recieved with delay ' + str(delay) )
    else:
        print('response for icmp scan of ' + dest_ip + '  was None' )
    return delay


# ip layer functions
def create_ipv4_header(source_ip,dest_ip,ip_proto,ip_id):
    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = ip_id
    ip_frag_off = 0
    ip_ttl = 255
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(source_ip)  # Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
                     ip_saddr, ip_daddr)
    return ip_header


# udp functions
def create_udp_header(user_data_bytes,source_ip,dest_ip,src_port,dest_port):
    # there is no option so header size is 8 bytes
    udp_length = 8 + len(user_data_bytes)
    udp_chksum = 0
    udp_header = struct.pack('!HHHH', src_port, dest_port, udp_chksum, udp_length)

    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_UDP
    psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, udp_length)
    psh = psh + udp_header + user_data_bytes
    udp_chksum = checksum(psh)

    udp_header = struct.pack('!HHHH', src_port, dest_port, udp_chksum, udp_length)
    return udp_header


def send_raw_udp_packet(raw_socket,src_ip,dest_ip,src_port,dest_port,user_data_bytes):
    ip_header = create_ipv4_header(src_ip,dest_ip,socket.IPPROTO_UDP,1234)
    udp_header = create_udp_header(user_data_bytes,src_ip,dest_ip,src_port,dest_port)

    packet = ip_header + udp_header + user_data_bytes
    raw_socket.sendto(packet, (dest_ip, 0))


# tcp functions
def create_tcp_header(user_data_bytes,source_ip,dest_ip,src_port,dest_port,tcp_seq,tcp_ack_seq,tcp_fin,tcp_syn,tcp_rst,tcp_psh,tcp_ack,tcp_urg,tcp_urg_ptr,tcp_options_bytes):

    options_len = int(len(tcp_options_bytes) / 4)
    tcp_doff = 5 + options_len  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
    tcp_window = socket.htons(5840)  # maximum allowed window size
    # tcp_window = 1024
    tcp_checksum = 0
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    tcp_header = struct.pack('!HHLLBBHHH', src_port, dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window,tcp_checksum, tcp_urg_ptr)
    tcp_header = tcp_header + tcp_options_bytes

    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data_bytes)

    psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header + user_data_bytes
    tcp_checksum = checksum(psh)

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    # tcp_header = struct.pack('!HHLLBBH', src_port, dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
    #                   tcp_window) + struct.pack(
    #     'H', tcp_checksum) + struct.pack('!H', tcp_urg_ptr) + struct()

    tcp_header = struct.pack('!HHLLBBHHH', src_port, dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                             tcp_window,
                             tcp_checksum, tcp_urg_ptr)
    tcp_header = tcp_header + tcp_options_bytes
    return tcp_header


def send_raw_tcp_packet(raw_socket,user_data_bytes,packet_id,src_ip,dest_ip,src_port,dest_port,tcp_seq,tcp_ack_seq,tcp_fin,tcp_syn,tcp_rst,tcp_psh,tcp_ack,tcp_urg,tcp_urg_ptr,tcp_options_bytes):

    ip_header = create_ipv4_header(src_ip,dest_ip,socket.IPPROTO_TCP,packet_id)
    tcp_header = create_tcp_header(user_data_bytes,src_ip,dest_ip,src_port,dest_port,tcp_seq,tcp_ack_seq,tcp_fin,tcp_syn,tcp_rst,tcp_psh,tcp_ack,tcp_urg,tcp_urg_ptr,tcp_options_bytes)

    if user_data_bytes.__len__() > 0:
        packet = ip_header + tcp_header + user_data_bytes
    else:
        packet = ip_header + tcp_header

    raw_socket.sendto(packet, (dest_ip, 0))


def convert_flags_bit_to_string_list(flags: int):
    flags_bits_str = "{0:b}".format(flags)
    while len(flags_bits_str) < 6:
        flags_bits_str = "0" + flags_bits_str
    res = []
    if flags_bits_str[-1] == "1":
        res.append("FIN")
    if flags_bits_str[-2] == "1":
        res.append("SYN")
    if flags_bits_str[-3] == "1":
        res.append("RST")
    if flags_bits_str[-4] == "1":
        res.append("PSH")
    if flags_bits_str[-5] == "1":
        res.append("ACK")
    if flags_bits_str[-6] == "1":
        res.append("URG")
    return res


# This function waits for the response of target on the given socket, and if there is a response
# in the time window it will return it
def receive_tcp_response(my_socket, request_src_port, request_sequence, time_sent, timeout):
    time_left = timeout
    while True:
        ready = select.select([my_socket], [], [], time_left)
        if not ready[0]:  # Timeout
            return None
        time_received = time.time()
        rec_packet, addr = my_socket.recvfrom(1024)
        tcp_header = rec_packet[20:40]

        # the ! in the pack format string means network order
        # H:    C Type : unsigned short 	Python type :integer 	Standard size:2
        # h:    C Type : short 	            Python type :integer 	Standard size:2
        # L:    C Type : unsigned long 	    Python type :integer 	Standard size:4
        # l:    C Type : long 	            Python type :integer 	Standard size:4
        # B:    C Type : unsigned char   	Python type :integer 	Standard size:1
        # s: 	C Type : char[] 	        Python type :bytes

        r = struct.unpack('!HHLL BBHHH ', tcp_header)
        response_src_port = r[0]
        response_dest_port = r[1]
        response_sequence_number = r[2]
        response_ack_number = r[3]
        response_dataOffset_reserved = r[4]
        response_dataOffset = response_dataOffset_reserved >> 4
        response_reserved_flags = r[5]
        response_window = r[6]
        response_checksum_val = hex(r[7])
        response_urg_ptr = r[8]

        if response_dest_port == request_src_port and request_sequence + 1 == response_ack_number:
            result = {
                "src_port": response_src_port,
                "dest_port": response_dest_port,
                "sequence_number": response_sequence_number,
                "ack_number": response_ack_number,
                "data_offset": response_dataOffset,
                "flags": convert_flags_bit_to_string_list(response_reserved_flags),
                "window": response_window,
                "checksum": response_checksum_val,
                "urgent_pointer": response_urg_ptr
            }
            return result

        time_left -= time_received - time_sent
        if time_left <= 0:
            return None


def do_tcp_syn_scan(dest_ip: str, dest_port: int, timeout=3, data=''):
    # Creating our raw socket
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except Exception as e:
        print('Exception in initializing socket for TCP SYN scanning for ' + dest_ip + ':'+str(dest_port)+ " , error : " + str(e) )
        raise

    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    raw_socket.settimeout(timeout)

    src_ip = get_src_ip_connected_to_dest_ip(dest_ip)
    src_port = random.randint(2048, 65535)

    # mtu size
    options_bytes = binascii.a2b_hex("020405b4")
    # data
    data_bytes = bytearray(data, 'ascii')

    # send a tcp packet to start a connection with setting the SYN flag to 1
    sequence_number = 0
    send_raw_tcp_packet(raw_socket, data_bytes, 0, src_ip, dest_ip, src_port, dest_port, sequence_number, 0, 0, 1, 0, 0, 0, 0, 0, options_bytes)
    tcp_header_info = receive_tcp_response(raw_socket, src_port, sequence_number, time.time(), timeout)

    if tcp_header_info is None:
        status = "CLOSED_OR_FILTERED"
    else:
        flags = tcp_header_info["flags"]
        if "RST" in flags or "FIN" in flags:
            status = "CLOSED"
        else:
            status = "OPEN"
    raw_socket.close()
    return {"response tcp header": tcp_header_info, "status": status}


def do_tcp_connection_scan(dest_ip: str, dest_port: int, timeout=300, data=''):
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except Exception as e:
        print('Exception in initializing socket for TCP SYN scanning for ' + dest_ip + ':' + str(
            dest_port) + " , error : " + str(e))
        raise

    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    raw_socket.settimeout(timeout)

    src_ip = get_src_ip_connected_to_dest_ip(dest_ip)
    src_port = random.randint(2048, 65535)

    # mtu size
    options_bytes = binascii.a2b_hex("020405b4")
    # data
    data_bytes = bytearray(data, 'ascii')

    ip_tables_command_add_drop_rule = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -s " + src_ip + " -d " + dest_ip +" --dport " + str(dest_port) + " -j DROP"
    ip_tables_command_remove_drop_rule = "iptables -D OUTPUT -p tcp --tcp-flags RST RST -s " + src_ip + " -d " + dest_ip + " --dport " + str(dest_port) + " -j DROP"

    os.system(ip_tables_command_add_drop_rule)

    # send a tcp packet to start a connection with setting the SYN flag to 1
    sequence_number = 0
    send_raw_tcp_packet(raw_socket, data_bytes, 0, src_ip, dest_ip, src_port, dest_port, sequence_number, 0, 0, 1, 0, 0, 0, 0, 0, options_bytes)

    response_tcp_header_info = receive_tcp_response(raw_socket, src_port, sequence_number, time.time(), timeout)
    if response_tcp_header_info is None:
        raw_socket.close()
        os.system(ip_tables_command_remove_drop_rule)
        return {"response tcp header": None, "status": "CLOSED_OR_FILTERED"}

    response_flags = response_tcp_header_info["flags"]
    response_sequence_number = response_tcp_header_info["sequence_number"]
    if "RST" in response_flags or "FIN" in response_flags:
        status = "CLOSED"
    elif "SYN" in response_flags and "ACK" in response_flags:
        status = "OPEN"
    else:
        status = "INVALID FLAGS"

    sequence_number = sequence_number + 1
    ack_sequence_number = response_sequence_number + 1


    send_raw_tcp_packet(raw_socket, data_bytes, 0, src_ip, dest_ip, src_port, dest_port, sequence_number, ack_sequence_number, 0, 0, 0, 0, 1, 0, 0, options_bytes)

    send_raw_tcp_packet(raw_socket, data_bytes, 0, src_ip, dest_ip, src_port, dest_port, sequence_number, ack_sequence_number, 0, 0, 1, 0, 1, 0, 0, options_bytes)
    raw_socket.close()
    os.system(ip_tables_command_remove_drop_rule)
    return {"response tcp header": response_tcp_header_info, "status": status}



###
# This implementation uses the normal socket, but I replaced it with using a raw socket so that
# the same information possible can be logged from every scan
###
def do_tcp_connection_scan_no_raw_socket(dest_ip: str, dest_port: int, close_connection_with_RST_flag=True, timeout=5):
    # Creating our socket
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if close_connection_with_RST_flag:
            # this is done to send a RST flag as soon as the response is received
            # this prevents the connection to close with normally with a FIN handshake
            # https://stackoverflow.com/questions/6439790/sending-a-reset-in-tcp-ip-socket-connection
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        conn.settimeout(timeout)
    except Exception as e:
        print('Exception in initializing socket for TCP connection scanning for ' + dest_ip + ':' + str(dest_port) + " , error : " + str(e))
        raise

    # Connecting to the destination
    try:
        ret = conn.connect_ex((dest_ip, dest_port))

        # DATA RECIEVED - SYN ACK
        if ret == 0:
            print('TCP_CONNECTION_SCAN : SYN_ACK from ' + dest_ip + ':' + str(dest_port))
            conn.close()
            status = "OPEN"

        # RST RECIEVED - PORT CLOSED
        elif ret == 111:
            print('TCP_CONNECTION_SCAN : RST flag from ' + dest_ip + ':' + str(dest_port))
            conn.close()
            status = "CLOSED"

        # ERR CODE 11 - TIMEOUT
        elif ret == 11:
            print('TCP_CONNECTION_SCAN : Time out from ' + dest_ip + ':' + str(dest_port))
            conn.close()
            status = "CLOSED_OR_FILTERED"

        # Other errors
        else:
            print('TCP_CONNECTION_SCAN : Error returned from host ' + dest_ip + ':' + str(dest_port) + ",Error code is :" + str(ret))
            conn.close()
            status = "DONT_KNOW"

        return {"return code": ret, "status": status}
    except socket.timeout as e:
        print('TCP_CONNECTION_SCAN : time out from ' + dest_ip + ':' + str(dest_port) +" with Eception : " + str(e))
        conn.close()
        return {"return code": None, "status": "TIMEOUT_CLOSED_OR_FILTERED"}


def do_udp_scan_no_raw_socket(dest_ip: str, dest_port: int, payload=None, timeout=1):
    default_UDP_payload = {
        "dns"	: b"\x24\x1a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
        "snmp"		: b"\x30\x2c\x02\x01\x00\x04\x07\x70\x75\x62\x6c\x69\x63\xA0\x1E\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x13\x30\x11\x06\x0D\x2B\x06\x01\x04\x01\x94\x78\x01\x02\x07\x03\x02\x00\x05\x00",
        "ntp"		: b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3"
    }

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.settimeout(timeout)
    except :
        raise print('Exception in initializing socket for UDP connection scanning for ' + dest_ip + ':' + str(dest_port) + " , error : " + str(e))

    try:
        if payload:
            conn.sendto(bytearray(payload,'ascii'), (dest_ip, dest_port))
        else:
            if dest_port == 123:
                conn.sendto(default_UDP_payload["ntp"], (dest_ip, dest_port))
            elif dest_port == 53:
                conn.sendto(default_UDP_payload["dns"], (dest_ip, dest_port))
            elif dest_port == 161:
                conn.sendto(default_UDP_payload["snmp"], (dest_ip, dest_port))
            else:
                conn.sendto(default_UDP_payload["scanner_payload"], (dest_ip, dest_port))

        d = conn.recv(1024)
        if len(d) > 0:
            conn.close()
            return {"return payload": d, "status": "OPEN"}

        conn.close()
        return {"return payload": None, "status": "CLOSED_OR_FILETERED"}
    except socket.timeout:
        conn.close()
        return {"return payload": None, "status": "TIMEOUT_CLOSED_OR_FILETERED"}