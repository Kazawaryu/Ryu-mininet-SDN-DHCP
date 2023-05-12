from ryu.base import app_manager
from ryu.lib import addrconv
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import udp
from ryu.ofproto import ofproto_v1_3

# RFC 2131
# DHCP packet format
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                            xid (4)                            |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |           secs (2)            |           flags (2)           |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          ciaddr  (4)                          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          yiaddr  (4)                          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          siaddr  (4)                          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          giaddr  (4)                          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                                                               |
#  |                          chaddr  (16)                         |
#  |                                                               |
#  |                                                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                                                               |
#  |                          sname   (64)                         |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                                                               |
#  |                          file    (128)                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                                                               |
#  |                          options (variable)                   |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99'  # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8'  # don't modify, just for the dns entry
    start_ip = '192.168.1.2'  # can be modified
    end_ip = '192.168.1.100'  # can be modified
    netmask = '255.255.255.0'  # can be modified

    # need more params here

    dhcp_server = '192.168.1.1'
    bin_netmask = addrconv.ipv4.text_to_bin(netmask)
    bin_dhcp_server = addrconv.ipv4.text_to_bin(dhcp_server)
    bin_dns = addrconv.ipv4.text_to_bin(dns)

    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer():
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    server_ip = Config.dhcp_server
    bin_netmask = Config.bin_netmask
    bin_server_ip = Config.bin_dhcp_server
    bin_dns_address = Config.bin_dns
    ip_pool = [1]*101
    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        # Generate DHCP ACK packet here
        # TODO: Fix yiaddr
        

        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol(ipv4.ipv4)
        req_udp = pkt.get_protocol(udp.udp)
        req = pkt.get_protocol(dhcp.dhcp)

        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 53))
        req.options.option_list.insert(0, dhcp.option(tag = 51, value = '8640'))
        req.options.option_list.insert(0, dhcp.option(tag = 53, value = bytes('05','ascii')))

        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(ethernet.ethernet(
            ethertype=req_eth.ethertype, dst = req_eth.src, src = cls.hardware_addr))
        ack_pkt.add_protocol(
            ipv4.ipv4(dst=req_ipv4.dst, src = cls.server_ip, proto=req_ipv4.proto))
        ack_pkt.add_protocol(
            udp.udp(src_port=67, dst_port=68))

        # might change yiaddr， it should be your client ip address
        ack_pkt.add_protocol(dhcp.dhcp(
            op=2, chaddr=req_eth.src,siaddr= cls.server_ip, boot_file= req.boot_file,
            yiaddr=cls.start_ip, xid=req.xid, options=req.options))

        print("Now get ack_pkt")
        return ack_pkt

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        # Generate DHCP OFFER packet here
        # TODO: get a valid dhcp address from pool (need a simple algorithm)
        ip_addr_offer = '192.168.1.'
        offered_addr = 0
        for idx in range(2,101):
            if cls.ip_pool[idx] == 1:
                offered_addr = idx
                cls.ip_pool[idx] = 0
                break
            if idx == 100:
                print("All ip pool are used")
        ip_addr_offer = ip_addr_offer + str(offered_addr)

        disc_eth = pkt.get_protocol(ethernet.ethernet)
        disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
        disc_udp = pkt.get_protocol(udp.udp)
        disc = pkt.get_protocol(dhcp.dhcp)
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 55))
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 53))
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 12))
        disc.options.option_list.insert(
            0, dhcp.option(tag = 1, value = cls.bin_netmask))
        disc.options.option_list.insert(
            0, dhcp.option(tag = 3, value = cls.bin_server_ip))
        disc.options.option_list.insert(
            0, dhcp.option(tag = 6, value = cls.bin_dns_address))
        disc.options.option_list.insert(
            0, dhcp.option(tag = 12, value = 'dhcp_host'))
        disc.options.option_list.insert(
            0, dhcp.option(tag = 53, value = bytes('02','ascii')))
        disc.options.option_list.insert(
            0, dhcp.option(tag = 54, value = cls.bin_server_ip))
        
        offer_pkt = packet.Packet()
        offer_pkt.add_protocol(ethernet.ethernet(
            ethertype=disc_eth.ethertype, dst=disc_eth.dst, src = cls.hardware_addr))
        offer_pkt.add_protocol(ipv4.ipv4(dst = disc_ipv4.dst, src = cls.server_ip, proto=disc_ipv4.proto))
        offer_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        offer_pkt.add_protocol(dhcp.dhcp(
            op=2, chaddr=disc_eth.src,siaddr=cls.server_ip,boot_file=disc.boot_file,
            yiaddr=ip_addr_offer, xid=disc.xid,options=disc.options))
        print(ip_addr_offer)
        print("Now get offer_pkt")
        return offer_pkt

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        # TODO: Specify the type of received DHCP packet
        # You may choose a valid IP from IP pool and generate DHCP OFFER packet
        # Or generate a DHCP ACK packet
        # Finally send the generated packet to the host by using _send_packet method
        pkt_dhcp = pkt.get_protocols(dhcp.dhcp)[0]
        dhcp_state = cls.get_state(pkt_dhcp)
        print(dhcp_state)
        if dhcp_state == 'DHCPDISCOVER':
            cls._send_packet(datapath, port, cls.assemble_offer(pkt, datapath))
        elif dhcp_state == 'DHCPREQUEST':
            cls._send_packet(datapath, port, cls.assemble_ack(pkt, datapath, port))
        else:
            return

    @classmethod
    def get_state(cls, pkt_dhcp):
        dhcp_state = ord([opt for opt in pkt_dhcp.options.option_list if opt.tag == 53][0].value)
        if dhcp_state == 1:
            state = 'DHCPDISCOVER'
        elif dhcp_state == 2:
            state = 'DHCPOFFER'
        elif dhcp_state == 3:
            state = 'DHCPREQUEST'
        elif dhcp_state == 5:
            state = 'DHCPACK'
        return state

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if isinstance(pkt, str):
            pkt = pkt.encode()
        # pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
