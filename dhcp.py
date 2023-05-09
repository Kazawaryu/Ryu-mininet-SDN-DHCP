from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp


class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99'  # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8'  # don't modify, just for the dns entry
    start_ip = '192.168.1.2'  # can be modified
    end_ip = '192.168.1.100'  # can be modified
    netmask = '255.255.255.0'  # can be modified

    # need more params here

    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer():
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        # TODO: Generate DHCP ACK packet here

        return ack_pkt

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        # TODO: Generate DHCP OFFER packet here
        # get a valid dhcp address from pool (need a simple algorithm)

        return offer_pkt

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        # TODO: Specify the type of received DHCP packet
        # You may choose a valid IP from IP pool and generate DHCP OFFER packet
        # Or generate a DHCP ACK packet
        # Finally send the generated packet to the host by using _send_packet method
        pkt_dhcp = pkt.get_protocols(dhcp.dhcp)[0]
        dhcp_state = cls.get_state(pkt_dhcp)
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
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
