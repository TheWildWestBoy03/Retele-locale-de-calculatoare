#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

mac_table = {}

# this is the class representation of the bpdu packet, it contains every noted aspect from the ocw presentation/capture from wireshark, including some more for easier handling
class BPDU:
    def __init__(self, source_mac, destination_mac, DSAP, SSAP, control, flags, root_bridge_id, root_path_cost, bridge_id, port_id, message_age, max_age, hello_time, forward_delay):
        self.source_mac = source_mac
        self.destination_mac = destination_mac
        self.DSAP = DSAP
        self.SSAP = SSAP
        self.control = control
        self.root_bridge_id = root_bridge_id
        self.root_path_cost = root_path_cost
        self.own_bridge_id = bridge_id
        self.port_id = port_id
        self.flags = flags
        self.message_age = message_age
        self.max_age = max_age
        self.hello_time = hello_time
        self.forward_delay = forward_delay
            
# the class representation of the switch
class SwitchStructure:
    def __init__(self, priority, interfaces, source_mac):
        self.priority = priority
        self.interfaces = interfaces
        self.interface_dictionary = {}          # the structure containing the plain information from the configuration files
        self.interface_types = {}               # structure handling interface types
        self.interface_vlans = {}               # structure handling vlans
        self.port_states = {}                   # structure handling states(listening/blocking)
        self.root_port = 0                  
        self.source_mac = source_mac        
        self.bpdu = None                        # switch's bpdu
        
        # own_bridge_ID  is switches current status  
        self.own_bridge_ID = priority

        # root_bridge_ID is equal to own_bridge_ID in the first phase
        self.root_bridge_ID = self.own_bridge_ID

        # the cost to the root bridge is clearly 0 in the first phase
        self.root_path_cost = 0

    def add_interface(self, interface_name, interface_type):
        self.interface_dictionary[interface_name] = interface_type
    def set_switch_bpdu(self, bpdu):
        self.bpdu = bpdu

    def get_interface_type(self, interface_name):
        return self.interface_types[interface_name]

    def add_interface_type_association(self, interface_name, interface_type):
        self.interface_types[interface_name] = interface_type

    def add_interface_vlans(self, interface_name, interface_vlan):
        self.interface_vlans[interface_name] = interface_vlan

    def remove_interface(self, interface_name):
        self.interface_dictionary[interface_name] = ""

    def add_interface_state(self, interface_name, state):
        self.port_states[interface_name] = state
    
    def set_interface_state(self, interface_name, state):
        self.port_states[interface_name] = state

    def get_interface_state(self, interface_name):
        return self.port_states[interface_name]
    
    def retrieve_interface_type(self, interface_name):
        return self.interface_types[interface_name]

    def print_structure(self):
        print(self.priority)
        for key in self.interface_dictionary:
            print("{} {}".format(key, self.interface_dictionary[key]))

        return None
    
    def is_port_trunk(self, interface_name):
        return self.get_interface_type(interface_name) == "trunk"

    def stp_initialization(self):
        for i in self.interfaces:
            named_interface = get_interface_name(i)
            state = "blocking"
            if str(self.retrieve_interface_type(named_interface)).startswith("access"):
                state = "listening"
        
            self.add_interface_state(named_interface, state)
            print(get_interface_name(i))

        return None
    
    # function which handles received BPDUs
    def receive_BPDU(self, BPDU, interface):
        if self.root_bridge_ID > BPDU.root_bridge_id:
            self.root_bridge_ID = BPDU.root_bridge_id
            self.root_path_cost = BPDU.root_path_cost + 10
            self.root_port = interface

            for i in self.interfaces:
                if i != self.root_port and self.retrieve_interface_type(get_interface_name(i)) == "trunk":
                    self.set_interface_state(get_interface_name(i), "blocking")
                
            if self.get_interface_state(get_interface_name(self.root_port)) == "blocking":
                self.set_interface_state(get_interface_name(self.root_port), "listening")
                
            BPDU.own_bridge_id = self.own_bridge_ID
            BPDU.root_path_cost = self.root_path_cost

            data = self.convert_bpdu_to_bytes_data(BPDU)

            for i in self.interfaces:
                if self.is_port_trunk(get_interface_name(i)):
                    send_to_link(i, len(data), data)


        elif self.root_bridge_ID == BPDU.root_bridge_id:
            if interface == self.root_port:
                if BPDU.root_path_cost + 10 < self.root_path_cost:
                    self.root_path_cost = BPDU.root_path_cost + 10
            elif interface != self.root_port:
                if BPDU.root_path_cost > self.root_path_cost:
                    if self.get_interface_state(get_interface_name(interface)) != "listening":
                        self.set_interface_state(get_interface_name(interface), "listening")

        elif BPDU.own_bridge_id == self.own_bridge_ID:
            self.set_interface_state(get_interface_name(interface), "blocking")

        if self.own_bridge_ID == self.root_bridge_ID:
            for i in self.interfaces:
                self.set_interface_state(get_interface_name(i), "listening")

        return None    
        
    def convert_bpdu_to_bytes_data(self, bpdu_to_send):
        data = bytearray()

        assert isinstance(bpdu_to_send, BPDU), "bpdu_to_send must be an instance of BPDU"

        data.extend(bytes.fromhex(bpdu_to_send.destination_mac.replace(':', '')))
        data.extend(bytes.fromhex(bpdu_to_send.source_mac.replace(':', '')))

        data.extend((0x2048).to_bytes(2, byteorder='big'))

        data.extend(bpdu_to_send.DSAP.to_bytes(4, byteorder='big'))
        data.extend(bpdu_to_send.SSAP.to_bytes(4, byteorder='big'))
        data.extend(bpdu_to_send.control.to_bytes(4, byteorder='big'))

        data.extend(bpdu_to_send.root_bridge_id.to_bytes(4, byteorder='big'))
        data.extend(bpdu_to_send.root_path_cost.to_bytes(4, byteorder='big'))
        data.extend(bpdu_to_send.own_bridge_id.to_bytes(4, byteorder='big'))

        data.extend(bpdu_to_send.port_id.to_bytes(1, byteorder='big'))
        data.extend(bpdu_to_send.flags.to_bytes(1, byteorder='big'))

        data.extend(bpdu_to_send.message_age.to_bytes(1, byteorder='big'))
        data.extend(bpdu_to_send.max_age.to_bytes(1, byteorder='big'))
        data.extend(bpdu_to_send.hello_time.to_bytes(1, byteorder='big'))
        data.extend(bpdu_to_send.forward_delay.to_bytes(1, byteorder='big'))

        data = bytes(data)

        return data

    
    def send_to_all(self, data, length):
        for i in self.interfaces:
            send_to_link(i, length, data)

    def send_to_trunk_ports(self, data, length, coming_interface):
        for i in self.interfaces:
            if self.is_port_trunk(get_interface_name(i)) and i != coming_interface:
                send_to_link(i, length, data)


def parse_configuration_file(filename, interfaces, switch_mac):
    file_descriptor = open(filename, "r")
    
    priority = int(file_descriptor.readline())
    switch_structure = SwitchStructure(priority, interfaces, switch_mac)

    lines = file_descriptor.readlines()

    for line in lines:
        interface, interface_type = line.split(" ")
        switch_structure.add_interface(interface, interface_type)
        if interface_type.startswith("T"):
            switch_structure.add_interface_type_association(interface, str("trunk"))
            switch_structure.add_interface_vlans(interface, 0)
        else:
            switch_structure.add_interface_type_association(interface, str("access"))
            switch_structure.add_interface_vlans(interface, int(interface_type))
    
    return switch_structure

def parse_BPDU_header(data):
    BPDU_data = BPDU(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    if len(data) < 44:
        raise ValueError("Data length is insufficient to parse BPDU")

    BPDU_data.source_mac = ':'.join(f'{b:02x}' for b in data[0:6])
    BPDU_data.destination_mac = ':'.join(f'{b:02x}' for b in data[6:12])

    protocol_type = int.from_bytes(data[12:14], byteorder='big')
    if protocol_type != 0x2048:
        raise ValueError("Unexpected protocol type")

    BPDU_data.DSAP = int.from_bytes(data[14:18], byteorder='big')
    BPDU_data.SSAP = int.from_bytes(data[18:22], byteorder='big')
    BPDU_data.control = int.from_bytes(data[22:26], byteorder='big')
    BPDU_data.root_bridge_id = int.from_bytes(data[26:30], byteorder='big')
    BPDU_data.root_path_cost = int.from_bytes(data[30:34], byteorder='big')
    BPDU_data.own_bridge_id = int.from_bytes(data[34:38], byteorder='big')
    BPDU_data.port_id = int.from_bytes(data[38:39], byteorder='big')
    BPDU_data.flags = int.from_bytes(data[39:40], byteorder='big')

    BPDU_data.message_age = int.from_bytes(data[40:41], byteorder='big')
    BPDU_data.max_age = int.from_bytes(data[41:42], byteorder='big')
    BPDU_data.hello_time = int.from_bytes(data[42:43], byteorder='big')
    BPDU_data.forward_delay = int.from_bytes(data[43:44], byteorder='big')

    return BPDU_data
    
def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def add_vlan_tag(data, new_vlan_tag):
    return data[0:12] + new_vlan_tag + data[12:]

def remove_vlan_tag(data):
    return data[0:12] + data[16:]

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)

        if switch_structure.own_bridge_ID == switch_structure.root_bridge_ID:
            switch_structure.bpdu.root_bridge_id == switch_structure.own_bridge_ID
            switch_structure.bpdu.own_bridge_id == switch_structure.own_bridge_ID
            switch_structure.bpdu.root_path_cost == switch_structure.own_bridge_ID

            data = switch_structure.convert_bpdu_to_bytes_data(switch_structure.bpdu)

            for i in switch_structure.interfaces:
                if switch_structure.is_port_trunk(get_interface_name(i)):
                    send_to_link(i, len(data), data)

            
# returns if a mac address is unicast or not
def is_unicast(mac_address):
    new_number = int(mac_address[0:2], 16)
    return new_number % 2 == 0

# this reads files according to the switch id
def config_file_reader(switch_id, interfaces, switch_mac):
    if switch_id == 0:
        return parse_configuration_file("configs/switch0.cfg", interfaces, switch_mac)
    if switch_id == 1:
        return parse_configuration_file("configs/switch1.cfg", interfaces, switch_mac)
    if switch_id == 2:
        return parse_configuration_file("configs/switch2.cfg", interfaces, switch_mac)

    return None

# this function sends frames based on vlan logic
def send_frame(data, length, vlan_id, coming_interface, next_interface):
    # the extracted vlan of the coming interface(from the interface database)
    last_vlan = switch_structure.interface_vlans[get_interface_name(coming_interface)]

    # the extracted vlan of the next interface(from the interface database)
    next_vlan = switch_structure.interface_vlans[get_interface_name(next_interface)]
    is_trunk = switch_structure.interface_types[get_interface_name(next_interface)] == "trunk"
    is_access = switch_structure.interface_types[get_interface_name(next_interface)] == "access"
    ok_to_send = False

    # state variables for easier handling of possible routes
    access_to_access = False
    access_to_trunk = False
    trunk_to_access = False
    trunk_to_trunk = False

    # check if the machine source is a host
    if vlan_id == -1:
        if is_access == True:
            access_to_access = True
        else:
            access_to_trunk = True

        vlan_id = last_vlan
    else:
        if is_trunk == True:
            trunk_to_trunk = True
        else:
            trunk_to_access = True
    
    # frame with tag added
    larger_frame = add_vlan_tag(data, create_vlan_tag(vlan_id))

    # frame with vlan tag removed
    normal_frame = remove_vlan_tag(data)

    # if vlans are equal OR the next interface is trunk
    if vlan_id == next_vlan or access_to_trunk == True or trunk_to_trunk == True:
        if access_to_trunk == True:
            data = larger_frame
            length += 4

        if trunk_to_access == True:
            length -= 4
            data = normal_frame

        ok_to_send = True

    # if actual next interface is on listening state
    if ok_to_send == True:
        if switch_structure.port_states[get_interface_name(next_interface)] == "listening":
            print(get_interface_name(next_interface))
            send_to_link(next_interface, length, data)

    return None


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    global mac_table
    global switch_structure
    global switch_mac
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    switch_mac = "".join(f'{b:02x}' for b in get_switch_mac())
    switch_structure = config_file_reader(int(switch_id, 10), interfaces, switch_mac)
 
    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # # Printing interface names
    switch_structure.stp_initialization()

    # initialization of hello BPDU parameters
    bpdu_switch_mac = switch_mac
    bpdu_dest_mac = "01:80:c2:00:00:00"
    bpdu_length = int(44)
    bpdu_dsap = int(0x42)
    bpdu_ssap = int(0x42)
    bpdu_control = int(0x03)
    bpdu_root_bridge_id = int(switch_structure.root_bridge_ID)
    bpdu_own_bridge_id = int(switch_structure.own_bridge_ID)
    bpdu_root_path_cost = int(switch_structure.root_path_cost)

    # create hello bpdu
    new_BPDU = BPDU(bpdu_switch_mac, bpdu_dest_mac, bpdu_dsap, bpdu_ssap, bpdu_control, 0, bpdu_root_bridge_id, bpdu_root_path_cost, bpdu_own_bridge_id, 0, 0, 100, 0, 0)
    
    # set switch current bpdu
    switch_structure.set_switch_bpdu(new_BPDU)

    # conversion of BPDU object to bytes
    data = switch_structure.convert_bpdu_to_bytes_data(new_BPDU)

    # send the hello bpdu
    switch_structure.send_to_all(data, len(data))

    while True:
        interface, data, length = recv_from_any_link()
        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        for i in interfaces:
            print(f"{get_interface_name(i)} and current state is: {switch_structure.get_interface_state(get_interface_name(i))}")

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # check if current_packet is from stp
        if dest_mac == "01:80:c2:00:00:00":
            new_BPDU = parse_BPDU_header(data)
            switch_structure.receive_BPDU(new_BPDU, interface)
            continue
        
        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, get_interface_name(interface)), flush=True)

        mac_table[src_mac] = interface

        # comutation table process
        if is_unicast(dest_mac):
            if dest_mac in mac_table:
                send_frame(data, length, vlan_id, interface, mac_table[dest_mac])
            else:
                for i in interfaces:
                    if interface != i:
                        send_frame(data, length, vlan_id, interface, i)
        else:
            for i in interfaces:
                if interface != i:
                    send_frame(data, length, vlan_id, interface, i)

if __name__ == "__main__":
    main()

