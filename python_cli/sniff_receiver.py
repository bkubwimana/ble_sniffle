#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2018-2024, NCC Group plc
# Released as open source under GPLv3

import argparse
import sys
import signal
from binascii import unhexlify
from sniffle.constants import BLE_ADV_AA
from sniffle.pcap import PcapBleWriter
from sniffle.sniffle_hw import (
    SniffleHW, PacketMessage, DebugMessage, StateMessage,
    MeasurementMessage, SnifferMode, PhyMode
)
from sniffle.packet_decoder import (
    AdvaMessage, AdvDirectIndMessage, AdvExtIndMessage,
    ScanRspMessage, DataMessage, str_mac
)
from sniffle.errors import UsageError
from sniffle.advdata.decoder import decode_adv_data

# globals
hw = None
pcwriter = None
_run = True

def signal_handler(sig, frame):
    global _run
    sys.stderr.write("\nInterrupted, shutting down...\n")
    _run = False

signal.signal(signal.SIGINT, signal_handler)

def main():
    global hw, pcwriter, _run
    aparse = argparse.ArgumentParser(description="Host-side receiver for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-c", "--advchan", default=40, choices=[37, 38, 39], type=int,
                        help="Advertising channel to listen on")
    aparse.add_argument("-p", "--pause", action="store_true",
                        help="Pause sniffer after disconnect")
    aparse.add_argument("-r", "--rssi", default=-128, type=int,
                        help="Filter packets by minimum RSSI")
    aparse.add_argument("-m", "--mac", default=None, help="Filter packets by advertiser MAC")
    aparse.add_argument("-i", "--irk", default=None, help="Filter packets by advertiser IRK")
    aparse.add_argument("-S", "--string", default=None,
                        help="Filter for advertisements containing the specified string")
    aparse.add_argument("-a", "--advonly", action="store_true",
                        help="Passive scanning, don't follow connections")
    aparse.add_argument("-A", "--scan", action="store_true",
                        help="Active scanning, don't follow connections")
    aparse.add_argument("-e", "--extadv", action="store_true",
                        help="Capture BT5 extended (auxiliary) advertising")
    aparse.add_argument("-H", "--hop", action="store_true",
                        help="Hop primary advertising channels in extended mode")
    aparse.add_argument("-l", "--longrange", action="store_true",
                        help="Use long range (coded) PHY for primary advertising")
    aparse.add_argument("-q", "--quiet", action="store_true",
                        help="Don't display empty packets")
    aparse.add_argument("-Q", "--preload", default=None, help="Preload expected encrypted connection parameter changes")
    aparse.add_argument("-n", "--nophychange", action="store_true",
                        help="Ignore encrypted PHY mode changes")
    aparse.add_argument("-C", "--crcerr", action="store_true",
                        help="Capture packets with CRC errors")
    aparse.add_argument("-d", "--decode", action="store_true",
                        help="Decode advertising data")
    aparse.add_argument("-o", "--output", default=None, help="PCAP output file name")
    args = aparse.parse_args()

    # argument sanity checks
    targ_specs = bool(args.mac) + bool(args.irk) + bool(args.string)
    if args.longrange and args.hop:
        raise UsageError("Primary ad channel hopping unsupported on long range PHY!")
    if targ_specs > 1:
        raise UsageError("MAC, IRK, and advertisement string filters are mutually exclusive!")
    if args.advchan != 40 and args.hop:
        raise UsageError("Don't specify an advertising channel if you want advertising channel hopping!")

    # initialize hardware
    hw = SniffleHW(args.serport)

    # setup channel hopping logic
    hop3 = True if targ_specs else False
    if args.advchan == 40:
        args.advchan = 37
    else:
        hop3 = False
    if args.extadv and not args.hop:
        hop3 = False

    # prepare filters
    mac = None
    irk = None
    if args.irk:
        irk = unhexlify(args.irk)
    elif args.mac:
        mac = [int(h, 16) for h in reversed(args.mac.split(":"))]
    elif args.string:
        search_str = args.string.encode('latin-1').decode('unicode_escape').encode('latin-1')
        sys.stderr.write("Waiting for advertisement containing specified string...\n")
        mac, _ = get_mac_from_string(search_str, args.longrange)
        sys.stderr.write(f"Found target MAC: {str_mac(mac)}\n")

    # choose sniffer mode
    if args.scan:
        sniffer_mode = SnifferMode.ACTIVE_SCAN
    elif args.advonly:
        sniffer_mode = SnifferMode.PASSIVE_SCAN
    else:
        sniffer_mode = SnifferMode.CONN_FOLLOW

    # configure sniffer
    hw.setup_sniffer(
        mode=sniffer_mode,
        chan=args.advchan,
        targ_mac=mac,
        targ_irk=irk,
        hop3=hop3,
        ext_adv=args.extadv,
        coded_phy=args.longrange,
        rssi_min=args.rssi,
        interval_preload=[tuple(map(int, p.split(':'))) for p in (args.preload or "").split(',') if p],
        phy_preload=None if args.nophychange else PhyMode.PHY_2M,
        pause_done=args.pause,
        validate_crc=not args.crcerr
    )

    # reset and clear buffers
    hw.mark_and_flush()

    # setup PCAP writer if requested
    if args.output:
        pcwriter = PcapBleWriter(args.output)

    # main capture loop, exits cleanly on Ctrl+C
    while _run:
        try:
            msg = hw.recv_and_decode()
            print_message(msg, args.quiet, args.decode)
        except KeyboardInterrupt:
            # redundant if signal handler already set _run=False
            break
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")
            break

    sys.stderr.write("Shutting down...\n")
    # optional cleanup if available
    try:
        if pcwriter:
            pcwriter.close()
        if hw:
            hw.close()
    except:
        pass

def print_message(msg, quiet, decode_ad):
    if isinstance(msg, PacketMessage):
        print_packet(msg, quiet, decode_ad)
    else:
        print(msg, end='\n\n')

def print_packet(dpkt, quiet, decode_ad):
    if isinstance(dpkt, (AdvaMessage, AdvDirectIndMessage, ScanRspMessage, AdvExtIndMessage)):
        print(dpkt.str_header())
        print(dpkt.str_decode())
        if decode_ad:
            for ad in decode_adv_data(dpkt.adv_data):
                print(ad)
        print(dpkt.hexdump(), end='\n\n')
    elif not (quiet and isinstance(dpkt, DataMessage) and dpkt.data_length == 0):
        print(dpkt, end='\n\n')
    if pcwriter:
        pcwriter.write_packet_message(dpkt)

def get_mac_from_string(s, coded_phy=False):
    hw.setup_sniffer(SnifferMode.ACTIVE_SCAN, ext_adv=True, coded_phy=coded_phy)
    hw.mark_and_flush()
    while True:
        msg = hw.recv_and_decode()
        if isinstance(msg, (AdvaMessage, AdvDirectIndMessage, ScanRspMessage, AdvExtIndMessage)) and msg.AdvA is not None:
            if s in msg.body:
                return msg.AdvA, not msg.TxAdd

if __name__ == "__main__":
    main()
