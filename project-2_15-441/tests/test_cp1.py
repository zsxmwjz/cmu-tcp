#!/usr/bin/env python3
# Copyright (C) 2022 Carnegie Mellon University
#
# This file is part of the TCP in the Wild course project developed for the
# Computer Networks course (15-441/641) taught at Carnegie Mellon University.
#
# No part of the project may be copied and/or distributed without the express
# permission of the 15-441/641 course staff.

from pathlib import Path

from scapy.all import rdpcap
from fabric import Connection

from common import PCAP, CMUTCP, SYN_MASK, ACK_MASK, IP_ADDRS,FIN_MASK



def test_pcap_packets_max_size():
    """Basic test: Check packets are smaller than max size"""
    print("Running test_pcap_packets_max_size()")
    print(
        "Please note that it's now testing on a sample test.pcap file. "
        "You should generate your own pcap file and run this test."
    )
    packets = rdpcap(PCAP)
    if len(packets) <= 10:
        print("Test Failed")
        return
    for pkt in packets:
        if CMUTCP in pkt:
            if len(pkt[CMUTCP]) > 1400:
                print("Found packet with length greater than max size")
                print("Test Failed")
                return
    print("Test passed")


def test_pcap_acks():
    """Basic test: Check that every data packet sent has a corresponding ACK
    Ignore handshake packets.
    """
    print("Running test_pcap_acks()")
    print(
        "Please note that it's now testing on a sample test.pcap file. "
        "You should generate your own pcap file and run this test."
    )
    packets = rdpcap(PCAP)
    if len(packets) <= 10:
        print("Test Failed")
        return

    expected_acks = []
    ack_nums = []
    for pkt in packets:
        if CMUTCP in pkt:
            # Ignore handshake packets, should test in a different test.
            if pkt[CMUTCP].flags == 0:
                payload_len = pkt[CMUTCP].plen - pkt[CMUTCP].hlen
                expected_acks.append(pkt[CMUTCP].seq_num + payload_len)
            elif pkt[CMUTCP].flags == ACK_MASK: # 无法区分是对数据包的ACK还是对SYNACK的ACK
                ack_nums.append(pkt[CMUTCP].ack_num)
            elif pkt[CMUTCP].flags == SYN_MASK | ACK_MASK:
                expected_acks.append(pkt[CMUTCP].seq_num + 1)

    # TODO: Probably not the best way to do this test!
    if max(set(expected_acks)) == max(set(ack_nums)):
        print("Test Passed")
    else:
        print("Test Failed")

def test_initiator_hand_shake():	#initiator handshake test
    """Basic test: Check that every data packet sent has a corresponding ACK
    Ignore handshake packets.
    """
    print("Running initiator_test_handshake()")
    
    #get packets from a .pcap file
    packets = rdpcap(PCAP)
    
	#last_syn = 0;
	#last_seq = 0;
	
	#confirmSeq = []
	
    mesToPrint = "Test Failed"
    mesPass = "Test Passed"
    
    i=0
    count=0
    pktArr = []
    while i<len(packets)-2:#select 3 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+2]:
            p3=packets[i+2]
        else :
            i=i+1
            continue


        # if pktArr[0][CMUTCP].SYN==1	:#Sends the first SYN packet properly
        #     last_seq = pktArr[0][CMUTCP].seq_num
        #     if (pktArr[1][CMUTCP].SYN ==1) and (pktArr[1][CMUTCP].ACK==1) and (pktArr[1][CMUTCP].ack_num == last_seq+1) :
        #         ast_seq = pktArr[1][CMUTCP].seq_num
        #         if(pktArr[2][CMUTCP].ACK==1) and (pktArr[2][CMUTCP].ack_num==last_seq+1) :
        #             if packets[i][CMUTCP].extension_length != 0: #Receives data packets properly after handshake finishes(test tentatively)
        #                 mesToPrint = "Test Passed";#Rejects malformed SYN-ACK packet from listener
        
        if p1[CMUTCP].flags==ACK_MASK	:#Sends the first SYN packet properly
            last_seq = p1[CMUTCP].seq_num
            mesToPrint = mesPass
            if (p2[CMUTCP].flags==ACK_MASK|SYN_MASK)and (p2[CMUTCP].ack_num == last_seq+1) :
                ast_seq = p2[CMUTCP].seq_num
                if(p3[CMUTCP].flags==ACK_MASK) and (p3[CMUTCP].ack_num==last_seq+1) :
                    if p4[CMUTCP].extension_length != 0: #Receives data packets properly after handshake finishes(test tentatively)
                        mesToPrint = "Test Passed"#Rejects malformed SYN-ACK packet from listener
        
        
        
        i = i+1
    print(mesToPrint)


def test_Reliability():	#Listener handshake test
    """Basic test: Check that every data packet sent has a corresponding ACK
    Ignore handshake packets.
    """
    print("Running test_Reliability")
    mesToPrint = "Test Faild"
    packets = rdpcap(PCAP)

    estimatedRTT = 3000
    timeout = 10000

    i=0
    count=0
    pktArr = []
    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p2.time-p1.time < timeout:#Retransmits data packets on timeout
            if p2.time-p1.time < 3*estimatedRTT:#Retransmits data packets within 1–3 estimated RTTs
                i = i+1
                mesToPrint = "Test Passed"
                continue
        i = i+1
    
    i=0
    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p2[CMUTCP].ack_num == p1[CMUTCP].ack_num + len(p1[CMUTCP]):#Transfers a file reliably under lossless conditions
            i = i+1
            mesToPrint = "Test Passed"
            continue
        if p2[CMUTCP].ack_num == p1[CMUTCP].ack_num:#Transfers a file reliably under lossy conditions
            i = i+1
            mesToPrint = "Test Passed"
            continue
        i = i+1

    print(mesToPrint)

def test_tear_down():	#Listener handshake test
    """Basic test: Check that every data packet sent has a corresponding ACK
    Ignore handshake packets.
    """
    print("Running test_tear_down")
    
    #get packets from a .pcap file
    packets = rdpcap(PCAP)

    last_syn = 0
    last_seq = 0
    i=0
    timeout = 10000


    confirmSeq = []
	
    mesToPrint = "Test Faild"

    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p1[CMUTCP].flags==FIN_MASK:#Sends FIN packet correctly
            mesToPrint = "Test Passed"
            i = i+1
            continue
        i = i+1

    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p1[CMUTCP].flags==FIN_MASK|ACK_MASK:#Sends a valid ACK packet after receiving a FIN-ACK
            mesToPrint = "Test Passed"
            if p2[CMUTCP].flags==ACK_MASK:
                i = i+1
                mesToPrint = "Test Passed"
                continue
        i = i+1


    i=0
    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p1[CMUTCP].extension_length!=0:#Sender transmits multiple data packets at a time
            if p2[CMUTCP].extension_length !=0:
                i = i+1
                mesToPrint = "Test Passed"
                continue
        i = i+1


    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p2.time-p1.time<timeout:#Retransmits FIN packet on timeout
            if p2[CMUTCP].flags==FIN_MASK:
                i = i+1
                mesToPrint = "Test Passed"
                continue
        i = i+1

    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p2[CMUTCP].seq_num>p1[CMUTCP].seq_num:#One side can still send data after the other side starts teardown
            i = i+1
            mesToPrint = "Test Passed"
            continue
        i = i+1
    
    print(mesToPrint)




def test_win_seq():	#Listener handshake test
    """Basic test: Check that every data packet sent has a corresponding ACK
    Ignore handshake packets.
    """
    print("Running test_win_seq")
    
    #get packets from a .pcap file
    packets = rdpcap(PCAP)
    
    testPassCount = 0;#count how many point the test passed,expected 5
    
    last_syn = 0
    last_seq = 0
    
	
    confirmSeq = []
	
    mesToPrint = "Test Failed"
    i=0
    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p1[CMUTCP].extension_length!=0:#Sender transmits multiple data packets at a time
            if p2[CMUTCP].extension_length !=0:
                i = i+1
                mesToPrint = "Test Passed"
                continue
        i = i+1

    i=0
    while i<len(packets)-1 :#select 4 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p1[CMUTCP].seq_num!=0:#Initiator correctly synchronizes sequence number
            if p2[CMUTCP].seq_num!=0:#Listener correctly synchronizes sequence number
                i=i+1
                mesToPrint = "Test Passed"
                continue
        i = i+1
    i=0
    while i<len(packets)-1 :#select 4 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p1[CMUTCP].seq_num!=0:#Initiator initializes sequence number randomly
            if p2[CMUTCP].seq_num!=0:#Listener initializes sequence number randomly
                i=i+1
                mesToPrint = "Test Passed"
                continue
        i = i+1






    print(mesToPrint)
    				
    			
def test_Listener_hand_shake():	#Listener handshake test
    """Basic test: Check that every data packet sent has a corresponding ACK
    Ignore handshake packets.
    """
    print("Running test_Listener_hand_shake")
    
    #get packets from a .pcap file
    packets = rdpcap(PCAP)
    
    testPassCount = 0;#count how many point the test passed,expected 5
    
    last_syn = 0
    last_seq = 0
	
    confirmSeq = []
	
    mesToPrint = "Test Failed"
    
    ####test1:
    i=0
    count=0
    pktArr = []
    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+2]:
            p3=packets[i+2]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+3]:
            p4=packets[i+3]
        else :
            i=i+1
            continue
        if p1[CMUTCP].flags!=SYN_MASK:
            mesToPrint = "Test Passed"
            if p2[CMUTCP].flags!=SYN_MASK:#Does not respond to invalid SYN packets
                break
        i = i+1
    			
    if i == i<len(packets)-1:
        testPassCount = testPassCount+1#test1 passed
    ####
    
    ####test2:
    i=0
    count=0
    pktArr = []
    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+2]:
            p3=packets[i+2]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+3]:
            p4=packets[i+3]
        else :
            i=i+1
            continue
        if p1[CMUTCP].flags==SYN_MASK:
            if p2[CMUTCP].flags==SYN_MASK | ACK_MASK:#Responds to valid SYN packets with a valid SYN-ACK packet
                break
        i = i+1
    			
    if i == i<len(packets)-1:
        testPassCount= testPassCount+1#test2 passed
    ####
    
    ####test3:
    i=0
    count=0
    pktArr = []
    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p1[CMUTCP].flags==SYN_MASK|ACK_MASK:
            if p2[CMUTCP].flags==SYN_MASK or p2[CMUTCP].flags==SYN_MASK|ACK_MASK:# Retransmits SYN-ACK packets on loss
                mesToPrint = "Test Passed"
                break
        i = i+1
    			
    if i == i<len(packets)-1:
        testPassCount= testPassCount+1#test2 passed
    ####test4:
    i=0
    count=0
    pktArr = []
    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if p1[CMUTCP].flags==SYN_MASK|ACK_MASK:
            if p2[CMUTCP].flags==SYN_MASK:# Properly handles invalid ACK packets after a SYN-ACK
                break
        i = i+1
    ####test5:
    i=0
    count=0
    pktArr = []
    while i<len(packets)-1 :#select 2 packets continuously
        if CMUTCP in packets[i]:
            p1=packets[i]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+1]:
            p2=packets[i+1]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+2]:
            p3=packets[i+2]
        else :
            i=i+1
            continue
        if CMUTCP in packets[i+3]:
            p4=packets[i+3]
        else :
            i=i+1
            continue
        if p1[CMUTCP].flags==SYN_MASK|ACK_MASK:
            if p2[CMUTCP].flags==ACK_MASK:
                if p3[CMUTCP].extension_data!=0:#Receives data packets properly after handshake finishes
                    mesToPrint = "Test Passed"
                    break
        i = i+1

    			
    # if i == i<len(packets)-1:
    #     testPassCount= testPassCount+1#test2 passed


    if testPassCount==5:
        mesToPrint = "Test Passed"#test passed
    
    print(mesToPrint)
    				

# This will try to run the server and client code.
def test_run_server_client():
    """Basic test: Run server and client, and initiate the file transfer."""
    print("Running test_run_server_client()")

    # We are using `tmux` to run the server and client in the background.
    #
    # This might also help you debug your code if the test fails. You may call
    # `getchar()` in your code to pause the program at any point and then use
    # `tmux attach -t pytest_server` or `tmux attach -t pytest_client` to
    # attach to the relevant TMUX session and see the output.

    start_server_cmd = (
        "tmux new -s pytest_server -d /vagrant/project-2_15-441/server"
    )
    start_client_cmd = (
        "tmux new -s pytest_client -d /vagrant/project-2_15-441/client"
    )
    stop_server_cmd = "tmux kill-session -t pytest_server"
    stop_client_cmd = "tmux kill-session -t pytest_client"

    failed = False

    original_file = Path("/vagrant/project-2_15-441/src/cmu_tcp.c")
    received_file = Path("/tmp/file.c")

    received_file.unlink(missing_ok=True)

    with (
        Connection(
            host=IP_ADDRS["server"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as server_conn,
        Connection(
            host=IP_ADDRS["client"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as client_conn,
    ):
        try:
            server_conn.run(start_server_cmd)
            server_conn.run("tmux has-session -t pytest_server")

            client_conn.run(start_client_cmd)
            client_conn.run("tmux has-session -t pytest_client")

            # Exit when server finished receiving file.
            server_conn.run(
                "while tmux has-session -t pytest_server; do sleep 1; done",
                hide=True,
            )
        except Exception:
            failed = True

        try:
            client_conn.run("tmux has-session -t pytest_client", hide=True)
            print("stop client")
            client_conn.run(stop_client_cmd, hide=True)
        except Exception:
            # Ignore error here that may occur if client already shut down.
            pass
        try:
            server_conn.local("tmux has-session -t pytest_server", hide=True)
            print("stop server")
            server_conn.local(stop_server_cmd, hide=True)
        except Exception:
            # Ignore error here that may occur if server already shut down.
            pass
        if failed:
            print("Test failed: Error running server or client")
            return

        # Compare SHA256 hashes of the files.
        server_hash_result = server_conn.run(f"sha256sum {received_file}")
        client_hash_result = client_conn.run(f"sha256sum {original_file}")

        if not server_hash_result.ok or not client_hash_result.ok:
            print("Test failed: Error getting file hashes")
            return

        server_hash = server_hash_result.stdout.split()[0]
        client_hash = client_hash_result.stdout.split()[0]

        if server_hash != client_hash:
            print("Test failed: File hashes do not match")
            return

        print("Test passed")


def test_basic_reliable_data_transfer():
    """Basic test: Check that when you run server and client starter code
    that the input file equals the output file
    """
    # Can you think of how you can test this? Give it a try!
    pass


def test_basic_retransmit():
    """Basic test: Check that when a packet is lost, it's retransmitted"""
    # Can you think of how you can test this? Give it a try!
    pass


if __name__ == "__main__":
    test_pcap_packets_max_size()
    test_pcap_acks()
    #test_run_server_client()
    test_initiator_hand_shake()
    test_Listener_hand_shake()
    test_Reliability()
    test_win_seq()
    test_tear_down()
