import pyshark
import csv
import time

def capture_packets(interface='eth0', output_file='network_data.csv', num_packets=10):
    # Open the CSV file for writing
    with open(output_file, mode='w', newline='') as csv_file:
        # Define CSV writer
        writer = csv.writer(csv_file)

        # Write header to CSV
        writer.writerow([
            'id', 'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
            'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
            'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat',
            'smean', 'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl',
            'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login',
            'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports',
            'attack_cat', 'label'
        ])

        # Start capturing packets
        capture = pyshark.LiveCapture(interface=interface)
        print(capture)


        # Initialize packet id
        packet_id = 1

        for packet in capture.sniff_continuously():
            try:
                # Extract required data from the packet
                print('Capturing:----'*5)
                print(packet)
                proto = packet.highest_layer
                service = packet.layers[-1].layer_name if hasattr(packet, 'layers') else '-'
                state = packet.tcp.flags if 'TCP' in packet else '-'
                spkts = packet.tcp.stream if 'TCP' in packet else 0
                dpkts = packet.ip.len if 'IP' in packet else 0
                sbytes = int(packet.length)
                dbytes = int(packet.length)
                rate = float(packet.captured_length) / float(packet.sniff_time.timestamp()) if packet.sniff_time.timestamp() != 0 else 0
                sttl = packet.ip.ttl if 'IP' in packet else 0
                dttl = packet.ip.ttl if 'IP' in packet else 0
                sload = float(packet.length) * 8  # Convert bytes to bits
                dload = float(packet.length) * 8  # Convert bytes to bits
                sinpkt = packet.tcp.time_delta if 'TCP' in packet else 0
                dinpkt = packet.tcp.time_delta if 'TCP' in packet else 0
                sjit = packet.tcp.time_relative if 'TCP' in packet else 0
                djit = packet.tcp.time_relative if 'TCP' in packet else 0
                swin = packet.tcp.window_size if 'TCP' in packet else 0
                stcpb = packet.tcp.stream if 'TCP' in packet else 0
                dtcpb = packet.tcp.stream if 'TCP' in packet else 0
                dwin = packet.tcp.window_size if 'TCP' in packet else 0
                tcprtt = packet.tcp.analysis_ack_rtt if 'TCP' in packet else 0
                synack = packet.tcp.flags_syn if 'TCP' in packet else 0
                ackdat = packet.tcp.flags_ack if 'TCP' in packet else 0
                smean = int(packet.length) // 2  # Simplified mean calculation
                dmean = int(packet.length) // 2  # Simplified mean calculation
                trans_depth = 0
                response_body_len = 0
                ct_srv_src = 1
                ct_state_ttl = 1
                ct_dst_ltm = 1
                ct_src_dport_ltm = 1
                ct_dst_sport_ltm = 1
                ct_dst_src_ltm = 1
                is_ftp_login = 0
                ct_ftp_cmd = 0
                ct_flw_http_mthd = 0
                ct_src_ltm = 1
                ct_srv_dst = 1
                is_sm_ips_ports = 0
                attack_cat = 'Exploits'
                label = 1

                # Write row to CSV
                writer.writerow([
                    packet_id, time.time() - float(packet.sniff_timestamp), proto, service, state,
                    spkts, dpkts, sbytes, dbytes, rate, sttl, dttl, sload, dload, 0, 0, sinpkt,
                    dinpkt, sjit, djit, swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat, smean,
                    dmean, trans_depth, response_body_len, ct_srv_src, ct_state_ttl, ct_dst_ltm,
                    ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm, is_ftp_login, ct_ftp_cmd,
                    ct_flw_http_mthd, ct_src_ltm, ct_srv_dst, is_sm_ips_ports, attack_cat, label
                ])

                # Increment packet id
                packet_id += 1
                print('End Capturing:----'*5)


            except AttributeError as e:
                # Some fields might not be available for all packets
                print(f"Could not parse packet: {e}")
                pass

if __name__ == "__main__":
    capture_packets(interface='Wi-Fi 2', output_file='network_data.csv', num_packets=10)
