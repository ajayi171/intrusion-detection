import asyncio
import streamlit as st
import pyshark
import pandas as pd
import time
import pickle
import numpy as np
from numpy import hstack
from PIL import Image
from concurrent.futures import ThreadPoolExecutor

# Define the columns for the DataFrame based on your packet data structure
columns = [
    'id', 'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat',
    'smean', 'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl',
    'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst',
    'is_sm_ips_ports', 'attack_cat', 'label'
]

def detect_attack_category(packet):
    """
    Determine the attack category based on packet attributes.
    """
    try:
        # Example heuristic rules for detecting attack categories
        if 'TCP' in packet:
            flags = packet.tcp.flags
            if flags == '0x00000002':  # SYN flag only
                return 'Fuzzer'
            elif flags == '0x00000012':  # SYN, ACK
                return 'Exploits'
            elif flags == '0x00000011':  # FIN, ACK
                return 'Worms'

        if packet.highest_layer == 'HTTP' and 'attack' in packet.http.request_full_uri:
            return 'Exploits'

        if int(packet.length) > 1500:  # Example rule for unusual packet size
            return 'DoS'

        # Add more rules as needed for other attack categories

        return 'Normal'  # Default to normal if no rules match
    except AttributeError:
        return 'Normal'  # Default to normal for packets with missing attributes

def extract_packet_info(packet):
    """
    Extract information from a packet based on the defined data structure.
    """
    try:
        proto = packet.highest_layer
        service = packet.layers[-1].layer_name if hasattr(packet, 'layers') else '-'
        state = packet.tcp.flags if 'TCP' in packet else '-'
        spkts = packet.tcp.stream if 'TCP' in packet else 0
        dpkts = packet.ip.len if 'IP' in packet else 0
        sbytes = int(packet.length)
        dbytes = int(packet.length)
        rate = float(packet.captured_length) / float(packet.sniff_time.timestamp()) if packet.sniff_time.timestamp() != 0 else 0
        sttl = int(packet.ip.ttl) if 'IP' in packet else 0
        dttl = int(packet.ip.ttl) if 'IP' in packet else 0
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
        smean = int(packet.length) // 2
        dmean = int(packet.length) // 2
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
        attack_cat = detect_attack_category(packet)
        label = 1

        return (
            time.time(),  # Example packet id (timestamp)
            time.time() - float(packet.sniff_timestamp), proto, service, state,
            spkts, dpkts, sbytes, dbytes, rate, sttl, dttl, sload, dload, 0, 0, sinpkt,
            dinpkt, sjit, djit, swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat, smean,
            dmean, trans_depth, response_body_len, ct_srv_src, ct_state_ttl, ct_dst_ltm,
            ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm, is_ftp_login, ct_ftp_cmd,
            ct_flw_http_mthd, ct_src_ltm, ct_srv_dst, is_sm_ips_ports, attack_cat, label
        )
    except AttributeError as e:
        return None
loop = asyncio.ProactorEventLoop()
asyncio.set_event_loop(loop)
def start_live_capture(interface, packet_count=10):
    """
    Start capturing packets and return a DataFrame with captured packet data.
    """
    capture = pyshark.LiveCapture(interface=interface, eventloop=loop)

    packet_data = []

    for packet in capture.sniff_continuously(packet_count=packet_count):
        packet_info = extract_packet_info(packet)
        if packet_info:
            packet_data.append(packet_info)

    df = pd.DataFrame(packet_data, columns=columns)
    return df

# Streamlit UI
st.title("Live Network Packet Capture")

def super_learner_predictions(X, models, meta_model):
    meta_X = [model.predict_proba(X) for model in models]
    meta_X = hstack(meta_X)
    return meta_model.predict(meta_X)

def prepare(data):
    attack_df = data[sf]
    intr_df = data[sf2]
    attack_df = st.session_state.scaler1.transform(attack_df)
    intr_df = st.session_state.scaler2.transform(intr_df)
    return attack_df, intr_df

col3 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm',
        'dload','ct_srv_src','sbytes','dur', 'sload', 'tcprtt',
        'ct_srv_dst', 'dbytes', 'smean']

col4 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm',
        'dload','ct_srv_src','sbytes','dur', 'sload', 'tcprtt',
        'ct_srv_dst', 'dbytes', 'smean','attack_cat']

sf = ['dur', 'sbytes', 'dbytes', 'sttl', 'sload', 'dload', 
     'smean', 'dmean', 'ct_srv_src', 'ct_srv_dst']

sf2 =  ['sbytes', 'rate', 'sttl', 'sload', 'dload', 'tcprtt',
    'smean', 'ct_state_ttl', 'ct_dst_src_ltm', 'ct_srv_dst']

tags = ['No. for each state according to specific range of values for source/destination time to live',
'rate','Source to destination time to live value', 'Mean of the row packet size transmitted by the dst',
'No of connections of the same source and the destination address in 100 connections according to the last time.',
'Destination bits per second',
'No. of connections that contain the same service and source address in 100 connections according to the last time.',
'Number of data bytes transferred from source to destination in single connection',
'duration of connection', 'Source bits per second','TCP connection setup round-trip time',
'No. of connections that contain the same service and destination address in 100 connections according to the last time.',
'Number of data bytes transferred from destination to source in single connection',
'Mean of the row packet size transmitted by the source'
]

# Initialize session state variables if they don't exist
if 'running' not in st.session_state:
    st.session_state['running'] = False
if 'dataframe' not in st.session_state:
    st.session_state.dataframe = pd.DataFrame(columns=columns)
if 'models_loaded' not in st.session_state:
    st.session_state.models_loaded = False

# Load models once
if st.button("Load Models") and not st.session_state.models_loaded:
    st.session_state.att_model = pickle.load(open('att_model.pkl', 'rb'))
    st.session_state.models = pickle.load(open('sl_model.pkl', 'rb'))
    st.session_state.meta_model = pickle.load(open('meta_model.pkl', 'rb'))
    st.session_state.label_encoder2 = pickle.load(open('le2.pkl', 'rb'))
    st.session_state.label_encoder4 = pickle.load(open('le4.pkl', 'rb'))
    st.session_state.scaler1 = pickle.load(open('att_scal.pkl', 'rb'))
    st.session_state.scaler2 = pickle.load(open('scal.pkl', 'rb'))
    st.session_state.encoder = pickle.load(open('enc.pkl', 'rb'))
    st.session_state.models_loaded = True
    st.success("Models loaded successfully")

packet_display = st.empty()  # Placeholder for updating packet display

def capture_packets():
    """
    Continuously capture and display packets.
    """
    with ThreadPoolExecutor() as executor:
        while st.session_state['running']:
            future = executor.submit(start_live_capture, 'Wi-Fi 2')
            new_df = future.result()
            st.session_state.dataframe = pd.concat([st.session_state.dataframe, new_df])
            packet_display.dataframe(st.session_state.dataframe)
            time.sleep(1)  # Adjust sleep duration as needed

if st.button("Start Capture") and not st.session_state['running']:
    st.session_state['running'] = True
    st.spinner("Capturing packets...")
    capture_packets()

if st.button("Stop Capture"):
    st.session_state['running'] = False

# Select row for prediction
if not st.session_state.dataframe.empty:
    data2 = st.session_state.dataframe[col3]
    data3 = st.session_state.dataframe[col4]
    row_num = st.number_input('Select Row, You would like to Predict', min_value=0, max_value=data2.shape[0]-1, step=1)
    new_d = data2.iloc[row_num]
    new_ddd = new_d.to_list()
    new_d = pd.DataFrame(new_d)
    new_d['Full Name'] = tags
    st.dataframe(new_d)
    feat2 = np.array(new_ddd).reshape(1,-1)
    feat2 = pd.DataFrame(feat2,columns=col3)

    if st.button('Prediction'):
        attack_df, intr_df = prepare(feat2)
        pred = super_learner_predictions(intr_df, st.session_state.models, st.session_state.meta_model)
        if pred[0] == 0:
            st.write("Normal Activity Permission Granted")
        else:
            pred1 = st.session_state.att_model.predict(attack_df)
            attack = st.session_state.label_encoder4.inverse_transform(pred1)
            st.warning(f"{attack[0]} Intrusion Detected")
            st.image("dz1.gif")



# import streamlit as st
# import pyshark

# def main():
#     st.title("Packet Capture with PyShark")

#     # Select the network interface
#     interfaces = pyshark.find_my_interfaces()
#     interface = st.selectbox("Select a network interface", interfaces)

#     if st.button("Start Capture"):
#         try:
#             # Start the packet capture
#             capture = pyshark.LiveCapture(interface=interface)
#             st.write(f"Capturing packets on interface: {interface}")

#             for packet in capture.sniff_continuously():
#                 # Display the packet details
#                 st.write(f"Timestamp: {packet.sniff_timestamp}")
#                 st.write(f"Protocol: {packet.highest_layer}")
#                 st.write(f"Source: {packet.ip.src}")
#                 st.write(f"Destination: {packet.ip.dst}")
#                 st.write(f"Length: {packet.length} bytes")
#                 st.write("---")

#         except Exception as e:
#             st.error(f"Error: {e}")

# if __name__ == "__main__":
#     main()