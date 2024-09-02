import asyncio
import streamlit as st
import pyshark
import pandas as pd
import time
import pickle
import numpy as np
import pandas as pd 
from numpy import hstack
from numpy import vstack
from numpy import asarray
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
    except AttributeError:
        return 'Normal'  # Default to normal for packets with missing attributes

# def detect_attack_category(packet):
#     """
#     Placeholder function for attack detection.
#     In a real-world scenario, this would involve more sophisticated analysis.
#     """
#     # This is a very simplistic example and should be replaced with actual attack detection logic
#     if 'TCP' in packet and bool(packet.tcp.flags_syn) and not bool(packet.tcp.flags_ack):
#         return "Potential SYN Flood"
#     elif 'HTTP' in packet and hasattr(packet.http, 'request_method') and packet.http.request_method == 'GET':
#         return "Potential HTTP Flood"
#     # Add more attack detection logic here
#     return "Normal"

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
        # st.write(f"Could not parse packet: {e}")
        return None
# loop = asyncio.ProactorEventLoop()
# asyncio.set_event_loop(loop)
def start_live_capture(interface, packet_count=100):
    """
    Start capturing packets and return a DataFrame with captured packet data.
    """
    capture = pyshark.LiveCapture(interface=interface)

    packet_data = []

    for i, packet in enumerate(capture.sniff_continuously(packet_count=packet_count)):
        packet_info = extract_packet_info(packet)
        if packet_info:
            packet_data.append(packet_info)
    df = pd.DataFrame(packet_data, columns=columns)
    return df

# Streamlit UI
st.title("Live Network Packet Capture")

col3 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm',
        'dload','ct_srv_src','sbytes','dur','sload', 'tcprtt','synack',
        'ct_srv_dst', 'dbytes', 'smean']

col4 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm',
        'dload','ct_srv_src','sbytes','dur', 'sload', 'tcprtt',
        'ct_srv_dst', 'dbytes', 'smean','attack_cat']


# col3 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm',
#         'dload','ct_srv_src','sbytes','dur', 'sload', 'tcprtt',
#         'ct_srv_dst', 'dbytes', 'smean','synack']

# col4 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm',
#         'dload','ct_srv_src','sbytes','dur', 'sload', 'tcprtt',
#         'ct_srv_dst', 'dbytes', 'smean','attack_cat']

# sf = ['sbytes', 'dbytes', 'sttl', 'sload', 'dload', 
#      'smean', 'dmean', 'ct_srv_src', 'ct_srv_dst']

# sf2 =  ['sbytes', 'rate', 'sttl', 'sload', 'dload', 'tcprtt',
#     'smean', 'ct_state_ttl', 'ct_dst_src_ltm', 'ct_srv_dst']

selected_features = ['sbytes', 'smean', 'ct_srv_dst', 'dbytes', 'ct_srv_src', 'dmean',
       'sttl', 'sload', 'dload']
selected_features1 = ['sttl', 'ct_dst_src_ltm', 'sbytes', 'ct_srv_dst', 'ct_state_ttl',
       'smean', 'dload', 'synack', 'sload', 'rate']

tags = [
    'No. for each state according to specific range of values for source/destination time to live',  # ct_state_ttl
    'Rate',  # rate
    'Source to destination time to live value',  # sttl
    'Mean of the row packet size transmitted by the destination',  # dmean
    'No. of connections of the same source and destination address in 100 connections according to the last time',  # ct_dst_src_ltm
    'Destination bits per second',  # dload
    'No. of connections that contain the same service and source address in 100 connections according to the last time',  # ct_srv_src
    'Number of data bytes transferred from source to destination in a single connection',  # sbytes
    'duration of connection', # dur
    'Source bits per second',  # sload
    'TCP connection setup round-trip time',  # tcprtt
    'SynAck',  # synack
    'No. of connections that contain the same service and destination address in 100 connections according to the last time',  # ct_srv_dst
    'Number of data bytes transferred from destination to source in a single connection',  # dbytes
    'Mean of the row packet size transmitted by the source'  # smean
]

# tags = ['No. for each state according to specific range of values for source/destination time to live',
# 'rate','Source to destination time to live value', 'Mean of the row packet size transmitted by the dst',
# 'No of connections of the same source and the destination address in 100 connections according to the last time.',
# 'Destination bits per second',
# 'No. of connections that contain the same service and source address in 100 connections according to the last time.',
# 'Number of data bytes transferred from source to destination in single connection',
# 'duration of connection', 'Source bits per second','TCP connection setup round-trip time',
# 'No. of connections that contain the same service and destination address in 100 connections according to the last time.',
# 'Number of data bytes transferred from destination to source in single connection',
# 'Mean of the row packet size transmitted by the source',
# ]


# Initialize session state variables if they don't exist
if 'running' not in st.session_state:
    st.session_state['running'] = False
if 'dataframe' not in st.session_state:
    st.session_state.dataframe = pd.DataFrame(columns=columns)
if 'new_data' not in st.session_state:
    st.session_state['new_data'] = False
if 'models_loaded' not in st.session_state:
    st.session_state.models_loaded = False


# Initialize session state variables if they don't exist
if 'scaler1' not in st.session_state:
    st.session_state.scaler1 = None

if 'scaler2' not in st.session_state:
    st.session_state.scaler2 = None

if 'att_model' not in st.session_state:
    st.session_state.att_model = None

if 'models' not in st.session_state:
    st.session_state.models = None

if 'meta_model' not in st.session_state:
    st.session_state.meta_model = None

if 'label_encoder2' not in st.session_state:
    st.session_state.label_encoder2 = None

if 'label_encoder4' not in st.session_state:
    st.session_state.label_encoder4 = None

if 'encoder' not in st.session_state:
    st.session_state.encoder = None

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
    
def super_learner_predictions(X, models, meta_model):
    meta_X = [model.predict_proba(X) for model in models]
    meta_X = hstack(meta_X)
    return meta_model.predict(meta_X)

def prepare(data):
    attack_df = data[selected_features]
    intr_df = data[selected_features1]
    attack_df = st.session_state.scaler1.transform(attack_df)
    intr_df = st.session_state.scaler2.transform(intr_df)
    return attack_df, intr_df

if st.button("Start Capture") and not st.session_state['running']:
    st.session_state['running'] = True
    with st.spinner("Capturing packets..."):
        progress_bar = st.progress(0)  # Initialize progress bar
     
        with ThreadPoolExecutor() as executor:
            future = executor.submit(start_live_capture, 'Wi-Fi 2')
            df = future.result()
           
        st.session_state.dataframe = df
        for i in range(len(st.session_state.dataframe)):
                # Update progress bar
                progress_bar.progress((i+1) / 100)
                
# data_new = start_live_capture('Wi-Fi 2')

# Display dataframe
if not st.session_state.dataframe.empty:
    st.dataframe(st.session_state.dataframe)
    data_new = st.session_state.dataframe
    data2 = data_new[col3]
    data3 = data_new[col4]

    row_num = st.number_input('Select Row, You would like to Predict', min_value=0, max_value=data2.shape[0]-1, step=1)
    new_d = data2.iloc[row_num]
    new_ddd = new_d.to_list()
    new_d = pd.DataFrame(new_d)
    new_d['Full Name'] = tags
    st.dataframe(new_d)
    feat2 = np.array(new_ddd).reshape(1,-1)
    feat2 = pd.DataFrame(feat2,columns=col3)
    # del feat2['dur']
    # if st.button('Prediction'):
    #     try:
    #         attack_df, intr_df = prepare(feat2)
    #         pred = super_learner_predictions(intr_df, st.session_state.models, st.session_state.meta_model)
    #         if pred[0] == 0:
    #            st.write("Normal Activity Permission Granted")
    #         else:
    #             pred1 = st.session_state.att_model.predict(attack_df)
    #             attack = st.session_state.label_encoder4.inverse_transform(pred1)
    #             st.warning(f"{attack[0]} Intrusion Detected")
    #             st.image("dz1.gif")

    #     except Exception as err:
    #         print(f"The error is {err}:---"*5)
            
    
if st.button('Prediction'):
    try:
        # Convert 'False' and 'True' in feat2 to 0 and 1
        feat2 = feat2.replace({'False': 0, 'True': 1})

        # Ensure all data is numeric
        feat2 = feat2.apply(pd.to_numeric, errors='coerce')

        # Prepare the data
        attack_df, intr_df = prepare(feat2)

        # Make predictions
        pred = super_learner_predictions(intr_df, st.session_state.models, st.session_state.meta_model)
        
        # Check the prediction result
        if pred[0] == 0:
            st.write("Normal Activity Permission Granted")
        else:
            pred1 = st.session_state.att_model.predict(attack_df)
            attack = st.session_state.label_encoder4.inverse_transform(pred1)
            st.warning(f"{attack[0]} Intrusion Detected")
            st.image("dz1.gif")

    except Exception as err:
        st.error(f"The error is: {err}")



# row_num = st.number_input('Select Row, You would like to Predict', min_value=0, max_value=data2.shape[0]-1, step=1)
# new_d = data2.iloc[row_num]
# new_ddd = new_d.to_list()
# new_d = pd.DataFrame(new_d)
# new_d['Full Name'] = tags
# st.dataframe(new_d)
# feat2 = np.array(new_ddd).reshape(1,-1)
# feat2 = pd.DataFrame(feat2,columns=col3)



# if st.button("Stop Capture") and st.session_state['running']:
#     st.session_state['running'] = False










# def super_learner_predictions(X, models, meta_model):
#     meta_X = list()
#     for model in models:
#         yhat = model.predict_proba(X)
#         meta_X.append(yhat)
#     meta_X = hstack(meta_X)
#     return meta_model.predict(meta_X)

# def prepare(data):
#     attack_df = data[sf]
#     intr_df = data[sf2]

#     attack_df = scaler1.transform(attack_df)
#     intr_df = scaler2.transform(intr_df)

#     return attack_df, intr_df

# # Streamlit UI
# st.title("Live Network Packet Capture")

# if 'running' not in st.session_state:
#     st.session_state['running'] = False

# if 'dataframe' not in st.session_state:
#     st.session_state.dataframe = pd.DataFrame(columns=columns)

# if 'new_data' not in st.session_state:
#     st.session_state['new_data'] = False

# # UI Controls
# if st.button("Start Capture"):
#     if not st.session_state['running']:
#         st.session_state['running'] = True

#         with st.spinner("Capturing packets..."):
#             with ThreadPoolExecutor() as executor:
#                 future = executor.submit(start_live_capture, 'Wi-Fi 2')
#                 df = future.result()

#             st.session_state.dataframe = df

#             # Load models
#             att_model = pickle.load(open('att_model.pkl', 'rb'))
#             models = pickle.load(open('sl_model.pkl', 'rb'))
#             meta_model = pickle.load(open('meta_model.pkl', 'rb'))
#             label_encoder2 = pickle.load(open('le2.pkl', 'rb'))
#             label_encoder4 = pickle.load(open('le4.pkl', 'rb'))
#             scaler1 = pickle.load(open('att_scal.pkl', 'rb'))
#             scaler2 = pickle.load(open('scal.pkl', 'rb'))
#             encoder = pickle.load(open('enc.pkl', 'rb'))

#             data_new = df

#             col3 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm','dload',
#                     'ct_srv_src','sbytes','dur', 'sload', 'tcprtt','ct_srv_dst', 
#                     'dbytes', 'smean']
#             col4 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm','dload',
#                     'ct_srv_src','sbytes','dur', 'sload', 'tcprtt','ct_srv_dst', 
#                     'dbytes', 'smean','attack_cat']

#             sf = ['dur', 'sbytes', 'dbytes', 'sttl', 'sload', 'dload', 
#                 'smean', 'dmean', 'ct_srv_src', 'ct_srv_dst']
#             sf2 =  ['sbytes', 'rate', 'sttl', 'sload', 'dload', 'tcprtt',
#                 'smean', 'ct_state_ttl', 'ct_dst_src_ltm', 'ct_srv_dst']

#             tags = ['No. for each state according to specific range of values for source/destination time to live',
#                     'rate', 'Source to destination time to live value', 'Mean of the row packet size transmitted by the dst',
#                     'No of connections of the same source and the destination address in 100 connections according to the last time.',
#                     'Destination bits per second',
#                     'No. of connections that contain the same service and source address in 100 connections according to the last time.',
#                     'Number of data bytes transferred from source to destination in single connection',
#                     'duration of connection', 'Source bits per second','TCP connection setup round-trip time',
#                     'No. of connections that contain the same service and destination address in 100 connections according to the last time.',
#                     'Number of data bytes transferred from destination to source in single connection',
#                     'Mean of the row packet size transmitted by the source']

#             data2 = data_new[col3]
#             data3 = data_new[col4]

#             row_num = st.number_input('Select Row, You would like to Predict', min_value=0, max_value=data2.shape[0]-1, step=1)
#             new_d = data2.iloc[row_num]
#             new_ddd = new_d.to_list()
#             new_d = pd.DataFrame(new_d)
#             new_d['Full Name'] = tags
#             st.dataframe(new_d)
#             feat2 = np.array(new_ddd).reshape(1,-1)
#             feat2 = pd.DataFrame(feat2,columns=col3)

#             if st.button('Prediction'):
#                 attack_df, intr_df = prepare(feat2)
#                 pred = super_learner_predictions(intr_df, models, meta_model)

#                 if pred[0] == 0:
#                     st.write("Normal Activity Permission Granted")
#                 else:
#                     pred1 = att_model.predict(attack_df)
#                     attack = label_encoder4.inverse_transform(pred1)
#                     st.warning(f"{attack[0]} Intrusion Detected")
#                     st.image("dz1.gif")

# if st.button("Stop Capture") and st.session_state['running']:
#     st.session_state['running'] = False

# if st.button("Start Capture"):
#     # Use a thread pool executor to run the capture in a separate thread
#     with ThreadPoolExecutor() as executor:
#         future = executor.submit(start_live_capture, 'Wi-Fi 2')
#         df = future.result()
#         st.dataframe(df)

#         att_model = pickle.load(open('att_model.pkl', 'rb'))
#         # intr_model = pickle.load(open('k_model.pkl', 'rb'))
#         models = pickle.load(open('sl_model.pkl', 'rb'))
#         meta_model=pickle.load(open('meta_model.pkl', 'rb'))

#         label_encoder2 = pickle.load(open('le2.pkl', 'rb'))
#         label_encoder4 = pickle.load(open('le4.pkl', 'rb'))

#         scaler1 = pickle.load(open('att_scal.pkl', 'rb'))

#         scaler2 = pickle.load(open('scal.pkl', 'rb'))

#         encoder = pickle.load(open('enc.pkl', 'rb'))

#         data_new = df

#         col3 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm',
#                 'dload','ct_srv_src','sbytes','dur', 'sload', 'tcprtt',
#                 'ct_srv_dst', 'dbytes', 'smean']

#         col4 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm',
#                 'dload','ct_srv_src','sbytes','dur', 'sload', 'tcprtt',
#                 'ct_srv_dst', 'dbytes', 'smean','attack_cat']

#         sf = ['dur', 'sbytes', 'dbytes', 'sttl', 'sload', 'dload', 
#             'smean', 'dmean', 'ct_srv_src', 'ct_srv_dst']

#         sf2 =  ['sbytes', 'rate', 'sttl', 'sload', 'dload', 'tcprtt',
#             'smean', 'ct_state_ttl', 'ct_dst_src_ltm', 'ct_srv_dst']

#         tags = ['No. for each state according to specific range of values for source/destination time to live',
#         'rate','Source to destination time to live value', 'Mean of the row packet size transmitted by the dst',
#         'No of connections of the same source and the destination address in 100 connections according to the last time.',
#         'Destination bits per second',
#         'No. of connections that contain the same service and source address in 100 connections according to the last time.',
#         'Number of data bytes transferred from source to destination in single connection',
#         'duration of connection', 'Source bits per second','TCP connection setup round-trip time',
#         'No. of connections that contain the same service and destination address in 100 connections according to the last time.',
#         'Number of data bytes transferred from destination to source in single connection',
#         'Mean of the row packet size transmitted by the source'
#         ]

#         data2 = data_new[col3]
#         data3 = data_new[col4]
#         # st.dataframe(data3)


#         row_num = st.number_input('Select Row, You would like to Predict', min_value=0, max_value=data2.shape[0]-1, step=1)
#         new_d = data2.iloc[row_num]
#         new_ddd = new_d.to_list()
#         new_d = pd.DataFrame(new_d)
#         new_d['Full Name'] = tags
#         st.dataframe(new_d)
#         feat2 = np.array(new_ddd).reshape(1,-1)
#         feat2 = pd.DataFrame(feat2,columns=col3)


#         def super_learner_predictions(X, models, meta_model):
#             meta_X = list()
#             for model in models:
#                 yhat = model.predict_proba(X)
#                 meta_X.append(yhat)
#             meta_X = hstack(meta_X)
#             # predict
#             return meta_model.predict(meta_X)


#         def prepare(data):

#             attack_df = data[sf]
#             #attack_df['service'] = label_encoder2.transform(attack_df['service'])
#             intr_df = data[sf2]

#             attack_df = scaler1.transform(attack_df)
#             intr_df = scaler2.transform(intr_df)

#             return attack_df, intr_df


#         if st.button('Prediction'):
#             attack_df, intr_df = prepare(feat2)

#             pred = super_learner_predictions(intr_df, models, meta_model)

#             if pred[0] == 0:
#                 st.write("Normal Activity Permision Granted")
#             else:
#                 pred1 = att_model.predict(attack_df)
#                 attack = label_encoder4.inverse_transform(pred1)
#                 # st.subheader(f"{attack[0]}")
#                 st.warning(f"{attack[0]} Intrusion Detected")
#                 st.image("dz1.gif")



# loop = asyncio.ProactorEventLoop()
# asyncio.set_event_loop(loop)
# loop = new_event_loop()
# set_event_loop(loop)
# results = run(coro)

# Streamlit UI
# st.title("Live Network Packet Capture")
# if st.button("Start Capture"):
#     df = start_live_capture(interface='Wi-Fi 2')  # Replace 'Wi-Fi 2' with the appropriate interface
#     st.dataframe(df)

# # Streamlit UI
# st.title("Live Network Packet Capture")
# if st.button("Start Capture"):
#     run_async_task(start_live_capture(interface='Wi-Fi 2'))  