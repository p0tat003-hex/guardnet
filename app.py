import streamlit as st
import pandas as pd
import numpy as np
import joblib
import subprocess
import ipaddress
import logging
import altair as alt  # For creating interactive and visually appealing charts
from streamlit_autorefresh import st_autorefresh

# ---------------------------
# Configuration and Setup
# ---------------------------

# Define file paths for the CSV output and log files
CSV_FILE = 'Outputs/labeled_combined_output.csv'
LOG_FILE = 'Logs/app.log'

# Set the title of the Streamlit app
st.title('Real-Time DDoS Attack Detection')

# Configure logging to capture events and errors
logging.basicConfig(
    level=logging.INFO,
    filename=LOG_FILE,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# ---------------------------
# Load Machine Learning Model
# ---------------------------

@st.cache_resource
def load_model():
    """
    Load the pre-trained machine learning model and scaler from disk.

    Returns:
        model: Trained machine learning model for predictions.
        scaler: Scaler used for feature normalization.
    """
    model = joblib.load('models/model.pkl')
    scaler = joblib.load('models/scaler.pkl')
    return model, scaler


# Load the model and scaler
model, scaler = load_model()

# ---------------------------
# Define Attack Types
# ---------------------------

# Mapping of numerical labels to human-readable attack types
ATTACK_MAPPING = {
    0: 'Normal Traffic',
    1: 'Hulk Attack',
    2: 'Slowloris Attack',
    # Add more attack types as per your model's classes
}

# ---------------------------
# Feature Definitions
# ---------------------------

# List of feature names expected by the model
TRAINING_FEATURES = [
    'src_port', 'dst_port', 'protocol', 'flow_duration', 'flow_byts_s', 'flow_pkts_s',
    'fwd_pkts_s', 'bwd_pkts_s', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts',
    'totlen_bwd_pkts', 'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean',
    'fwd_pkt_len_std', 'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean',
    'bwd_pkt_len_std', 'pkt_len_max', 'pkt_len_min', 'pkt_len_mean', 'pkt_len_std',
    'pkt_len_var', 'fwd_header_len', 'bwd_header_len', 'fwd_seg_size_min',
    'fwd_act_data_pkts', 'flow_iat_mean', 'flow_iat_max', 'flow_iat_min',
    'flow_iat_std', 'fwd_iat_tot', 'fwd_iat_max', 'fwd_iat_min', 'fwd_iat_mean',
    'fwd_iat_std', 'bwd_iat_tot', 'bwd_iat_max', 'bwd_iat_min', 'bwd_iat_mean',
    'bwd_iat_std', 'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags',
    'bwd_urg_flags', 'fin_flag_cnt', 'syn_flag_cnt', 'rst_flag_cnt',
    'psh_flag_cnt', 'ack_flag_cnt', 'urg_flag_cnt', 'ece_flag_cnt',
    'down_up_ratio', 'pkt_size_avg', 'init_fwd_win_byts', 'init_bwd_win_byts',
    'active_max', 'active_min', 'active_mean', 'active_std', 'idle_max',
    'idle_min', 'idle_mean', 'idle_std', 'fwd_byts_b_avg', 'fwd_pkts_b_avg',
    'bwd_byts_b_avg', 'bwd_pkts_b_avg', 'fwd_blk_rate_avg', 'bwd_blk_rate_avg',
    'fwd_seg_size_avg', 'bwd_seg_size_avg', 'cwr_flag_count', 'subflow_fwd_pkts',
    'subflow_bwd_pkts', 'subflow_fwd_byts', 'subflow_bwd_byts'
]

# ---------------------------
# Session State Initialization
# ---------------------------

# Initialize a set to keep track of blocked IPs in the session state
if 'blocked_ips' not in st.session_state:
    st.session_state['blocked_ips'] = set()


# ---------------------------
# Helper Functions
# ---------------------------

def is_valid_ip(ip):
    """
    Validate if a string is a valid IP address.

    Args:
        ip (str): The IP address to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def block_ip(ip_address):
    """
    Block a given IP address using iptables.

    Args:
        ip_address (str): The IP address to block.
    """
    if is_valid_ip(ip_address):
        command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        subprocess.run(command, shell=True)
        logging.info(f"Blocked IP: {ip_address}")
        st.session_state['blocked_ips'].add(ip_address)  # Add IP to blocked list
    else:
        logging.warning(f"Invalid IP address: {ip_address}")


def unblock_ip(ip_address):
    """
    Unblock a given IP address using iptables.

    Args:
        ip_address (str): The IP address to unblock.
    """
    if is_valid_ip(ip_address):
        command = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
        subprocess.run(command, shell=True)
        logging.info(f"Unblocked IP: {ip_address}")
        st.session_state['blocked_ips'].discard(ip_address)  # Remove IP from blocked list
    else:
        logging.warning(f"Invalid IP address: {ip_address}")


@st.cache_data(ttl=2)
def read_and_process_data(csv_file):
    """
    Read the CSV file containing network flow data, preprocess it,
    perform scaling, and make predictions using the loaded model.

    Args:
        csv_file (str): Path to the CSV file.

    Returns:
        df (pd.DataFrame): The processed DataFrame with predictions.
        attacker_ips (pd.Series): Series containing attacker IPs and their attack counts.
    """
    try:
        df = pd.read_csv(csv_file)
    except (pd.errors.EmptyDataError, FileNotFoundError):
        # Return empty structures if file is not found or empty
        return pd.DataFrame(), pd.Series(dtype=int)

    if df.empty:
        return df, pd.Series(dtype=int)

    # Ensure all required features are present in the DataFrame
    for col in TRAINING_FEATURES:
        if col not in df.columns:
            df[col] = 0  # Assign default value if missing

    # Preprocess the data: handle missing and infinite values
    df.fillna(0, inplace=True)
    df.replace([np.inf, -np.inf], 0, inplace=True)

    # Scale the features using the loaded scaler
    X_scaled = scaler.transform(df[TRAINING_FEATURES])

    # Make predictions using the loaded model
    predictions = model.predict(X_scaled)
    df['Label'] = predictions  # Add predictions to the DataFrame

    # Filter out normal traffic (Label 0) and exclude local IP addresses
    attack_df = df[df['Label'] != 0]
    public_ips = attack_df[~attack_df['src_ip'].str.startswith(('10.', '172.', '192.168.100'))]
    attacker_ips = public_ips['src_ip'].value_counts()

    return df, attacker_ips


def start_cicflowmeter(interfaces, output_file):
    """
    Start the CICFlowMeter tool to capture network traffic on specified interfaces.

    Args:
        interfaces (list): List of network interfaces to monitor.
        output_file (str): Path to the output CSV file.
    """
    # Build the command to run CICFlowMeter with multiple interfaces
    command = ['sudo', 'cicflowmeter']
    for interface in interfaces:
        command.extend(['-i', interface])
    command.extend(['-c', output_file])

    try:
        # Start CICFlowMeter as a non-blocking subprocess
        subprocess.Popen(command)
        logging.info(f"CICFlowMeter started on interfaces: {', '.join(interfaces)}")
    except Exception as e:
        st.error(f"Error starting CICFlowMeter: {e}")
        logging.error(f"Failed to start CICFlowMeter: {e}")


# ---------------------------
# Streamlit Application Structure
# ---------------------------

def main():
    """
    Main function to control the flow of the Streamlit app.
    It sets up the sidebar navigation and renders the selected tab.
    """
    st.sidebar.title("Navigation")
    selected_tab = st.sidebar.radio("Select a tab", ["Dashboard", "Logs"])

    if selected_tab == "Dashboard":
        dashboard_tab()
    elif selected_tab == "Logs":
        logs_tab()


def dashboard_tab():
    """
    Renders the Dashboard tab, which includes:
    - Input fields for network interfaces and output CSV path.
    - Button to start CICFlowMeter.
    - Display of detected attacks with counts and visualizations.
    - Attacker IPs with blocking options.
    """
    st.header("Dashboard")

    # Automatically refresh the app every 2 seconds to display real-time data
    st_autorefresh(interval=2000, limit=None, key="datarefresh")

    # Input field for specifying network interfaces (comma-separated)
    interface_input = st.text_input(
        "Enter the capture interface(s) (comma-separated):",
        value='vboxnet0'
    )
    interfaces = [iface.strip() for iface in interface_input.split(',')]

    # Input field for specifying the output CSV file path
    output_file = st.text_input("Enter the output CSV path:", value=CSV_FILE)

    # Button to start the CICFlowMeter process
    if st.button("Start CICFlowMeter"):
        start_cicflowmeter(interfaces, output_file)
        st.success("CICFlowMeter has been started.")

    # Read and process the captured data
    df, ips = read_and_process_data(output_file)

    # Check if there is any data to display
    if not df.empty:
        detected_attacks = df['Label'].value_counts()
        # Remove the Normal Traffic (label 0) from the count
        detected_attacks = detected_attacks.drop(index=0, errors='ignore')

        if not detected_attacks.empty:
            st.warning("🚨 DDoS attack(s) detected!")

            # Map numerical labels to attack names
            attack_counts = detected_attacks.rename(index=ATTACK_MAPPING)

            # Prepare data for display and visualization
            attack_data = attack_counts.reset_index()
            attack_data.columns = ['Attack Type', 'Count']

            # Display each attack type and its occurrence
            st.markdown("### Detected Attack Types and Occurrences:")
            for _, row in attack_data.iterrows():
                st.write(f"**{row['Attack Type']}:** {row['Count']} occurrence(s)")

            # Create an interactive bar chart using Altair
            st.markdown("### Attack Types Distribution")
            chart = alt.Chart(attack_data).mark_bar(color='firebrick').encode(
                x=alt.X('Attack Type', sort='-y', title='Attack Type'),
                y=alt.Y('Count', title='Number of Occurrences'),
                tooltip=['Attack Type', 'Count']
            ).properties(
                width=700,
                height=400,
                title='DDoS Attack Types Distribution'
            ).configure_title(
                fontSize=20,
                anchor='middle'
            ).configure_axis(
                labelFontSize=12,
                titleFontSize=14
            )

            st.altair_chart(chart, use_container_width=True)

            # Display attacker IPs and provide blocking options
            st.markdown("### Attacker IPs:")
            if not ips.empty:
                top_ip = ips.idxmax()  # IP with the highest number of attacks
                top_ip_count = ips.max()  # Number of attacks from the top IP

                col1, col2 = st.columns([3, 1])
                col1.write(f"**{top_ip}**: {top_ip_count} attack(s)")

                # Button to block the top attacker IP if not already blocked
                if top_ip not in st.session_state['blocked_ips']:
                    if col2.button(f"Block {top_ip}", key=f"block_{top_ip}"):
                        block_ip(top_ip)
                        st.success(f"Blocked IP {top_ip}")
                else:
                    col2.write("Already blocked")
        else:
            st.success("✅ No DDoS attack detected.")

        # Optionally display the raw captured data in an expandable section
        with st.expander("Show Captured Data"):
            st.dataframe(df)
    else:
        st.info("No captured data available. Start CICFlowMeter to capture traffic.")


def logs_tab():
    """
    Renders the Logs tab, which includes:
    - Display of the application log file.
    - List of blocked IPs with options to unblock them.
    """
    st.header("Logs and Blocked IPs")

    # Display the contents of the log file
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.read()
        st.subheader("Log File Contents")
        st.text_area("Logs", logs, height=300)
    except FileNotFoundError:
        st.warning("Log file not found.")

    # Display the list of blocked IPs with an option to unblock each
    if st.session_state['blocked_ips']:
        st.subheader("Blocked IPs")
        for ip in sorted(st.session_state['blocked_ips']):
            col1, col2 = st.columns([3, 1])
            col1.write(ip)
            if col2.button(f"Unblock {ip}", key=f"unblock_{ip}"):
                unblock_ip(ip)
                st.success(f"Unblocked IP {ip}")
    else:
        st.info("No IPs have been blocked.")


# ---------------------------
# Run the Application
# ---------------------------

if __name__ == "__main__":
    main()
