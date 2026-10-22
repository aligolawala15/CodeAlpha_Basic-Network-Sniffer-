
import csv
import threading
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from scapy.all import sniff, IP, TCP, UDP, ICMP


# ---------------- CONFIGURATION ----------------

st.set_page_config(
    page_title="CodeAlpha | Network Sniffer",
    page_icon="🛡️",
    layout="wide",
)

BASE_DIR = Path(__file__).resolve().parent
CSV_FILE = BASE_DIR / "packets.csv"

COLUMNS = [
    "Timestamp",
    "Packet Number",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Packet Size",
    "Payload Preview",
]

CSV_LOCK = threading.Lock()


# ---------------- CSV MANAGEMENT ----------------

def ensure_csv():
    """Create the CSV or migrate the older sniffer CSV format."""
    if not CSV_FILE.exists() or CSV_FILE.stat().st_size == 0:
        with CSV_FILE.open("w", newline="", encoding="utf-8") as file:
            csv.DictWriter(file, fieldnames=COLUMNS).writeheader()
        return

    with CSV_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        old_columns = reader.fieldnames or []
        rows = list(reader)

    if old_columns == COLUMNS:
        return

    # Convert records from the original sniffer's CSV format.
    converted = []
    for row in rows:
        converted.append({
            "Timestamp": row.get("Timestamp", ""),
            "Packet Number": row.get("Packet Number", ""),
            "Source IP": row.get("Source IP", ""),
            "Destination IP": row.get("Destination IP", ""),
            "Protocol": row.get("Protocol", "Other"),
            "Source Port": row.get("Source Port", ""),
            "Destination Port": row.get("Destination Port", ""),
            "Packet Size": row.get("Packet Size", ""),
            "Payload Preview": row.get("Payload Preview", ""),
        })

    with CSV_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(converted)


def read_packets():
    ensure_csv()

    try:
        with CSV_LOCK:
            data = pd.read_csv(CSV_FILE)
    except (pd.errors.EmptyDataError, PermissionError):
        return pd.DataFrame(columns=COLUMNS)

    for column in COLUMNS:
        if column not in data.columns:
            data[column] = ""

    data["Packet Size"] = pd.to_numeric(
        data["Packet Size"], errors="coerce"
    ).fillna(0)

    data["Packet Number"] = pd.to_numeric(
        data["Packet Number"], errors="coerce"
    )

    for column in [
        "Source IP", "Destination IP", "Protocol",
        "Source Port", "Destination Port",
        "Timestamp", "Payload Preview",
    ]:
        data[column] = data[column].fillna("").astype(str)

    return data[COLUMNS]


# ---------------- PACKET CAPTURE ----------------

def capture_packets(stop_event, interface, bpf_filter, errors):
    """Capture traffic until the stop event is set."""
    packet_number = len(read_packets())

    def handle_packet(packet):
        nonlocal packet_number

        if IP not in packet:
            return

        packet_number += 1
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        source_port = ""
        destination_port = ""

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        # Store only a short preview; this is not full payload inspection.
        try:
            payload = bytes(packet[IP].payload)
            payload_preview = repr(payload[:40]) if payload else ""
        except Exception:
            payload_preview = ""

        record = {
            "Timestamp": datetime.now().astimezone().isoformat(
                timespec="seconds"
            ),
            "Packet Number": packet_number,
            "Source IP": source_ip,
            "Destination IP": destination_ip,
            "Protocol": protocol,
            "Source Port": source_port,
            "Destination Port": destination_port,
            "Packet Size": len(packet),
            "Payload Preview": payload_preview,
        }

        with CSV_LOCK:
            with CSV_FILE.open(
                "a", newline="", encoding="utf-8"
            ) as file:
                writer = csv.DictWriter(file, fieldnames=COLUMNS)
                writer.writerow(record)

    try:
        while not stop_event.is_set():
            sniff(
                iface=interface or None,
                filter=bpf_filter or None,
                prn=handle_packet,
                store=False,
                timeout=1,
            )
    except Exception as exc:
        errors.append(str(exc))


# ---------------- SESSION STATE ----------------

if "capture_thread" not in st.session_state:
    st.session_state.capture_thread = None
if "stop_event" not in st.session_state:
    st.session_state.stop_event = None
if "capture_errors" not in st.session_state:
    st.session_state.capture_errors = []


# ---------------- SIDEBAR ----------------

with st.sidebar:
    st.title("🛡️ CodeAlpha")
    st.caption("NETWORK SNIFFER")
    st.divider()

    st.subheader("Capture Controls")

    interface = st.text_input(
        "Network interface",
        placeholder="Leave blank for default",
        help="Optional Scapy interface name. Leave blank to use the default.",
    )

    bpf_filter = st.text_input(
        "BPF capture filter",
        placeholder="e.g. tcp or udp or icmp",
        help="Optional packet filter. Leave blank to capture all IP protocols.",
    )

    current_thread = st.session_state.capture_thread
    is_running = (
        current_thread is not None and current_thread.is_alive()
    )

    if not is_running:
        if st.button("▶ Start Capture", use_container_width=True):
            ensure_csv()
            st.session_state.capture_errors = []
            event = threading.Event()
            thread = threading.Thread(
                target=capture_packets,
                args=(
                    event,
                    interface.strip(),
                    bpf_filter.strip(),
                    st.session_state.capture_errors,
                ),
                daemon=True,
            )
            st.session_state.stop_event = event
            st.session_state.capture_thread = thread
            thread.start()
            st.rerun()
    else:
        st.success("Capture is running")
        if st.button("⏹ Stop Capture", use_container_width=True):
            st.session_state.stop_event.set()
            st.rerun()

    if st.button("🔄 Refresh Dashboard", use_container_width=True):
        st.rerun()

    st.divider()
    st.caption("For authorized educational and lab use only.")


# ---------------- DASHBOARD HEADER ----------------

st.title("🛡️ Network Traffic Monitor")
st.caption(
    "CodeAlpha Cyber Security Internship | "
    "Capture, analyze, filter, and export network packets"
)

current_thread = st.session_state.capture_thread
is_running = (
    current_thread is not None and current_thread.is_alive()
)

if is_running:
    st.info("🟢 Live capture is active. Dashboard data refreshes automatically.")
else:
    st.warning("⚪ Capture is stopped. You can still analyze saved packets.")

if st.session_state.capture_errors:
    st.error(
        "Capture error: " + st.session_state.capture_errors[-1]
        + "\n\nCheck that Npcap is installed, the interface/filter is valid, "
        "and PowerShell has the required permissions."
    )


# ---------------- LIVE DASHBOARD ----------------

@st.fragment(run_every=2)
def render_dashboard():
    data = read_packets()

    total_packets = len(data)
    total_bytes = int(data["Packet Size"].sum())

    protocol_counts = (
        data["Protocol"].str.upper()
        .value_counts()
        .reindex(["TCP", "UDP", "ICMP", "Other"], fill_value=0)
    )

    tcp_count = int(protocol_counts["TCP"])
    udp_count = int(protocol_counts["UDP"])
    icmp_count = int(protocol_counts["ICMP"])

    # Summary cards
    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Total Packets", f"{total_packets:,}")
    c2.metric("TCP Packets", f"{tcp_count:,}")
    c3.metric("UDP Packets", f"{udp_count:,}")
    c4.metric("ICMP Packets", f"{icmp_count:,}")
    c5.metric("Traffic Size", f"{total_bytes:,} B")

    st.divider()

    # Charts
    left, right = st.columns(2)

    with left:
        st.subheader("Protocol Distribution")
        chart_data = pd.DataFrame({
            "Protocol": protocol_counts.index,
            "Packets": protocol_counts.values,
        })
        chart_data = chart_data[chart_data["Packets"] > 0]

        if not chart_data.empty:
            fig = px.pie(
                chart_data,
                names="Protocol",
                values="Packets",
                hole=0.55,
                title="Captured packets by protocol",
            )
            fig.update_layout(
                template="plotly_dark",
                margin=dict(t=50, b=10, l=10, r=10),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No packets captured yet.")

    with right:
        st.subheader("Packet Volume")
        if not data.empty:
            chart_data = (
                data["Protocol"].str.upper()
                .value_counts()
                .rename_axis("Protocol")
                .reset_index(name="Packets")
            )
            fig = px.bar(
                chart_data,
                x="Protocol",
                y="Packets",
                color="Protocol",
                title="Packets per protocol",
            )
            fig.update_layout(
                template="plotly_dark",
                showlegend=False,
                margin=dict(t=50, b=10, l=10, r=10),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("The chart will appear after packets are captured.")

    st.divider()

    # Filters
    st.subheader("Packet Explorer")

    f1, f2, f3 = st.columns([1, 1, 2])

    protocols = ["All"] + sorted(
        p for p in data["Protocol"].unique() if p
    )

    with f1:
        selected_protocol = st.selectbox(
            "Protocol", protocols
        )

    with f2:
        source_search = st.text_input(
            "Source IP contains", placeholder="e.g. 192.168"
        )

    with f3:
        destination_search = st.text_input(
            "Destination IP contains", placeholder="e.g. 8.8.8.8"
        )

    filtered = data.copy()

    if selected_protocol != "All":
        filtered = filtered[
            filtered["Protocol"].str.upper()
            == selected_protocol.upper()
        ]

    if source_search.strip():
        filtered = filtered[
            filtered["Source IP"].str.contains(
                source_search.strip(), case=False, regex=False
            )
        ]

    if destination_search.strip():
        filtered = filtered[
            filtered["Destination IP"].str.contains(
                destination_search.strip(), case=False, regex=False
            )
        ]

    st.caption(
        f"Showing {len(filtered):,} of {len(data):,} packets"
    )

    display_columns = [
        "Timestamp",
        "Packet Number",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Source Port",
        "Destination Port",
        "Packet Size",
    ]

    st.dataframe(
        filtered[display_columns].iloc[::-1],
        use_container_width=True,
        hide_index=True,
    )

    # Packet detail inspector
    st.subheader("Packet Details")

    if not filtered.empty:
        options = filtered["Packet Number"].dropna().tolist()
        if options:
            selected_number = st.selectbox(
                "Select packet number",
                options,
                format_func=lambda n: f"Packet {int(n)}",
            )

            selected_rows = filtered[
                filtered["Packet Number"] == selected_number
            ]

            if not selected_rows.empty:
                packet = selected_rows.iloc[0]
                d1, d2 = st.columns(2)

                with d1:
                    st.write("**Source:**", packet["Source IP"])
                    st.write("**Destination:**", packet["Destination IP"])
                    st.write("**Protocol:**", packet["Protocol"])
                    st.write("**Packet size:**", int(packet["Packet Size"]), "bytes")

                with d2:
                    st.write("**Source port:**", packet["Source Port"] or "N/A")
                    st.write("**Destination port:**", packet["Destination Port"] or "N/A")
                    st.write("**Timestamp:**", packet["Timestamp"] or "N/A")

                st.write("**Payload preview:**")
                st.code(packet["Payload Preview"] or "No preview available")
    else:
        st.info("No packets match these filters.")

    # Export filtered or complete data
    st.divider()
    st.subheader("Export Data")

    e1, e2 = st.columns(2)

    with e1:
        st.download_button(
            "⬇ Download Filtered CSV",
            data=filtered.to_csv(index=False).encode("utf-8"),
            file_name="filtered_packets.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with e2:
        st.download_button(
            "⬇ Download All Packets",
            data=data.to_csv(index=False).encode("utf-8"),
            file_name="all_packets.csv",
            mime="text/csv",
            use_container_width=True,
        )

    st.caption(
        "Packet records are stored locally in packets.csv. "
        "Payload previews may contain sensitive data; handle exports carefully."
    )


render_dashboard()
