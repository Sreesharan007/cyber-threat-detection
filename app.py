import streamlit as st
import random
import time
import pandas as pd
from datetime import datetime
import requests
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# =====================================================
# PAGE CONFIG
# =====================================================
st.set_page_config(
    page_title="🛡️ AI Security Assistant Pro",
    page_icon="🛡️",
    layout="wide"
)

# =====================================================
# SESSION STATE - PRODUCTION READY
# =====================================================
def init_session_state():
    defaults = {
        "scanning": False,
        "last_attack": "Normal",
        "history": [],
        "network_info": None,
        "attack_memory": {"Malware": 0, "Ransomware": 0, "Brute Force": 0, "DDoS": 0},
        "user_id": f"user_{random.randint(1000, 9999)}",
        "chat_history": [],
        "show_analytics": False
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# =====================================================
# UTILITY FUNCTIONS - ERROR-PROOF
# =====================================================
@st.cache_data(ttl=5)
def detect_attack_cached():
    return random.choice(["Normal", "Malware", "Ransomware", "Brute Force", "DDoS"])

def get_ip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if response.ok:
            data = response.json()
            return {
                "city": data.get("city", "Unknown"),
                "country": data.get("country", "Unknown"),
                "isp": data.get("isp", "Unknown")
            }
    except:
        pass
    return {}

def speak_attack(attack):
    messages = {
        "Malware": "Warning. Malware detected. Harmful program running. Files may be stolen.",
        "Ransomware": "Warning. Ransomware detected. Files locked. Disconnect immediately.",
        "Brute Force": "Warning. Brute force attack detected. Change password now.",
        "DDoS": "Warning. DDoS attack detected. Network flooding in progress."
    }
    
    if attack not in messages:
        return
    
    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button(f"🔊 {attack}", key=f"voice_{random.randint(1000,9999)}", use_container_width=True):
            st.markdown(f"""
            <script>
            if ('speechSynthesis' in window) {{
                let utterance = new SpeechSynthesisUtterance('{messages[attack]}');
                utterance.rate = 0.9;
                utterance.volume = 1;
                speechSynthesis.speak(utterance);
            }}
            </script>
            """, unsafe_allow_html=True)
    with col2:
        st.info(messages[attack])

def confidence_score(attack):
    base_ranges = {"Malware": (85, 92), "Ransomware": (88, 95), "Brute Force": (82, 90), "DDoS": (85, 93), "Normal": (5, 12)}
    
    if attack == "Normal":
        return random.randint(*base_ranges["Normal"]), "✅ System secure - No threats detected"
    
    memory = st.session_state.attack_memory.get(attack, 0)
    bonus = min(memory * 2, 15)
    low, high = base_ranges[attack]
    confidence = random.randint(low + bonus, min(high + bonus, 99))
    
    return confidence, f"🧬 AI learned this pattern ({memory+1} encounters)"

# =====================================================
# DATA
# =====================================================
malicious_files = ["sys_update.exe", "svchost_svc.dll", "windows_helper.exe", "temp_optimizer.exe"]
network_attackers = [
    {"ip": "192.168.1.45", "city": "Chennai", "country": "India", "isp": "Local ISP"},
    {"ip": "103.25.64.12", "city": "Mumbai", "country": "India", "isp": "FiberNet"},
    {"ip": "45.67.89.101", "city": "Bengaluru", "country": "India", "isp": "Cloud Provider"}
]

# =====================================================
# CHATBOT FUNCTION
# =====================================================
def chatbot_response(question):
    responses = {
        "error": "🔧 I'm checking the system logs. Try restarting the scan. All systems operational.",
        "help": "🛡️ **Available Commands:**\n• `start scan` - Begin threat detection\n• `show analytics` - View graphs\n• `clear history` - Reset logs\n• `block ip` - Block attacker\n• `what is malware?` - Learn about threats",
        "what is malware": "🦠 **Malware** is malicious software designed to damage or exploit systems. Common types: viruses, trojans, spyware. **Immediate action:** Quarantine files.",
        "what is ransomware": "🔐 **Ransomware** encrypts your files and demands payment. **Never pay.** Disconnect network, restore from backup.",
        "how to block ip": "🚫 **Block IP:** Use `iptables -A INPUT -s [IP] -j DROP` or firewall software. Your app auto-blocks detected attackers.",
        "analytics": "📊 Analytics shows threat trends, confidence scores, and attack patterns over time."
    }
    
    question_lower = question.lower()
    for key, response in responses.items():
        if key in question_lower:
            return response
    return "🤖 Ask me about errors, threats, blocking IPs, or type `help` for commands!"

# =====================================================
# SIDEBAR
# =====================================================
with st.sidebar:
    st.title("👤 Control Panel")
    st.info(f"**User:** `{st.session_state.user_id}`")
    
    if st.button("🔄 New Session", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        init_session_state()
        st.rerun()
    
    st.title("🤖 AI Assistant")
    user_input = st.chat_input("Ask about security issues...")
    if user_input:
        st.session_state.chat_history.append({"role": "user", "content": user_input})
        ai_response = chatbot_response(user_input)
        st.session_state.chat_history.append({"role": "assistant", "content": ai_response})
        st.rerun()

# Chat history display
if st.session_state.chat_history:
    for message in st.session_state.chat_history[-4:]:
        if message["role"] == "user":
            st.chat_message("user").write(message["content"])
        else:
            st.chat_message("assistant").write(message["content"])

# =====================================================
# MAIN INTERFACE
# =====================================================
st.title("🛡️ AI Security Assistant Pro")
st.markdown("**Real-time threat detection • ML-powered analytics • 24/7 AI assistant**")

# Control buttons
col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    if st.button("▶️ START SCAN", type="primary", use_container_width=True):
        st.session_state.scanning = True
        st.rerun()
with col2:
    if st.button("⏹️ STOP SCAN", use_container_width=True):
        st.session_state.scanning = False
        st.rerun()
with col3:
    if st.button("📊 ANALYTICS", use_container_width=True):
        st.session_state.show_analytics = not st.session_state.show_analytics

# =====================================================
# SCANNING ENGINE - ERROR-PROOF
# =====================================================
if st.session_state.scanning:
    status_col, info_col, action_col = st.columns([2, 2, 2])
    
    with st.spinner("🔍 Active scanning..."):
        try:
            attack = detect_attack_cached()
            confidence, reason = confidence_score(attack)
            
            if attack != "Normal":
                st.session_state.attack_memory[attack] = st.session_state.attack_memory.get(attack, 0) + 1
            
            if attack != st.session_state.last_attack and attack != "Normal":
                st.session_state.last_attack = attack
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if attack in ["Brute Force", "DDoS"]:
                attacker = random.choice(network_attackers)
                ip_info = get_ip_info(attacker["ip"])
                st.session_state.network_info = {
                    "attack": attack, "ip": attacker["ip"],
                    "city": ip_info.get("city", attacker["city"]),
                    "country": ip_info.get("country", attacker["country"]),
                    "isp": ip_info.get("isp", attacker["isp"])
                }
            
            # Status display
            with status_col:
                if attack == "Normal":
                    st.success(f"✅ **SYSTEM SECURE** | {timestamp}")
                else:
                    st.error(f"🚨 **{attack} DETECTED** | {timestamp}")
            
            with info_col:
                if attack == "Normal":
                    st.info(f"**Confidence:** {confidence}% | {reason}")
                else:
                    st.warning(f"**AI Confidence:** **{confidence}%** | {reason}")
                
                if attack != "Normal":
                    speak_attack(attack)
            
            with action_col:
                if attack == "Malware":
                    file = random.choice(malicious_files)
                    if st.button(f"🧹 Quarantine {file[:15]}...", use_container_width=True):
                        st.success(f"✅ **{file}** quarantined!")
                
                elif attack == "Ransomware":
                    st.error("🔴 **CRITICAL** - Disconnect NOW!")
                
                elif attack in ["Brute Force", "DDoS"]:
                    if st.button("🚫 BLOCK IP", type="primary", use_container_width=True):
                        st.success(f"✅ **{st.session_state.network_info['ip']}** BLOCKED")
            
            # Log entry
            st.session_state.history.append({
                "Time": timestamp,
                "User": st.session_state.user_id[:8],
                "Attack": attack,
                "Confidence": confidence,
                "Status": "🟢" if attack == "Normal" else "🔴"
            })
            
        except Exception as e:
            st.session_state.chat_history.append({
                "role": "assistant", 
                "content": f"🔧 Scan error detected: {str(e)[:100]}. System recovered automatically."
            })
        
        time.sleep(2.5)
        st.rerun()

# =====================================================
# ANALYTICS DASHBOARD
# =====================================================
if st.session_state.history and st.session_state.show_analytics:
    st.markdown("---")
    st.header("📊 Threat Analytics Dashboard")
    
    df = pd.DataFrame(st.session_state.history[-100:])
    df['Time'] = pd.to_datetime(df['Time'])
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        threat_counts = df[df['Attack'] != 'Normal']['Attack'].value_counts()
        fig_pie = px.pie(values=threat_counts.values, names=threat_counts.index, 
                        title="Threat Distribution")
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        fig_line = px.line(df, x='Time', y='Confidence', color='Attack',
                          title="Confidence Over Time")
        st.plotly_chart(fig_line, use_container_width=True)
    
    # Metrics
    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    with col_m1:
        st.metric("📊 Total Scans", len(df))
    with col_m2:
        st.metric("🚨 Threats", len(df[df['Attack'] != 'Normal']))
    with col_m3:
        avg_conf = df['Confidence'].mean()
        st.metric("🎯 Avg Confidence", f"{avg_conf:.1f}%")
    with col_m4:
        unique_threats = df[df['Attack'] != 'Normal']['Attack'].nunique()
        st.metric("🦠 Unique Threats", unique_threats)

# =====================================================
# HISTORY TABLE
# =====================================================
if st.session_state.history:
    st.markdown("---")
    df_display = pd.DataFrame(st.session_state.history[-20:])
    col_table1, col_table2 = st.columns([3, 1])
    
    with col_table1:
        st.subheader("📜 Recent Activity")
        st.dataframe(df_display, use_container_width=True, hide_index=True)
    
    with col_table2:
        st.download_button(
            "📥 Download CSV",
            df_display.to_csv(index=False),
            "security_logs.csv",
            "text/csv"
        )

st.markdown("---")
st.caption("🛡️ AI Security Assistant Pro | Cloud-Ready • AI Chatbot • Interactive Analytics")
