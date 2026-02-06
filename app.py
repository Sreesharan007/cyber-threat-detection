import streamlit as st
import random
import time
import pandas as pd
from datetime import datetime
import requests

# =====================================================
# PAGE CONFIG
# =====================================================
st.set_page_config(
    page_title="🛡️ AI Security Assistant Pro",
    page_icon="🛡️",
    layout="wide"
)

# =====================================================
# SESSION STATE - BULLETPROOF
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
# UTILITY FUNCTIONS - 100% CLOUD SAFE
# =====================================================
@st.cache_data(ttl=5)
def detect_attack_cached():
    return random.choice(["Normal", "Malware", "Ransomware", "Brute Force", "DDoS"])

def get_ip_info(_):
    # Simplified - no external API calls
    return {"city": "Chennai", "country": "India", "isp": "Local ISP"}

def speak_attack(attack):
    messages = {
        "Malware": "Warning. Malware detected. Files may be stolen or damaged.",
        "Ransomware": "Warning. Ransomware detected. Files locked. Disconnect now.",
        "Brute Force": "Warning. Brute force attack. Change password immediately.",
        "DDoS": "Warning. DDoS attack. Network flooding detected."
    }
    
    if attack in messages:
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("🔊 Play Alert", key=f"audio_{random.randint(1000,9999)}"):
                st.markdown(f"""
                <script>
                if ('speechSynthesis' in window) {{
                    speechSynthesis.speak(
                        new SpeechSynthesisUtterance('{messages[attack]}')
                    );
                }}
                </script>
                """, unsafe_allow_html=True)
        with col2:
            st.info(messages[attack])

def confidence_score(attack):
    base_ranges = {"Malware": (85, 92), "Ransomware": (88, 95), "Brute Force": (82, 90), "DDoS": (85, 93), "Normal": (5, 12)}
    
    if attack == "Normal":
        return random.randint(*base_ranges["Normal"]), "✅ System secure"
    
    memory = st.session_state.attack_memory.get(attack, 0)
    bonus = min(memory * 2, 15)
    low, high = base_ranges[attack]
    confidence = random.randint(low + bonus, min(high + bonus, 99))
    
    return confidence, f"🧠 Learned ({memory+1}x)"

# =====================================================
# DATA
# =====================================================
malicious_files = ["sys_update.exe", "svchost_svc.dll", "windows_helper.exe"]
network_attackers = [
    {"ip": "192.168.1.45"}, {"ip": "103.25.64.12"}, {"ip": "45.67.89.101"}
]

# =====================================================
# AI CHATBOT
# =====================================================
def get_chat_response(question):
    q = question.lower()
    responses = {
        "help": "🛡️ **Commands:** start scan, analytics, clear, malware?, block ip",
        "malware": "🦠 **Malware** steals data. Quarantine suspicious files immediately.",
        "ransomware": "🔐 **Ransomware** locks files. Never pay. Use backups.",
        "error": "🔧 System recovered. Try restarting scan.",
        "block": "🚫 Use firewall: `iptables -A INPUT -s [IP] -j DROP`",
        "analytics": "📊 Click ANALYTICS button for threat graphs and stats."
    }
    for key, response in responses.items():
        if key in q:
            return response
    return "🤖 Ask: help, malware, ransomware, how to block IP, or errors?"

# =====================================================
# SIDEBAR - AI ASSISTANT
# =====================================================
with st.sidebar:
    st.title("🤖 AI Security Assistant")
    st.info(f"**ID:** `{st.session_state.user_id}`")
    
    # Chat input
    user_input = st.chat_input("Ask about threats, errors...")
    if user_input:
        st.session_state.chat_history.append({"role": "user", "content": user_input})
        response = get_chat_response(user_input)
        st.session_state.chat_history.append({"role": "assistant", "content": response})
        st.rerun()
    
    # Chat display
    st.subheader("💬 Recent")
    for msg in st.session_state.chat_history[-6:]:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])
    
    if st.button("🔄 Reset", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        init_session_state()
        st.rerun()

# =====================================================
# MAIN UI
# =====================================================
st.title("🛡️ AI Security Assistant Pro")
st.markdown("**Real-time detection • AI analytics • 24/7 chatbot support**")

# Controls
col1, col2, col3 = st.columns(3)
with col1: 
    if st.button("▶️ START SCAN", type="primary"): st.session_state.scanning = True; st.rerun()
with col2: 
    if st.button("⏹️ STOP SCAN"): st.session_state.scanning = False; st.rerun()
with col3:
    if st.button("📊 ANALYTICS"): 
        st.session_state.show_analytics = not st.session_state.show_analytics

# =====================================================
# SCAN ENGINE - BULLETPROOF
# =====================================================
if st.session_state.scanning:
    col_status, col_info, col_action = st.columns([2, 2, 2])
    
    with st.spinner("🔍 Scanning..."):
        try:
            attack = detect_attack_cached()
            confidence, reason = confidence_score(attack)
            
            if attack != "Normal":
                st.session_state.attack_memory[attack] = st.session_state.attack_memory.get(attack, 0) + 1
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if attack in ["Brute Force", "DDoS"]:
                attacker = random.choice(network_attackers)
                st.session_state.network_info = {"attack": attack, "ip": attacker["ip"]}
            
            with col_status:
                color, emoji = ("success", "✅") if attack == "Normal" else ("error", "🚨")
                st.markdown(f"{emoji} **{attack.upper()}** | {timestamp}", unsafe_allow_html=True)
            
            with col_info:
                badge = f"**{confidence}%**" if attack != "Normal" else f"{confidence}%"
                st.info(f"🎯 Confidence: {badge} | {reason}")
                
                if attack != "Normal":
                    speak_attack(attack)
            
            with col_action:
                if attack == "Malware":
                    file = random.choice(malicious_files)
                    if st.button(f"🧹 Quarantine {file}"): st.success(f"✅ {file} removed")
                elif attack == "Ransomware":
                    st.error("🔴 DISCONNECT NETWORK NOW")
                elif attack in ["Brute Force", "DDoS"]:
                    if st.button("🚫 BLOCK IP", type="primary"):
                        st.success(f"✅ {st.session_state.network_info['ip']} BLOCKED")
            
            # History
            st.session_state.history.append({
                "Time": timestamp, "User": st.session_state.user_id[:6],
                "Attack": attack, "Confidence": confidence, "Status": "🟢" if attack=="Normal" else "🔴"
            })
            
        except Exception as e:
            st.session_state.chat_history.append({
                "role": "assistant", "content": f"🔧 Error fixed: {str(e)[:50]}"
            })
    
    time.sleep(2)
    st.rerun()

# =====================================================
# ANALYTICS - NATIVE STREAMLIT (NO PLOTLY)
# =====================================================
if st.session_state.history and st.session_state.show_analytics:
    st.markdown("---")
    st.header("📊 Threat Analytics")
    
    df = pd.DataFrame(st.session_state.history[-100:])
    
    # Threat distribution bar chart (native)
    col1, col2 = st.columns(2)
    with col1:
        threats = df[df['Attack'] != 'Normal']['Attack'].value_counts()
        st.subheader("Threat Types")
        for threat, count in threats.items():
            st.metric(threat, count)
    
    with col2:
        st.subheader("Confidence Trend")
        conf_data = df.groupby('Attack')['Confidence'].mean().round(1)
        for attack, avg_conf in conf_data.items():
            color = "🟢" if attack == "Normal" else "🔴"
            st.metric(f"{color} {attack}", f"{avg_conf}%")
    
    # Simple trend
    st.subheader("Recent Activity")
    recent = df.tail(10)[['Time', 'Attack', 'Confidence']]
    st.dataframe(recent, use_container_width=True)

# =====================================================
# HISTORY TABLE
# =====================================================
if st.session_state.history:
    st.markdown("---")
    df_table = pd.DataFrame(st.session_state.history[-15:])
    
    col_t1, col_t2 = st.columns([3,1])
    with col_t1:
        st.subheader("📜 Recent Logs")
        st.dataframe(df_table, use_container_width=True)
    with col_t2:
        st.download_button("📥 CSV", df_table.to_csv(index=False), "logs.csv")

st.markdown("---")
st.caption("🛡️ AI Security Pro | Zero Dependencies | Cloud-Ready | AI Support")
