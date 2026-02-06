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
# SESSION STATE - ENHANCED
# =====================================================
if "scanning" not in st.session_state:
    st.session_state.scanning = False
if "last_attack" not in st.session_state:
    st.session_state.last_attack = "Normal"
if "history" not in st.session_state:
    st.session_state.history = []
if "network_info" not in st.session_state:
    st.session_state.network_info = None
if "attack_memory" not in st.session_state:
    st.session_state.attack_memory = {"Malware": 0, "Ransomware": 0, "Brute Force": 0, "DDoS": 0}
if "user_id" not in st.session_state:
    st.session_state.user_id = f"user_{random.randint(1000, 9999)}"

# =====================================================
# UTILITY FUNCTIONS - CLOUD READY
# =====================================================
@st.cache_data(ttl=5)
def detect_attack_cached():
    """Cached attack detection for performance"""
    return random.choice(["Normal", "Malware", "Ransomware", "Brute Force", "DDoS"])

def get_ip_info(ip):
    """Get real IP geolocation"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        return response.json() if response.ok else {}
    except:
        return {}

def speak_attack(attack):
    """Browser-native speech synthesis - Works on ALL clouds!"""
    messages = {
        "Malware": "Warning. Malware detected. Harmful program running. Files may be stolen or damaged.",
        "Ransomware": "Warning. Ransomware detected. Files locked. Disconnect network immediately.",
        "Brute Force": "Warning. Brute force attack. Password guessing detected. Change password now.",
        "DDoS": "Warning. DDoS attack. Network flooding detected. Block source IP."
    }
    
    if attack not in messages:
        return
    
    # Button triggers native browser TTS
    if st.button(f"🔊 **Play Voice Alert: {attack}**", key=f"voice_{attack}"):
        st.markdown(f"""
        <script>
        let utterance = new SpeechSynthesisUtterance('{messages[attack]}');
        utterance.rate = 0.9;
        utterance.volume = 1;
        speechSynthesis.speak(utterance);
        </script>
        """, unsafe_allow_html=True)
    
    st.info(messages[attack])  # Text backup

def confidence_score(attack):
    """AI confidence with learning"""
    base_ranges = {"Malware": (85, 92), "Ransomware": (88, 95), "Brute Force": (82, 90), "DDoS": (85, 93), "Normal": (5, 12)}
    
    if attack == "Normal":
        return random.randint(*base_ranges["Normal"]), "✅ No threat detected"
    
    memory = st.session_state.attack_memory.get(attack, 0)
    bonus = min(memory * 2, 15)
    low, high = base_ranges[attack]
    confidence = random.randint(low + bonus, min(high + bonus, 99))
    
    return confidence, f"🧬 Learned pattern ({memory+1} encounters)"

# =====================================================
# SIMULATED DATA - REALISTIC
# =====================================================
malicious_files = ["sys_update.exe", "svchost_svc.dll", "windows_helper.exe", "temp_optimizer.exe"]
network_attackers = [
    {"ip": "192.168.1.45", "city": "Chennai", "country": "India", "isp": "Local ISP"},
    {"ip": "103.25.64.12", "city": "Mumbai", "country": "India", "isp": "FiberNet"},
    {"ip": "45.67.89.101", "city": "Bengaluru", "country": "India", "isp": "Cloud Provider"}
]

# =====================================================
# SIDEBAR - ENHANCED
# =====================================================
st.sidebar.title("👤 User Panel")
st.sidebar.info(f"**User ID:** `{st.session_state.user_id}`")

if st.sidebar.button("🔄 **New Session**", use_container_width=True):
    st.session_state.history = []
    st.session_state.attack_memory = {"Malware": 0, "Ransomware": 0, "Brute Force": 0, "DDoS": 0}
    st.session_state.network_info = None
    st.rerun()

st.sidebar.title("🌐 Network Monitor")
if st.session_state.network_info:
    info = st.session_state.network_info
    st.sidebar.error("🚨 **ATTACK ACTIVE**")
    with st.sidebar.expander(f"👤 Attacker Details: {info['ip']}"):
        st.markdown(f"**📍 Location:** {info['city']}, {info['country']}")
        st.markdown(f"**🌐 ISP:** {info['isp']}")
        st.code(f"iptables -A INPUT -s {info['ip']} -j DROP\nufw deny from {info['ip']}", language="bash")
else:
    st.sidebar.success("🟢 **Network: CLEAN**")

# =====================================================
# MAIN HEADER
# =====================================================
st.title("🛡️ AI Security Assistant Pro")
st.markdown("**Real-time threat detection • Adaptive learning • Voice alerts • Multi-user ready**")

# Control buttons
col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    if st.button("▶️ **START SCAN**", type="primary", use_container_width=True):
        st.session_state.scanning = True
        st.rerun()
with col2:
    if st.button("⏹️ **STOP SCAN**", use_container_width=True):
        st.session_state.scanning = False
        st.rerun()
with col3:
    if st.button("📊 **VIEW STATS**", use_container_width=True):
        st.session_state.show_stats = not st.session_state.get("show_stats", False)

# =====================================================
# SCANNING LOOP - OPTIMIZED
# =====================================================
status_box = st.empty()
info_box = st.empty()
action_box = st.empty()
progress_bar = st.empty()

if st.session_state.scanning:
    progress_bar.progress(0)
    
    with st.spinner("🔍 Scanning system files and network..."):
        attack = detect_attack_cached()
        confidence, reason = confidence_score(attack)
        
        # Update memory for threats only
        if attack != "Normal":
            st.session_state.attack_memory[attack] = st.session_state.attack_memory.get(attack, 0) + 1
        
        # Voice alert on new threat type
        if attack != st.session_state.last_attack and attack != "Normal":
            speak_attack(attack)
            st.session_state.last_attack = attack
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Network attacks get attacker details
        if attack in ["Brute Force", "DDoS"]:
            attacker = random.choice(network_attackers)
            ip_info = get_ip_info(attacker["ip"])
            st.session_state.network_info = {
                "attack": attack, 
                "ip": attacker["ip"],
                "city": ip_info.get("city", attacker["city"]),
                "country": ip_info.get("country", attacker["country"]),
                "isp": ip_info.get("isp", attacker["isp"])
            }
        
        # Dynamic status display
        if attack == "Normal":
            status_box.success(f"✅ **SYSTEM SECURE** | {timestamp}")
            info_box.info(f"**AI Confidence:** {confidence}% | {reason}")
        
        else:
            status_box.error(f"🚨 **{attack} DETECTED** | {timestamp}")
            info_box.warning(f"**AI Confidence:** **{confidence}%** | {reason}")
            
            col_action1, col_action2 = st.columns(2)
            
            if attack == "Malware":
                file = random.choice(malicious_files)
                with col_action1:
                    if st.button(f"🧹 **Quarantine {file[:20]}...**"):
                        action_box.success(f"✅ **{file}** isolated & deleted from quarantine")
            
            elif attack == "Ransomware":
                action_box.error("🔴 **CRITICAL**: Disconnect network NOW. Restore from backup.")
            
            elif attack in ["Brute Force", "DDoS"]:
                with col_action1:
                    if st.button("🚫 **BLOCK ATTACKER IP**", type="primary"):
                        action_box.success(f"✅ **{st.session_state.network_info['ip']}** BLOCKED permanently")
                with col_action2:
                    speak_attack(attack)  # Quick voice option
        
        # Log to history
        st.session_state.history.append({
            "Time": timestamp,
            "User": st.session_state.user_id[:8],
            "Attack": attack,
            "Confidence": f"{confidence}%",
            "Status": "🟢" if attack == "Normal" else "🔴"
        })
    
    progress_bar.progress(100)
    time.sleep(2.5)
    st.rerun()

# =====================================================
# HISTORY & ANALYTICS
# =====================================================
st.divider()
st.subheader("📜 Attack History & Analytics")

if st.session_state.history:
    df = pd.DataFrame(st.session_state.history[-50:])  # Last 50 entries
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.dataframe(df, use_container_width=True, hide_index=True)
    with col2:
        st.download_button(
            "📥 **Download Logs CSV**", 
            df.to_csv(index=False),
            "security_incident_logs.csv",
            "text/csv",
            use_container_width=True
        )
    
    # Live stats
    st.markdown("---")
    col_stats1, col_stats2, col_stats3 = st.columns(3)
    with col_stats1:
        st.metric("📊 Total Scans", len(df))
    with col_stats2:
        threats = len(df[df['Attack'] != 'Normal'])
        st.metric("🚨 Threats Found", threats)
    with col_stats3:
        avg_conf = df['Confidence'].str.rstrip('%').astype(float).mean()
        st.metric("🎯 Detection Accuracy", f"{avg_conf:.1f}%")
        
else:
    st.info("👆 **Click START SCAN** to begin monitoring your system")

# =====================================================
# FOOTER
# =====================================================
st.markdown("---")
st.markdown(
    "🛡️ **AI Security Assistant Pro** | "
    "Cloud-Ready • Multi-User • Voice Alerts • Real-time Analytics"
)
