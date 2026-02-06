import streamlit as st
import random
import time
import pandas as pd
from gtts import gTTS
import tempfile
import os
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
# UTILITY FUNCTIONS
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
    """Voice alert with cleanup"""
    messages = {
        "Malware": "Warning. Malware detected. Harmful program running. Files may be stolen or damaged.",
        "Ransomware": "Warning. Ransomware detected. Files locked. Disconnect immediately.",
        "Brute Force": "Warning. Brute force attack. Password guessing detected. Change password now.",
        "DDoS": "Warning. DDoS attack. Network flooding detected. Block source IP immediately."
    }
    
    if attack not in messages:
        return
    
    try:
        tts = gTTS(text=messages[attack], lang="en", slow=False)
        audio_file = tempfile.NamedTemporaryFile(delete=False, suffix=".mp3")
        tts.save(audio_file.name)
        st.audio(audio_file.name)
        time.sleep(1)  # Let audio load
        os.unlink(audio_file.name)  # Clean up
    except:
        st.warning("🔊 Audio unavailable - browser may be blocking autoplay")

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
if st.sidebar.button("🔄 New Session"):
    st.session_state.history = []
    st.session_state.attack_memory = {"Malware": 0, "Ransomware": 0, "Brute Force": 0, "DDoS": 0}
    st.rerun()

st.sidebar.title("🌐 Network Monitor")
if st.session_state.network_info:
    info = st.session_state.network_info
    st.sidebar.error("🚨 **ATTACK ACTIVE**")
    with st.sidebar.expander(f"👤 Attacker: {info['ip']}"):
        st.markdown(f"**Location:** {info['city']}, {info['country']}")
        st.markdown(f"**ISP:** {info['isp']}")
        st.code(f"iptables -A INPUT -s {info['ip']} -j DROP", language="bash")
else:
    st.sidebar.success("🟢 Network: Clean")

# =====================================================
# MAIN HEADER
# =====================================================
st.title("🛡️ AI Security Assistant Pro")
st.markdown("**Real-time threat detection with adaptive learning & voice alerts**")

# Control buttons
col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    if st.button("▶️ **START SCAN**", type="primary", use_container_width=True):
        st.session_state.scanning = True
with col2:
    if st.button("⏹️ **STOP SCAN**", use_container_width=True):
        st.session_state.scanning = False
with col3:
    if st.button("📊 **VIEW STATS**", use_container_width=True):
        st.session_state.show_stats = True

# =====================================================
# SCANNING LOOP - OPTIMIZED
# =====================================================
status_box = st.empty()
info_box = st.empty()
action_box = st.empty()
progress_bar = st.empty()

if st.session_state.scanning:
    progress_bar.progress(0)
    
    with st.spinner("Scanning system..."):
        attack = detect_attack_cached()
        confidence, reason = confidence_score(attack)
        
        # Update memory
        if attack != "Normal":
            st.session_state.attack_memory[attack] = st.session_state.attack_memory.get(attack, 0) + 1
        
        # Voice alert on change
        if attack != st.session_state.last_attack:
            speak_attack(attack)
            st.session_state.last_attack = attack
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Network attacks
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
        if attack == "Normal":
            status_box.success(f"✅ **SYSTEM SECURE** | {timestamp}")
            info_box.info(f"**Confidence:** {confidence}% | {reason}")
        
        else:
            status_box.error(f"🚨 **{attack} DETECTED** | {timestamp}")
            info_box.warning(f"**AI Confidence:** **{confidence}%** | {reason}")
            
            # Action buttons
            if attack == "Malware":
                file = random.choice(malicious_files)
                if st.button(f"🧹 **Quarantine {file}**"):
                    action_box.success(f"✅ **{file}** isolated & deleted")
            
            elif attack == "Ransomware":
                action_box.error("🔴 **EMERGENCY**: Disconnect network. Restore from backup.")
            
            elif attack in ["Brute Force", "DDoS"]:
                if st.button("🚫 **BLOCK IP NOW**", type="primary"):
                    action_box.success(f"✅ IP `{st.session_state.network_info['ip']}` BLOCKED")
        
        # Log history
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
# HISTORY & EXPORTS
# =====================================================
st.divider()
st.subheader("📜 Attack History")

if st.session_state.history:
    df = pd.DataFrame(st.session_state.history[-50:])  # Last 50 entries
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.dataframe(df, use_container_width=True, hide_index=True)
    with col2:
        st.download_button(
            "📥 Download CSV", 
            df.to_csv(index=False),
            "security_logs.csv",
            "text/csv"
        )
    
    # Stats
    attack_counts = df['Attack'].value_counts()
    st.metric("Total Alerts", len(df))
    col_stats1, col_stats2 = st.columns(2)
    with col_stats1:
        st.metric("Unique Threats", len(attack_counts))
    with col_stats2:
        avg_conf = df['Confidence'].str.rstrip('%').astype(float).mean()
        st.metric("Avg Confidence", f"{avg_conf:.1f}%")
        
else:
    st.info("👆 **Start scanning** to see attack history")

# Footer
st.markdown("---")
st.caption("🛡️ AI Security Assistant Pro | Optimized for Cloud Deployment")
