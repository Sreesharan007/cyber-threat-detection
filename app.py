import streamlit as st
import requests
import os
import re

# ---------- CONFIG ----------
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
API_URL = "https://api.abuseipdb.com/api/v2/check"

# ---------- FUNCTIONS ----------
def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip) is not None

def check_ip(ip):
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(API_URL, headers=headers, params=params, timeout=10)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def classify_risk(score):
    if score >= 70:
        return "HIGH RISK"
    elif score >= 30:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"

# ---------- STREAMLIT UI ----------
st.set_page_config(page_title="Cyber Threat Detection Assistant", page_icon="🔐")

st.title("🔐 Cyber Threat Detection Voice Assistant")
st.write("Cloud-hosted prototype using real Threat Intelligence")

ip_input = st.text_input("Enter a public IPv4 address", placeholder="Example: 8.8.8.8")

if st.button("🔍 Analyze IP"):
    if not API_KEY:
        st.error("API key not found. Please add ABUSEIPDB_API_KEY in Secrets.")
        st.stop()

    if not ip_input:
        st.warning("Please enter an IP address.")
        st.stop()

    if not is_valid_ip(ip_input):
        st.error("Invalid IP address format.")
        st.stop()

    with st.spinner("Analyzing threat intelligence..."):
        result = check_ip(ip_input)

    if "error" in result:
        st.error("Network or API error occurred.")
        st.stop()

    if "data" not in result:
        st.error("Threat data unavailable. API may be rate-limited or key is invalid.")
        st.stop()

    data = result["data"]
    score = data.get("abuseConfidenceScore", 0)
    risk = classify_risk(score)

    # ---------- DISPLAY ----------
    st.subheader("📊 Threat Report")
    st.write("**IP Address:**", data.get("ipAddress", "N/A"))
    st.write("**Country:**", data.get("countryName", "Unknown"))
    st.write("**Abuse Confidence Score:**", score)
    st.write("**Risk Level:**", risk)

    # ---------- VOICE OUTPUT ----------
    message = f"The IP address {ip_input} is classified as {risk}. Abuse score is {score}."

    st.markdown(
        f"""
        <script>
        var msg = new SpeechSynthesisUtterance("{message}");
        window.speechSynthesis.speak(msg);
        </script>
        """,
        unsafe_allow_html=True
    )

    st.success("Analysis completed successfully.")
