import streamlit as st
import requests
import os

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json()

st.set_page_config(page_title="Cyber Threat Detection Assistant")

st.title("🔐 Cyber Threat Detection Voice Assistant")
st.write("Cloud-based prototype using Threat Intelligence")

ip_input = st.text_input("Enter IP address")

if st.button("Analyze"):
    if ip_input:
        result = check_ip(ip_input)
        data = result["data"]

        score = data["abuseConfidenceScore"]

        if score >= 70:
            risk = "HIGH RISK"
        elif score >= 30:
            risk = "MEDIUM RISK"
        else:
            risk = "LOW RISK"

        message = f"The IP address {ip_input} is classified as {risk}. Abuse score is {score}."

        st.subheader("📊 Threat Report")
        st.write("IP:", data["ipAddress"])
        st.write("Country:", data["countryName"])
        st.write("Abuse Score:", score)
        st.write("Risk Level:", risk)

        # Browser-based voice output
        st.markdown(
            f"""
            <script>
            var msg = new SpeechSynthesisUtterance("{message}");
            window.speechSynthesis.speak(msg);
            </script>
            """,
            unsafe_allow_html=True
        )
    else:
        st.warning("Please enter an IP address")
