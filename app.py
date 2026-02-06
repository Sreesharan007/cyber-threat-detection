import streamlit as st
import requests
import pyttsx3
import speech_recognition as sr

API_KEY = "PASTE_YOUR_ABUSEIPDB_API_KEY"

# ---------- Voice Engine ----------
engine = pyttsx3.init()

def speak(text):
    engine.say(text)
    engine.runAndWait()

# ---------- Threat Check ----------
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

# ---------- Speech to Text ----------
def listen():
    r = sr.Recognizer()
    with sr.Microphone() as source:
        audio = r.listen(source)
    return r.recognize_google(audio)

# ---------- Streamlit UI ----------
st.set_page_config(page_title="Cyber Voice Assistant", layout="centered")

st.title("🔐 Cyber Threat Detection Voice Assistant")
st.write("Check if an IP address is malicious using threat intelligence")

ip_input = st.text_input("Enter IP address")

if st.button("🎙️ Speak IP"):
    try:
        ip_input = listen()
        st.success(f"Detected IP: {ip_input}")
    except:
        st.error("Voice recognition failed")

if st.button("🔍 Analyze"):
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

        st.subheader("📊 Threat Report")
        st.write("IP:", data["ipAddress"])
        st.write("Country:", data["countryName"])
        st.write("Abuse Score:", score)
        st.write("Risk Level:", risk)

        speak(f"The IP address {ip_input} is classified as {risk}")

    else:
        st.warning("Please enter an IP address")
