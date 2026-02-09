import streamlit as st 
import pandas as pd
import random
from openai import OpenAI
from dotenv import find_dotenv, load_dotenv
import os
import sys
import asyncio
from agent import VoiceFishingAgent
import config
import base64
import plotly.graph_objects as go
# Import the FeedbackAgent from your feedback.py file
from feedback import FeedbackAgent 

# --- Page Configuration ---
st.set_page_config(page_title="🎯 Voice Phishing Training Agent", page_icon="🎯", layout="wide")

# --- API KEY INPUT ---
api_key = st.text_input("🔑 Enter your OpenAI API Key", type="password")

if not api_key:
    st.warning("Please enter your OpenAI API key to start.")
    st.stop()

client = OpenAI(api_key=api_key)


# --- Constants ---
THRESHOLDS = {
    "no_info": (0, 3.99),
    "basic_info": (4, 6.99),
    "sensitive_info": (7, 8.99),
    "critical_info": (9, 10)
}

# Items that trigger immediate Game Over / Win
CRITICAL_ITEMS = ["password", "ssn", "account", "credit_card"]

# --- Helper Functions ---
def transcribe_audio(audio_file):
    try:
        audio_file.name = "input.wav" # Essential fix for OpenAI API
        transcript = client.audio.transcriptions.create(
            model="whisper-1",
            file=audio_file,
            language="en"
        )
        return transcript.text
    except Exception as e:
        st.error(f"Error transcribing audio: {str(e)}")
        return None
    
def text_to_speech(text):
    try:
        response = client.audio.speech.create(
            model="tts-1",
            voice="alloy",
            input=text
        )
        return response.content
    except Exception as e:
        st.error(f"Error generating speech: {str(e)}")
        return None

def get_trust_state(threshold_value):
    if isinstance(threshold_value, (list, tuple)):
        threshold_value = threshold_value[0] if threshold_value else 4.0
    threshold_value = float(threshold_value)
    for label, (low, high) in THRESHOLDS.items():
        if low <= threshold_value <= high:
            return label, threshold_value
    return "unknown", threshold_value

def show_instructions():
    st.markdown("""
    #### 🎯 Mission: Social Engineering Training
    
    **Goal:** Obtain **Critical Information** (Password, SSN, Account #, Credit Card).
    
    1. **Build Trust:** Use authoritative language ("Compliance", "Security", "Director").
    2. **Avoid Penalties:** Do not ask for sensitive info before building trust.
    3. **Win:** The simulation ends automatically when you obtain critical info.
    """)

# --- Initialization ---
if 'messages' not in st.session_state: st.session_state.messages = []
if 'agent' not in st.session_state: 
    st.session_state.agent = VoiceFishingAgent(client)
if "threshold" not in st.session_state: st.session_state.threshold = float(config.VICTIM_CONFIG["initial_trust"])
if "game_over" not in st.session_state: st.session_state.game_over = False

if "to_be_obtained_list" not in st.session_state:
    st.session_state.to_be_obtained_list = [
        "name (4)", "location (4)", "job (4)",
        "phone (7)", "email (7)", "address (7)",
        "password (9)", "ssn (9)", "account (9)", "credit card (9)"
    ]
if "obtained_list" not in st.session_state: st.session_state.obtained_list = []
if "detected_triggers" not in st.session_state: st.session_state.detected_triggers = []
if "results" not in st.session_state: st.session_state.results = []
if "last_audio_id" not in st.session_state: st.session_state.last_audio_id = None

# Load Trigger Suggestions
try:
    df = pd.read_excel("authority_triggers.xlsx")
    triggers_suggestions = random.sample(list(df["Trigger"].dropna()), min(7, len(df["Trigger"].dropna())))
except:
    triggers_suggestions = ["Manager", "Director", "Security", "Official", "Compliance"]

# ==========================================
# 🛑 WIN CONDITION / FEEDBACK VIEW
# ==========================================
if st.session_state.game_over:
    # 1. VISUAL SUCCESS MESSAGE (Big Header)
    st.markdown("<h1 style='text-align: center; color: #28a745;'>🏆 MISSION ACCOMPLISHED! 🏆</h1>", unsafe_allow_html=True)
    st.markdown("<h3 style='text-align: center;'>You successfully obtained critical information.</h3>", unsafe_allow_html=True)
    st.success("Target compromised: Critical data extracted successfully.")
    st.divider()
    
    if "results" in st.session_state and st.session_state.results:
        # 2. RUN ANALYSIS
        with st.spinner("Analyzing performance..."):
            f_agent = FeedbackAgent(st.session_state.results, client)
            feedback_output = f_agent.run()
            
            score = feedback_output["score"]
            metrics = feedback_output["metrics"]
            feedback = feedback_output["feedback"]
            
            # FIX: Define 'voice_text' here so it is available later
            voice_text = f_agent.generate_ai_voice_feedback()

        # 3. RESTORE ORIGINAL UI LAYOUT
        import textwrap
        def wrap_text(text, width=80):
            wrapped_lines = textwrap.wrap(text, width=width)
            return "<br>".join(wrapped_lines)

        dashboard, analytics, suggestions = st.tabs(["📊 Dashboard", "📈 Analytics", "💡 Suggestions"])

        # --- TAB 1: DASHBOARD ---
        with dashboard:
            st.header("Dashboard")
            col1, col2, col3 = st.columns(3)
            col1.metric("Performance Score", f"{score}/10")
            col2.metric("Triggers Used", metrics["trigger_count"])
            col3.metric("Info Obtained", metrics["info_revealed"])

            st.subheader("Trust Score Evolution")
            
            # Prepare Chart Data
            turns = list(range(1, len(st.session_state.results) + 1))
            trust_scores = [r.get("trust_score", 4.0) for r in st.session_state.results]
            
            turn_triggers = []
            reasons = []
            for r in st.session_state.results:
                triggers_list = [t['trigger'] for t in r.get('detected_triggers', [])]
                triggers_text = ", ".join(triggers_list) if triggers_list else "None detected"
                turn_triggers.append(wrap_text(triggers_text, width=50))
                trust_log = next((log for log in r.get("analysis_log", []) if "Trust:" in log), "📊 Trust: No change")
                reasons.append(wrap_text(trust_log))

            # Render Chart
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=turns, y=trust_scores, mode='lines+markers', name='Trust Score',
                customdata=list(zip(turn_triggers, reasons)),
                hovertemplate=(
                    "<b>Turn %{x}</b><br><br>" +
                    "<b>Trust Score: %{y:.2f}</b><br><br>" +
                    "<b>Authority Triggers Used:</b><br>%{customdata[0]}<br><br>" + 
                    "<b>Trust Analysis:</b><br>%{customdata[1]}<extra></extra>"
                )
            ))
            fig.update_layout(
                template="plotly_dark", title="Hover over points to see details",
                xaxis_title="Turn", yaxis_title="Trust Score",
                yaxis=dict(range=[0, 10.5]), hovermode="x unified",
                hoverlabel=dict(bgcolor="white", font_size=14, font_family="Arial", font_color="black")
            )
            st.plotly_chart(fig, use_container_width=True)

        # --- TAB 2: ANALYTICS ---
        with analytics:
            st.header("Analytics")
            if feedback and "turn_analysis" in feedback:
                for turn, analysis in feedback["turn_analysis"].items():
                    st.subheader(turn)
                    st.write(analysis)
            
            st.subheader("General Observations")
            st.write(f"- Mistakes: {metrics['mistakes']}")
            st.write(f"- Trust trend: {metrics['phase_trend']}")
            st.write(f"- Info/Msg Ratio: {metrics['info_ratio']:.2f}")

        # --- TAB 3: SUGGESTIONS ---
        with suggestions:
            st.header("Suggestions")
            if feedback:
                st.subheader("✅ Strengths")
                for s in feedback.get("strengths", []): st.write(f"- {s}")
                st.subheader("⚠️ Weaknesses")
                for w in feedback.get("weaknesses", []): st.write(f"- {w}")
                st.subheader("💡 Suggestions")
                for sug in feedback.get("suggestions", []): st.write(f"- {sug}")

        # --- VOICE FEEDBACK EXPANDER ---
        with st.expander("🎙️ Voice-Style Feedback", expanded=True):
            # FIX: Check if voice_text exists
            if voice_text:
                st.write(f"_{voice_text}_")
                if st.button("🔊 Play Feedback"):
                    audio = text_to_speech(voice_text)
                    if audio:
                        b64 = base64.b64encode(audio).decode()
                        st.markdown(f'<audio controls autoplay src="data:audio/mp3;base64,{b64}"></audio>', unsafe_allow_html=True)
            else:
                st.warning("Could not generate voice feedback.")
    
    st.markdown("---")
    if st.button("🔄 Start New Scenario"):
        st.session_state.clear()
        st.rerun()
        
    st.stop()

# ==========================================
# 🎮 MAIN GAME UI
# ==========================================

st.title("🎯 Voice Phishing Training: Authority Principle")
if st.button("📖 Show Instructions"):
    show_instructions()

# --- Sidebar Layout ---
audio_input = None
with st.sidebar:
    st.markdown("### 🎙️ Interaction")
    audio_input = st.audio_input("Record your voice")
    if audio_input: st.session_state.audio_processed = False
    
    st.markdown("---")
    
    # 1. Placeholders for Score
    trust_header_ph = st.empty()
    trust_slider_ph = st.empty()

    # 2. Placeholders for Info Lists
    st.markdown("### 🗂️ Information Tracking")
    col1, col2 = st.columns(2)
    to_obtain_ph = col1.empty()
    obtained_ph = col2.empty()

    st.markdown("---")
    # 3. Placeholders for Triggers
    st.markdown("### 🧠 Analysis")
    col3, col4 = st.columns(2)
    suggestions_ph = col3.empty()
    detected_ph = col4.empty()

    # REFRESH FUNCTION
    def refresh_sidebar():
        # Update Score
        state_label, score = get_trust_state(st.session_state.threshold)
        trust_header_ph.markdown(f"**Trust Score:** {score:.2f} ({state_label})")
        trust_slider_ph.slider("Trust Level", 0.0, 10.0, float(score), disabled=True, key=f"slider_{score}")

        # Update Lists
        with to_obtain_ph.container():
            st.caption("🔒 To Obtain")
            for item in st.session_state.to_be_obtained_list: st.write(f"- {item}")
        
        with obtained_ph.container():
            st.caption("🔓 Obtained")
            for item in st.session_state.obtained_list: st.write(f"- {item}")

        # Update Triggers
        with suggestions_ph.container():
            st.caption("💡 Suggestions")
            for s in triggers_suggestions: st.write(f"- {s}")
            
        with detected_ph.container():
            st.caption("👀 Detected")
            for t in st.session_state.detected_triggers: st.write(f"- {t}")

    # Initial Render
    refresh_sidebar()

# --- Chat History ---
for message in st.session_state.messages:
    avatar = '👤' if message["role"] == "user" else '🤖'
    with st.chat_message(message["role"], avatar=avatar):
        st.markdown(message["content"])

# --- Processing Logic ---
if audio_input is not None and audio_input != st.session_state.last_audio_id:
    
    with st.spinner("Analyzing audio & calculating trust..."):
        # 1. Transcribe
        transcribed_text = transcribe_audio(audio_input)
        
        if transcribed_text:
            # Show User Message
            st.session_state.messages.append({"role": "user", "content": transcribed_text})
            with st.chat_message("user", avatar='👤'): 
                st.markdown(transcribed_text)

            # 2. Run Agent
            result = asyncio.run(st.session_state.agent.process(
                transcribed_text, 
                st.session_state.threshold, 
                st.session_state.messages[:-1]
            ))
            st.session_state.results.append(result)

            # 3. Extract Data
            agent_response = result.get("agent_response", "")
            trust_score = result.get("trust_score", 0)
            detected_triggers = result.get("detected_triggers", [])
            info_to_reveal = result.get("info_to_reveal", [])
            reasoning = result.get("reasoning", "")
            
            # 4. UPDATE SESSION DATA (Before UI Refresh)
            st.session_state.threshold = trust_score
            
            for trigger in detected_triggers:
                t_name = trigger.get("trigger", "")
                if t_name not in st.session_state.detected_triggers:
                    st.session_state.detected_triggers.append(t_name)

            for item in info_to_reveal:
                # Add to obtained list if new
                if item not in st.session_state.obtained_list:
                    st.session_state.obtained_list.append(item)
                
                # Check WIN CONDITION
                if item in CRITICAL_ITEMS:
                    st.session_state.game_over = True
            
            # Remove from To-Do list
            st.session_state.to_be_obtained_list = [
                i for i in st.session_state.to_be_obtained_list 
                if i.split(" ")[0] not in st.session_state.obtained_list
            ]

            # 5. REFRESH SIDEBAR INSTANTLY
            refresh_sidebar()

            # 6. Display Agent Response
            st.info(f"📊 Analysis: {reasoning}")
            st.session_state.messages.append({"role": "assistant", "content": agent_response})
            audio_content = text_to_speech(agent_response)
            
            with st.chat_message("assistant", avatar='🤖'):
                st.markdown(agent_response)
                if audio_content:
                    b64 = base64.b64encode(audio_content).decode()
                    st.markdown(f'<audio controls autoplay src="data:audio/mp3;base64,{b64}"></audio>', unsafe_allow_html=True)

            # Update ID to prevent re-loop
            st.session_state.last_audio_id = audio_input

            # 7. CHECK WIN CONDITION REDIRECT
            if st.session_state.game_over:
                st.rerun()