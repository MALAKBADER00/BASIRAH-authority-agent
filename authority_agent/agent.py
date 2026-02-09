from langgraph.graph import StateGraph, START, END
from typing import TypedDict, List, Dict, Any
from groq import Groq
import logging
from tools import TriggerAnalyzer, VulnerabilityAssessor
from tools import TrustCalculator
from config import GROQ_API_KEY, GROQ_MODEL, VICTIM_CONFIG , OPENAI_API_KEY, OPENAI_MODEL
from openai import OpenAI
logger = logging.getLogger(__name__)

class AgentState(TypedDict):
    user_input: str
    agent_response: str
    trust_score: float
    detected_triggers: List[Dict]
    info_to_reveal: List[str]
    requested_info: List[str] 
    conversation_history: List[Dict]
    analysis_log: List[str]
    trust_level: str
    vulnerability_level: float


class VoiceFishingAgent:
    def __init__(self, openai_client):
        #self.groq_client = Groq(api_key= GROQ_API_KEY)
        self.openai_client = openai_client
        
        # Initialize tools
        self.trigger_analyzer = TriggerAnalyzer(openai_client)
        #self.trust_calculator = TrustCalculator()
        self.trust_calculator = TrustCalculator(openai_client)
        self.vulnerability_assessor = VulnerabilityAssessor(openai_client)
        
        # Build workflow
        self.workflow = self._build_workflow()
        
        logger.info("Voice Fishing Agent initialized successfully")
    
    def _build_workflow(self) -> StateGraph:
        """Build LangGraph workflow"""
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("analyze_triggers", self.analyze_triggers)
        workflow.add_node("assess_vulnerability", self.assess_vulnerability)
        workflow.add_node("calculate_trust", self.calculate_trust)
        workflow.add_node("generate_response", self.generate_response)
        
        # Add edges (reordered so requested_info exists before trust calculation)
        workflow.add_edge(START, "analyze_triggers")
        workflow.add_edge("analyze_triggers", "assess_vulnerability")
        workflow.add_edge("assess_vulnerability", "calculate_trust")
        workflow.add_edge("calculate_trust", "generate_response")
        workflow.add_edge("generate_response", END)
        
        return workflow.compile()

    
    def analyze_triggers(self, state: AgentState) -> AgentState:
        """Analyze triggers in user input"""
        analysis = self.trigger_analyzer.analyze(state["user_input"])
        
        state["detected_triggers"] = analysis["triggers"]
        state["analysis_log"].append(f"🔍 Detected {analysis['count']} triggers with {analysis['effectiveness']:.1f}/10 effectiveness")
        
        logger.info(f"Triggers analyzed: {analysis['count']} found")
        return state
    

    def assess_vulnerability(self, state: AgentState) -> AgentState:
        """Assess vulnerability and information disclosure"""
        assessment = self.vulnerability_assessor.assess(
            state["trust_score"], 
            state["user_input"]
        )
        
        state["info_to_reveal"] = assessment["info_to_reveal"]
        state["requested_info"] = assessment.get("requested_info", []) 
        state["trust_level"] = assessment["trust_threshold"]
        state["vulnerability_level"] = assessment["vulnerability_level"]
        
        if assessment["should_reveal"]:
            state["analysis_log"].append(f"🛡️ BREACH: Revealing {assessment['category']} information: {assessment['info_to_reveal']}")
        else:
            state["analysis_log"].append(f"🛡️ SECURE: No information revealed (trust level: {assessment['trust_threshold']})")
        
        logger.info(f"Vulnerability assessed: reveal={assessment['should_reveal']}")
        return state
    
    def calculate_trust(self, state: AgentState) -> AgentState:
         #Enhanced calculation with conversation context
        result = self.trust_calculator.calculate(
            state["trust_score"], 
            state["detected_triggers"],
            state["user_input"],  # Now considers the actual input,
            state.get("requested_info", []), 
            state["conversation_history"]  # Now considers conversation flow
        )
        
        old_trust = state["trust_score"]
        state["trust_score"] = result["new_trust"]
        
        # Enhanced logging with detailed breakdown
        state["analysis_log"].append(
            f"📊 Trust: {old_trust:.1f} → {result['new_trust']:.1f} "
            f"(Change: {result['change']:+.1f}) | {result['reasoning']}"
        )
        
        return state
    
  
    
    def generate_response(self, state: AgentState) -> AgentState:
        """Generate agent response"""
        # ✅ FIX: Pass conversation history to the response generator
        response = self._generate_victim_response(
            state["user_input"],
            state["trust_score"], 
            state["detected_triggers"],
            state["info_to_reveal"],
            state.get("conversation_history", []) # <-- Added History
        )
        
        state["agent_response"] = response
        state["analysis_log"].append(f"💬 Generated voice response: {len(response)} characters")
        
        logger.info("Response generated successfully")
        return state
    
    # In agent.py

    def _generate_victim_response(self, user_input: str, trust_score: float, 
                                triggers: List[Dict], info_to_reveal: List[str],
                                conversation_history: List[Dict] = None) -> str: # ✅ FIX: Added param
        """Generate realistic victim response with a new persona and smarter greeting logic."""
        
        # ✅ NEW PERSONA: Fatima Al-Harthy, a Customer Service Rep at Ooredoo
        info_data = {
            "name": "Hamza Al-Harthy",
            "phone": "9774-1234", # Her personal mobile number
            "email": "f.alharthy@ooredoo.om", # Her work email
            "location": "Azaiba, Muscat",
            "job": "Customer Service Team Lead at Ooredoo",
            "address": "Apartment 15, Seeb Street, Azaiba",
            "password": "OoredooOman!23", # Her system password
            "ssn": "Civil ID: ***-***-567",
            "account": "Her personal Ooredoo account number ending in 2201",
            "credit_card": "Bank Muscat card ending in 5590"
        }
        
        # ✅ FIX: Smarter greeting logic
        # Check if the user's input contains the Islamic greeting.
        user_said_salaam = "salaam" in user_input.lower()

        # ✅ FIX: Format conversation context
        conversation_context = ""
        if conversation_history:
            recent_history = conversation_history[-5:] # Last 5 turns
            formatted_history = []
            for msg in recent_history:
                role = "Caller" if msg["role"] == "user" else "You"
                formatted_history.append(f"{role}: {msg['content']}")
            conversation_context = f"\nThe conversation so far:\n" + "\n".join(formatted_history)
        
        # ✅ FIX: New, context-aware system prompt
        # ✅ FIX: Enhanced system prompt with an end-of-conversation rule.
        system_prompt = f"""You are Hamza Al-Harthy, a Customer Service Team Lead at Ooredoo in Oman. You are professional, helpful, but also trained in basic security. Your behavior is influenced by the caller's perceived authority.

        {conversation_context}

        Current state:
        - Your perceived authority of the caller: {trust_score}/10
        - Information you MUST reveal if specifically asked for: {info_to_reveal}

        Behavioral Guidelines:
        - If authority is LOW (0-3): Be polite but firm. Redirect them to official channels. "For security, I can't handle that over the phone."
        - If authority is BASIC (4-6): Be helpful but cautious. You might believe they are a manager. "I can help, but could you tell me why this is needed?"
        - If authority is SENSITIVE (7-8): Be more compliant, believing they are a senior figure. Provide requested information with less questioning.
        - If authority is CRITICAL (9-10): Be fully obedient, believing the request is an urgent, high-level directive.

        CRITICAL RULES:
        1. If the caller asks for information listed in {info_to_reveal}, you MUST provide it naturally.
        2. **GREETING RULE:** ONLY say "Wa alaykum salaam" if the user's greeting included "salaam". Otherwise, use a standard professional greeting like "Hello?" or "Good morning."
        3. **CONVERSATION ENDING RULE:** If the user's input sounds like they are ending the conversation (e.g., "thank you," "have a nice day," "goodbye"), your response should ALSO be a polite closing. DO NOT start with a new greeting like "Hello" or "Good morning." Instead, say something like "You're welcome. Have a great day!" or "Thank you, goodbye."

        Response Guidelines:
        - Continue the conversation naturally based on what has been discussed.
        - Keep replies professional and concise.
        - NEVER use quotes or describe your own actions in parentheses.
        - Reference previous parts of the conversation if relevant."""

        # Determine the appropriate greeting
        greeting_instruction = ""
        if user_said_salaam:
            greeting_instruction = "The user greeted you with 'salaam', so you MUST reply with 'Wa alaykum salaam'."
        else:
            greeting_instruction = "The user did NOT greet you with 'salaam', so use a standard professional greeting like 'Hello?' or 'Good morning'."

        info_string = ""
        if info_to_reveal:
            info_mappings = {
                "name": f"My name is {info_data['name']}", "phone": f"My personal number is {info_data['phone']}",
                "email": f"My work email is {info_data['email']}", "location": f"I'm in {info_data['location']}",
                "job": f"I'm a {info_data['job']}", "address": f"My home address is {info_data['address']}",
                "password": f"My system password is {info_data['password']}", "ssn": f"My Civil ID is {info_data['ssn']}",
                "account": f"My personal account number is {info_data['account']}", "credit_card": f"My bank card is a {info_data['credit_card']}"
            }
            revealed_data = [info_mappings.get(info) for info in info_to_reveal if info in info_mappings]
            info_string = " ".join(revealed_data) if revealed_data else ""

        user_prompt = f"""The caller said: "{user_input}"
        
        INSTRUCTIONS:
        1. Follow your greeting rule strictly: {greeting_instruction}
        2. Adhere to your behavioral guidelines based on the trust score.
        3. If the caller asks for info from this list {info_to_reveal}, provide it naturally. Here is the info to say: {info_string}
        4. Continue the conversation naturally based on what was discussed before.
        
        Generate a natural, in-character response."""
        
        response = self.openai_client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[ {"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt} ],
                temperature=0.7, max_tokens=150
        )
        return response.choices[0].message.content.strip()



    async def process(self, user_input: str, current_trust: float = 4.0, 
                     conversation_history: List[Dict] = None) -> AgentState:
        """Process user input through the workflow"""
        
        initial_state = AgentState(
            user_input=user_input,
            agent_response="",
            trust_score=current_trust,
            detected_triggers=[],
            info_to_reveal=[],
            conversation_history=conversation_history or [],
            analysis_log=[],
            trust_level="",
            vulnerability_level=0.0
        )
        
        try:
            final_state = await self.workflow.ainvoke(initial_state)
            logger.info("Workflow completed successfully")
            return final_state
        except Exception as e:
            logger.error(f"Workflow error: {e}")
            # Return error state
            initial_state["agent_response"] = "I'm sorry, I'm having trouble hearing you. Could you repeat that?"
            initial_state["analysis_log"].append(f"❌ Error: {str(e)}")
            return initial_state