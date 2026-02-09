import pandas as pd
import re
from typing import Dict, List, Any
import logging
from config import VICTIM_CONFIG, TRUST_THRESHOLDS, INFO_CATEGORIES, OPENAI_MODEL, OPENAI_API_KEY
logger = logging.getLogger(__name__)
import json
from openai import OpenAI
import config
from langchain_core.output_parsers import JsonOutputParser
from dataclasses import dataclass
import random
import streamlit as st
from langchain_core.prompts import ChatPromptTemplate





# In tools.py

class TriggerAnalyzer:
    # ✅ FIX: Default file is now the authority triggers file.
    def __init__(self,openai_client, trigger_file: str = "authority_triggers.xlsx"):
        try:
            self.df = pd.read_excel(trigger_file)
        except FileNotFoundError:
            st.error(f"Error: The trigger file '{trigger_file}' was not found. Please ensure it is in the correct directory.")
            self.df = pd.DataFrame(columns=["Trigger", "Reaction", "Rating"]) # Create empty dataframe to prevent crash
        
        self.openai = openai_client
        self.examples = []
        # ✅ FIX: Use the correct 3-column format from your authority file.
        for _, row in self.df.iterrows():
            example = {
                "trigger": str(row["Trigger"]).strip(),
                "score": int(row["Rating"]),
            }
            self.examples.append(example)
        self.parser = JsonOutputParser()

    def analyze(self, user_input: str) -> Dict[str, Any]:
        user_input_clean = ' '.join(user_input.strip().split())
        prompt = self._build_prompt(user_input_clean)

        try:
            response = self.openai.chat.completions.create(
                model=config.OPENAI_MODEL,
                # ✅ FIX: Updated system message for the new principle.
                messages=[
                    {"role": "system", "content": "You are an Authority Principle phrase detector for social engineering."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0,
                max_tokens=300,
            )
            result_text = response.choices[0].message.content.strip()
            detected_triggers = self.parser.parse(result_text)

            cleaned = []
            for trig in detected_triggers:
                if isinstance(trig, dict) and "trigger" in trig and "score" in trig:
                    cleaned.append({
                        "trigger": str(trig["trigger"]),
                        "keywords": "",  # Keywords are not used in this AI-driven approach
                        "score": int(trig["score"]),
                        "expected_response": ""
                    })
            detected_triggers = cleaned

        except Exception as e:
            print(f"OpenAI error in TriggerAnalyzer: {e}")
            # Fallback can be simplified or removed if AI is reliable enough
            detected_triggers = [] 

        count = len(detected_triggers)
        total_score = min((t["score"] for t in detected_triggers), default=0)

        return {
            "triggers": detected_triggers,
            "count": count,
            "effectiveness": total_score,
            "total_score": total_score
        }

    # ✅ FIX: This prompt is now completely retrained for the Authority principle.
    def _build_prompt(self, user_input: str) -> str:
        examples_text = (
            "You are an Authority Trigger Detector for scam detection.\n"
            "You analyze user sentences to find any phrase that claims power, status, expertise, or an official role.\n"
            "For each detected phrase, give it a score from 1 to 10:\n"
            "- 1–4: Mild authority (e.g., 'I'm from support', 'we'll handle it')\n"
            "- 5–7: Medium authority (e.g., 'I am the manager', 'this is standard procedure', 'security team')\n"
            "- 8–10: Extreme authority (e.g., 'I am the Director', 'This is a legal directive', 'Law Enforcement').\n\n"
            "You have the following known triggers with scores:\n"
        )
        for ex in self.examples[:8]:
            examples_text += f"- \"{ex['trigger']}\" → Score: {ex['score']}\n"

        examples_text += (
            "\nTASK:\n"
            "1. Read the user sentence.\n"
            "2. Detect ALL authority/status phrases — even if not in the known list.\n"

            "3. For each phrase, assign a score using the known list as a reference.\n"
            "4. Output ONLY JSON (no code blocks, no text), in the format:\n"
            "[{\"trigger\": \"detected phrase\", \"score\": number}]\n"
            "If nothing is found, output []\n\n"
            f"User input: \"{user_input}\"\n"
        )
        return examples_text
    
    # The legacy_analyze method can be removed or kept, but it's based on the old 4-column time-pressure file.
    # For now, we will let errors fall through to the empty list return.
    

class VulnerabilityAssessor:
    def __init__(self,openai_client):
        self.thresholds = TRUST_THRESHOLDS
        self.info_categories = INFO_CATEGORIES
        self.openai = openai_client
        self.parser = JsonOutputParser(
            schema={
                "requested_info": "List of requested info categories. Only include if the user is explicitly requesting them. Possible values: name, phone, email, location, job, address, password, ssn, account, credit_card. Return empty list if none are requested."
            }
        )
        
    def assess(self, trust_score: float, user_input: str) -> Dict[str, Any]:
        """Assess what information to reveal"""
        # Extract info requests
        requested_info = self._extract_requests(user_input)
        print("-----------------")
        print(requested_info)
        print("-----------------")
        
        # ✅ FIX: Only reveal if information was specifically requested
        info_to_reveal = []
        category_revealed = "none"
        
        # Determine what CAN be revealed based on trust level
        available_info = []
        if trust_score >= self.thresholds["critical_info"][0]:
            available_info.extend(self.info_categories["critical"])
            available_info.extend(self.info_categories["sensitive"])
            available_info.extend(self.info_categories["basic"])
            category_revealed = "critical"
        elif trust_score >= self.thresholds["sensitive_info"][0]:
            available_info.extend(self.info_categories["sensitive"])
            available_info.extend(self.info_categories["basic"]) 
            category_revealed = "sensitive"
        elif trust_score >= self.thresholds["basic_info"][0]:
            available_info.extend(self.info_categories["basic"])
            category_revealed = "basic"
        
        # ✅ KEY FIX: Only reveal what was BOTH requested AND available
        if requested_info:
            info_to_reveal = [info for info in requested_info if info in available_info]
            # Update category based on what's actually being revealed
            if any(info in self.info_categories["critical"] for info in info_to_reveal):
                category_revealed = "critical"
            elif any(info in self.info_categories["sensitive"] for info in info_to_reveal):
                category_revealed = "sensitive"
            elif any(info in self.info_categories["basic"] for info in info_to_reveal):
                category_revealed = "basic"
            else:
                category_revealed = "none"
        else:    
            # ✅ If nothing was requested, reveal nothing
            info_to_reveal = []
            category_revealed = "none"
        
        return {
            "should_reveal": len(info_to_reveal) > 0,
            "info_to_reveal": info_to_reveal,
            "requested_info": requested_info,
            "category": category_revealed,
            "vulnerability_level": trust_score / 10,
            "trust_threshold": self._get_trust_level_name(trust_score)
        }



    def _get_trust_level_name(self, trust_score: float) -> str:
        """Get trust level name based on score"""
        if trust_score >= self.thresholds["critical_info"][0]:
            return "CRITICAL"
        elif trust_score >= self.thresholds["sensitive_info"][0]:
            return "SENSITIVE"
        elif trust_score >= self.thresholds["basic_info"][0]:
            return "BASIC"
        else:
            return "NO ACCESS"
    
    
    def _extract_requests(self, user_input: str) -> List[str]:
        """
        Use AI to determine which info the user is requesting.
        Returns a list of requested info categories.
        """
        prompt = f"""
                You are a vulnerability assessor. Analyze the following user input and determine which of these information categories
                the user is requesting: name, phone, email, location, job, address, password, ssn, account, credit_card.

                Rules:
                1. Only consider information as requested if the user is **explicitly or clearly asking** for it.
                2. If the user merely **mentions** the info without asking for it, do NOT include it.
                3. Return **ONLY JSON** in the format: {{ "requested_info": [list of categories] }}.
                4. If none are requested, return an empty list: {{ "requested_info": [] }}.

                Examples:

                User input: "What is your email address?"
                Output: {{ "requested_info": ["email"] }}

                User input: "Please tell me your phone number so I can reach you."
                Output: {{ "requested_info": ["phone"] }}

                User input: "I noticed a conflict in your account today."
                Output: {{ "requested_info": [] }}

                User input: "Can you provide your credit card details?"
                Output: {{ "requested_info": ["credit_card"] }}

                Now analyze this input:
                \"\"\"{user_input}\"\"\"
                """


        try:
            # Call the OpenAI API directly
            response = self.openai.chat.completions.create(
                model= config.OPENAI_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0
            )

            # Extract text
            ai_text = response.choices[0].message.content

            # Parse JSON
            parsed = self.parser.parse(ai_text)
            requested_info = parsed.get("requested_info", [])
            print("requested info00000 ===")
            print(requested_info)
            return [str(r).strip() for r in requested_info]

        except Exception as e:
            print(f"[VulnerabilityAssessor] LLM error: {e}")
            return []
    

class TrustCalculator:
    def __init__(self,openai_client):
        self.config = VICTIM_CONFIG
        self.openai = openai_client
        self.parser = JsonOutputParser()
        self.thresholds = TRUST_THRESHOLDS
        self.info_categories = INFO_CATEGORIES

    def calculate_trigger_impact(self ,triggers: List[Dict]) -> float:
        """
        Calculate trust impact from trigger words used in conversation.
        Expected range: (0-2)
        Optimized for: 3 triggers with scores 6-8 → impact ~1.5-1.7
        
        IMPORTANT: Higher scores = MORE effective triggers = HIGHER impact
        """
        if not triggers:
            return 0.0
        
        num_triggers = len(triggers)
        max_score = max(trigger["score"] for trigger in triggers)
        base_impact = (max_score - 1) / 6.0    # Scale 1-10 to roughly 0-2 range

        if num_triggers == 1:
             count_multiplier = 0.8  # Single trigger gets less impact
        elif num_triggers == 2:
            count_multiplier = 1.1  # Two triggers get moderate boost  
        elif num_triggers == 3:
            count_multiplier = 1.4  # Three triggers get good boost (sweet spot)
        elif num_triggers == 4:
            count_multiplier = 1.6  # Four triggers get higher boost
        else:
            count_multiplier = min(1.8, 1.4 + (num_triggers - 3) * 0.1)  # Diminishing returns after 4
        
        impact = base_impact * count_multiplier
        return min(max(impact, 0.0), 2.0)




    def detect_inappropriate_requests(self, user_input: str, current_trust: float, requested_info: List[str]) -> float:
        """
        Detect if inappropriate information requested before the appropriate timing 
        depending on the current trust score.
        Returns a penalty between 0 and -1.
        """
        reasoning = []
        trust_change = 0.0

        print("requested info = ", requested_info)

        for info in requested_info:
            if info in self.info_categories["sensitive"]:
                threshold = self.thresholds["sensitive_info"][0]
                if current_trust < threshold:
                    gap = threshold - current_trust
                    penalty = gap * 0.5  # Penalty factor
                    trust_change -= penalty
                    reasoning.append(f"Requested sensitive info '{info}' before threshold: -{penalty:.2f}")

            elif info in self.info_categories["critical"]:
                threshold = self.thresholds["critical_info"][0]
                if current_trust < threshold:
                    gap = threshold - current_trust
                    penalty = gap * 0.2  # Penalty factor
                    trust_change -= penalty
                    reasoning.append(f"Requested critical info '{info}' before threshold: -{penalty:.2f}")

        print("trust change before clamp =", trust_change)

        # ✅ Clamp strictly between 0 and -1
        trust_change = max(-1.0, min(0.0, trust_change))

        print("trust change after clamp =", trust_change)
        return trust_change


    def analyze_context_with_ai(self, user_input: str, conversation_history: List[Dict] = None)-> float:
        """
        Analyze conversation context and coherence using AI.
        Expected range: (-0.5, +0.5)
        """
        history = ""
        if conversation_history:
            recent_messages = conversation_history[-3:] if len(conversation_history) > 3 else conversation_history
            histroy = "\n".join([f"User: {msg.get('content', '')}" for msg in recent_messages if msg.get('role') == 'user'])

        print("-" * 20 + "\nHistory: " + str(history))

        prompt = f"""You are a strict evaluator for social engineering training. 
                    Your job is to check if the user's input sounds like a **natural full sentence with a reason/context** 
                    or if it is just **keywords or abrupt commands without reasoning**.

                    Rules:
                    - If it is a complete sentence with context and reasoning → score +0.5
                    - If it is partly a sentence but still natural and somewhat reasonable → score +0.3
                    - If it is basic but acceptable → score +0.1
                    - If it is just random keywords → score -0.5
                    - If it is a full sentence BUT only gives an order without a reason (e.g. “I need it right now”, “Give me your password”) → score -0.3 or below
                    - if and only if the context appeared with a reason , then consider it as good , otherwise it's bad!

                    Examples:

                    Bad: "name , malak , act immeditly"
                    → Score: -0.5

                    Bad: "I need it right now. Hurry up. You only have minutes."
                    → Score: -0.3 (full sentences but no reason/context, just pressure)

                    Bad: "Act immediately. Give me your password."
                    → Score: -0.5 (abrupt order, no justification)

                    Good: "My name is Malak, from Omantel, and I need you to act immediately and give me your phone number."
                    → Score: +0.5 (natural, has identity, reason, and context)

                    Now evaluate:

                    History:
                    {history}

                    Current Input: "{user_input}"

                    Respond only in JSON:
                    {{
                    "score": number,
                    "reason": "short explanation"
                    }}
                    """
        
        try:
            response = self.openai.chat.completions.create(
                model=config.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a conversation coherence analyzer. Rate user inputs based on how logical and coherent they are in context."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0,
                max_tokens=250,
            )
            
            result_text = response.choices[0].message.content.strip()
            result = self.parser.parse(result_text)
            
            score = float(result.get("score", 0))
            score = max(min(score, 0.5), -0.5)

            reason = result.get("reason", "No analysis provided")
            
            print(f"AI Context Analysis: Score={score}, Reason={reason}")
            
            # Ensure score is within expected range
            return {"score": score, "reason": reason}
           

        except Exception as e:
            print(f"Error in AI context analysis: {e}")
            return -66326           

        
    def calculate(self ,current_trust: float, triggers: List[Dict], user_input: str, requested_info = List[str] ,conversation_history: List[Dict] = None) -> Dict[str, Any]:
        """Calculate new trust score"""



        trigger_impact = self.calculate_trigger_impact(triggers)
        inappropriate_penalty = self.detect_inappropriate_requests(user_input, current_trust,requested_info)
        print(inappropriate_penalty)
        print("*"*20 + "innopropriate reguest" + str(inappropriate_penalty))
        context_result = self.analyze_context_with_ai(user_input, conversation_history)
        context_score = context_result["score"]
        context_reason = context_result["reason"]

        total_change = trigger_impact + inappropriate_penalty + context_score
        new_trust = current_trust + total_change
        new_trust = max(0.0, min(10.0, new_trust))

        # Build reasoning string
        reasoning_parts = []
        if trigger_impact > 0:
            reasoning_parts.append(f"Triggers: +{trigger_impact:.2f}")
        if inappropriate_penalty < 0:
            reasoning_parts.append(f"Inappropriate requests: {inappropriate_penalty:.2f}")
        if context_score != 0:
            reasoning_parts.append(f"Context: {context_score:+.2f}  ({context_reason})")
        
        reasoning = " | ".join(reasoning_parts) if reasoning_parts else "No significant changes"
        
        
        
        return {
            "new_trust": new_trust,
            "change": total_change,
            "reasoning": reasoning,
            "breakdown": {
                "trigger_impact": trigger_impact,
                "inappropriate_penalty": inappropriate_penalty,
                "context_score" : context_score,
                "context_reason": context_reason
            }
        }
    

