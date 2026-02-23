"""Groq AI integration service (Llama 3.3 70B)."""

import json
import logging
from typing import Any, Dict, List, Optional

from groq import AsyncGroq

from app.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are SENTINEL AI, a threat intelligence analyst assistant integrated into "
    "the SENTINEL Threat Intelligence Platform. You help security analysts understand "
    "indicators of compromise (IOCs), threat actors, attack patterns, and cyber threats. "
    "Provide concise, actionable intelligence. Use technical cybersecurity terminology "
    "appropriately. Format responses in clear sections when applicable."
)


class GroqService:
    """Wrapper around Groq API for threat intelligence analysis."""

    def __init__(self):
        self.api_key = settings.GROQ_API_KEY
        self.model_name = "llama-3.3-70b-versatile"
        self._client: Optional[AsyncGroq] = None

    def _get_client(self) -> AsyncGroq:
        if not self.api_key:
            raise ValueError("GROQ_API_KEY is not configured")
        if self._client is None:
            self._client = AsyncGroq(api_key=self.api_key)
        return self._client

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    async def analyze_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        enrichment_data: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate AI threat analysis for an IOC."""
        client = self._get_client()

        enrichment_text = ""
        if enrichment_data:
            enrichment_text = "\n\nEnrichment data:\n" + json.dumps(
                enrichment_data, indent=2, default=str
            )

        prompt = (
            f"Analyze this indicator of compromise (IOC) from a threat intelligence perspective.\n\n"
            f"IOC Type: {ioc_type}\n"
            f"IOC Value: {ioc_value}\n"
            f"{enrichment_text}\n\n"
            f"Provide your analysis in the following JSON format:\n"
            f'{{\n'
            f'  "summary": "Brief 1-2 sentence summary of the threat",\n'
            f'  "risk_level": "critical|high|medium|low",\n'
            f'  "analysis": "Detailed multi-paragraph analysis of the IOC including potential threat actor associations, known campaigns, attack patterns, and historical context",\n'
            f'  "recommendations": ["actionable recommendation 1", "actionable recommendation 2", "actionable recommendation 3"]\n'
            f'}}\n\n'
            f"Return ONLY valid JSON, no markdown formatting."
        )

        response = await client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )
        text = response.choices[0].message.content.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3].strip()
        if text.startswith("json"):
            text = text[4:].strip()

        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            result = {
                "summary": "AI analysis completed.",
                "risk_level": "medium",
                "analysis": text,
                "recommendations": ["Review the IOC manually for additional context."],
            }

        return result

    async def chat(
        self,
        messages: List[Dict[str, str]],
        system_context: Optional[str] = None,
    ) -> str:
        """Send a chat message and get a response."""
        client = self._get_client()

        system = SYSTEM_PROMPT
        if system_context:
            system += f"\n\nAdditional context:\n{system_context}"

        groq_messages = [{"role": "system", "content": system}]
        for msg in messages:
            role = "user" if msg["role"] == "user" else "assistant"
            groq_messages.append({"role": role, "content": msg["content"]})

        response = await client.chat.completions.create(
            model=self.model_name,
            messages=groq_messages,
            temperature=0.7,
        )

        return response.choices[0].message.content

    async def generate_ai_report(
        self,
        ioc_data: List[Dict[str, Any]],
        stats: Dict[str, Any],
    ) -> Dict[str, str]:
        """Generate an AI-written threat intelligence report."""
        client = self._get_client()

        prompt = (
            f"Generate a professional threat intelligence report based on the following data.\n\n"
            f"Platform Statistics:\n{json.dumps(stats, indent=2, default=str)}\n\n"
            f"Recent Critical IOCs ({len(ioc_data)} indicators):\n"
            f"{json.dumps(ioc_data[:30], indent=2, default=str)}\n\n"
            f"Write a comprehensive threat intelligence brief that includes:\n"
            f"1. Executive Summary\n"
            f"2. Key Findings\n"
            f"3. Threat Landscape Overview\n"
            f"4. Critical Indicators Analysis\n"
            f"5. Recommendations\n\n"
            f"Write in a professional, concise style suitable for a SOC team. "
            f"Use markdown formatting for headers and lists."
        )

        response = await client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.5,
        )

        return {
            "title": "AI Threat Intelligence Brief",
            "content": response.choices[0].message.content,
        }


# Singleton instance
groq_service = GroqService()
