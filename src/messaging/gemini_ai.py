"""
Archipel — Module 4.2 : Intégration Gemini API
Assistant IA fonctionnant de manière isolée pour le réseau P2P.
"""

import os
import json
import urllib.request
import urllib.error

def query_gemini(conversation_context: str, user_query: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "[IA] Erreur: Clé API Gemini non configurée (variable d'environnement GEMINI_API_KEY manquante)."

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    
    prompt = f"Contexte récent de la conversation:\n{conversation_context}\n\nQuestion utilisateur:\n{user_query}"
    
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}]
            }
        ]
    }
    
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result["candidates"][0]["content"]["parts"][0]["text"]
            
    except urllib.error.URLError as e:
        return f"[IA] Mode hors-ligne strict (échec API: {e})"
    except (KeyError, IndexError, ValueError):
        return "[IA] Impossible de comprendre la réponse de l'API Gemini."

if __name__ == "__main__":
    print(query_gemini("Alice dit: Bonjour le réseau!", "Que dit Alice ?"))
