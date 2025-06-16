import requests

def ask_ollama(prompt, model="llama3"):
    """
    Sends a user query and vault entry context to Ollama to extract the correct key.
    Uses strict few-shot formatting to ensure it returns only the vault key.
    """

    instruction = (
        "You are a credential key extractor.\n"
        "You are given vault entries in the format:\n"
        "    key ← aliases: alias1, alias2\n"
        "Your job is to identify the BEST MATCHING `key` based on a user query.\n"
        "- Match based on key names and aliases.\n"
        "- Use context clues to guess which is best if multiple are similar.\n"
        "- Return ONLY the exact key text (before the '←').\n"
        "- DO NOT respond with explanations, extra text, or apologies.\n"
        "- DO NOT invent keys.\n"
        "\n"
        "Examples:\n"
        "User query: What's my Github login?\n"
        "Output: github\n\n"
        "User query: login for wizard101 alt?\n"
        "Output: wizard101 alt\n\n"
        "User query: show me wizard101 main credentials\n"
        "Output: wizard101 main\n\n"
        "User query: school email login\n"
        "Output: umd elms\n\n"
        "Now process this:\n"
    )

    full_prompt = instruction + prompt

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": model, "prompt": full_prompt, "stream": False}
        )
        return response.json()["response"].strip().lower()
    except Exception as e:
        return "error: " + str(e)
