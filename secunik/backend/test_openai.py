# test_gpt4o.py
import os
from dotenv import load_dotenv
from openai import OpenAI

# Load .env file
load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")
print(f"✅ API Key found: {bool(api_key)}")
if api_key:
    print(f"✅ Key starts with: {api_key[:20]}...")
else:
    print("❌ No API key found!")
    exit()

try:
    client = OpenAI(api_key=api_key)
    
    # Test with GPT-4o
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "What model are you?"}],
        max_tokens=50
    )
    
    print("✅ OpenAI GPT-4o connection successful!")
    print(f"Response: {response.choices[0].message.content}")
    print(f"Model used: {response.model}")
    
except Exception as e:
    print(f"❌ Error: {e}")