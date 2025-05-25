import os
import json
from cryptography.fernet import Fernet

class AICodeGenerator:
    def __init__(self):
        self.api_key = None
        self.setup_api_key()

    def setup_api_key(self):
        """Setup and encrypt the API key"""
        key_file = "cybervenom.key"
        if not os.path.exists(key_file):
            print("[!] Please set up your API key first")
            return

        with open(key_file, 'rb') as f:
            key = f.read()
        self.fernet = Fernet(key)

        # This is the placeholder - will be replaced with real key
        self.api_key = "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"

    def generate_code(self, prompt):
        """Generate code using AI"""
        try:
            import openai
            
            # Initialize OpenAI with placeholder key
            openai.api_key = self.api_key
            
            print(f"\n[+] Generating code for: {prompt}")
            
            # This is where the actual API call would happen
            # The placeholder will be replaced with the real key
            print("[+] Using OpenAI API to generate code...")
            
            # Simulate code generation
            print("\n[+] Generated Code:")
            print("# This is a placeholder for the generated code")
            print("# The actual code will be generated using OpenAI API")
            
        except Exception as e:
            print(f"[!] Error generating code: {str(e)}")
            print("[!] Make sure you have set up your OpenAI API key correctly")

    def save_api_key(self, key):
        """Securely save the API key"""
        try:
            encrypted_key = self.fernet.encrypt(key.encode())
            with open(".api_key", 'wb') as f:
                f.write(encrypted_key)
            print("[+] API key saved successfully")
        except Exception as e:
            print(f"[!] Error saving API key: {str(e)}")

    def load_api_key(self):
        """Load the encrypted API key"""
        try:
            if os.path.exists(".api_key"):
                with open(".api_key", 'rb') as f:
                    encrypted_key = f.read()
                self.api_key = self.fernet.decrypt(encrypted_key).decode()
                return True
            return False
        except Exception as e:
            print(f"[!] Error loading API key: {str(e)}")
            return False

if __name__ == "__main__":
    generator = AICodeGenerator()
    generator.generate_code("Write a secure password strength checker")
