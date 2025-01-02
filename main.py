import httpx
import os
import re
import json
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def identify_emails(domain: str):
    """Identify emails from the specified domain."""
    url = f"https://{domain}"
    try:
        response = httpx.get(url)
        response.raise_for_status()  # Raise an error for bad responses
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Regex pattern for matching email addresses
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        emails = set(re.findall(email_pattern, soup.get_text()))
        
        return list(emails)
    except Exception as e:
        print(f"Error fetching emails from {domain}: {e}")
        return []

def verify_email(email: str):
    """Verify the email using Hunter.io API."""
    api_key = os.getenv("HUNTER_API_KEY")
    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={api_key}"
    try:
        response = httpx.get(url)
        response.raise_for_status()  # Raise an error for bad responses
        return response.json()
    except Exception as e:
        print(f"Error verifying email {email}: {e}")
        return {}

def domain_search(domain: str):
    """Search for emails associated with a domain using Hunter.io API."""
    api_key = os.getenv("HUNTER_API_KEY")
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
    try:
        response = httpx.get(url)
        response.raise_for_status()  # Raise an error for bad responses
        return response.json()
    except Exception as e:
        print(f"Error searching domain {domain}: {e}")
        return {}

def print_header():
    """Print the application header."""
    header = r"""
     ____            _                _             
    |  _ \ _ __ ___ | |__   ___ _ __ | |_ ___  _ __ 
    | |_) | '__/ _ \| '_ \ / _ \ '_ \| __/ _ \| '__|
    |  __/| | | (_) | | | |  __/ | | | || (_) | |   
    |_|   |_|  \___/|_| |_|\___|_| |_|\__\___/|_|   
                                                    
    """
    print(header)

def main():
    print_header()  # Print the application header
    while True:
        print("\nEmail Finder Application")
        print("1. Identify Emails from Domain")
        print("2. Verify Email")
        print("3. Domain Search")
        print("4. Exit")
        
        choice = input("Select an option (1-4): ")
        
        if choice == '1':
            domain = input("Enter the domain name (e.g., example.com): ")
            emails_found = identify_emails(domain)
            if emails_found:
                print("Found Emails:")
                print(json.dumps(emails_found, indent=4))
            else:
                print("No emails found.")
        
        elif choice == '2':
            email = input("Enter the email address to verify: ")
            verification_result = verify_email(email)
            print(f"Verification result for {email}: {json.dumps(verification_result, indent=4)}")
        
        elif choice == '3':
            domain = input("Enter the domain name (e.g., example.com): ")
            domain_result = domain_search(domain)
            if 'data' in domain_result and domain_result['data']:
                print("Emails found for the domain:")
                for item in domain_result['data']:
                    print(f"Email: {item['email']}, Name: {item.get('first_name', '')} {item.get('last_name', '')}")
            else:
                print("No emails found for the domain.")
        
        elif choice == '4':
            print("Exiting application.")
            break
        
        else:
            print("Invalid choice. Please select again.")

if __name__ == "__main__":
    main()