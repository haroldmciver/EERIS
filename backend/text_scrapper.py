import json
from typing import Dict, Any
from openai import OpenAI
from datetime import datetime

# Define the schema for receipt data
RECEIPT_SCHEMA = {
    "type": "object",
    "properties": {
        "store_name": {"type": "string"},
        "phone": {"type": "string", "pattern": "^[0-9-+()\\s]*$"},
        "website": {"type": "string", "format": "uri"},
        "address": {"type": "string"},
        "date": {"type": "string", "format": "date"},
        "time": {"type": "string", "pattern": "^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$"},
        "line_items": {
            "type": "array",
            "items": {"type": "string"}
        },
        "total_payment": {
            "type": "string",
            "pattern": "^\\$?\\d+\\.?\\d*$"
        },
        "payment_method": {"type": "string"},
        "expense_category": {
            "type": "string",
            "enum": ["travel", "meals", "office supplies", "entertainment", "training", "transportation", ""]
        }
    },
    "required": [
        "store_name", "phone", "website", "address", "date", 
        "time", "line_items", "total_payment", "payment_method",
        "expense_category"
    ]
}

def parse_receipt_text(text: str, api_key: str) -> Dict[str, Any]:
    """
    Parse receipt text using GPT to extract structured data.
    
    Args:
        text: Raw OCR text from receipt
        api_key: OpenAI API key
        
    Returns:
        Dictionary containing extracted receipt fields
    """
    # Set up OpenAI client
    client = OpenAI(api_key=api_key)
    
    # System message to instruct GPT
    system_msg = f"""You are an assistant that extracts structured data from receipt text.
        Return ONLY valid JSON matching this exact schema, with no additional text or commentary:

        {json.dumps(RECEIPT_SCHEMA, indent=2)}

        Notes on formatting:
        - Phone numbers should contain only numbers, spaces, and -() characters
        - Website URLs must start with http:// or https://
        - Dates must be in YYYY-MM-DD format
        - Times must be in 24-hour HH:MM format
        - Total payment must be in $XX.XX format
        - Expense category must be one of: travel, meals, office supplies, entertainment, training, transportation
          * Choose the most appropriate category based on the store name and purchased items
          * If none of these categories clearly apply, use an empty string ""
        - Use empty string "" for any fields not found in the receipt"""
    
    # User message with instructions
    user_msg = f"""Extract the receipt data into JSON format following the schema exactly.
        If any field is missing or unclear, use an empty string "".
        For line items, include all purchased items as an array of strings.
        For expense category, analyze the store name and purchased items to determine the most appropriate category from the allowed list.

        Receipt text:
        {text}"""
    
    try:
        # Call GPT API
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg}
            ],
            temperature=0.1  # Low temperature for more consistent output
        )
        
        # Extract and parse JSON response
        json_str = response.choices[0].message.content.strip()
        parsed_data = json.loads(json_str)
        
        # Ensure all required fields exist with proper defaults
        required_fields = {
            'store_name': '',
            'phone': '',
            'website': '',
            'address': '',
            'date': '',
            'time': '',
            'line_items': [],
            'total_payment': '',
            'payment_method': '',
            'expense_category': ''
        }
        
        # Update with parsed values, using defaults for missing fields
        result = {**required_fields, **parsed_data}
        
        # Ensure proper formatting
        if result['total_payment'] and not result['total_payment'].startswith('$'):
            result['total_payment'] = f"${result['total_payment'].strip()}"
        
        if result['website'] and not (result['website'].startswith('http://') or result['website'].startswith('https://')):
            result['website'] = f"https://{result['website']}"
        
        return result
        
    except Exception as e:
        raise Exception(f"Error parsing receipt text: {str(e)}")

def format_receipt_data(data: Dict[str, Any]) -> None:
    """
    Format and display the parsed receipt data in the terminal.
    
    Args:
        data: Dictionary containing parsed receipt data
    """
    print("\n=== Parsed Receipt Data ===")
    print(f"Store: {data['store_name']}")
    print(f"Phone: {data['phone']}")
    print(f"Website: {data['website']}")
    print(f"Address: {data['address']}")
    print(f"Date: {data['date']}")
    print(f"Time: {data['time']}")
    print("\nItems purchased:")
    for item in data['line_items']:
        print(f"  - {item}")
    print(f"\nTotal: {data['total_payment']}")
    print(f"Payment Method: {data['payment_method']}")
    print(f"Expense Category: {data['expense_category']}")
    print("==========================") 