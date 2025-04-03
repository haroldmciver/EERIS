import json
from typing import Dict, Any, List, Union
from openai import OpenAI

def process_chat_request(
    message: str, 
    user_data: List[Dict[str, Any]], 
    api_key: str,
    conversation_history: List[Dict[str, str]] = None
) -> str:
    """
    Process a chat request and generate a response based on user's receipt data.
    
    Args:
        message: The user's query/message
        user_data: List of receipt data for the user
        api_key: OpenAI API key
        conversation_history: List of previous messages in the conversation
        
    Returns:
        The assistant's response to the user's question
    """
    try:
        # If no receipts, return a simple message
        if not user_data:
            return "You don't have any receipts in the system yet. Upload some receipts to ask questions about them."
        
        # Extract the list of usernames present in the data
        known_users = set()
        for receipt in user_data:
            if 'username' in receipt:
                known_users.add(receipt['username'])
        
        # Prepare context for OpenAI
        context = json.dumps(user_data, indent=2)
        
        # Set up OpenAI client
        client = OpenAI(api_key=api_key)
        
        # Prepare messages for the API call
        messages = [
            {
                "role": "system", 
                "content": (
                    "You are a helpful assistant that answers questions about receipt data. "
                    "Keep your responses concise but friendly. Avoid unnecessary details. "
                    "If asked about a person who doesn't exist in the data, respond 'I don't know who that is' and list the users you do have information about. "
                    f"The known users in the system are: {', '.join(known_users) if known_users else 'none'}. "
                    "Help analyze expenses, spending patterns, and provide insights when asked. "
                    "You can reference previous parts of the conversation if relevant."
                )
            }
        ]
        
        # Add data context as a separate system message
        messages.append({
            "role": "system",
            "content": f"Receipt data context (JSON):\n{context}"
        })
        
        # Add conversation history if provided
        if conversation_history and len(conversation_history) > 0:
            # Only use the first message as context setting if it's from the user
            first_msg = conversation_history[0]
            if first_msg["role"] == "user":
                # For the first message, combine with context to ensure data is considered
                messages.append({
                    "role": "user",
                    "content": f"My question about my receipts is: {first_msg['content']}"
                })
                # Add the rest of the conversation history starting from second message
                messages.extend(conversation_history[1:])
            else:
                # If first message isn't from user, just add all messages
                messages.extend(conversation_history)
        else:
            # If no history, just add the current message
            messages.append({
                "role": "user",
                "content": f"My question about my receipts is: {message}"
            })
        
        # Call OpenAI API
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages
        )
        
        # Extract and return the response
        return response.choices[0].message.content
        
    except Exception as e:
        return f"Sorry, I encountered an error: {str(e)}" 