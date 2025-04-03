from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename
import sys
import json
from datetime import datetime
import uuid
from openai import OpenAI

# Add backend directory to Python path
sys.path.append('backend')

from image_to_text import extract_text_from_file
from text_scrapper import parse_receipt_text, format_receipt_data
from chat_assistant import process_chat_request

app = Flask(__name__,
           template_folder='frontend/pages', 
           static_folder='frontend/css')      
CORS(app)  # Enable CORS
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key

# Get the directory containing app.py (backend), then go one level up to the project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'database', 'uploads')  # Store files in database/uploads
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Database paths
USERS_DB = os.path.join(BASE_DIR, 'database', 'users.json')
RECEIPTS_DB = os.path.join(BASE_DIR, 'database', 'receipts.json')

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'database'), exist_ok=True)  # Use absolute path

# Create database files if they don't exist
if not os.path.exists(USERS_DB):
    with open(USERS_DB, 'w') as f:
        json.dump({"users": {}}, f)

if not os.path.exists(RECEIPTS_DB):
    with open(RECEIPTS_DB, 'w') as f:
        json.dump({"receipts": {}}, f)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_users():
    with open(USERS_DB, 'r') as f:
        return json.load(f)

def save_users(data):
    with open(USERS_DB, 'w') as f:
        json.dump(data, f, indent=2)

def load_receipts():
    with open(RECEIPTS_DB, 'r') as f:
        return json.load(f)

def save_receipts(data):
    with open(RECEIPTS_DB, 'w') as f:
        json.dump(data, f, indent=2)

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
        
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    users = load_users()
    
    if username not in users['users'] or users['users'][username]['password'] != password:
        return jsonify({'error': 'Invalid username or password'}), 401
    
    session['username'] = username
    session['role'] = users['users'][username]['role']  
    return jsonify({'message': 'Login successful'})

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')  # Get role from request, default to 'user'
    
    users = load_users()
    
    if username in users['users']:
        return jsonify({'error': 'Username already exists'}), 400
    
    users['users'][username] = {
        'password': password,
        'created_at': datetime.now().isoformat(),
        'role': role  # Add role to user data
    }
    
    save_users(users)
    return jsonify({'message': 'Signup successful'})

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/process_receipt', methods=['POST'])
def process_receipt():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    
    try:
        # Generate unique filename
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Save uploaded file
        file.save(filepath)
        
        # Process the receipt
        text = extract_text_from_file(filepath)
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            return jsonify({'error': 'OpenAI API key not set'}), 500
        
        receipt_data = parse_receipt_text(text, api_key)
        receipt_data['image_filename'] = unique_filename
        
        return jsonify(receipt_data)
        
    except Exception as e:
        # Clean up file if there's an error
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': str(e)}), 500

@app.route('/save_receipt', methods=['POST'])
def save_receipt():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        receipt_data = request.get_json()
        
        # Add metadata
        receipt_data['processed_at'] = datetime.now().isoformat()
        receipt_data['status'] = 'submitted'
        
        # Ensure image_filename is preserved
        if 'image_filename' not in receipt_data and hasattr(request, 'image_filename'):
            receipt_data['image_filename'] = request.image_filename
        
        # Save to database
        receipts = load_receipts()
        if session['username'] not in receipts['receipts']:
            receipts['receipts'][session['username']] = []
            
        receipts['receipts'][session['username']].append(receipt_data)
        save_receipts(receipts)
        
        return jsonify({'message': 'Receipt saved successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/uploads/<filename>')
def serve_receipt(filename):
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Check if user has access to this receipt
        receipts = load_receipts()
        has_access = False
        
        # Supervisors have access to all receipts
        if session.get('role') == 'supervisor':
            has_access = True
        else:
            # Regular users can only access their own receipts
            user_receipts = receipts['receipts'].get(session['username'], [])
            has_access = any(receipt.get('image_filename') == filename for receipt in user_receipts)
        
        if not has_access:
            return jsonify({'error': 'Unauthorized'}), 403
            
        upload_path = os.path.join(os.path.dirname(__file__), app.config['UPLOAD_FOLDER'])
        return send_from_directory(upload_path, filename)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/my_receipts')
def my_receipts():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    receipts = load_receipts()
    
    # If user is supervisor, return all receipts
    if session.get('role') == 'supervisor':
        all_receipts = []
        for username, user_receipts in receipts['receipts'].items():
            # Add username to each receipt for identification
            for receipt in user_receipts:
                receipt['username'] = username
            all_receipts.extend(user_receipts)
        return jsonify(all_receipts)
    
    # For regular users, return only their receipts
    user_receipts = receipts['receipts'].get(session['username'], [])
    return jsonify(user_receipts)

@app.route('/check_role')
def check_role():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify({'role': session.get('role', 'user')})

@app.route('/update_receipt_status', methods=['POST'])
def update_receipt_status():
    if 'username' not in session or session.get('role') != 'supervisor':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        username = data.get('username')
        processed_at = data.get('processed_at')
        new_status = data.get('status')
        
        if not all([username, processed_at, new_status]):
            return jsonify({'error': 'Missing required fields'}), 400
            
        receipts = load_receipts()
        
        # Find and update the receipt
        user_receipts = receipts['receipts'].get(username, [])
        for receipt in user_receipts:
            if receipt['processed_at'] == processed_at:
                receipt['status'] = new_status
                save_receipts(receipts)
                return jsonify({'message': 'Status updated successfully'})
        
        return jsonify({'error': 'Receipt not found'}), 404
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/update_receipt', methods=['POST'])
def update_receipt():
    try:
        if 'username' not in session:
            return jsonify({'error': 'Not logged in'}), 401

        data = request.get_json()
        username = data.get('username') or session['username']
        processed_at = data.get('processed_at')

        # Load current receipts
        with open(RECEIPTS_DB, 'r') as f:
            receipts_data = json.load(f)

        # Find and update the receipt
        user_receipts = receipts_data['receipts'].get(username, [])
        for receipt in user_receipts:
            if receipt['processed_at'] == processed_at:
                # Update receipt data while preserving certain fields
                preserved_fields = ['image_filename', 'processed_at', 'status']
                for field in preserved_fields:
                    if field in receipt:
                        data[field] = receipt[field]
                
                # Update the receipt with new data
                receipt.update(data)
                break

        # Save updated receipts
        with open(RECEIPTS_DB, 'w') as f:
            json.dump(receipts_data, f, indent=2)

        return jsonify({'message': 'Receipt updated successfully'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        message = data.get('message')
        conversation_history = data.get('conversation_history', [])
        
        if not message:
            return jsonify({'error': 'No message provided'}), 400
        
        # Get only this user's receipts
        receipts = load_receipts()
        
        # For supervisors, get all receipts
        if session.get('role') == 'supervisor':
            all_receipts = []
            for username, user_receipts in receipts['receipts'].items():
                for receipt in user_receipts:
                    receipt_with_user = receipt.copy()
                    receipt_with_user['username'] = username
                    all_receipts.append(receipt_with_user)
            user_data = all_receipts
        else:
            # For regular users, only get their receipts
            user_data = receipts['receipts'].get(session['username'], [])
        
        # Get OpenAI API key
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            return jsonify({'error': 'OpenAI API key not set'}), 500
        
        # Process the chat request using the external function, passing conversation history
        response_text = process_chat_request(
            message=message, 
            user_data=user_data, 
            api_key=api_key,
            conversation_history=conversation_history
        )
        
        return jsonify({'response': response_text})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 