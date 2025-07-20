from flask import Flask, render_template, request, jsonify
import re
import math
from collections import Counter

app = Flask(__name__)

class PasswordChecker:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', 'password123', 'admin', 'qwerty', 
            'letmein', 'welcome', 'monkey', '1234567890', 'abc123'
        ]
    
    def check_strength(self, password):
        if not password:
            return {
                'score': 0,
                'strength': 'No Password',
                'feedback': ['Please enter a password'],
                'color': 'red'
            }
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) < 8:
            feedback.append('Use at least 8 characters')
        elif len(password) < 12:
            score += 1
            feedback.append('Consider using 12+ characters for better security')
        else:
            score += 2
        
        # Character variety checks
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append('Add lowercase letters')
            
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append('Add uppercase letters')
            
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append('Add numbers')
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append('Add special characters (!@#$%^&*)')
        
        # Common password check
        if password.lower() in self.common_passwords:
            score = max(0, score - 3)
            feedback.append('Avoid common passwords')
        
        # Repeated characters check
        if len(set(password)) < len(password) * 0.6:
            score = max(0, score - 1)
            feedback.append('Reduce repeated characters')
        
        # Sequential characters check
        sequential = any(
            ord(password[i]) == ord(password[i-1]) + 1 
            for i in range(1, min(len(password), 4))
        )
        if sequential:
            score = max(0, score - 1)
            feedback.append('Avoid sequential characters (abc, 123)')
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        if entropy > 60:
            score += 1
        
        # Determine strength
        if score <= 2:
            strength = 'Weak'
            color = 'red'
        elif score <= 4:
            strength = 'Fair'
            color = 'orange'
        elif score <= 6:
            strength = 'Good'
            color = 'yellow'
        else:
            strength = 'Strong'
            color = 'green'
        
        if not feedback:
            feedback = ['Great! Your password looks secure.']
        
        return {
            'score': min(score, 7),
            'strength': strength,
            'feedback': feedback,
            'color': color,
            'entropy': round(entropy, 1),
            'length': len(password)
        }
    
    def calculate_entropy(self, password):
        """Calculate password entropy"""
        char_space = 0
        if re.search(r'[a-z]', password):
            char_space += 26
        if re.search(r'[A-Z]', password):
            char_space += 26
        if re.search(r'\d', password):
            char_space += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            char_space += 32
        
        if char_space == 0:
            return 0
        
        return len(password) * math.log2(char_space)

checker = PasswordChecker()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_password():
    data = request.get_json()
    password = data.get('password', '')
    result = checker.check_strength(password)
    return jsonify(result)

@app.route('/generate')
def generate_password():
    import secrets
    import string
    
    # Generate a secure password
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(chars) for _ in range(16))
    
    # Ensure it has all character types
    password = list(password)
    password[0] = secrets.choice(string.ascii_lowercase)
    password[1] = secrets.choice(string.ascii_uppercase)
    password[2] = secrets.choice(string.digits)
    password[3] = secrets.choice("!@#$%^&*")
    
    return jsonify({'password': ''.join(password)})

if __name__ == '__main__':
    print("Password Security Checker is running!")
    print("Open http://127.0.0.1:5000 in your browser")
    print("\nFeatures:")
    print("- Real-time password strength analysis")
    print("- Security recommendations")
    print("- Secure password generator")
    print("- Entropy calculation")
    print("- Mobile-responsive design")
    
    app.run(debug=True)