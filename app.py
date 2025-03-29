import json
import hashlib
import time
import base64
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = "UDHtJdtKYBAMoZfWEUXC5A=="  # Secure key
BLOCK_SIZE = 16  # Block size for AES encryption
AES_KEY = "Ght9xL4sV7yQ2mNp"  # 16-byte key
AES_IV = "1234567890abcdef"  # 16-byte IV

# Encryption function
def encrypt_message(message, key=AES_KEY, iv=AES_IV):
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())  # Use correct IV
    encrypted = cipher.encrypt(pad(message.encode(), BLOCK_SIZE))
    return base64.b64encode(encrypted).decode()

# Decryption function
def decrypt_message(encrypted_message, key=AES_KEY, iv=AES_IV):
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())  # Use correct IV
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_message)), BLOCK_SIZE)
    return decrypted.decode()

# Blockchain class
class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_messages = []
        self.load_data()

    def load_data(self):
        """Load blockchain data from file."""
        try:
            with open("blockchain1.json", "r") as f:
                data = json.load(f)
                self.chain = data.get("chain", [])
                self.pending_messages = data.get("pending", [])
        except (FileNotFoundError, json.JSONDecodeError):
            self.chain = []
            self.pending_messages = []

    def save_data(self):
        """Save blockchain data to file."""
        with open("blockchain1.json", "w") as f:
            json.dump({"chain": self.chain, "pending": self.pending_messages}, f, indent=4)

    def register_user(self, password):
        """Register a new user with a hashed password."""
        username_hashed = hashlib.sha256(str(time.time()).encode()).hexdigest()[:10]
        password_hashed = generate_password_hash(password)
        user_block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "username": username_hashed,
            "password": password_hashed,
            "type": "user"
        }
        self.chain.append(user_block)
        self.save_data()
        return {"message": "User registered successfully!", "username": username_hashed}

    def login_user(self, username, password):
        """Authenticate a user."""
        for block in self.chain:
            if block.get("type") == "user" and block["username"] == username:
                if check_password_hash(block["password"], password):
                    session["username"] = username
                    return "Login successful!"
        return "Invalid username or password!"

    def send_message(self, sender, receiver, message):
        """Encrypt and store a message in pending transactions."""
        encrypted_message = encrypt_message(message)
        self.pending_messages.append({"sender": sender, "receiver": receiver, "message": encrypted_message})
        self.save_data()  # Save message in pending state
        return "Message sent successfully!"

    def mine_block(self):
        """Mine a block of pending messages."""
        self.load_data()  # Ensure latest pending messages are fetched
        if not self.pending_messages:
            return "No messages to mine!"
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "messages": self.pending_messages
        }
        self.chain.append(block)
        self.pending_messages = []
        self.save_data()
        return "Block mined successfully!"

    def get_messages(self, address):
        self.load_data()  # Ensure the latest blockchain data is loaded
        print("DEBUG: Blockchain Data:", json.dumps(self.chain, indent=4))  # Print the blockchain data

        messages = []
        for block in self.chain:
            for message in block.get("messages", []):
                if message.get("sender") == address or message.get("receiver") == address:
                    decrypted_message = decrypt_message(message["message"])
                    messages.append({
                        "sender": message["sender"],
                        "receiver": message["receiver"],
                        "message": decrypted_message
                    })

        print("DEBUG: Retrieved Messages:", messages)  # Debug output
        return messages


blockchain = Blockchain()

@app.route("/")
def home():
    """Render chat homepage if logged in, otherwise redirect to login."""
    if "username" not in session:
        return redirect(url_for("login_page"))
    return render_template("chat.html", username=session["username"])

@app.route("/login", methods=["GET", "POST"])
def login_page():
    """Handle user login."""
    if request.method == "POST":
        data = request.json
        message = blockchain.login_user(data["username"], data["password"])
        return jsonify({"message": message}), 200
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Handle user registration."""
    if request.method == "POST":
        data = request.json if request.is_json else request.form
        if "password" not in data:
            return jsonify({"message": "Password is required"}), 400

        response = blockchain.register_user(data["password"])
        return jsonify(response), 200
    return render_template("register.html")  # Serve the register page on GET request

@app.route("/logout")
def logout():
    """Log out the user."""
    session.pop("username", None)
    return redirect(url_for("login_page"))

@app.route("/send_message", methods=["POST"])
def send_message():
    """Send a message if user is logged in."""
    if "username" not in session:
        return redirect(url_for("login_page"))
    data = request.json
    response = blockchain.send_message(session["username"], data["receiver"], data["message"])
    return jsonify({"message": response}), 200

@app.route("/messages", methods=["GET"])
def retrieve_messages():
    """Retrieve user messages as JSON."""
    if "username" not in session:
        return jsonify({"error": "Not logged in"}), 401

    messages = blockchain.get_messages(session["username"])
    return jsonify({"messages": messages})  # Return JSON instead of rendering HTML


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


