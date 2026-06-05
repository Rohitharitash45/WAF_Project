import re
import os
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash
from pymongo import MongoClient

app = Flask(__name__)
app.secret_key = "super_secret_waf_key" # Flash messages ke liye zaroori hai

# Fallback structures taaki agar database connect na ho to project crash na kare
MEMORY_USERS = [
    {"username": "admin", "role": "Administrator"},
    {"username": "rohit", "role": "Developer"},
    {"username": "rahul", "role": "Security Analyst"}
]
MEMORY_LOGS = []
USING_CLOUD_DB = False

# Variables ko globally pehle hi define kar diya
client = None
db = None
logs_collection = None
users_collection = None

# 1. MongoDB Connection Setup
try:
    client = MongoClient(
        "mongodb+srv://rohit_waf:wafproject123@cluster0.vby7u.mongodb.net/?retryWrites=true&w=majority", 
        serverSelectionTimeoutMS=2000
    )
    db = client["waf_database"]          
    logs_collection = db["waf_logs"]    
    users_collection = db["users"]      
    
    client.server_info() 
    USING_CLOUD_DB = True
    print("[+] Cloud MongoDB Connected Successfully!")
except Exception as e:
    print(f"[-] MongoDB Connection Error: {e}")
    print("[!] Working in Fail-Safe Local Memory Mode (Logs will stay until server is running)")

# 2. Dummy Data Injection
def init_db():
    if USING_CLOUD_DB and users_collection is not None:
        try:
            if users_collection.count_documents({}) == 0:
                users_collection.insert_many(MEMORY_USERS)
                print("[+] Dummy user data injected into Cloud MongoDB.")
        except Exception as e:
            print(f"[-] Init DB Error: {e}")

# 3. WAF Detection Patterns
WAF_RULES = {
    "SQL Injection": re.compile(r"UNION\s+SELECT|SELECT\s+.*\s+FROM|OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|'--|--|\/\*", re.IGNORECASE),
    "Cross-Site Scripting (XSS)": re.compile(r"<script.*?>|<\/script>|javascript:|onerror=|onload=", re.IGNORECASE)
}

# 4. Attack Logs Save karne ka function
def log_attack(ip, attack_type, payload):
    log_data = {
        "ip_address": ip,
        "attack_type": attack_type,
        "payload": payload,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Fail-safe mode: Pehle memory logs me daal dete hain taaki instant dikhe
    MEMORY_LOGS.insert(0, log_data)
    
    if USING_CLOUD_DB and logs_collection is not None:
        try:
            logs_collection.insert_one(log_data)
            print("[+] Attack logged to Cloud MongoDB successfully.")
        except Exception as e:
            print(f"[-] Failed to log to cloud: {e}")

# 5. WAF Middleware (Yahan badlav kiya hai taaki crash na ho aur reload ho jaye)
@app.before_request
def web_application_firewall():
    # static files ya resources ko scan nahi karna hai
    if request.endpoint == 'static':
        return
        
    request_params = {**request.args.to_dict(), **request.form.to_dict()}
    client_ip = request.remote_addr

    for param, value in request_params.items():
        for attack_name, pattern in WAF_RULES.items():
            if pattern.search(value):
                print(f"[!] ALERT: {attack_name} detected from IP {client_ip}. Payload: {value}")
                log_attack(client_ip, attack_name, value)
                
                # 403 error page par bhejne ke bajay user ko dashboard par hi alert ke sath redirect karo
                flash(f"⚠️ Malicious Activity Detected! {attack_name} request has been blocked by WAF.", "danger")
                return redirect(url_for('index'))

# 6. Routes (Frontend Dashboard Controller)
@app.route('/', methods=['GET', 'POST'])
def index():
    search_result = None
    search_query = ""
    
    if request.method == 'POST':
        search_query = request.form.get('search', '')
        
    # User Search logic
    if USING_CLOUD_DB and users_collection is not None:
        try:
            if request.method == 'POST' and search_query:
                query = {"username": {"$regex": search_query, "$options": "i"}}
                search_result = list(users_collection.find(query, {"_id": 0, "username": 1, "role": 1}))
            
            # Agar cloud database se connectivity achhi hai to wahan se logs uthao
            cloud_logs = list(logs_collection.find().sort("_id", -1))
            all_logs = cloud_logs if cloud_logs else MEMORY_LOGS
        except Exception as e:
            print(f"[-] Database Fetch Error, shifting to memory: {e}")
            if request.method == 'POST':
                search_result = [u for u in MEMORY_USERS if search_query.lower() in u['username'].lower()]
            all_logs = MEMORY_LOGS
    else:
        if request.method == 'POST' and search_query:
            search_result = [u for u in MEMORY_USERS if search_query.lower() in u['username'].lower()]
        all_logs = MEMORY_LOGS
        
    return render_template('index.html', search_result=search_result, logs=all_logs, mode="Cloud MongoDB" if USING_CLOUD_DB else "Fail-Safe Memory Mode")

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)