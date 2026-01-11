#!/data/data/com.termux/files/usr/bin/python3
"""
Complete AI Terminal Assistant with working GUI
Fixed API issues and GUI functionality
"""

import os
import sys
import json
import subprocess
import threading
import time
import requests
import re
import hashlib
import uuid
import socket
import sqlite3
import webbrowser
from datetime import datetime
import http.server
import socketserver
import html

# ANSI Color Codes
COLOR = {
    'RESET': '\033[0m',
    'RED': '\033[1;31m',
    'GREEN': '\033[1;32m',
    'YELLOW': '\033[1;33m',
    'BLUE': '\033[1;34m',
    'MAGENTA': '\033[1;35m',
    'CYAN': '\033[1;36m',
    'WHITE': '\033[1;37m'
}

# Configuration
CONFIG_DIR = os.path.expanduser("~/.ai-terminal-complete")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
USERS_DB = os.path.join(CONFIG_DIR, "users.db")
TOOLS_DB = os.path.join(CONFIG_DIR, "tools.db")

# Correct DeepSeek API Endpoint (Free tier)
DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"

class DatabaseManager:
    """Database management"""
    
    def __init__(self):
        self.init_databases()
    
    def init_databases(self):
        """Initialize databases"""
        os.makedirs(CONFIG_DIR, exist_ok=True)
        
        # Users database
        conn = sqlite3.connect(USERS_DB)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT,
                date_of_birth TEXT,
                api_key TEXT,
                user_hash TEXT UNIQUE,
                registration_date TEXT,
                last_login TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER,
                start_time TEXT,
                end_time TEXT,
                interface_type TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Tools database
        conn = sqlite3.connect(TOOLS_DB)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_id TEXT,
                timestamp TEXT,
                command TEXT,
                output TEXT,
                interface TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

class UserManager:
    """User management"""
    
    def __init__(self):
        self.db_path = USERS_DB
    
    def register_user(self):
        """Register new user"""
        print(f"\n{COLOR['CYAN']}[USER REGISTRATION]{COLOR['RESET']}")
        print(f"{COLOR['BLUE']}====================={COLOR['RESET']}\n")
        
        username = input(f"{COLOR['YELLOW']}Username: {COLOR['RESET']}").strip()
        
        if self.user_exists(username):
            print(f"{COLOR['RED']}Username already exists{COLOR['RESET']}")
            return None
        
        full_name = input(f"{COLOR['YELLOW']}Full Name: {COLOR['RESET']}").strip()
        
        while True:
            date_of_birth = input(f"{COLOR['YELLOW']}Date of Birth (YYYY-MM-DD): {COLOR['RESET']}").strip()
            try:
                datetime.strptime(date_of_birth, "%Y-%m-%d")
                break
            except ValueError:
                print(f"{COLOR['RED']}Invalid date format. Use YYYY-MM-DD{COLOR['RESET']}")
        
        print(f"\n{COLOR['YELLOW']}DeepSeek API Key:{COLOR['RESET']}")
        print("1. Visit: https://platform.deepseek.com")
        print("2. Sign up and get API key")
        print("3. Free tier available")
        api_key = input(f"{COLOR['YELLOW']}API Key: {COLOR['RESET']}").strip()
        
        # If no API key provided, use a test key (will use local fallback)
        if not api_key:
            print(f"{COLOR['YELLOW']}No API key provided. Using local command database.{COLOR['RESET']}")
            api_key = "local_mode"
        
        # Generate user hash
        user_hash = hashlib.sha256(
            f"{username}:{full_name}:{date_of_birth}:{api_key}".encode()
        ).hexdigest()[:32]
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (username, full_name, date_of_birth, api_key, user_hash, registration_date, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            username, full_name, date_of_birth, api_key, user_hash,
            datetime.now().isoformat(), datetime.now().isoformat()
        ))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"\n{COLOR['GREEN']}[SUCCESS] User registered!{COLOR['RESET']}")
        print(f"{COLOR['BLUE']}User Hash: {user_hash}{COLOR['RESET']}")
        
        return {
            'id': user_id,
            'username': username,
            'user_hash': user_hash,
            'api_key': api_key
        }
    
    def authenticate(self):
        """Authenticate user"""
        print(f"\n{COLOR['CYAN']}[AUTHENTICATION]{COLOR['RESET']}")
        print(f"{COLOR['BLUE']}================={COLOR['RESET']}\n")
        
        if not self.has_users():
            print(f"{COLOR['YELLOW']}No users found. Creating new user...{COLOR['RESET']}")
            return self.register_user()
        
        print("1. Login with username")
        print("2. Login with user hash")
        print("3. Register new user")
        
        choice = input(f"{COLOR['YELLOW']}Select option [1-3]: {COLOR['RESET']}").strip()
        
        if choice == '1':
            username = input(f"{COLOR['YELLOW']}Username: {COLOR['RESET']}").strip()
            return self.login_with_username(username)
        elif choice == '2':
            user_hash = input(f"{COLOR['YELLOW']}User Hash: {COLOR['RESET']}").strip()
            return self.login_with_hash(user_hash)
        elif choice == '3':
            return self.register_user()
        else:
            print(f"{COLOR['RED']}Invalid option{COLOR['RESET']}")
            return self.authenticate()
    
    def login_with_username(self, username):
        """Login with username"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, api_key, user_hash FROM users 
            WHERE username = ? AND status = 'active'
        ''', (username,))
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            user_id, username, api_key, user_hash = user
            self.update_last_login(user_id)
            return {
                'id': user_id,
                'username': username,
                'user_hash': user_hash,
                'api_key': api_key
            }
        
        print(f"{COLOR['RED']}User not found{COLOR['RESET']}")
        return None
    
    def login_with_hash(self, user_hash):
        """Login with user hash"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, api_key FROM users 
            WHERE user_hash = ? AND status = 'active'
        ''', (user_hash,))
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            user_id, username, api_key = user
            self.update_last_login(user_id)
            return {
                'id': user_id,
                'username': username,
                'user_hash': user_hash,
                'api_key': api_key
            }
        
        print(f"{COLOR['RED']}Invalid user hash{COLOR['RESET']}")
        return None
    
    def user_exists(self, username):
        """Check if user exists"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    
    def has_users(self):
        """Check if any users exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    
    def update_last_login(self, user_id):
        """Update user's last login"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET last_login = ? WHERE id = ?',
                     (datetime.now().isoformat(), user_id))
        conn.commit()
        conn.close()

class CommandDatabase:
    """Local command database for fallback when API fails"""
    
    def __init__(self):
        self.commands = {
            'network': {
                'scan network': 'nmap -sP 192.168.1.0/24',
                'scan ports': 'nmap -sS -p 1-1000 192.168.1.1',
                'check connectivity': 'ping -c 4 8.8.8.8',
                'show ip': 'ip addr show',
                'show routes': 'ip route show',
                'dns lookup': 'nslookup google.com'
            },
            'system': {
                'system info': 'uname -a',
                'disk usage': 'df -h',
                'memory usage': 'free -h',
                'process list': 'ps aux',
                'top processes': 'top -n 1 -b',
                'logged users': 'who'
            },
            'files': {
                'list files': 'ls -la',
                'find files': 'find . -type f -name "*.txt"',
                'file size': 'du -sh *',
                'search text': 'grep -r "pattern" .',
                'count lines': 'wc -l file.txt',
                'file permissions': 'stat file.txt'
            },
            'wifi': {
                'wifi interfaces': 'iwconfig',
                'scan wifi': 'iwlist wlan0 scan 2>/dev/null || echo "Need root"',
                'wifi info': 'iw dev wlan0 info',
                'signal strength': 'iwconfig wlan0 | grep Signal'
            },
            'security': {
                'open ports': 'netstat -tulpn',
                'firewall status': 'iptables -L',
                'ssh status': 'systemctl status ssh',
                'failed logins': 'lastb | head -20'
            }
        }
    
    def get_command(self, query):
        """Get command from local database"""
        query_lower = query.lower()
        
        # Search for matching commands
        for category, cmds in self.commands.items():
            for desc, cmd in cmds.items():
                if any(word in query_lower for word in desc.split()):
                    return cmd
        
        # Fallback based on keywords
        keywords = {
            'ping': 'ping -c 4 8.8.8.8',
            'nmap': 'nmap -sP 192.168.1.0/24',
            'port': 'netstat -tulpn',
            'file': 'ls -la',
            'directory': 'ls -la',
            'process': 'ps aux',
            'memory': 'free -h',
            'disk': 'df -h',
            'cpu': 'top -n 1 -b',
            'user': 'whoami',
            'network': 'ip addr show',
            'wifi': 'iwconfig',
            'ip': 'ip addr show',
            'route': 'ip route show'
        }
        
        for keyword, cmd in keywords.items():
            if keyword in query_lower:
                return cmd
        
        return None

class AIManager:
    """AI Manager with fallback to local database"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.local_db = CommandDatabase()
        self.use_local = api_key == "local_mode" or not api_key
    
    def query(self, prompt):
        """Query AI or use local database"""
        
        # If using local mode or no API key, use local database
        if self.use_local:
            return self.query_local(prompt)
        
        # Try API first
        api_response = self.query_api(prompt)
        
        # If API fails, fallback to local
        if not api_response["success"]:
            print(f"{COLOR['YELLOW']}[INFO] API failed, using local database{COLOR['RESET']}")
            return self.query_local(prompt)
        
        return api_response
    
    def query_api(self, prompt):
        """Query DeepSeek API"""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": "deepseek-chat",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a Linux terminal expert. Provide only the Linux command to accomplish the user's request. Output ONLY the command without any explanation, code blocks, or additional text."
                    },
                    {
                        "role": "user", 
                        "content": f"Provide the Linux command for: {prompt}"
                    }
                ],
                "max_tokens": 100,
                "temperature": 0.3
            }
            
            response = requests.post(
                DEEPSEEK_API_URL, 
                headers=headers, 
                json=data, 
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                ai_response = result['choices'][0]['message']['content'].strip()
                
                # Clean up response
                ai_response = ai_response.replace('```bash', '').replace('```', '').strip()
                
                return {
                    "success": True,
                    "response": f"Command: {ai_response}",
                    "command": ai_response,
                    "source": "api"
                }
            else:
                return {
                    "success": False,
                    "error": f"API Error {response.status_code}: {response.text[:100]}",
                    "command": None,
                    "source": "api"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Connection error: {str(e)}",
                "command": None,
                "source": "api"
            }
    
    def query_local(self, prompt):
        """Query local command database"""
        command = self.local_db.get_command(prompt)
        
        if command:
            return {
                "success": True,
                "response": f"Local command: {command}",
                "command": command,
                "source": "local"
            }
        else:
            # Generate a generic command based on prompt
            words = prompt.lower().split()
            if 'list' in words or 'show' in words:
                cmd = 'ls -la'
            elif 'scan' in words or 'network' in words:
                cmd = 'ping -c 4 8.8.8.8'
            elif 'file' in words:
                cmd = 'find . -type f | head -20'
            elif 'process' in words:
                cmd = 'ps aux | head -20'
            else:
                cmd = 'echo "Please be more specific about what you want to do"'
            
            return {
                "success": True,
                "response": f"Suggested: {cmd}",
                "command": cmd,
                "source": "fallback"
            }

class TerminalInterface:
    """Terminal interface"""
    
    def __init__(self, user_info, ai_manager):
        self.user_info = user_info
        self.ai_manager = ai_manager
        self.current_dir = os.path.expanduser("~")
        self.running = True
        self.session_id = str(uuid.uuid4())
        self.command_count = 0
        
        # Create session record
        self.create_session('terminal')
    
    def create_session(self, interface_type):
        """Create session record"""
        conn = sqlite3.connect(USERS_DB)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sessions (session_id, user_id, start_time, interface_type)
            VALUES (?, ?, ?, ?)
        ''', (self.session_id, self.user_info['id'], datetime.now().isoformat(), interface_type))
        
        conn.commit()
        conn.close()
    
    def show_banner(self):
        """Show banner"""
        banner = f"""
{COLOR['CYAN']}╔══════════════════════════════════════════════════════════╗
║           AI TERMINAL ASSISTANT - TERMINAL MODE          ║
╚══════════════════════════════════════════════════════════╝{COLOR['RESET']}

{COLOR['GREEN']}User:{COLOR['RESET']} {self.user_info['username']}
{COLOR['BLUE']}Session:{COLOR['RESET']} {self.session_id[:8]}...
{COLOR['YELLOW']}AI Mode:{COLOR['RESET']} {'API Connected' if self.user_info['api_key'] not in ['local_mode', ''] else 'Local Database'}

{COLOR['CYAN']}══════════════════════════════════════════════════════════{COLOR['RESET']}

{COLOR['YELLOW']}Type commands or describe tasks in plain English.
Examples:
  "scan my network"
  "check disk space" 
  "list all files"
  "show processes"

{COLOR['GREEN']}Special commands:{COLOR['RESET']}
  help     - Show help
  gui      - Start browser GUI
  clear    - Clear screen
  history  - Show command history
  exit     - Exit terminal

{COLOR['CYAN']}══════════════════════════════════════════════════════════{COLOR['RESET']}
        """
        print(banner)
    
    def run(self):
        """Main loop"""
        self.show_banner()
        
        while self.running:
            try:
                prompt = self.build_prompt()
                user_input = input(prompt).strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() == 'exit':
                    self.running = False
                    print(f"{COLOR['GREEN']}Goodbye!{COLOR['RESET']}")
                elif user_input.lower() == 'gui':
                    self.start_gui()
                elif user_input.lower() == 'help':
                    self.show_help()
                elif user_input.lower() == 'clear':
                    subprocess.run('clear', shell=True)
                elif user_input.lower() == 'history':
                    self.show_history()
                else:
                    self.process_input(user_input)
                    
            except KeyboardInterrupt:
                print(f"\n{COLOR['YELLOW']}Type 'exit' to quit{COLOR['RESET']}")
            except EOFError:
                break
            except Exception as e:
                print(f"{COLOR['RED']}Error: {str(e)}{COLOR['RESET']}")
        
        self.end_session()
    
    def build_prompt(self):
        """Build prompt"""
        dir_name = os.path.basename(self.current_dir)
        if len(dir_name) > 15:
            dir_name = "..." + dir_name[-12:]
        
        return f"\n{COLOR['GREEN']}{self.user_info['username']}{COLOR['RESET']}@{COLOR['BLUE']}{dir_name}{COLOR['RESET']} $> "
    
    def process_input(self, user_input):
        """Process user input"""
        print(f"{COLOR['YELLOW']}[AI] Processing request...{COLOR['RESET']}")
        
        ai_response = self.ai_manager.query(user_input)
        
        if ai_response["success"]:
            self.handle_ai_response(ai_response, user_input)
        else:
            print(f"{COLOR['RED']}[AI Error] {ai_response['error']}{COLOR['RESET']}")
            # Fallback to local
            local_response = self.ai_manager.query_local(user_input)
            if local_response["success"]:
                self.handle_ai_response(local_response, user_input)
    
    def handle_ai_response(self, ai_response, original_query):
        """Handle AI response"""
        command = ai_response.get("command")
        response_text = ai_response.get("response", "")
        source = ai_response.get("source", "unknown")
        
        print(f"\n{COLOR['GREEN']}[AI Assistant - {source.upper()}]{COLOR['RESET']}")
        
        if response_text:
            print(f"{COLOR['CYAN']}{response_text}{COLOR['RESET']}")
        
        if command:
            print(f"\n{COLOR['YELLOW']}Execute this command? (y/n/edit): {COLOR['RESET']}", end='')
            choice = input().strip().lower()
            
            if choice == 'y':
                self.execute_command(command)
            elif choice == 'edit':
                print(f"{COLOR['YELLOW']}Edit command [{command}]:{COLOR['RESET']}")
                new_cmd = input(f"{COLOR['CYAN']}>> {COLOR['RESET']}").strip()
                if new_cmd:
                    self.execute_command(new_cmd)
            else:
                print(f"{COLOR['YELLOW']}Command ready for manual use.{COLOR['RESET']}")
        else:
            print(f"{COLOR['YELLOW']}No command generated. Try being more specific.{COLOR['RESET']}")
    
    def execute_command(self, command):
        """Execute command"""
        print(f"{COLOR['CYAN']}[Executing] {command}{COLOR['RESET']}")
        print(f"{COLOR['WHITE']}{'─' * 60}{COLOR['RESET']}")
        
        try:
            # Handle cd separately
            if command.startswith('cd '):
                self.change_directory(command[3:].strip())
                return
            
            # Execute command
            os.chdir(self.current_dir)
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Display output
            if process.stdout:
                print(process.stdout)
            
            if process.stderr:
                print(f"{COLOR['RED']}{process.stderr}{COLOR['RESET']}")
            
            print(f"{COLOR['WHITE']}{'─' * 60}{COLOR['RESET']}")
            
            # Save to history
            self.command_count += 1
            self.save_history(command, process.stdout + process.stderr)
            
        except subprocess.TimeoutExpired:
            print(f"{COLOR['RED']}[Error] Command timed out after 30 seconds{COLOR['RESET']}")
        except Exception as e:
            print(f"{COLOR['RED']}[Error] {str(e)}{COLOR['RESET']}")
    
    def change_directory(self, path):
        """Change directory"""
        try:
            if path == '~':
                new_dir = os.path.expanduser('~')
            elif path.startswith('~/'):
                new_dir = os.path.expanduser(path)
            elif os.path.isabs(path):
                new_dir = path
            else:
                new_dir = os.path.join(self.current_dir, path)
            
            if os.path.isdir(new_dir):
                self.current_dir = os.path.abspath(new_dir)
                print(f"{COLOR['GREEN']}[Directory] {self.current_dir}{COLOR['RESET']}")
            else:
                print(f"{COLOR['RED']}[Error] Directory not found: {path}{COLOR['RESET']}")
        except Exception as e:
            print(f"{COLOR['RED']}[Error] {str(e)}{COLOR['RESET']}")
    
    def start_gui(self):
        """Start GUI interface"""
        print(f"{COLOR['YELLOW']}[Starting GUI server...]{COLOR['RESET']}")
        
        # Start GUI server
        gui_server = GUIServer(self.user_info, self.ai_manager, self.session_id)
        server_thread = threading.Thread(target=gui_server.start, daemon=True)
        server_thread.start()
        
        # Wait for server to start
        time.sleep(2)
        
        # Open browser
        try:
            webbrowser.open("http://localhost:8080")
        except:
            print(f"{COLOR['CYAN']}Open browser to: http://localhost:8080{COLOR['RESET']}")
        
        print(f"{COLOR['GREEN']}[GUI running] Terminal remains active.{COLOR['RESET']}")
        print(f"{COLOR['YELLOW']}Press Enter to continue in terminal...{COLOR['RESET']}")
        input()
    
    def show_help(self):
        """Show help"""
        help_text = f"""
{COLOR['CYAN']}══════════════════════════════════════════════════════════
                   AI TERMINAL ASSISTANT - HELP
══════════════════════════════════════════════════════════{COLOR['RESET']}

{COLOR['YELLOW']}BASIC USAGE:{COLOR['RESET']}
  • Describe what you want to do in plain English
  • AI will suggest appropriate Linux commands
  • Review and execute suggested commands

{COLOR['GREEN']}COMMANDS:{COLOR['RESET']}
  {COLOR['CYAN']}help{COLOR['RESET']}     - Show this help screen
  {COLOR['CYAN']}gui{COLOR['RESET']}      - Start browser GUI interface
  {COLOR['CYAN']}clear{COLOR['RESET']}    - Clear terminal screen
  {COLOR['CYAN']}history{COLOR['RESET']}  - Show command history
  {COLOR['CYAN']}exit{COLOR['RESET']}     - Exit terminal

{COLOR['YELLOW']}EXAMPLES:{COLOR['RESET']}
  "scan my local network"
  "show disk usage statistics"
  "find large files in home directory"
  "list all running processes"
  "check network connectivity"
  "show system information"

{COLOR['GREEN']}TIPS:{COLOR['RESET']}
  • Be specific about what you want to accomplish
  • You can edit AI suggestions before executing
  • Works offline with local command database
  • GUI mode provides web interface

{COLOR['CYAN']}══════════════════════════════════════════════════════════{COLOR['RESET']}
        """
        print(help_text)
    
    def show_history(self):
        """Show command history"""
        conn = sqlite3.connect(TOOLS_DB)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, command FROM command_history 
            WHERE user_id = ? AND session_id = ?
            ORDER BY timestamp DESC LIMIT 10
        ''', (self.user_info['id'], self.session_id))
        
        history = cursor.fetchall()
        conn.close()
        
        if history:
            print(f"\n{COLOR['CYAN']}[COMMAND HISTORY]{COLOR['RESET']}")
            print(f"{COLOR['WHITE']}{'─' * 60}{COLOR['RESET']}")
            
            for timestamp, cmd in history:
                time_str = datetime.fromisoformat(timestamp).strftime("%H:%M:%S")
                cmd_display = cmd if len(cmd) <= 70 else cmd[:67] + "..."
                print(f"{COLOR['YELLOW']}{time_str}{COLOR['RESET']}: {cmd_display}")
            
            print(f"{COLOR['WHITE']}{'─' * 60}{COLOR['RESET']}")
        else:
            print(f"{COLOR['YELLOW']}[No command history]{COLOR['RESET']}")
    
    def save_history(self, command, output):
        """Save command history"""
        conn = sqlite3.connect(TOOLS_DB)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO command_history (user_id, session_id, timestamp, command, output, interface)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            self.user_info['id'],
            self.session_id,
            datetime.now().isoformat(),
            command,
            output[:1000],  # Limit output size
            'terminal'
        ))
        
        conn.commit()
        conn.close()
    
    def end_session(self):
        """End session"""
        conn = sqlite3.connect(USERS_DB)
        cursor = conn.cursor()
        
        cursor.execute('UPDATE sessions SET end_time = ? WHERE session_id = ?',
                     (datetime.now().isoformat(), self.session_id))
        
        conn.commit()
        conn.close()

class GUIServer:
    """GUI Server with working functionality"""
    
    def __init__(self, user_info, ai_manager, session_id):
        self.user_info = user_info
        self.ai_manager = ai_manager
        self.session_id = session_id
        self.port = 8080
        self.running = True
    
    def start(self):
        """Start server"""
        handler = self.create_handler()
        
        try:
            server = socketserver.TCPServer(("", self.port), handler)
            print(f"{COLOR['GREEN']}[GUI] Server started on http://localhost:{self.port}{COLOR['RESET']}")
            server.serve_forever()
        except Exception as e:
            print(f"{COLOR['RED']}[GUI Error] {str(e)}{COLOR['RESET']}")
    
    def create_handler(self):
        """Create HTTP handler"""
        
        class GUIHandler(http.server.BaseHTTPRequestHandler):
            """HTTP Handler for GUI"""
            
            server_instance = self  # Reference to GUIServer instance
            
            def do_GET(self):
                try:
                    if self.path == '/':
                        self.send_homepage()
                    elif self.path == '/api/user':
                        self.send_user_info()
                    elif self.path.startswith('/api/query?'):
                        self.handle_query()
                    elif self.path.startswith('/api/execute?'):
                        self.handle_execute()
                    elif self.path == '/api/history':
                        self.get_history()
                    elif self.path == '/style.css':
                        self.send_css()
                    elif self.path == '/script.js':
                        self.send_js()
                    else:
                        self.send_error(404)
                except Exception as e:
                    print(f"{COLOR['RED']}GUI Handler Error: {str(e)}{COLOR['RESET']}")
                    self.send_error(500)
            
            def send_homepage(self):
                """Send HTML page"""
                html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Terminal Assistant - GUI</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AI Terminal Assistant</h1>
            <div class="user-info">
                <span id="username">User</span>
                <span id="status">● Connected</span>
            </div>
        </div>
        
        <div class="main">
            <div class="sidebar">
                <div class="ai-panel">
                    <h3>🤖 AI Assistant</h3>
                    <div class="ai-chat" id="ai-chat">
                        <div class="message ai">Hello! I'm your AI assistant. Describe what you want to do and I'll suggest Linux commands.</div>
                    </div>
                    <div class="ai-input">
                        <input type="text" id="ai-input" placeholder="Describe task (e.g., 'scan network')">
                        <button onclick="askAI()">Ask AI</button>
                    </div>
                </div>
                
                <div class="quick-actions">
                    <h3>⚡ Quick Actions</h3>
                    <button onclick="quickAction('system')">System Info</button>
                    <button onclick="quickAction('network')">Network Scan</button>
                    <button onclick="quickAction('disk')">Disk Usage</button>
                    <button onclick="quickAction('process')">Process List</button>
                </div>
                
                <div class="history">
                    <h3>📜 History</h3>
                    <div id="history-list"></div>
                </div>
            </div>
            
            <div class="terminal-area">
                <div class="terminal-header">
                    <h3>💻 Terminal</h3>
                    <div class="terminal-controls">
                        <button onclick="clearTerminal()">Clear</button>
                        <button onclick="toggleTheme()">Theme</button>
                    </div>
                </div>
                
                <div class="terminal-output" id="terminal-output">
                    <div class="output-line info">AI Terminal Assistant - GUI Mode</div>
                    <div class="output-line info">Type commands or use AI assistant on the left</div>
                </div>
                
                <div class="terminal-input">
                    <span class="prompt">$</span>
                    <input type="text" id="command-input" placeholder="Enter command or describe task..." 
                           onkeypress="if(event.key=='Enter') executeCommand()">
                    <button onclick="executeCommand()">Run</button>
                </div>
                
                <div class="ai-suggestion" id="ai-suggestion" style="display: none;">
                    <div class="suggestion-header">
                        <strong>AI Suggestion</strong>
                        <button onclick="useSuggestion()">Use</button>
                        <button onclick="hideSuggestion()">×</button>
                    </div>
                    <div class="suggestion-content" id="suggestion-content"></div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <div class="session-info">
                <span>Session: <span id="session-id">---</span></span>
                <span>Commands: <span id="command-count">0</span></span>
                <button onclick="refreshPage()">🔄 Refresh</button>
            </div>
        </div>
    </div>
    
    <script src="script.js"></script>
</body>
</html>
                """
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html_content.encode())
            
            def send_user_info(self):
                """Send user info"""
                data = {
                    'username': self.server_instance.user_info['username'],
                    'session_id': self.server_instance.session_id[:8],
                    'api_connected': self.server_instance.user_info['api_key'] not in ['local_mode', '']
                }
                self.send_json(data)
            
            def handle_query(self):
                """Handle AI query"""
                import urllib.parse
                query = self.path.split('query=')[1] if 'query=' in self.path else ''
                query = urllib.parse.unquote(query)
                
                if query:
                    ai_response = self.server_instance.ai_manager.query(query)
                    self.send_json(ai_response)
                else:
                    self.send_error(400)
            
            def handle_execute(self):
                """Execute command"""
                import urllib.parse
                query = self.path.split('execute?command=')[1] if 'execute?command=' in self.path else ''
                command = urllib.parse.unquote(query)
                
                if command:
                    try:
                        process = subprocess.run(
                            command,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        
                        output = process.stdout + process.stderr
                        
                        # Save to history
                        self.save_history(command, output)
                        
                        self.send_json({
                            'success': True,
                            'output': output,
                            'exit_code': process.returncode
                        })
                    except Exception as e:
                        self.send_json({
                            'success': False,
                            'error': str(e)
                        })
                else:
                    self.send_error(400)
            
            def get_history(self):
                """Get command history"""
                conn = sqlite3.connect(TOOLS_DB)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT timestamp, command FROM command_history 
                    WHERE user_id = ? AND session_id = ?
                    ORDER BY timestamp DESC LIMIT 10
                ''', (self.server_instance.user_info['id'], self.server_instance.session_id))
                
                history = cursor.fetchall()
                conn.close()
                
                formatted = []
                for timestamp, cmd in history:
                    formatted.append({
                        'time': datetime.fromisoformat(timestamp).strftime("%H:%M"),
                        'command': cmd[:50] + ('...' if len(cmd) > 50 else '')
                    })
                
                self.send_json({'history': formatted})
            
            def save_history(self, command, output):
                """Save command history"""
                conn = sqlite3.connect(TOOLS_DB)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO command_history (user_id, session_id, timestamp, command, output, interface)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    self.server_instance.user_info['id'],
                    self.server_instance.session_id,
                    datetime.now().isoformat(),
                    command,
                    output[:1000],
                    'gui'
                ))
                
                conn.commit()
                conn.close()
            
            def send_css(self):
                """Send CSS"""
                css = """
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    line-height: 1.6;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 20px;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

.header {
    background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
    padding: 20px 30px;
    border-radius: 12px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.header h1 {
    color: white;
    font-size: 1.8rem;
    font-weight: 600;
}

.user-info {
    display: flex;
    align-items: center;
    gap: 20px;
    background: rgba(255, 255, 255, 0.1);
    padding: 8px 16px;
    border-radius: 8px;
}

#username {
    font-weight: 600;
    color: white;
}

#status {
    color: #10b981;
    font-size: 0.9rem;
}

.main {
    display: flex;
    flex: 1;
    gap: 20px;
    margin-bottom: 20px;
}

.sidebar {
    width: 320px;
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.ai-panel, .quick-actions, .history {
    background: #1e293b;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.ai-panel h3, .quick-actions h3, .history h3 {
    color: #60a5fa;
    margin-bottom: 15px;
    font-size: 1.1rem;
    display: flex;
    align-items: center;
    gap: 8px;
}

.ai-chat {
    height: 200px;
    overflow-y: auto;
    background: #0f172a;
    border-radius: 8px;
    padding: 15px;
    margin-bottom: 15px;
    border: 1px solid #334155;
}

.message {
    padding: 10px 14px;
    margin-bottom: 10px;
    border-radius: 8px;
    max-width: 90%;
    word-wrap: break-word;
}

.message.ai {
    background: #1e3a8a;
    border-left: 4px solid #3b82f6;
}

.message.user {
    background: #7c3aed;
    border-left: 4px solid #8b5cf6;
    margin-left: auto;
}

.ai-input {
    display: flex;
    gap: 10px;
}

.ai-input input {
    flex: 1;
    padding: 12px;
    background: #0f172a;
    border: 2px solid #334155;
    border-radius: 8px;
    color: white;
    font-size: 0.95rem;
}

.ai-input input:focus {
    outline: none;
    border-color: #3b82f6;
}

.ai-input button {
    padding: 12px 24px;
    background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    transition: transform 0.2s;
}

.ai-input button:hover {
    transform: translateY(-2px);
}

.quick-actions {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
}

.quick-actions button {
    padding: 12px;
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 500;
    transition: transform 0.2s;
}

.quick-actions button:hover {
    transform: translateY(-2px);
}

.history {
    flex: 1;
}

#history-list {
    background: #0f172a;
    border-radius: 8px;
    padding: 15px;
    height: 200px;
    overflow-y: auto;
    border: 1px solid #334155;
}

.history-item {
    padding: 10px;
    margin-bottom: 8px;
    background: #1e293b;
    border-radius: 6px;
    border-left: 3px solid #8b5cf6;
}

.history-time {
    font-size: 0.8rem;
    color: #94a3b8;
    margin-bottom: 4px;
}

.history-command {
    font-family: monospace;
    color: #fbbf24;
}

.terminal-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    background: #1e293b;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.terminal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 2px solid #334155;
}

.terminal-header h3 {
    color: #f59e0b;
    font-size: 1.2rem;
    display: flex;
    align-items: center;
    gap: 8px;
}

.terminal-controls {
    display: flex;
    gap: 10px;
}

.terminal-controls button {
    padding: 8px 16px;
    background: #475569;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 500;
}

.terminal-output {
    flex: 1;
    background: #0f172a;
    border-radius: 8px;
    padding: 20px;
    font-family: 'Courier New', monospace;
    overflow-y: auto;
    margin-bottom: 20px;
    border: 1px solid #334155;
    color: #10b981;
    line-height: 1.5;
}

.output-line {
    margin-bottom: 8px;
    word-break: break-all;
}

.output-line.info {
    color: #60a5fa;
}

.output-line.error {
    color: #ef4444;
}

.output-line.command {
    color: #fbbf24;
    font-weight: bold;
}

.terminal-input {
    display: flex;
    align-items: center;
    gap: 12px;
    background: #0f172a;
    padding: 15px;
    border-radius: 8px;
    border: 1px solid #334155;
}

.prompt {
    color: #10b981;
    font-weight: bold;
    font-size: 1.1rem;
}

#command-input {
    flex: 1;
    padding: 12px;
    background: transparent;
    border: none;
    color: white;
    font-family: monospace;
    font-size: 1rem;
}

#command-input:focus {
    outline: none;
}

.terminal-input button {
    padding: 12px 24px;
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    transition: transform 0.2s;
}

.terminal-input button:hover {
    transform: translateY(-2px);
}

.ai-suggestion {
    background: rgba(59, 130, 246, 0.1);
    border: 2px solid #3b82f6;
    border-radius: 8px;
    padding: 15px;
    margin-top: 15px;
}

.suggestion-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
    color: #60a5fa;
    font-weight: 600;
}

.suggestion-header button {
    padding: 6px 12px;
    margin-left: 8px;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.9rem;
}

.suggestion-content {
    background: #0f172a;
    padding: 12px;
    border-radius: 6px;
    font-family: monospace;
    color: #fbbf24;
    white-space: pre-wrap;
    word-break: break-all;
}

.footer {
    background: #1e293b;
    padding: 15px 30px;
    border-radius: 12px;
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 30px;
}

.session-info {
    display: flex;
    align-items: center;
    gap: 20px;
    color: #94a3b8;
}

.session-info button {
    padding: 8px 16px;
    background: #7c3aed;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 500;
}

::-webkit-scrollbar {
    width: 8px;
}

::-webkit-scrollbar-track {
    background: #1e293b;
}

::-webkit-scrollbar-thumb {
    background: #475569;
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: #64748b;
}
                """
                self.send_response(200)
                self.send_header('Content-type', 'text/css')
                self.end_headers()
                self.wfile.write(css.encode())
            
            def send_js(self):
                """Send JavaScript"""
                js = """
let commandCount = 0;
let currentSuggestion = '';
let isDarkTheme = true;

function loadUserInfo() {
    fetch('/api/user')
        .then(response => response.json())
        .then(data => {
            document.getElementById('username').textContent = data.username;
            document.getElementById('session-id').textContent = data.session_id;
            const statusEl = document.getElementById('status');
            if (data.api_connected) {
                statusEl.textContent = '● API Connected';
                statusEl.style.color = '#10b981';
            } else {
                statusEl.textContent = '● Local Mode';
                statusEl.style.color = '#f59e0b';
            }
        })
        .catch(error => console.error('Error loading user info:', error));
}

function askAI() {
    const input = document.getElementById('ai-input');
    const query = input.value.trim();
    
    if (!query) {
        alert('Please enter a query');
        return;
    }
    
    // Add user message
    addAIMessage(query, 'user');
    input.value = '';
    
    // Show loading
    addAIMessage('Thinking...', 'ai');
    
    // Query AI
    fetch('/api/query?query=' + encodeURIComponent(query))
        .then(response => response.json())
        .then(data => {
            // Remove loading message
            const chat = document.getElementById('ai-chat');
            chat.removeChild(chat.lastChild);
            
            if (data.success) {
                addAIMessage(data.response, 'ai');
                
                if (data.command) {
                    showSuggestion(data.command, data.response);
                }
            } else {
                addAIMessage('Error: ' + data.error, 'ai');
            }
        })
        .catch(error => {
            const chat = document.getElementById('ai-chat');
            chat.removeChild(chat.lastChild);
            addAIMessage('Network error: ' + error, 'ai');
        });
}

function addAIMessage(text, sender) {
    const chat = document.getElementById('ai-chat');
    const message = document.createElement('div');
    message.className = 'message ' + sender;
    message.textContent = text;
    chat.appendChild(message);
    chat.scrollTop = chat.scrollHeight;
}

function executeCommand() {
    const input = document.getElementById('command-input');
    const command = input.value.trim();
    
    if (!command) {
        alert('Please enter a command');
        return;
    }
    
    // Show command in terminal
    addTerminalOutput('$ ' + command, 'command');
    input.value = '';
    
    // Execute command
    fetch('/api/execute?command=' + encodeURIComponent(command))
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                addTerminalOutput(data.output, 'output');
                commandCount++;
                document.getElementById('command-count').textContent = commandCount;
                loadHistory();
            } else {
                addTerminalOutput('Error: ' + data.error, 'error');
            }
        })
        .catch(error => {
            addTerminalOutput('Network error: ' + error, 'error');
        });
}

function addTerminalOutput(text, type) {
    const terminal = document.getElementById('terminal-output');
    const line = document.createElement('div');
    line.className = 'output-line ' + type;
    line.textContent = text;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function showSuggestion(command, explanation) {
    currentSuggestion = command;
    
    const content = document.getElementById('suggestion-content');
    content.innerHTML = `<div style="margin-bottom: 10px; color: #e2e8f0">${explanation}</div>
                        <div style="color: #10b981; font-weight: bold">${command}</div>`;
    
    document.getElementById('ai-suggestion').style.display = 'block';
}

function useSuggestion() {
    if (currentSuggestion) {
        document.getElementById('command-input').value = currentSuggestion;
        document.getElementById('command-input').focus();
        hideSuggestion();
    }
}

function hideSuggestion() {
    document.getElementById('ai-suggestion').style.display = 'none';
    currentSuggestion = '';
}

function clearTerminal() {
    document.getElementById('terminal-output').innerHTML = 
        '<div class="output-line info">Terminal cleared</div>';
}

function toggleTheme() {
    isDarkTheme = !isDarkTheme;
    if (isDarkTheme) {
        document.body.style.background = '#0f172a';
        document.body.style.color = '#e2e8f0';
    } else {
        document.body.style.background = '#f8fafc';
        document.body.style.color = '#0f172a';
    }
}

function quickAction(type) {
    const commands = {
        'system': 'uname -a && df -h && free -h',
        'network': 'ip addr show && ping -c 2 8.8.8.8',
        'disk': 'du -h --max-depth=1 ~ | sort -hr | head -10',
        'process': 'ps aux | head -20'
    };
    
    if (commands[type]) {
        document.getElementById('command-input').value = commands[type];
        executeCommand();
    }
}

function loadHistory() {
    fetch('/api/history')
        .then(response => response.json())
        .then(data => {
            const list = document.getElementById('history-list');
            list.innerHTML = '';
            
            data.history.forEach(item => {
                const div = document.createElement('div');
                div.className = 'history-item';
                div.innerHTML = `
                    <div class="history-time">${item.time}</div>
                    <div class="history-command">${item.command}</div>
                `;
                list.appendChild(div);
            });
        })
        .catch(error => console.error('Error loading history:', error));
}

function refreshPage() {
    loadUserInfo();
    loadHistory();
    clearTerminal();
    addTerminalOutput('Session refreshed', 'info');
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadUserInfo();
    loadHistory();
    
    // Setup event listeners
    document.getElementById('ai-input').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') askAI();
    });
    
    document.getElementById('command-input').focus();
    
    // Auto-refresh every 30 seconds
    setInterval(loadHistory, 30000);
});
                """
                self.send_response(200)
                self.send_header('Content-type', 'application/javascript')
                self.end_headers()
                self.wfile.write(js.encode())
            
            def send_json(self, data):
                """Send JSON response"""
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())
            
            def log_message(self, format, *args):
                """Suppress log messages"""
                pass
        
        return GUIHandler

class MainSystem:
    """Main system"""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.user_manager = UserManager()
        self.current_user = None
        self.ai_manager = None
    
    def start(self):
        """Start system"""
        self.show_welcome()
        
        # Authenticate
        self.current_user = self.user_manager.authenticate()
        
        if not self.current_user:
            print(f"{COLOR['RED']}Authentication failed{COLOR['RESET']}")
            return
        
        # Initialize AI
        self.ai_manager = AIManager(self.current_user['api_key'])
        
        print(f"\n{COLOR['GREEN']}[SUCCESS] Welcome {self.current_user['username']}!{COLOR['RESET']}")
        
        # Choose interface
        self.choose_interface()
    
    def show_welcome(self):
        """Show welcome"""
        welcome = f"""
{COLOR['CYAN']}╔══════════════════════════════════════════════════════════╗
║          AI TERMINAL ASSISTANT - COMPLETE VERSION        ║
║                  With Working GUI & API                  ║
╚══════════════════════════════════════════════════════════╝{COLOR['RESET']}

{COLOR['GREEN']}Features:{COLOR['RESET']}
  • Terminal interface with AI assistant
  • Browser GUI at http://localhost:8080
  • Works with or without API key
  • Local command database fallback
  • User authentication system

{COLOR['YELLOW']}API Key:{COLOR['RESET']}
  Get free API key from: https://platform.deepseek.com
  Or press Enter to use local mode

{COLOR['CYAN']}══════════════════════════════════════════════════════════{COLOR['RESET']}
        """
        print(welcome)
    
    def choose_interface(self):
        """Choose interface"""
        print(f"\n{COLOR['CYAN']}[INTERFACE SELECTION]{COLOR['RESET']}")
        print(f"{COLOR['BLUE']}════════════════════════{COLOR['RESET']}\n")
        
        print("1. Terminal Mode (Command line interface)")
        print("2. GUI Mode (Browser interface)")
        print("3. Both Modes (Terminal + GUI)")
        print("4. Exit")
        
        choice = input(f"{COLOR['YELLOW']}Select option [1-4]: {COLOR['RESET']}").strip()
        
        if choice == '1':
            self.start_terminal()
        elif choice == '2':
            self.start_gui()
        elif choice == '3':
            self.start_both()
        elif choice == '4':
            print(f"{COLOR['GREEN']}Goodbye!{COLOR['RESET']}")
        else:
            print(f"{COLOR['RED']}Invalid choice{COLOR['RESET']}")
            self.choose_interface()
    
    def start_terminal(self):
        """Start terminal"""
        terminal = TerminalInterface(self.current_user, self.ai_manager)
        terminal.run()
    
    def start_gui(self):
        """Start GUI"""
        print(f"{COLOR['YELLOW']}[Starting GUI server...]{COLOR['RESET']}")
        
        session_id = str(uuid.uuid4())
        gui_server = GUIServer(self.current_user, self.ai_manager, session_id)
        
        # Start server in thread
        server_thread = threading.Thread(target=gui_server.start, daemon=True)
        server_thread.start()
        
        time.sleep(2)
        
        # Open browser
        try:
            webbrowser.open("http://localhost:8080")
        except:
            print(f"{COLOR['CYAN']}Open browser to: http://localhost:8080{COLOR['RESET']}")
        
        print(f"{COLOR['GREEN']}[GUI server running]{COLOR['RESET']}")
        print(f"{COLOR['YELLOW']}Press Ctrl+C to stop{COLOR['RESET']}")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{COLOR['YELLOW']}[Stopping GUI server]{COLOR['RESET']}")
    
    def start_both(self):
        """Start both interfaces"""
        print(f"{COLOR['YELLOW']}[Starting both interfaces...]{COLOR['RESET']}")
        
        session_id = str(uuid.uuid4())
        
        # Start GUI server
        gui_server = GUIServer(self.current_user, self.ai_manager, session_id)
        gui_thread = threading.Thread(target=gui_server.start, daemon=True)
        gui_thread.start()
        
        time.sleep(2)
        
        # Open browser
        try:
            webbrowser.open("http://localhost:8080")
        except:
            print(f"{COLOR['CYAN']}GUI: http://localhost:8080{COLOR['RESET']}")
        
        print(f"{COLOR['GREEN']}[GUI server started]{COLOR['RESET']}")
        print(f"{COLOR['YELLOW']}Starting terminal interface...{COLOR['RESET']}")
        print(f"{COLOR['CYAN']}Press Enter to continue{COLOR['RESET']}")
        input()
        
        # Start terminal with same session ID
        terminal = TerminalInterface(self.current_user, self.ai_manager)
        terminal.session_id = session_id
        terminal.run()

def check_dependencies():
    """Check and install dependencies"""
    try:
        import requests
        return True
    except ImportError:
        print(f"{COLOR['YELLOW']}Installing required packages...{COLOR['RESET']}")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'requests'])
            print(f"{COLOR['GREEN']}Dependencies installed!{COLOR['RESET']}")
            return True
        except:
            print(f"{COLOR['RED']}Failed to install dependencies. Run: pip install requests{COLOR['RESET']}")
            return False

def main():
    """Main function"""
    print(f"{COLOR['CYAN']}[Starting AI Terminal Assistant]{COLOR['RESET']}")
    
    # Check dependencies
    if not check_dependencies():
        return
    
    try:
        system = MainSystem()
        system.start()
    except KeyboardInterrupt:
        print(f"\n{COLOR['YELLOW']}[Interrupted]{COLOR['RESET']}")
    except Exception as e:
        print(f"{COLOR['RED']}[Error] {str(e)}{COLOR['RESET']}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()