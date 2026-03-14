"""
Pentagon Security Dashboard - Flask Application
A web-based dashboard for monitoring IoT security testing operations.
Features real-time progress tracking, interactive visualizations, and a global threat map.
"""

import os
import sys
import json
import queue
import secrets
import hashlib
import threading
import subprocess
import re
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, jsonify, request, Response, 
    session, redirect, url_for, flash
)

# =============================================================================
# APPLICATION SETUP
# =============================================================================

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max upload
)

# =============================================================================
# SECURITY AND AUTHENTICATION
# =============================================================================

# In production, use environment variables or a secure configuration file
DEFAULT_USERNAME = os.environ.get('PENTAGON_USER', 'admin')
DEFAULT_PASSWORD_HASH = hashlib.sha256(
    os.environ.get('PENTAGON_PASSWORD', 'pentagon_secure_2024').encode()
).hexdigest()


def validate_credentials(username, password):
    """Validate user credentials securely."""
    if not username or not password:
        return False
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return secrets.compare_digest(username, DEFAULT_USERNAME) and \
           secrets.compare_digest(password_hash, DEFAULT_PASSWORD_HASH)


def login_required(f):
    """Decorator to require authentication for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def validate_ip_address(ip):
    """Validate IPv4 address format for security."""
    if not ip or not isinstance(ip, str):
        return False
    
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\\', '"', "'"]
    for char in dangerous_chars:
        if char in ip:
            return False
    
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    if re.match(ipv4_pattern, ip):
        parts = ip.split('/')[0].split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return False


# =============================================================================
# GLOBAL STATE MANAGEMENT
# =============================================================================

class TaskManager:
    """Manages background tasks and their states."""
    
    def __init__(self):
        self.tasks = {}
        self.task_lock = threading.Lock()
        self.event_queues = []
        self.queues_lock = threading.Lock()
    
    def create_task(self, task_id, task_type, target=''):
        """Create a new task entry."""
        with self.task_lock:
            self.tasks[task_id] = {
                'id': task_id,
                'type': task_type,
                'target': target,
                'status': 'pending',
                'progress': 0,
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'results': [],
                'logs': [],
                'process': None,
                'hosts_found': 0,
                'ports_scanned': 0,
                'packets_captured': 0
            }
        self.broadcast_event('task_created', self.tasks[task_id])
        return task_id
    
    def update_task(self, task_id, **kwargs):
        """Update task properties."""
        with self.task_lock:
            if task_id in self.tasks:
                self.tasks[task_id].update(kwargs)
                self.broadcast_event('task_updated', self.tasks[task_id])
    
    def get_task(self, task_id):
        """Get task by ID."""
        with self.task_lock:
            return self.tasks.get(task_id, {}).copy()
    
    def get_all_tasks(self):
        """Get all tasks."""
        with self.task_lock:
            return {k: v.copy() for k, v in self.tasks.items()}
    
    def add_log(self, task_id, message):
        """Add a log message to a task."""
        with self.task_lock:
            if task_id in self.tasks:
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'message': message
                }
                self.tasks[task_id]['logs'].append(log_entry)
                self.broadcast_event('task_log', {'task_id': task_id, 'log': log_entry})
    
    def add_result(self, task_id, result):
        """Add a result to a task."""
        with self.task_lock:
            if task_id in self.tasks:
                self.tasks[task_id]['results'].append(result)
                self.broadcast_event('task_result', {'task_id': task_id, 'result': result})
    
    def subscribe(self):
        """Subscribe to task events."""
        q = queue.Queue(maxsize=100)
        with self.queues_lock:
            self.event_queues.append(q)
        return q
    
    def unsubscribe(self, q):
        """Unsubscribe from task events."""
        with self.queues_lock:
            if q in self.event_queues:
                self.event_queues.remove(q)
    
    def broadcast_event(self, event_type, data):
        """Broadcast an event to all subscribers."""
        event_data = {
            'type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        }
        with self.queues_lock:
            dead_queues = []
            for q in self.event_queues:
                try:
                    q.put_nowait(event_data)
                except queue.Full:
                    dead_queues.append(q)
            for q in dead_queues:
                self.event_queues.remove(q)


# Global task manager instance
task_manager = TaskManager()

# Sample GeoIP data for demonstration (in production, use a real GeoIP database)
SAMPLE_GEOIP_DATA = {
    '8.8.8.8': {'city': 'Mountain View', 'country': 'United States', 'lat': 37.386, 'lon': -122.084},
    '1.1.1.1': {'city': 'San Francisco', 'country': 'United States', 'lat': 37.774, 'lon': -122.419},
    '208.67.222.222': {'city': 'San Francisco', 'country': 'United States', 'lat': 37.774, 'lon': -122.419},
    '192.168.1.1': {'city': 'Local Network', 'country': 'Private', 'lat': 0, 'lon': 0},
}


def get_geoip_info(ip):
    """Get geolocation information for an IP address."""
    # Check for private IP ranges
    if ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                      '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                      '127.', '169.254.')):
        return {'city': 'Local Network', 'country': 'Private', 'lat': 0, 'lon': 0}
    
    return SAMPLE_GEOIP_DATA.get(ip, {
        'city': 'Unknown',
        'country': 'Unknown',
        'lat': 0,
        'lon': 0
    })


# =============================================================================
# AUTHENTICATION ROUTES
# =============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if validate_credentials(username, password):
            session['authenticated'] = True
            session['username'] = username
            session.permanent = True
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'error')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Handle user logout."""
    session.clear()
    return redirect(url_for('login'))


# =============================================================================
# DASHBOARD ROUTES
# =============================================================================

@app.route('/')
@login_required
def dashboard():
    """Main dashboard view."""
    return render_template('dashboard.html')


@app.route('/api/status')
@login_required
def api_status():
    """Get current system status."""
    tasks = task_manager.get_all_tasks()
    
    active_tasks = sum(1 for t in tasks.values() if t['status'] == 'running')
    completed_tasks = sum(1 for t in tasks.values() if t['status'] == 'completed')
    
    return jsonify({
        'status': 'online',
        'active_tasks': active_tasks,
        'completed_tasks': completed_tasks,
        'total_tasks': len(tasks),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/tasks')
@login_required
def api_tasks():
    """Get all tasks."""
    tasks = task_manager.get_all_tasks()
    # Remove process objects before JSON serialization
    for task_id in tasks:
        tasks[task_id].pop('process', None)
    return jsonify(tasks)


@app.route('/api/tasks/<task_id>')
@login_required
def api_task_detail(task_id):
    """Get task details."""
    task = task_manager.get_task(task_id)
    if task:
        task.pop('process', None)
        return jsonify(task)
    return jsonify({'error': 'Task not found'}), 404


@app.route('/api/events')
@login_required
def api_events():
    """Server-Sent Events endpoint for real-time updates."""
    def generate():
        q = task_manager.subscribe()
        try:
            # Send initial connection event
            yield f"data: {json.dumps({'type': 'connected', 'timestamp': datetime.now().isoformat()})}\n\n"
            
            while True:
                try:
                    event = q.get(timeout=30)
                    # Filter out process objects
                    if 'data' in event and isinstance(event['data'], dict):
                        event['data'].pop('process', None)
                    yield f"data: {json.dumps(event)}\n\n"
                except queue.Empty:
                    # Send keepalive
                    yield f": keepalive\n\n"
        finally:
            task_manager.unsubscribe(q)
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


# =============================================================================
# SCAN MANAGEMENT ROUTES
# =============================================================================

@app.route('/api/scan/nmap', methods=['POST'])
@login_required
def start_nmap_scan():
    """Start an nmap network scan."""
    data = request.get_json()
    target = data.get('target', '')
    scan_type = data.get('scan_type', 'quick')
    
    if not validate_ip_address(target):
        return jsonify({'error': 'Invalid target IP address'}), 400
    
    task_id = f"nmap_{secrets.token_hex(8)}"
    task_manager.create_task(task_id, 'nmap', target)
    
    # Start scan in background thread
    thread = threading.Thread(target=run_nmap_scan, args=(task_id, target, scan_type))
    thread.daemon = True
    thread.start()
    
    return jsonify({'task_id': task_id, 'status': 'started'})


def run_nmap_scan(task_id, target, scan_type):
    """Execute nmap scan in background."""
    task_manager.update_task(task_id, status='running', progress=10)
    task_manager.add_log(task_id, f'Starting {scan_type} scan on {target}')
    
    # Build nmap command based on scan type
    scan_args = {
        'quick': ['-sn', '-T4'],
        'ports': ['-sS', '-T4', '--top-ports', '100'],
        'services': ['-sV', '-T4', '--top-ports', '100'],
        'full': ['-sS', '-sV', '-O', '-T4', '-p-'],
        'vuln': ['--script=vuln', '-T4']
    }
    
    args = scan_args.get(scan_type, scan_args['quick'])
    cmd = ['nmap'] + args + ['-oX', '-', target]
    
    try:
        task_manager.update_task(task_id, progress=20)
        task_manager.add_log(task_id, f'Executing: nmap {" ".join(args)} {target}')
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            # Parse basic results from nmap output
            hosts_found = stdout.count('<host ')
            ports_open = stdout.count('state="open"')
            
            task_manager.update_task(
                task_id,
                status='completed',
                progress=100,
                end_time=datetime.now().isoformat(),
                hosts_found=hosts_found,
                ports_scanned=ports_open
            )
            task_manager.add_log(task_id, f'Scan completed. Found {hosts_found} hosts, {ports_open} open ports.')
            
            # Store parsed results
            task_manager.add_result(task_id, {
                'type': 'scan_summary',
                'hosts_found': hosts_found,
                'ports_open': ports_open,
                'target': target
            })
        else:
            task_manager.update_task(task_id, status='failed', progress=100, end_time=datetime.now().isoformat())
            task_manager.add_log(task_id, f'Scan failed: {stderr}')
            
    except FileNotFoundError:
        task_manager.update_task(task_id, status='failed', progress=100, end_time=datetime.now().isoformat())
        task_manager.add_log(task_id, 'Error: nmap not found. Please install nmap.')
    except Exception as e:
        task_manager.update_task(task_id, status='failed', progress=100, end_time=datetime.now().isoformat())
        task_manager.add_log(task_id, f'Error: {str(e)}')


@app.route('/api/scan/traffic', methods=['POST'])
@login_required
def start_traffic_capture():
    """Start traffic capture."""
    data = request.get_json()
    interface = data.get('interface', 'eth0')
    duration = min(int(data.get('duration', 30)), 300)  # Max 5 minutes
    
    # Validate interface name (alphanumeric and limited special chars)
    if not re.match(r'^[a-zA-Z0-9_-]+$', interface):
        return jsonify({'error': 'Invalid interface name'}), 400
    
    task_id = f"capture_{secrets.token_hex(8)}"
    task_manager.create_task(task_id, 'traffic_capture', interface)
    
    # Start capture in background thread
    thread = threading.Thread(target=run_traffic_capture, args=(task_id, interface, duration))
    thread.daemon = True
    thread.start()
    
    return jsonify({'task_id': task_id, 'status': 'started'})


def run_traffic_capture(task_id, interface, duration):
    """Execute traffic capture in background."""
    task_manager.update_task(task_id, status='running', progress=5)
    task_manager.add_log(task_id, f'Starting traffic capture on {interface} for {duration}s')
    
    # Simulate packet capture progress
    start_time = time.time()
    packets_captured = 0
    
    while time.time() - start_time < duration:
        elapsed = time.time() - start_time
        progress = int((elapsed / duration) * 100)
        packets_captured += 10  # Simulated packet count
        
        task_manager.update_task(
            task_id,
            progress=progress,
            packets_captured=packets_captured
        )
        time.sleep(1)
    
    task_manager.update_task(
        task_id,
        status='completed',
        progress=100,
        end_time=datetime.now().isoformat(),
        packets_captured=packets_captured
    )
    task_manager.add_log(task_id, f'Capture completed. {packets_captured} packets captured.')


@app.route('/api/scan/spoof', methods=['POST'])
@login_required
def start_arp_spoof():
    """Start ARP spoofing operation."""
    data = request.get_json()
    target = data.get('target', '')
    gateway = data.get('gateway', '')
    
    if not validate_ip_address(target) or not validate_ip_address(gateway):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    task_id = f"spoof_{secrets.token_hex(8)}"
    task_manager.create_task(task_id, 'arp_spoof', f'{target} -> {gateway}')
    
    # Start spoofing in background thread
    thread = threading.Thread(target=run_arp_spoof, args=(task_id, target, gateway))
    thread.daemon = True
    thread.start()
    
    return jsonify({'task_id': task_id, 'status': 'started'})


def run_arp_spoof(task_id, target, gateway):
    """Execute ARP spoofing in background (simulation)."""
    task_manager.update_task(task_id, status='running', progress=50)
    task_manager.add_log(task_id, f'Starting ARP spoof: {target} <-> {gateway}')
    
    # Add geo information for visualization
    target_geo = get_geoip_info(target)
    gateway_geo = get_geoip_info(gateway)
    
    task_manager.add_result(task_id, {
        'type': 'geo_data',
        'source': {'ip': gateway, **gateway_geo},
        'target': {'ip': target, **target_geo}
    })
    
    # Simulate ongoing spoofing
    for i in range(10):
        time.sleep(1)
        task_manager.add_log(task_id, f'Spoofing packets sent: {(i+1) * 100}')
    
    task_manager.update_task(
        task_id,
        status='completed',
        progress=100,
        end_time=datetime.now().isoformat()
    )
    task_manager.add_log(task_id, 'ARP spoofing simulation completed.')


@app.route('/api/task/<task_id>/stop', methods=['POST'])
@login_required
def stop_task(task_id):
    """Stop a running task."""
    task = task_manager.get_task(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    if task.get('status') == 'running':
        task_manager.update_task(
            task_id,
            status='stopped',
            end_time=datetime.now().isoformat()
        )
        task_manager.add_log(task_id, 'Task stopped by user.')
        return jsonify({'status': 'stopped'})
    
    return jsonify({'error': 'Task is not running'}), 400


@app.route('/api/geoip/<ip>')
@login_required
def api_geoip(ip):
    """Get geolocation data for an IP address."""
    if not validate_ip_address(ip):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    geo_info = get_geoip_info(ip)
    return jsonify({
        'ip': ip,
        **geo_info
    })


@app.route('/api/map/connections')
@login_required
def api_map_connections():
    """Get all active connections for the map visualization."""
    tasks = task_manager.get_all_tasks()
    connections = []
    
    for task in tasks.values():
        if task.get('type') in ['nmap', 'arp_spoof', 'traffic_capture']:
            target = task.get('target', '')
            if target:
                # Parse target IP
                target_ip = target.split()[0] if ' ' in target else target
                if validate_ip_address(target_ip.split('/')[0]):
                    geo_info = get_geoip_info(target_ip.split('/')[0])
                    connections.append({
                        'task_id': task['id'],
                        'type': task['type'],
                        'status': task['status'],
                        'target': {
                            'ip': target_ip,
                            **geo_info
                        }
                    })
    
    return jsonify(connections)


# =============================================================================
# STATISTICS ROUTES
# =============================================================================

@app.route('/api/stats')
@login_required
def api_stats():
    """Get aggregated statistics."""
    tasks = task_manager.get_all_tasks()
    
    # Calculate statistics
    task_types = {}
    status_counts = {}
    total_hosts = 0
    total_ports = 0
    total_packets = 0
    
    for task in tasks.values():
        task_type = task.get('type', 'unknown')
        task_types[task_type] = task_types.get(task_type, 0) + 1
        
        status = task.get('status', 'unknown')
        status_counts[status] = status_counts.get(status, 0) + 1
        
        total_hosts += task.get('hosts_found', 0)
        total_ports += task.get('ports_scanned', 0)
        total_packets += task.get('packets_captured', 0)
    
    return jsonify({
        'task_types': task_types,
        'status_counts': status_counts,
        'total_hosts_found': total_hosts,
        'total_ports_scanned': total_ports,
        'total_packets_captured': total_packets,
        'total_tasks': len(tasks)
    })


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

def run_dashboard(host='127.0.0.1', port=5000, debug=False, ssl_context=None):
    """
    Run the Pentagon Dashboard server.
    
    Args:
        host: Host address to bind (default: 127.0.0.1 for local only)
        port: Port number (default: 5000)
        debug: Enable debug mode (default: False)
        ssl_context: SSL context for HTTPS (default: None)
    """
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║            PENTAGON SECURITY DASHBOARD                       ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Server running at: {'https' if ssl_context else 'http'}://{host}:{port}              
    ║  Press Ctrl+C to stop                                        ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Note: In production, use a proper WSGI server like gunicorn
    if ssl_context:
        app.run(host=host, port=port, debug=debug, ssl_context=ssl_context, threaded=True)
    else:
        app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Pentagon Security Dashboard')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Port number (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--remote', action='store_true', help='Allow remote connections (binds to 0.0.0.0)')
    
    args = parser.parse_args()
    
    host = '0.0.0.0' if args.remote else args.host
    run_dashboard(host=host, port=args.port, debug=args.debug)
