import hashlib
import socket
import platform
import uuid
import subprocess
import re
import geocoder
# math is only used in verify_device, so import it there
# from math import radians, sin, cos, sqrt, atan2 

def get_mac_address():
    """Get device MAC address"""
    try:
        mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        return mac
    except:
        return "00:00:00:00:00:00"

def get_ip_address():
    """Get device IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_wifi_ssid():
    """Get connected WiFi SSID"""
    try:
        if platform.system() == 'Windows':
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], 
                                             encoding='utf-8', errors='ignore')
            for line in output.split('\n'):
                if 'SSID' in line and 'BSSID' not in line:
                    # .strip() handles whitespace
                    ssid = line.split(':', 1)[1].strip() 
                    if ssid:
                        return ssid
        elif platform.system() == 'Darwin':  # macOS
            output = subprocess.check_output(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                                             encoding='utf-8', errors='ignore')
            for line in output.split('\n'):
                if ' SSID:' in line:
                    ssid = line.split(':', 1)[1].strip()
                    if ssid:
                        return ssid
        elif platform.system() == 'Linux':
            output = subprocess.check_output(['iwgetid', '-r'], 
                                             encoding='utf-8', errors='ignore')
            ssid = output.strip()
            if ssid:
                return ssid
    except Exception:
        pass
    return None # Return None if no SSID is found (e.g., Ethernet)

def get_geolocation():
    """Get device geolocation using IP"""
    try:
        g = geocoder.ip('me')
        if g.ok:
            return g.latlng
    except:
        pass
    return [None, None]

def get_device_info():
    """Get comprehensive device information"""
    mac = get_mac_address()
    ip = get_ip_address()
    wifi_ssid = get_wifi_ssid()
    lat, lng = get_geolocation()
    
    return {
        'mac_address': mac,
        'ip_address': ip,
        'wifi_ssid': wifi_ssid,
        'latitude': lat,
        'longitude': lng,
        'hostname': socket.gethostname(),
        'platform': platform.system(),
        'machine': platform.machine()
    }

def generate_device_hash():
    """Generate unique device hash"""
    device_info = get_device_info()
    
    # Combine stable identifiers
    hash_string = f"{device_info['mac_address']}"
    
    # Generate SHA256 hash
    return hashlib.sha256(hash_string.encode()).hexdigest()

def verify_device(stored_device_hash, stored_mac, stored_ip, stored_wifi_ssid, stored_lat, stored_lng):
    """Verify if current device matches stored device credentials"""
    current_info = get_device_info()
    current_hash = generate_device_hash()
    
    # Check device hash
    if current_hash != stored_device_hash:
        return False, "Device hash mismatch"
    
    # Check MAC address (primary identifier)
    if current_info['mac_address'] != stored_mac:
        return False, "MAC address mismatch"
    
    # Check IP address (can change but flag it)
    ip_match = current_info['ip_address'] == stored_ip
    
    # --- MODIFIED WIFI LOGIC (Stricter) ---
    # This now correctly handles cases where one or both SSIDs are None
    wifi_match = True
    if stored_wifi_ssid:
        # If a Wi-Fi was stored, the current Wi-Fi MUST match it.
        # If the current Wi-Fi is None (Ethernet), it's a mismatch.
        if current_info['wifi_ssid'] != stored_wifi_ssid:
            wifi_match = False
    elif current_info['wifi_ssid']:
        # If no Wi-Fi was stored (e.g., Ethernet) but we are now on Wi-Fi,
        # this is also a mismatch.
        wifi_match = False
    # If both are None (e.g., always on Ethernet), wifi_match remains True, which is correct.
    # --- END MODIFICATION ---
    
    # Check location (with tolerance of ~100km)
    location_match = True
    if stored_lat and stored_lng and current_info['latitude'] and current_info['longitude']:
        from math import radians, sin, cos, sqrt, atan2
        
        # Haversine formula
        R = 6371  # Earth radius in km
        lat1, lon1 = radians(stored_lat), radians(stored_lng)
        lat2, lon2 = radians(current_info['latitude']), radians(current_info['longitude'])
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        distance = R * c
        
        if distance > 100:  # More than 100km away
            location_match = False
    
    # Strict verification
    if not (ip_match and wifi_match and location_match):
        reasons = []
        if not ip_match:
            reasons.append("IP address changed")
        if not wifi_match:
            reasons.append("WiFi network changed")
        if not location_match:
            reasons.append("Location significantly changed")
        
        return False, " | ".join(reasons)
    
    # --- BUG FIX ---
    # This must return True if all checks pass
    return True, "Device verified successfully"