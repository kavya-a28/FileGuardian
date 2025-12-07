import threading
from django.core.mail import send_mail
from django.conf import settings

def send_alert_email(filename, reason, ip_address, device_name):
    """Sends a security alert email in a background thread"""
    
    subject = f"🚨 SECURITY ALERT: Unauthorized Access Blocked - {filename}"
    message = f"""
    FILE GUARDIAN SECURITY SYSTEM
    -----------------------------
    
    An unauthorized attempt to decrypt a file was detected and BLOCKED.
    
    📂 File: {filename}
    🛑 Reason: {reason}
    
    INTRUDER DETAILS:
    -----------------
    🌐 IP Address: {ip_address}
    💻 Device Name: {device_name}
    
    Status: Access Denied. Canary Token Triggered.
    """
    
    def _send():
        try:
            # Only send if email is configured
            if not getattr(settings, 'EMAIL_HOST_USER', None):
                print("⚠️ Email not configured in settings.py - Alert skipped.")
                return

            print(f"📧 Sending alert email to {settings.EMAIL_HOST_USER}...")
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [settings.EMAIL_HOST_USER], # Send to yourself
                fail_silently=False,
            )
            print("✅ Email sent successfully!")
        except Exception as e:
            print(f"❌ Failed to send email: {e}")

    # Run in background thread to avoid hanging the UI
    threading.Thread(target=_send).start()