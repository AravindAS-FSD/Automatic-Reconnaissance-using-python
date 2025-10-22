# EmailAutomation.py

import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# --- CONFIGURATION - YOU MUST EDIT THIS SECTION ---
SENDER_EMAIL = "asaravind435@gmail.com";
SENDER_PASSWORD = "rotc gsnp hcyj qcph";

def send_email_report(recipient_email, attachment_filepath):
    """
    Sends an email with the specified PDF report as an attachment.
    """
    if not os.path.exists(attachment_filepath):
        return (False, f"Attachment file not found at: {attachment_filepath}")
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email
    filename = os.path.basename(attachment_filepath)
    domain = filename.replace("PDF_Report_", "").replace(".pdf", "")
    msg['Subject'] = f"Automated Reconnaissance Report for {domain}"
    body = f"Please find the attached automated reconnaissance report for the domain: {domain}"
    msg.attach(MIMEText(body, 'plain'))
    try:
        with open(attachment_filepath, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename= {filename}')
        msg.attach(part)
    except Exception as e:
        return (False, f"Could not read or attach the file: {e}")
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        text = msg.as_string()
        server.sendmail(SENDER_EMAIL, recipient_email, text)
        server.quit()
        return (True, "Email sent successfully!")
    except smtplib.SMTPAuthenticationError:
        return (False, "Authentication failed. Check SENDER_EMAIL and SENDER_PASSWORD (must be an App Password).")
    except Exception as e:
        return (False, f"An error occurred while sending the email: {e}")

if __name__ == '__main__':
    print("This is the email automation module. It is designed to be imported.")