# Importing necessary libraries
import email
from email.parser import BytesParser
from email import policy
import hashlib
import requests  # for running hash through vt
import re  # for finding URLS
import urllib.parse  # import entire urllib.parse library to use unquote for decoding mimecast encoded URLs
import validators  # for checking validity of URLs
import language_tool_python
from bs4 import BeautifulSoup  # needed for parsing HTML content
import io
from langdetect import detect, DetectorFactory  # for detecting language of the email content

filename = input('Enter the path to your email file: ')

# FUNCTION TO EXTRACT PLAIN TEXT FROM EMAIL BODY
def get_plain_text(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode('utf-8', errors='ignore')
            elif part.get_content_type() == 'text/html':
                html_content = part.get_payload(decode=True)
                soup = BeautifulSoup(html_content, 'html.parser')
                return soup.get_text()
    else:
        return msg.get_payload(decode=True).decode('utf-8', errors='ignore')
    return None

# Main function to process the email file
def process_email_file(filename):
    try:
        with open(filename, 'rb') as f:
            msg_bytes = f.read()
    except FileNotFoundError:
        print('File not found. Please review file path and try again.')
        return
    except Exception as e:
        print('An error occurred:', e)
        return

    print("File read successfully. Processing email...")
    msg = BytesParser(policy=policy.default).parse(io.BytesIO(msg_bytes))

    # Display useful header information immediately after reading the file
    print('From:', msg.get('From'))
    print('To:', msg.get('To'))
    print('Subject:', msg.get('Subject'))
    print('Date/Time:', msg.get('Date'))

    # EXTRACT IP ADDRESS FROM THE HEADER
    received_header = msg.get('Received')
    if received_header:
        # Extract IP address from Received header
        ip_address = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', received_header)
        ip_address = ip_address.group(0) if ip_address else 'IP address not found'
    else:
        ip_address = 'IP address not found'

    # Check SPF, DKIM, DMARC
    spf_result = msg.get('Received-SPF')
    dkim_result = msg.get('DKIM-Signature')
    dmarc_result = msg.get('DMARC-Result')
    print('SPF:', spf_result)
    print('DKIM:', dkim_result)
    print('DMARC:', dmarc_result)

    # Check if SPF, DKIM, DMARC are present
    if spf_result and dkim_result and dmarc_result:
        if 'pass' in spf_result.lower() and 'pass' in dkim_result.lower() and 'pass' in dmarc_result.lower():
            print('All authentication results passed')
        else:
            print('At least one authentication result failed \U0001F6A9')
    else:
        print('Not all authentication results provided \U0001F6A9')

    # Extract sender domain and check in VirusTotal
    sender = msg.get('From')
    vt_api_key = input('ENTER YOUR VIRUS TOTAL API KEY: ')
    if sender:
        domain = extract_domain(sender)
        check_domain_vt(domain, vt_api_key)

    # Check IP address in AbuseIPDB
    if ip_address != 'IP address not found':
        abuseip_api_key = input('ENTER YOUR ABUSEIPDB API KEY: ')
        check_abuseipdb(ip_address, abuseip_api_key)

        # Check IP address in Virustotal using the same API key
        check_ip_address_vt(ip_address, vt_api_key)

    # CHECK FOR ATTACHMENTS
    att_content = None

    # Walk through the email parts to find attachments
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            print('.eml file contains attachments \U0001F6A8')

            # Display attachment details
            filename = part.get_filename()
            content_type = part.get_content_type()
            print('Filename:', filename)
            print('Content Type:', content_type)
            att_content = part.get_payload(decode=True)
            break  # Exit loop once we've found the attachment

    # CREATE HASH OF ATTACHMENT
    if att_content is not None:
        att_hash = hashlib.sha256(att_content).hexdigest()
        print('Sha256 Attachment Hash', att_hash)

        # Grab api for hash check
        check_attachment_hash_vt(att_hash, vt_api_key)
    else:
        print('No attachments found')

    # FUNCTION TO EXTRACT PLAIN TEXT FROM BODY
    plain_text = get_plain_text(msg)

    # CHECK FOR GRAMMATICAL AND SPELLING ERRORS IN THE BODY
    tool = language_tool_python.LanguageTool('en-US')
    if plain_text:
        try:
            language = detect(plain_text)
            print(f'Detected language: {language}')
            # check if language is English
            if language == 'en':
                matches = tool.check(plain_text)
                if matches:
                    print('Body contains grammatical and spelling errors \U0001F6A9')
                    print(matches)
                else:
                    print('Body does not contain grammatical and spelling errors')
            else:
                print('Detected language is not English \U0001F6A9')
        except Exception as e:
            print('Could not detect language:', e)

    # FIND URLS IN FILE
    print('Searching for URLs in the email...')
    if plain_text:
        regex = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        match = re.findall(regex, plain_text)

        if match:
            print('URL(s) detected in the email: ')
            for url in match:
                print(url, '\U0001F6A8')

                # Check if URL is Mimecast encoded
                if '://url.usb.m.mimecastprotect.com' in url:
                    print('Mimecast encoded URL detected, decoding...')
                    decoded_url = urllib.parse.unquote(url)  # Decode Mimecast-encoded URLs
                    print('Decoded URL: ', decoded_url)
                else:
                    decoded_url = url  # Use the original URL if not Mimecast encoded

                # Check if URL is valid
                print('Checking validity of URL...')
                validation = validators.url(decoded_url)
                if validation:
                    print('URL is valid')
                else:
                    print('URL is not valid \U0001F6A9')
                    continue  # Skip to the next URL if it's not valid

                # Check URL for malicious content
                print('Scanning URL in VirusTotal...')
                vt_url = f"https://www.virustotal.com/api/v3/urls/{urllib.parse.quote(decoded_url)}"
                headers = {'x-apikey': vt_api_key}

                try:
                    # Send GET request to VT
                    response = requests.get(vt_url, headers=headers)

                    # Check status of request
                    if response.status_code == 200:
                        # Parse the JSON response
                        data = response.json()

                        # Display results
                        print('Results for:', decoded_url)

                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        print('Malicious detections:', stats.get('malicious', 'None'))
                        print('Undetected:', stats.get('undetected', 'None'))
                        print('Clean:', stats.get('clean', 'None'))
                    else:
                        print(f'Error: Unable to retrieve data from VIRUSTOTAL. Status code: {response.status_code}')
                        print('Response:', response.text)  # Print the response text for more details
                except Exception as e:
                    print(f'An exception occurred: {e}')
        else:
            print('No URLs detected in the email')

# Function to extract domain from sender email
def extract_domain(sender_email):
    return sender_email.split('@')[-1].replace('>', '').lower().strip()

# Function to check domain in VirusTotal
def check_domain_vt(domain, vt_api_key):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': vt_api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        print('Results for:', domain)
        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious_detections = stats.get('malicious', 0)

        # to print red flag right after malicious detection value over 0
        if malicious_detections > 0:
            print(f'Malicious detections: {malicious_detections} \U0001F6A9')
        else:
            print(f'Malicious detections: {malicious_detections}')

        print('Undetected:', stats.get('undetected', 'None'))
        print('Clean:', stats.get('clean', 'None'))
    else:
        print('Error: Unable to retrieve data from VIRUSTOTAL')
        print('Status Code:', response.status_code)
        print('Response:', response.text)

# Function to check IP address in AbuseIPDB
def check_abuseipdb(ip_address, abuseip_api_key):
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': abuseip_api_key}
    querystring = {'ipAddress': ip_address, 'maxAgeInMonths': '12'}
    response = requests.get(url, headers=headers, params=querystring)

    if response.status_code == 200:
        data = response.json()
        print('Abuse Confidence Score:', data['data']['abuseConfidenceScore'])
        if data['data']['abuseConfidenceScore'] > 20:
            print('Threat score >= 20/100, threat detected \U0001F6A9')
        else:
            print('Threat score <= 20/100, may not be considered a threat')
    else:
        print('Error: Unable to retrieve data from ABUSEIPDB API')
        print('Status Code:', response.status_code)
        print('Response:', response.text)

# Function to check IP address in VirusTotal
def check_ip_address_vt(ip_address, vt_api_key):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': vt_api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        print('Results for:', ip_address)
        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious_detections = stats.get('malicious', 0)

        # to print red flag right after malicious detection value over 0
        if malicious_detections > 0:
            print(f'Malicious detections: {malicious_detections} \U0001F6A9')
        else:
            print(f'Malicious detections: {malicious_detections}')

        print('Undetected:', stats.get('undetected', 'None'))
        print('Clean:', stats.get('clean', 'None'))

def check_attachment_hash_vt(att_hash, vt_api_key):
    url = f"https://www.virustotal.com/api/v3/files/{att_hash}"
    headers = {'x-apikey': vt_api_key}

    # Send GET request to VT
    response = requests.get(url, headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the JSON response
        data = response.json()

        # Display results
        print('Results for:', att_hash)

        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious_detections = stats.get('malicious', 0)

        # to print red flag right after malicious detection value over 0
        if malicious_detections > 0:
            print(f'Malicious detections: {malicious_detections} \U0001F6A9')
        else:
            print(f'Malicious detections: {malicious_detections}')

        print('Undetected:', stats.get('undetected', 'None'))
        print('Clean:', stats.get('clean', 'None'))
    else:
        print('Error: Unable to retrieve data from VIRUSTOTAL')
        print('Status Code:', response.status_code)
        print('Response:', response.text)

# FUNCTION TO EXTRACT PLAIN TEXT FROM EMAIL BODY
def get_plain_text(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode('utf-8', errors='ignore')
            elif part.get_content_type() == 'text/html':
                html_content = part.get_payload(decode=True)
                soup = BeautifulSoup(html_content, 'html.parser')
                return soup.get_text()
    else:
        return msg.get_payload(decode=True).decode('utf-8', errors='ignore')
    return None

# Function to check for red flags based on output lines
def check_for_red_flags(output):
    red_flags = 0
    if 'At least one authentication result failed \U0001F6A9' in output:
        red_flags += 1
    if 'Not all authentication results provided \U0001F6A9' in output:
        red_flags += 1
    if 'Sender domains do not match \U0001F6A9' in output:
        red_flags += 1
    if 'Threat score >= 20/100, threat detected \U0001F6A9' in output:
        red_flags += 1
    if 'Body contains grammatical and spelling errors \U0001F6A9' in output:
        red_flags += 1
    if 'URL is not valid \U0001F6A9' in output:
        red_flags += 1
    if 'Detected language is not English \U0001F6A9' in output:
        red_flags += 1

    # If malicious detections found, add red flags to count
    malicious_detections_found = 'Malicious detections: '
    if malicious_detections_found in output:
        # Extract the value after 'Malicious detections: '
        start_index = output.index(malicious_detections_found) + len(malicious_detections_found)
        end_index = output.find('\n', start_index)  # find end of line
        if end_index == -1:  # take rest of string if not found
            end_index = len(output)
        malicious_count = output[start_index:end_index].strip()  # strip whitespace
        try:
            if int(malicious_count) < 50:  # convert to int and check if greater than 0
                red_flags += 1
            elif 50 <= int(malicious_count) < 75:
                red_flags += 2
            elif int(malicious_count) >= 75:
                red_flags += 3
        except ValueError:
            pass  # if conversion fails, do nothing
    return red_flags

# Call the function with the provided filename
process_email_file(filename)

# Collect messages based on previous tests above
output_lines = []
if 'At least one authentication result failed \U0001F6A9' in output_lines:
    output_lines.append('At least one authentication result failed \U0001F6A9')
if 'Not all authentication results provided \U0001F6A9' in output_lines:
    output_lines.append('Not all authentication results provided \U0001F6A9')
if 'Sender domains do not match \U0001F6A9' in output_lines:
    output_lines.append('Sender domains do not match \U0001F6A9')
if 'Threat score >= 20/100, threat detected \U0001F6A9' in output_lines:
    output_lines.append('Threat score >= 20/100, threat detected \U0001F6A9')
if 'Body contains grammatical and spelling errors \U0001F6A9' in output_lines:
    output_lines.append('Body contains grammatical and spelling errors \U0001F6A9')
if 'URL is not valid \U0001F6A9' in output_lines:
    output_lines.append('URL is not valid \U0001F6A9')
if 'Detected language is not English \U0001F6A9' in output_lines:
    output_lines.append('Detected language is not English \U0001F6A9')

output = '\n'.join(output_lines)

# Calculate red flags after all checks
red_flags = check_for_red_flags(output)

# Assign Malicious Score
if red_flags <= 1:
    malicious_score = 10
elif red_flags <= 3:
    malicious_score = 30
elif red_flags >= 5:
    malicious_score = 50
elif red_flags >= 7:
    malicious_score = 100

# Print the Malicious Score after all checks
print('Malicious Score:', malicious_score)

print('Email Scan Complete')