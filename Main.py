import os
import base64
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import pickle
import re
import requests
import time


# Set up API keys and endpoints
VIRUSTOTAL_API_KEY = "Make_this_your_own"
VIRUSTOTAL_URL = "Make_this_your_own"
URLSCAN_API_KEY = 'Make_this_your_own'

# Gmail API authentication
def get_gmail_service():
    creds = None
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", ["https://www.googleapis.com/auth/gmail.readonly"])
            creds = flow.run_local_server(port=0)
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)
    return build("gmail", "v1", credentials=creds)

def get_latest_email(service):
    try:
        results = service.users().messages().list(userId="me", q="is:unread", maxResults=1).execute()
        messages = results.get("messages", [])

        if not messages:
            print("No new messages.")
            return None

        msg_id = messages[0]["id"]
        message = service.users().messages().get(userId="me", id=msg_id, format="full").execute()

        payload = message["payload"]
        headers = payload["headers"]

        subject = ""
        body = ""

        for header in headers:
            if header["name"] == "subject" or header["name"] == "Subject":
                subject = header["value"]
            if header["name"] == "From" or header["name"] == "from":
                sender = header["value"]

        if "parts" in payload:
            parts = payload["parts"]
            for part in parts:
                if part["mimeType"] == "text/plain":
                    body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")

        return {"subject": subject, "sender": sender, "body": body}

    except HttpError as error:
        print(f"An error occurred: {error}")
        return None

def check_virustotal(url):
    params = {'apikey': VIRUSTOTAL_API_KEY, 'url': url}
    response = requests.post(VIRUSTOTAL_URL + "/scan", data=params)

    if response.status_code == 200:
        response_data = response.json()
        if 'scan_id' in response_data:
            scan_id = response_data["scan_id"]
            vt_result = requests.get(VIRUSTOTAL_URL + "/report", params={"apikey": VIRUSTOTAL_API_KEY, "resource": scan_id})
            return vt_result.json()
        else:
            print("Error: 'scan_id' not found in the VirusTotal API response")
            return None
    else:
        print(f"Error in VirusTotal API call. Status code: {response.status_code}")
        return None


def check_email_quality(email, api_key):
    url = f"https://www.ipqualityscore.com/api/json/email/{api_key}/{email}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error {response.status_code}: Unable to fetch data from IPQS.")
        return None

def submit_urlscan(url, api_key):
    headers = {'API-Key': api_key}
    data = {'url': url}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=data)

    if response.status_code == 200:
        result = response.json()
        return result
    else:
        print(f"Error {response.status_code}: Unable to submit URL to URLScan.io.")
        return None

def get_urlscan_result(uuid, api_key):
    headers = {'API-Key': api_key}
    response = requests.get(f'https://urlscan.io/api/v1/result/{uuid}/', headers=headers)

    if response.status_code == 200:
        result = response.json()
        return result

def wait_for_urlscan_result(uuid, api_key, timeout=300, interval=10):
    start_time = time.time()

    while time.time() - start_time < timeout:
        result = get_urlscan_result(uuid, api_key)
        if result:
            return result

        time.sleep(interval)

    print("Timed out waiting for URLScan.io result.")
    return None

def extract_urls(text):
    return re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)

def extract_ips(text):
    return re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)

def extract_email(text):
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    emails = re.findall(email_pattern, text)
    return emails

def extract_target_url(redirect_url):
    response = requests.get(redirect_url, allow_redirects=False)

    if response.status_code in (301, 302, 303, 307, 308):
        target_url = response.headers.get("Location")
        return target_url
    else:
        print(f"Error {response.status_code}: Unable to fetch target URL.")
        return None

def traffic_light_COMMANDER(URLSCANlight, VIRUSTOTALlight):
    overall = 0

    if VIRUSTOTALlight >=1 and VIRUSTOTALlight <= 3:
        overall+=1
    elif VIRUSTOTALlight >= 4:
        overall+=2
    else:
        None


    if URLSCANlight >= 1:
        overall+=1
    else:
        None

    if overall == 1:
         print("Yellow flag to the IT Team")
    elif overall >= 2:
        print("RED do not open flag to the IT Team")
    else:
        print("GREEN Happy to open ")

def main():
    service = get_gmail_service()
    email = get_latest_email(service)

    if email:
        urls = extract_urls(email['body'])

        for url in urls:
            # Check base URL
            vt_result_base = check_virustotal(url)
            if vt_result_base:
                VIRUSTOTAL_Count_base = vt_result_base['positives']
            else:
                print("VirusTotal result not available for the base URL.")
                continue

            submit_result_base = submit_urlscan(url, URLSCAN_API_KEY)

            if submit_result_base:
                scan_uuid_base = submit_result_base['uuid']
                scan_result_base = wait_for_urlscan_result(scan_uuid_base, URLSCAN_API_KEY)

                if scan_result_base:
                    if 'verdicts' in scan_result_base:
                        URLSCAN_Count_base = scan_result_base['verdicts']['overall']['score']
                    else:
                        print("The 'verdicts' field is not found in the JSON response.")
            else:
                print("URLScan result not available for the base URL.")
                continue

            traffic_light_COMMANDER(URLSCAN_Count_base, VIRUSTOTAL_Count_base)

            # Check redirected URL if base URL results are green
            if URLSCAN_Count_base == 0 and VIRUSTOTAL_Count_base == 0:
                extracted_url = extract_target_url(url)
                vt_result_redirect = check_virustotal(extracted_url)
                if vt_result_redirect:
                    VIRUSTOTAL_Count_redirect = vt_result_redirect['positives']
                else:
                    print("VirusTotal result not available for the redirected URL.")
                    continue

                submit_result_redirect = submit_urlscan(url, URLSCAN_API_KEY)

                if submit_result_redirect:
                    scan_uuid_redirect = submit_result_redirect['uuid']
                    scan_result_redirect = wait_for_urlscan_result(scan_uuid_redirect, URLSCAN_API_KEY)

                    if scan_result_redirect:
                        if 'verdicts' in scan_result_redirect:
                            URLSCAN_Count_redirect = scan_result_redirect['verdicts']['overall']['score']
                        else:
                            print("The 'verdicts' field is not found in the JSON response.")
                else:
                    print("URLScan result not available for the redirected URL.")
                    continue

                traffic_light_COMMANDER(URLSCAN_Count_redirect, VIRUSTOTAL_Count_redirect)

if __name__ == "__main__":
    main()

