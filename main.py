"""Using the provided sample JSON below and the haveibeenpwned API, 
create a program which will provide a report of users with compromised passwords. """

import requests
import json
import hashlib
import csv
import time
from datetime import datetime
from pathlib import Path
import os

# Global vars
URL = "https://api.pwnedpasswords.com/range/{password}"
report_data = []
output_path = Path('output')

# create the output path if it doesnt exist or gets deleted
if not os.path.exists(output_path):
    output_path.mkdir(parents=True, exist_ok=True)


# this is good practice for a user-agent, according to haveibeenpwned docs
USER_AGENT = {"user-agent": "Beyond The Frame"}


# function to grab password hash to use, sh1 is fine for this
def sha1_hash(password):
    sha1 = hashlib.sha1()
    sha1.update(password.encode('utf-8'))
    return sha1.hexdigest().upper()


# format the password field with the password hash in URL
def format_password_url(password):
    global URL
    return URL.format(password=sha1_hash(password))


# Load the json file provided in the prompt
def load_user_json(file):
    try:
        with open(file, 'r') as user_file:
            users = json.load(user_file)
    except FileNotFoundError:
        print(f"{user_file} not found!")
        return
    except json.JSONDecodeError as e:
        print(f"error decoding JSONL:", e)
        
    return users


# send the actual api query, then parse the results for a match
def query_api_passwords(hash_prefix, full_hash):
    global URL
    url = URL.format(password=hash_prefix)
    resp = requests.get(url, headers=USER_AGENT)
    try:
        if resp.status_code == 200:
            # the way that haveibeenpwned api works is that you inject a prefix (5 chars) of a hash, and it responds with the remaining values that match the prefix
            hash_suffix = full_hash[5:]
            response_hash = resp.text.splitlines()
            for line in response_hash:
                # the results have count appended to the hash, so we have to split that
                hash, count = line.split(':')
                if hash_suffix == hash:
                    return ("Found", full_hash, count)
    except Exception as error:
        print(f"an Error has occured\nresponse status: {resp.status_code}\nMessage Details: {error}")
    return None, None, None
    

# We have to generate a report for the results, csv would work
def generate_csv_report(data):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    # added a timestamp to the nameso that the report doesnt just delete itself
    filename = output_path / f"userpwn_report_{timestamp}.csv"
    print("Generating report on findings...")
    time.sleep(2)
    with open(filename, "w", newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        # row headers
        writer.writerow(
                [
                    "Index",
                    "ID", 
                    "GUID",
                    "Account",
                    "Name",
                    "Company", 
                    "Count_Of_Matches", 
                    "Compromised_Hash",  
                    "isActive", 
                    "Status", 
                    "pwLastChanged"
                ]
             )
        for entry in data:
            # row values
            writer.writerow(
                [
                    entry['index'],
                    entry['id'], 
                    entry['guid'], 
                    entry['account'],
                    entry['name'],
                    entry['company'],
                    entry['count'], 
                    entry['details'], 
                    entry['isActive'],
                    entry['status'] ,
                    entry['passwordLastChangedDate']
                ]
            )   
    print(f"Report generation completed. Report can be found in: {filename}")
            

def main():
    print("Querying haveibeenpwned api for matched hashes...")
    time.sleep(1)
    users = load_user_json("users.json")
    for user in users:
        for creds in user['credentials']:
            password_hash = sha1_hash(creds['password'])            
            hash_prefix = password_hash[:5]
            status, details, count = query_api_passwords(hash_prefix, password_hash)
            if status is not None:
            # this is the results from the json format, plus newly retrieved values
                report_data.append(
                        {
                            "id": user["_id"],
                            "index": user["index"],
                            "guid": user["guid"],
                            "isActive": user["isActive"],
                            "account": user["email"],
                            "status": status,
                            "count": count,
                            "passwordLastChangedDate": creds["last_changed"],
                            "details": details,
                            "name": user["name"],
                            "company": user["company"]
                            # the rest is collectively considered PII data (even though its a test account) and shouldnt' be used.
                        }
                    )
            else:
                pass
    generate_csv_report(report_data)

if __name__=="__main__":
    main()
