import requests
import json
from datetime import datetime

from config import BASE_URL, RESPONSE_FILE

def save_response_to_json(cve_info):
    try:
        with open(RESPONSE_FILE, 'w') as file:
            json.dump(cve_info, file, indent=4)
            file.close()
        print(f"SAVED TO {RESPONSE_FILE}")
    except:
        print("No CVE data to save.")


    
def save_cve_info(cve_data):
    if cve_data:
        cve_info = []
        totalResults = cve_data['totalResults']
        cve_info.append({'TotalResults':totalResults})
        for vulnerability in cve_data['vulnerabilities']:
            cve_id = vulnerability['cve']['id']
            last_modified = vulnerability['cve']['lastModified']
            vuln_status = vulnerability['cve']['vulnStatus']
            description_en = next((desc['value'] for desc in vulnerability['cve']['descriptions'] if desc['lang'] == 'en'), None)
            cve_info.append({
                
                'CVE_ID': cve_id,
                'Last_Modified': last_modified,
                'Vulnerability_Status': vuln_status,
                'Description': description_en
            })
        save_response_to_json(cve_info)

def GET_TO_BASE_URL():
    try:
        response = requests.get(BASE_URL)
        if response.status_code == 200:
            return response.json()       
    except:
        print("SOMETHING WENT WRONG")
        return None
    
def open_json_file(fname):
    with open(RESPONSE_FILE, 'r') as file:
        response = json.load(file)
        file.close()
    return response
def calculate():
    
    response = open_json_file(RESPONSE_FILE)

    total_vulnerabilities = response[0]['TotalResults']
    start_date = datetime(2023, 3, 1)
    end_date = datetime(2024, 3, 31)
    days_in_range = (end_date - start_date).days

    avg_vulnerabilities_per_day = total_vulnerabilities / days_in_range

    time_per_cve_minutes = 5
    time_per_week_minutes = avg_vulnerabilities_per_day * time_per_cve_minutes * 7

    print("Average number of vulnerabilities reported per day:", avg_vulnerabilities_per_day)
    print("Time spent per week reviewing CVEs (in minutes):", time_per_week_minutes)

def main():
    calculate()
    #response = GET_TO_BASE_URL()
    #save_cve_info(response)     
   
    

main()