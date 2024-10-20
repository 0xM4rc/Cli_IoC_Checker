import requests
import json


apikey = ""
vtUrl = "https://www.virustotal.com/api/v3/search?query="

class AnalysisStats:
    def __init__(self, malicious:str, suspicious:str):
        self.malicious = malicious
        self.suspicious = suspicious

#################################################
#                   REQUESTS                    #
#################################################

# Function to make the request to VirusTotal
def make_request(apikey:str, search_data:str):
    requestUrl = vtUrl+search_data

    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }

    try:
        response = requests.get(requestUrl, headers=headers)
        # Validate if the response is successful (status code 200)
        if response.status_code == 200:
            return response.json()  # Return the parsed JSON data
        else:
            print(f"Error: Could not perform the search. Status code: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Connection error: {e}")
        return None

#################################################
#                   RESPONSE                    #
#################################################

def extract_json(jsonRequest: dict):
    try:
        # Check if 'data' exists and contains at least one element
        if len(jsonRequest['data']) > 0:
            last_analysis_stats = jsonRequest['data'][0]['attributes']['last_analysis_stats']
            malicious = last_analysis_stats['malicious']
            suspicious = last_analysis_stats['suspicious']
            return AnalysisStats(malicious, suspicious)
        else:
            # If there's no data in the list, print an error message
            # print(jsonRequest)
            # print("Error: The response does not contain data in 'data'.")
            return None
    except KeyError:
        print("Error: Unable to find the analysis stats in the response.")
        return None

