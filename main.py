import vt_utils
import ioc_detector
import getpass
import sys
import os

# Store the API Key globally
apikey = None

def get_api_key():
    """
    Prompts for and stores the API Key from the user once.
    """
    global apikey
    if apikey is None:
        apikey = getpass.getpass("Enter your VirusTotal API Key (input will be hidden): ")
        if not apikey:
            print("Error: API Key is required.")
            exit()
    return apikey

def clear_screen():
    """
    Clears the screen based on the operating system.
    """
    os.system('cls' if os.name == 'nt' else 'clear')

def analyze_text(api_key):
    """
    Main function to analyze the text entered by the user.
    """
    excluded_iocs = []

    print("Enter the text to analyze (To finish: Ctrl+D UNIX, Ctrl+Z Windows):")

    try:
        sample_text = sys.stdin.read()
    except EOFError:
        print("No text provided.")
        return

    iocs = ioc_detector.detect_all(sample_text)

    print("\n--------------------Results--------------------\n")

    for ioc in iocs:
        # Make the request to the API
        response = vt_utils.make_request(api_key, ioc)
        stats = vt_utils.extract_json(response)

        # Check if the results are valid or should be excluded
        if not stats or (stats.malicious == 0 and stats.suspicious == 0):
            excluded_iocs.append(ioc)
        else:
            print(f"{ioc} [{stats.malicious}-{stats.suspicious}]")

    if excluded_iocs:
        print("\n--------------------Excluded IoCs--------------------\n")
        for ioc in excluded_iocs:
            print(ioc)

def main():
    """
    Main loop to continue execution until the user decides to stop.
    """
    api_key = get_api_key()

    while True:
        analyze_text(api_key)

        continue_choice = input("\nWould you like to analyze more text? (yes/no): ").strip().lower()

        if continue_choice in ['no', 'n']:
            print("Exiting the program.")
            break
        else:
            clear_screen()

if __name__ == "__main__":
    main()
