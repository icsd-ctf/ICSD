import requests
import paramiko
import sys

# Replace with your actual Bearer token and category_variable
bearer_token = "ctfd_sampleToken"
machine ="blitz"
server_ip="10.20.52.2"

ssh_username="root"

ssh_password="PasswordOfRoot"

# Define the URL for the initial request
initial_url = f"http://localhost:8000/api/v1/challenges?category={machine}"

# Set headers with the Bearer token
headers = {
    "Authorization": f"Token {bearer_token}",
    "Content-Type":"application/json"

}

ssh_client=paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

def send_telegram_message(text):
    message_data = {
        'chat_id' : 'TelegramGroupChatId',
        'text' : 'Overwriter script - error in Blitz machine - ' + text
    }
    requests.post("https://api.telegram.org/botTokenProvidedByTelegram/sendMessage",data=message_data)


try:
    ssh_client.connect(server_ip,username=ssh_username,password = ssh_password,timeout=10)
except:
    send_telegram_message("no SSH access")
    sys.exit()

try:
    # Make the initial request to get challenges
    response = requests.get(initial_url, headers=headers)
    # Check if the initial request was successful (status code 200)
    if response.status_code == 200:
        challenges = response.json()["data"]

    # Iterate over the list of challenges
        for challenge in challenges:
            challenge_id = challenge["id"]
            challenge_name = challenge["name"]
            # Define the URL for the second request using the challenge_id
            flags_url = f"http://localhost:8000/api/v1/flags?challenge_id={challenge_id}"

            # Make the second request for flags
            response = requests.get(flags_url, headers=headers)
            # Check if the second request was successful (status code 200)
            if response.status_code == 200:
                flag = response.json()["data"][0]["content"]
                if challenge_name == "user1.txt":
                    stdin,stdout,stderr = ssh_client.exec_command(f"rm -rf /user1.txt ; echo {flag}> /user1.txt")
                    error_message = stderr.read()
                    if(error_message):
                        send_telegram_message(error_message.decode('utf-8'))
                        print("ERROR" + error_message.decode('utf-8'))
                    print(f"SSHing {flag} into /user1.txt")
                elif challenge_name == "user2.txt":
                    stdin,stdout,stderr = ssh_client.exec_command(f"rm -rf /home/git/user2.txt ; cd /home/git && touch user2.txt && echo {flag}> user2.txt && chown git:git user2.txt && chmod 600 user2.txt")
                    error_message = stderr.read()
                    if(error_message):
                        send_telegram_message(error_message.decode('utf-8'))
                        print("ERROR" + error_message.decode('utf-8'))
                    print(f"SSHing {flag} into /home/git/user2.txt")
                elif challenge_name == "user3.txt":
                    stdin,stdout,stderr = ssh_client.exec_command(f"rm -rf /home/node/user3.txt ; cd /home/node && touch user3.txt && echo {flag}> user3.txt && chown node:node user3.txt && chmod 600 user3.txt")
                    error_message = stderr.read()
                    if(error_message):
                        send_telegram_message(error_message.decode('utf-8'))
                        print("ERROR" + error_message.decode('utf-8'))

                    print(f"SSHing {flag} into /home/node/user3.txt")
                elif challenge_name == "root.txt":
                    stdin,stdout,stderr = ssh_client.exec_command(f"rm -rf /root/root.txt ; echo {flag}> /root/root.txt")
                    error_message = stderr.read()
                    if(error_message):
                        send_telegram_message(error_message.decode('utf-8'))
                        print("ERROR" + error_message.decode('utf-8'))

                    print(f"SSHing {flag} into  /root/root.txt")
                else:
                    print("ERROR . CHALLENGE NOT FOUND IN OVERWRITE BLITZ")
            else:
                print(f"BLITZ Failed to retrieve flags for Challenge {challenge_id}. Status Code: {response.status_code}")
    else:
        print(f"BLITZ Failed to retrieve challenges. Status Code: {response.status_code}")
except Exception as e:
     send_telegram_message(str(e))
     print(f"BLITZ An error occurred: {str(e)}")

ssh_client.close()
