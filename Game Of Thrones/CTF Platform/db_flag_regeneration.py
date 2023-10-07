import requests
import sys
import json
import hashlib
import datetime

def main(argv):
   option = argv[0]
   if(option):
        request_url=""
        bearer_token="ctfd_sampletoken"
        if(option == "--all"):
            request_url="http://localhost:8000/api/v1/challenges"
            print("Generating flags in DB for all machines.")
        elif(option != ''):
            request_url=f"http://localhost:8000/api/v1/challenges?category={option}"
            print(f"Generating flags in DB for {option} machine")

        headers = {
            "Authorization": f"Token {bearer_token}",
            "Content-Type":"application/json"
        }

        challenges_response = requests.get(request_url, headers=headers)
        if challenges_response.status_code == 200:
            challenges = challenges_response.json()["data"]
            for challenge in challenges:
                challenge_id=challenge["id"]
                challenge_name=challenge["name"]
                machine = challenge["category"]
                flags_response=requests.get(f"http://localhost:8000/api/v1/flags?challenge_id={challenge_id}", headers=headers)
                if flags_response.status_code == 200:
                    flag = flags_response.json()["data"][0]
                    flag_id = flag["id"]

                    ct = str(datetime.datetime.now())
                    pre_hash= ct + ";" + str(flag_id) + ";" + str(machine) + ";" + str (challenge_name)
                    new_flag_hash=hashlib.md5(pre_hash.encode('utf-8')).hexdigest()
                    new_flag=f"ICSD{{{new_flag_hash}}}"
                    flag_change_data = {
                        'content':f'{new_flag}',
                        'data':'',
                        'type':'static',
                        'id': f'{flag_id}'
                    }
                    flag_regenerate_response = requests.patch(f"http://localhost:8000/api/v1/flags/{flag_id}", data=json.dumps(flag_change_data), headers=headers)
if __name__ == "__main__":
   main(sys.argv[1:])
