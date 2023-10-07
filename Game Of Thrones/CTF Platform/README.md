# CTF Platform
We used [CTFd](https://ctfd.io/) as a CTF Platform for flag submissions (Kudos for great open-source project!) , however, based on the fact that the structure and rules of our CTF were different than standart CTF competitions, we had to make our modifications to CTFd to satisfy the needed requirements. 

## Initial setup and configurations
CTFd runs on docker containers and all you need to do is pull the source code from [official repository](https://github.com/CTFd/CTFd), and run `docker compose up` command in the CTFd folder where docker-compose.yml file exists. This operation will run all the needed services (Application, Redis, MySQL and Nginx) with inital configurations and you can visit the platform at localhost:8000 to continue the configuration process where you set up password for administrator account, and tune some settings for CTF competition (such as Team mode activation, event start and end time, theme to use and etc.). 

> [!WARNING]  
> If you modify the source code or Dockerfile, you may need to execute `docker compose down` and `docker compose up` multiple times, which may lead to exhaustion of storage by images and containers. For overcoming this, you can run 'docker system prune' before your last run to ensure clean setup of platform.


### CTFd features that we used
For our CTF we used `Team mode` as 10 teams competed in our competition, and set the maximum amount of team members to three. We disabled public team and user registration in settings and registered all users and teams by ourselves. Two back-up teams were in reserve list, and they would be invited to competition if some teams in initial list didn't attend the event, thus, we created user and team accounts for them also, however, we set their account statuses to `disabled` to make them unvisible in scoreboard. Challenges are grouped by `category` field in CTFd, and we decided to use this feature for grouping challenges of one machine: we put the machine name as category title for all challenges of one machine, and the main dashboard visible for CTF Players looked like this:

![challenges](https://github.com/NotokDay/ICSD/assets/24704431/01a6e4b9-d5e9-46e3-9ff8-cc40c5d4ad8c)



During the competition, we decided to give hints, as teams struggled to get even the first flag of some machines. We needed to broadcast a hint to each player and we achieved this by using `Notifications` feature of CTFd. When publishing a notification, it gets popped out on screen of each CTF Player, also in main screen projected to the wall in event area. These notifications stay in notifications page of the platform. One of the real hints that we published during the competition was: 

(P.S. Hint messages were related to Game Of Thrones characters and their famous quotes. Just for fun ;) 

![hint](https://github.com/NotokDay/ICSD/assets/24704431/70c4a60e-be37-4ecc-9ada-4a872c4764f0)


## Our modifications

This is where the fun starts :smiling_imp:

### Disabling visibility of team solves 
As you know, an ELK platform was used by CTF Players to analyze the traffic and commands of other CTF Players. To make this process more interesting, we decided to disable the visibility of team solves - which means no one knows which team solved which challenge, thus, players needed to analyze all traffic coming from all sources without focusing on a specific IP/source. CTFd uses two methods to display data on pages. First, it does Server Side Rendering for some pages and renders pages with data beforehand. Second, in some pages CTFd API is called from front-end to get additional data, which we needed to block also (some endpoints). For first case : when a CTF Player visits public page of other team, following code piece on ['CTFd/CTFd/teams.py'](https://github.com/CTFd/CTFd/blob/master/CTFd/teams.py) runs:

```
def public(team_id):
    infos = get_infos()
    errors = get_errors()
    team = Teams.query.filter_by(id=team_id, banned=False, hidden=False).first_or_404()
    solves = team.get_solves()   //removed
    awards = team.get_awards()

    place = team.place
    score = team.score

    if errors:
        return render_template("teams/public.html", team=team, errors=errors)

    if config.is_scoreboard_frozen():
        infos.append("Scoreboard has been frozen")

    return render_template(
        "teams/public.html",
        solves=solves, //removed
        awards=awards,
        team=team,
        score=score,
        place=place,
        score_frozen=config.is_scoreboard_frozen(),
        infos=infos,
        errors=errors,
    )
```

We removed two lines (marked as removed above) , therefore, when CTF Players visited public page of other teams, they didn't see specific solves of them. However, the endpoint requested when team visits their own team page is different, thus, they can see their own solves without any constraint. 

Specific solves of users are also visible on public pages of users, which we need to remove. For this, we removed 'solves' section from ['themes/core-beta/users/public.html'](https://github.com/CTFd/CTFd/blob/master/CTFd/themes/core-beta/templates/users/public.html) 

For second part of data retrieval, the API, we needed to block API requests from user machines, but allow administrator machines to access same API endpoints freely. For this, we decided to play with Nginx configuration. By default, as stated earlier, Nginx is set up in docker-compose.yml file to run on-start with default configurations to proxy requests coming to port 80 to 8000 and nothing else. However, we changed configuration to have following lines: 

```
location ~ /api/v1/(teams|users|challenges)/\d+/(solves|fails) {
        deny 10.20.57.0/24;
        proxy_pass http://app_servers;
        proxy_redirect off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $server_name; 
}
``` 

Here, we declare that requests to pre-defined API endpoints that contain data about team and user solves (which we want users not to see) coming from CTF Players' VLAN (10.20.57.0/24) should be blocked. 

### Removing access of team members to the completed machine (by notifying staff through Telegram)
 
The second feature that we developed was a notification system to alert the staff about completion of challenges belonging to one machine by any team. The notification is sent to a group with staff members and our notifier Telegram bot in a following format: 

![team_finished_Tg](https://github.com/NotokDay/ICSD/assets/24704431/46dde791-6773-4b03-898c-2890c5d1110e)


In five minutes after the notification is received, firewall rules are updated to disable team Attacbox's access to the finished machine.  

For achieving this kind of functionality, first we created a Telegram Bot using BotFather. Then, we somehow needed to create a script to check status of completed challenges by team in every successful flag submission and in case of completion notify us through Telegram. We developed script called [`completion_checker.sh`](https://github.com/icsd-ctf/ICSD/blob/master/Game%20Of%20Thrones/CTF%20Platform/completion_checker.sh). Script uses the REST API provided by CTFd to retrieve the data about the completed challenge, checks if team has completed all challenges in same machine that submitted challenge belongs to, and in case of full completion, sends message to our Telegram group via notifier bot. The full code of script is displayed below:

```
#!/bin/bash

team_id=$1
team_name=$2
challenge_category=$3

if [ $# -ne 3 ]; then
	exit 1
fi

challenge_ids=($(curl -sS -X GET http://localhost:8000/api/v1/challenges?category=$challenge_category --header "Authorization: Token ctfd_sampletoken" --header "Content-Type: application/json"  | jq -r '.data[].id'))

allChallengesOfMachineCompleted=true

for id in "${challenge_ids[@]}"; do

submission_result_count=$(curl -sS -X GET "http://localhost:8000/api/v1/submissions?team_id=${team_id}&challenge_id=${id}&type=correct" --header "Authorization: Token ctfd_sampletoken" --header "Content-Type: application/json" | jq -r '.meta.pagination.total')

if [ "$submission_result_count" -ne 1 ]; then
	allChallengesOfMachineCompleted=false
fi

done

if [ ${#challenge_ids[@]} -eq 0 ]; then

allChallengesOfMachineCompleted=false

fi

if [ "$allChallengesOfMachineCompleted" = true ]; then

curl -sS -X GET "https://api.telegram.org/botTokenProvidedByTelegram/sendMessage?chat_id=groupChatIdHere&text=Team_$(echo $team_id)_finished_machine_$(echo $challenge_category)"

fi
```

This script is added to `CTFd/CTFd/api/v1/ctfd_scripts` folder and called in [`CTFd/CTFd/api/v1/challenges.py'](https://github.com/CTFd/CTFd/blob/master/CTFd/api/v1/challenges.py) as following (added to 637th line) : 

```
subprocess.run(['/opt/CTFd/CTFd/api/v1/ctfd_scripts/completion_checker.sh',f"{team.id}", f"{team.name}", f"{challenge.category}"])
```
P.S: For having access to `curl` and `jq` tools used inside script, we modified Dockerfile (second FROM block) to install curl and jq also to container: 

``` 
FROM python:3.9-slim-buster as release
WORKDIR /opt/CTFd

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libffi6 \
        libssl1.1 \
 curl \
 jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* 

``` 



### Regenerating flags every 30 minutes and on successful submission 

Another requirement to prevent cheating and make competition more competitive was to regenerate flags on platform and on vulnerable machines at same time. We achieved this by adding following cron entries to crontab:  
 
```
*/2 * * * * bash /home/ctf-platform/Desktop/CTFd/CTFd/api/v1/ctfd_scripts/overwrite_scripts/total_overwrite.sh
*/30 * * * * python3 /home/ctf-platform/Desktop/CTFd/CTFd/api/v1/ctfd_scripts/db_flag_regeneration.py --all

``` 

['total_overwrite.sh'](https://github.com/icsd-ctf/ICSD/blob/master/Game%20Of%20Thrones/CTF%20Platform/total_overwrite.sh) script just executes overwriter python script for each machine in background:

```
python3 /home/ctf-platform/Desktop/CTFd/CTFd/api/v1/ctfd_scripts/overwrite_scripts/blitz_overwrite.py &
python3 /home/ctf-platform/Desktop/CTFd/CTFd/api/v1/ctfd_scripts/overwrite_scripts/captivity_overwrite.py &
python3 /home/ctf-platform/Desktop/CTFd/CTFd/api/v1/ctfd_scripts/overwrite_scripts/bytescribe_overwrite.py &
python3 /home/ctf-platform/Desktop/CTFd/CTFd/api/v1/ctfd_scripts/overwrite_scripts/bytescribe_docker_overwrite.py &
python3 /home/ctf-platform/Desktop/CTFd/CTFd/api/v1/ctfd_scripts/overwrite_scripts/noteapp_overwrite.py &
python3 /home/ctf-platform/Desktop/CTFd/CTFd/api/v1/ctfd_scripts/overwrite_scripts/gitlab_overwrite.py &
python3 /home/ctf-platform/Desktop/CTFd/CTFd/api/v1/ctfd_scripts/overwrite_scripts/callobes_overwrite.py &

```

Each overwriter script is similar to each other, you can view the full source code for script in ['blitz_overwrite.py'](https://github.com/icsd-ctf/ICSD/blob/master/Game%20Of%20Thrones/CTF%20Platform/blitz_overwrite.py), however we can mention some parts here also. 
For SSH-ing into machine and putting flag into text file, we used following way:

```
if challenge_name == "user1.txt":
                    stdin,stdout,stderr = ssh_client.exec_command(f"rm -rf /user1.txt ; echo {flag}> /user1.txt")
                    error_message = stderr.read()
                    if(error_message):
                        send_telegram_message(error_message.decode('utf-8'))
                        print("ERROR" + error_message.decode('utf-8'))
                    print(f"SSHing {flag} into /user1.txt")

```

Moreover, this script also sends Telegram messages in case of failure (when machine is down, SSH port is closed, or directory or file system is corrupted) and administrational staff reverts the vulnerable machine to clean state. :

![error_overwriter_tg](https://github.com/NotokDay/ICSD/assets/24704431/1c314377-6272-45e2-b471-a29cee64451c)


We reinsert flags to machines every two minutes (without regenerating) and regenerate the flags in DB by using CTFd API every thirty mintues and on successful flag submission by team (by adding following line to 'CTFd/CTFd/api/v1/challenges.py' (pasting it just after the previous subprocess call we added for completion_checker.sh )) : 
``` 
subprocess.run(['python3','/opt/CTFd/CTFd/api/v1/ctfd_scripts/db_flag_regeneration.py',f"{challenge.category}"]) 
```

['db_flag_regeneration.py'](https://github.com/icsd-ctf/ICSD/blob/master/Game%20Of%20Thrones/CTF%20Platform/db_flag_regeneration.py) is a python script that also uses CTFd API to edit the flag in database to a newly generated flag.

```
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

```
 

## Conclusion

This was a challenging experience for our team to set up, configure and extend a open-source product for our needs and we successfully accomplished it via the ways shown above.  
Thank you for your interest and patience for reading this.
