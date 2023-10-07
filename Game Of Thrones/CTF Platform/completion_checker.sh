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


