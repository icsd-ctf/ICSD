# 'Game of Thrones' - Capture the Flag

As PROSOL, we had the opportunity to host the ICSD 2023 conference - an event dedicated to cybersecurity days for the third time! The event was co-hosted by PROSOL and the State Service for Special Communication and Information Security.

Within the framework of the event, which took place on September 21-23, 2023, a CTF competition in the format of "Game of Thrones" was organized by the hosts. According to the event schedule, the competition took place on September 22 and lasted for 6 hours. Ten teams, each consisting of three members, competed for a prize pool totaling 3000AZN and additional exciting prizes.

CyberYashma emerged as the winner of the competition, scoring 220 out of 600 possible points. The second and third place teams (DoublePulsar and ALLSAFE) both achieved a score of 110.

In this repository, we will share all the materials that we used during the CTF to express our appreciation for open source. Moreover, to support this idea, we have used one easy machine from [vulnhub](https://www.vulnhub.com/entry/election-1,503/) (Callobes)!

# General Information
6 vulnerable machines were presented to competitors. Machines were categorized as easy, medium, and hard. Each easy machine provided 50 points, each medium machine 100 points, and each hard machine 150 points, adding up to a total of 600 points. Moreover, competitors were able to access an ELK server where all HTTP logs, as well as each command run on attack boxes, were logged (to read more, please refer to [architecture section](https://github.com/NotokDay/ICSD/tree/main/Game%20Of%20Thrones/Architecture)). This, in theory, should have helped teams find the exact ways other teams exploited the machines and redo the steps to obtain the flags. This way, teams with better overall offensive and defensive skills would come out on top.

> [!NOTE]  
> In addition to the primary challenges, we introduced a secondary challenge: competitors were given the option to destroy the machines (for example delete important system files, block network access etc.) they had successfully exploited. However, there were consequences for this action.
> If other teams detected the destruction of a machine, they would be rewarded with an additional 50 points. On the other hand, the team that destroyed the machine would face a penalty of 20 points and a ban from accessing that specific machine.
> During the CTF, a couple of such incidents occurred where teams did damage the CTF machines. However, none were detected. 


# Standings

| Teams/Machines | Callobes | Gitlab | Bytescribe | Captivity | Blitz | Noteapp | Total |
|  :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
|  CyberYashma | 20 30 | 20 30 | 30 30 - | 30 30 - | - - - - | - - - |  220 |
|  DoublePulsar | 20 30 | - - | 30 30 - | - - - | - - - - | - - - |  110 |
|  ALLSAFE | 20 30 | - - | 30 30 - | - - - | - - - - | - - - |  110 |
|  CBAR_TEAM | 20 30 | 20 30 | - - - | - - - | - - - - | - - - |  100 |
|  ExploitationUnit | 20 30 | 20 30 | - - - | - - - | - - - - | - - - |  50 |

Unfortunately, the other 5 teams scored 0 points. 

During the competition, several hints were shared at random time intervals for each machine. These hints even included credentials for the gitlab machine in the format root:base64(password) and 2 CVE numbers! 

The fact that five teams were unable to score any points can be primarily attributed to their limited experience in CTF competitions. It's crucial to stress that this environment is simulated and can be quite challenging, not exactly mirroring real-world penetration testing experiences. Consequently, lower scores should not be seen as indicative of anyone's inability to perform penetration tests or blue teaming effectively.


# Some moments from the competition
![BAH_7833-min](https://github.com/NotokDay/ICSD/assets/115024808/fa85fe5b-1b6d-43a7-9aa7-98a07c38a7a5)
___
![BAH_7813](https://github.com/NotokDay/ICSD/assets/115024808/8a17e7b2-a72d-4db7-af07-4bc0990f038b)
___
![photo_5249282619873546109_y](https://github.com/NotokDay/ICSD/assets/115024808/6411fa2d-f4bb-4508-a908-d718eab84acf)
___
![0W1A1434](https://github.com/NotokDay/ICSD/assets/115024808/ddff6716-b967-438a-bc29-ce7f85a88884)
___
![BAH_7814](https://github.com/NotokDay/ICSD/assets/115024808/de1ae2cc-9729-4b0e-a6b3-59a999ee94a1)
___
![BAH_7820](https://github.com/NotokDay/ICSD/assets/115024808/bf2825fb-5fdf-4313-b418-def915b15228)
___
![BAH_7822](https://github.com/NotokDay/ICSD/assets/115024808/91796163-fb4e-4aed-b93d-6a86166ffc4d)
___
![BAH_7830](https://github.com/NotokDay/ICSD/assets/115024808/fc487ab8-2435-4f7a-97b4-c3422e1dcaab)
___
![photo_5249282619873546121_y(1)](https://github.com/NotokDay/ICSD/assets/115024808/68ef86cc-6afc-4b37-a065-a156b722381c)
