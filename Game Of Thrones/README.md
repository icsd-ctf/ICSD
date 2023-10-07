# 'Game of Thrones' - Capture the Flag

As PROSOL, we had the opportunity to host the ICSD 2023 conference - an event dedicated to cybersecurity days for the third time! The event was co-hosted by PROSOL and the State Service for Special Communication and Information Security.

Within the framework of the event, which took place on September 21-23, 2023, a CTF competition in the format of "Game of Thrones" was organized by the hosts. According to the event schedule, the competition took place on September 22 and lasted for 6 hours. Ten teams, each consisting of three members, competed for a prize pool totaling 3000AZN and additional exciting prizes.

CyberYashma emerged as the winner of the competition, scoring 220 out of 600 possible points. The second and third place teams (DoublePulsar and ALLSAFE) both achieved a score of 110.

In this repository, we will share all the materials that we used during the CTF to express our appreciation for open source. Moreover, to support this idea, we have used one easy machine from [vulnhub](https://www.vulnhub.com/entry/election-1,503/) (Callobes)!

# General Information
6 vulnerable machines were presented to competitors. Machines were categorized as easy, medium, and hard. Each easy machine provided 50 points, each medium machine 100 points, and each hard machine 150 points, adding up to a total of 600 points. Moreover, competitors were able to access an ELK server where all HTTP logs, as well as each command run on attack boxes, were logged (to read more, please refer to [architecture section](https://github.com/icsd-ctf/ICSD/tree/master/Game%20Of%20Thrones/Architecture/Writeup.md)). This, in theory, should have helped teams find the exact ways other teams exploited the machines and redo the steps to obtain the flags. This way, teams with better overall offensive and defensive skills would come out on top.

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

![BAH_7833-min](https://github.com/icsd-ctf/ICSD/assets/147237916/df9af7f6-d4a5-44f6-9cca-9372b5b05eea)
___
![BAH_7813](https://github.com/icsd-ctf/ICSD/assets/147237916/3ff3b80e-477f-45a7-861c-466afbcf4e53)
___
![BAH_7830](https://github.com/icsd-ctf/ICSD/assets/147237916/8a920361-5c47-4d98-a204-261eb71f87c2)
___
![BAH_7822](https://github.com/icsd-ctf/ICSD/assets/147237916/0fe1dbe7-0f48-44a2-9f5f-0dfd4cc9e2cc)
___
![photo_5249282619873546109_y](https://github.com/icsd-ctf/ICSD/assets/147237916/cdd58273-ac0a-4e07-b1d3-224877e32813)
___
![photo_5249282619873546110_y](https://github.com/icsd-ctf/ICSD/assets/147237916/725f2e85-2bca-4b9d-bc92-a8a67c0c4a74)
___
![0W1A1434](https://github.com/icsd-ctf/ICSD/assets/147237916/67f58365-9e1b-4f9e-aa4a-f60b40757342)
___
![BAH_7814](https://github.com/icsd-ctf/ICSD/assets/147237916/e5794b09-4e51-4f2e-8d1e-77ca0c698f09)
___
![BAH_7820](https://github.com/icsd-ctf/ICSD/assets/147237916/a97a0654-4de7-4924-9405-19702406fd85)
