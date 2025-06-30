# 사용방법
1. git clone https://github.com/lalamr/team1_project 명령어로 위 깃허브 링크를 클론합니다.
2. docker compose up -d --build 명령어로 실행합니다.
3. mysql, ai서버 3개, snort, kali서버가 실행된 것을 확인합니다.
4. docker exec -it kali /bin/bash 명령어로 컨테이너에 접속합니다. 
5. ai-1, ai-2, ai-3 각각 172.19.0.3, 172.19.0.4, 172.19.0.5 주소를 가지고 있습니다. 해당 주소로 hping3 -S -p 80 -i u1000 {ip주소} 명령어로 공격을 날릴 수 있습니다.
6. 아니면 루트 경로에 있는 attack_test.sh를 실행시킬 수도 있습니다.
7. 공격을 날리면 ai서버가 공격을 감지하고 mysql에 결과를 업데이트 합니다.
8. 확인을 위해 docker exec -it mysql /bin/sh 로 접속합니다.
9. mysql -u root -p rootpass 로 접속합니다.
10. use ai_security; select * from ips_signatures; 로 추가된 정보를 확인할 수 있습니다.
11. 이제 snort 업데이트를 확인하기 위해 docker exec -it ips /bin/sh 로 접속합니다.
12. /updater/ips_updater.py를 실행시키면 db에서 정보를 가져와서 ai_generated.rules가 업데이트 됩니다. 
