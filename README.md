# Sentinel

이게 뭐임?  
BOINC 서비스와 CPU를 지켜보는 감시자.  
텔레그램 연동하여 자원 사용량에 문제가 있으면 경고함.

## 동작

- `sentinel.timer`가 15분마다 one-shot 서비스를 실행
- 각 실행은 `boinc-client.service`의 cgroup v2 `cpu.stat`을 10초간 측정
- `boinccmd`는 BOINC data directory를 작업 디렉터리로 사용, `gui_rpc_auth.cfg`를 읽으므로 BOINC RPC 암호도 명령행에 노출하지 않음
- CPU 비율은 호스트의 2 vCPU 전체를 100%로 정규화하며 한 코어를 완전히 쓰면 약 50%
- 서비스가 active가 아니거나 `boinccmd --get_tasks`에 `EXECUTING` task가 없거나 CPU가 30% 미만이면 실패 판정
- 2회 연속 실패에서 Telegram 장애 알림을 보내고 지속 시 12시간마다 다시 알림. 정상 점검 한 번이면 실패 횟수를 초기화하고 이미 장애가 통보됐다면 복구 알림을 보냄
- 매주 월요일 9시 이후 첫 실행에서 지난주 점검·실패·장애 횟수와 현재 상태를 보냄
- 일감 고갈로 판정되면 `boinccmd --acct_mgr sync`로 자동복구를 1회 시도함 (아래 참고)
- 각 측정 상세는 journal에 남고 누적 DB는 만들지 않고 파일 DB 사용

## 자동복구

BOINC는 살아있는데 할 일이 없는 상태는 account manager가 일감 있는 프로젝트를
다시 배정하면 풀림. 그 신호를 감지하면 `boinccmd --acct_mgr sync`를 실행함.

이 호출은 조회가 아니라 **파괴적**임. account manager가 `<detach/>`로 답할 수
있고 BOINC `client/acct_mgr.cpp`는 유예 없이 `detach_project()`를 호출해서 해당
프로젝트가 진행 중이던 작업까지 버림. 그래서 세 겹으로 막아둠.

- **사유 게이팅** — `service_active`이고 probe error가 없고 `EXECUTING`이 0일
  때만 실행. 서비스가 죽었거나(재시작이 필요) 측정 자체가 실패했으면(신뢰 불가)
  건드리지 않음
- **전역 쿨다운** — 기본 6시간. detach 직후의 빈 구간이 다음 점검의 실패로
  이어져 다시 detach를 부르는 되먹임을 끊는 유일한 장치. 정상 점검이 껴들어도
  초기화되지 않으므로 상태가 요동쳐도 15분마다 sync하지 못함
- **장애당 시도 상한** — 기본 2회. 다 쓰면 자동복구를 포기하고 알림만 보냄

시도 전에 쿨다운을 먼저 state에 기록하고 저장한 뒤 명령을 실행함. 실행 도중
프로세스가 죽어도 시도 1회를 소모한 것으로 남아서 재시도 루프가 되지 않음.

성공·실패 모두 Telegram으로 알림. 기본값에서는 첫 실패에 자동복구가 돌고
장애 알림은 두 번째 실패에 나가므로, 자동으로 풀린 경우엔 장애 알림 없이
복구 알림만 받게 됨.

끄려면 `/etc/sentinel/sentinel.conf`에 `RECOVER_ENABLED=0`.

## 설치

Ubuntu 24.04의 root 셸에서 저장소 기준

저장소에는 실제 설정 대신 `config/sentinel.conf.example`과
`config/telegram-token.example`만 포함함. 실제 `sentinel.conf`,
`telegram-token`, `.env` 파일은 Git에서 제외됨.

```sh
sudo ./install.sh
```

인스톨러는 기존 상태와 로컬 설정을 덮어쓰지 않음.  
BOINC를 재시작하지 않고 `systemctl daemon-reload`만 수행한 뒤 timer를 활성화.

기존 Telegram bot의 chat ID를 root 전용 설정에 기록해야 함.

```sh
sudoedit /etc/sentinel/sentinel.conf
# TELEGRAM_CHAT_ID=1111111111111
```

bot token은 별도 root 전용 파일에 한 줄로 넣어야 함.  
이 파일은 systemd `LoadCredential`로 서비스에 전달되며 상태, 저장소, 프로세스 명령행에 들어가지 않음.

```sh
sudoedit /etc/sentinel/telegram-token
sudo chmod 0600 /etc/sentinel/sentinel.conf /etc/sentinel/telegram-token
sudo chown root:root /etc/sentinel/sentinel.conf /etc/sentinel/telegram-token
sudo systemctl start sentinel.service
```

결과 확인 명령어는 아래와 같음.

```sh
systemctl status sentinel.timer sentinel.service
journalctl -u sentinel.service -n 50 --no-pager
sudo /usr/local/sbin/sentinel show-state
```

## 상태와 복구

상태는 `/var/lib/sentinel/state.json` 하나이며 systemd `StateDirectory`가 만든 `0700 root:root` 디렉터리에 `0600 root:root`로 저장.  
같은 디렉터리의 임시 파일을 `fsync`하고 `os.replace()`로 교체.

- 부팅 ID 변경: 연속 실패 횟수와 장애당 복구 시도 횟수를 0으로 초기화. 쿨다운은 재부팅으로 풀리지 않음
- 주 변경: 지난 카운터를 고정 크기 pending summary로 옮김
- 손상된 JSON: `state.json.corrupt-<UTC>`로 보존, 초기화 알림을 재시도
- schema 0, 1: 현재 schema로 마이그레이션 (기존 카운터와 장애 이력은 보존)
- 더 새로운 schema: 파일을 수정하지 않고 서비스가 오류로 종료

수동 초기화도 파일을 삭제하지 않고 timestamp 백업을 만듦.

```sh
sudo systemctl stop sentinel.timer sentinel.service
sudo /usr/local/sbin/sentinel reset-state --yes
sudo systemctl start sentinel.timer
```

## 개발 검증

외부 패키지 X

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile src/sentinel.py
```
