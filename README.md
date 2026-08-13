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
- 각 측정 상세는 journal에 남고 누적 DB는 만들지 않고 파일 DB 사용

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

- 부팅 ID 변경: 연속 실패 횟수 0으로 초기화
- 주 변경: 지난 카운터를 고정 크기 pending summary로 옮김
- 손상된 JSON: `state.json.corrupt-<UTC>`로 보존, 초기화 알림을 재시도
- schema 0: schema 1로 마이그레이션
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
