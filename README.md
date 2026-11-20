# Sentinel

이게 뭐임?  
서버를 지켜보다 문제가 생기면 텔레그램으로 경고하는 감시자.  
서버마다 하나를 고르거나 `boinc,process`처럼 여러 개를 함께 설치함.

1. `boinc`: BOINC 서비스와 CPU 사용량 감시 (기존 동작)
2. `process`: 등록한 systemd 서비스나 프로세스의 생존과 재시작 감시
3. `docker`: 등록한 Docker 컨테이너의 생존, healthcheck, 재시작 감시
4. `resource`: 서버 CPU, 메모리, 디스크, 송신 트래픽이 기준을 넘는지 감시

`/etc/sentinel/sentinel.conf`의 `SENTINEL_MONITOR`로 정함. 값이 없으면 `boinc`.  
쉼표로 묶으면 한 번의 실행에서 모두 점검함 (예: `SENTINEL_MONITOR=boinc,process,resource`로 BOINC, tailscaled, 서버 자원을 같이 감시).
대상마다 장애·자동복구·쿨다운이 따로 관리되고, 자동복구는 그 대상을 맡은 옵션의 방식으로 실행됨.
`process`와 `docker`를 함께 쓰면 targets 파일 하나에 두 종류를 같이 적음.
셸에서 `sudo /usr/local/sbin/sentinel ...`로 직접 실행해도 이 파일을 읽으므로 timer와 같은 옵션으로 동작함.
환경변수가 있으면 환경변수가 이김 (systemd `EnvironmentFile`과 같은 규칙).

공통:
- 부팅 ID가 바뀌면 `🔄 재부팅 감지` 알림을 한 번 보냄
- timer 실행과 수동 실행이 겹치지 않게 `state.json.lock`으로 잠금. 60초 안에 못 잡으면 exit 4

## 1옵션 `boinc` 동작

- `sentinel.timer`가 15분마다 one-shot 서비스를 실행
- 각 실행은 `boinc-client.service`의 cgroup v2 `cpu.stat`을 10초간 측정
- `boinccmd`는 BOINC data directory를 작업 디렉터리로 사용, `gui_rpc_auth.cfg`를 읽으므로 BOINC RPC 암호도 명령행에 노출하지 않음
- CPU 비율은 호스트의 2 vCPU 전체를 100%로 정규화하며 한 코어를 완전히 쓰면 약 50%
- 서비스가 active가 아니거나 `boinccmd --get_tasks`에 `EXECUTING` task가 없거나 CPU가 30% 미만이면 실패 판정
- 2회 연속 실패에서 Telegram 장애 알림을 보내고 지속 시 12시간마다 다시 알림. 정상 점검 한 번이면 실패 횟수를 초기화하고 이미 장애가 통보됐다면 복구 알림을 보냄
- 매주 월요일 9시 이후 첫 실행에서 지난주 점검·실패·장애 횟수와 현재 상태를 보냄
- 일감 고갈로 판정되면 `boinccmd --acct_mgr sync`로 자동복구를 1회 시도함 (아래 참고)
- 각 측정 상세는 journal에 남고 누적 DB는 만들지 않고 파일 DB 사용

### 1옵션 자동복구

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

## 2옵션 `process` 동작

- `sentinel.timer`가 5분마다 실행 (`sentinel.timer.d/interval.conf`)
- 대상은 `/etc/sentinel/targets`에 한 줄에 하나씩 등록

```text
service tailscaled.service
process caddy
cmdline ^/usr/bin/python3 /opt/bot/main\.py
```

- `service <unit>`: `ActiveState`가 `active`가 아니면 실패. 확장자 없으면 `.service`를 붙임
- `process <name>`: `/proc/<pid>/comm` 또는 argv[0] basename이 정확히 같은 프로세스가 없으면 실패
- `cmdline <regex>`: 전체 명령행에 정규식이 걸리는 프로세스가 없으면 실패. `python3`, `node`처럼 이름만으로 구분 안 되는 스크립트용
- 대상마다 장애 확정, 재알림, 복구가 따로 돌아감. 2회 연속 실패면 약 10분 안에 알림
- 재시작 감지: 서비스는 `NRestarts` 증가. 프로세스는 직전 점검에서 본 프로세스가 전부 교체됐을 때(지금 가장 오래된 것이 직전의 가장 새 것보다 늦게 시작)만 재시작으로 봄. 워커 일부만 바뀌면 알리지 않음. 관리자의 수동 재시작은 서비스는 알리지 않고 프로세스는 구분 못 해서 알림
- 크래시 루프는 첫 재시작만 바로 알리고 이후 `REMINDER_HOURS` 동안 횟수를 모아 한 번에 보냄
- 주간 요약의 `대상 실패`는 대상별 실패 횟수 합. 여기에 재시작 횟수와 현재 장애 대상이 추가됨
- targets 파일을 고치면 `sudo /usr/local/sbin/sentinel check-config`로 검증. 상태 파일은 건드리지 않고 대상별 현재 상태만 출력함

### 2옵션 자동복구

`ActiveState=failed`인 **service 대상만** `systemctl reset-failed` 후 `systemctl restart`함.
`inactive`는 관리자가 멈춘 것으로 보고, `activating`은 systemd가 이미 처리 중이라 건드리지 않음.
process/cmdline 대상은 재시작 방법이 없어서 알림만 보냄.

BOINC와 같은 `RECOVER_*` 설정을 쓰고 쿨다운과 장애당 시도 상한은 대상마다 따로 셈.
시도 전에 쿨다운을 먼저 저장하는 것도 같음.

systemd는 호출자의 capability를 볼 수 있으면 root라도 `CAP_SYS_ADMIN`이 있어야 restart를
허가함(`sd_bus_query_sender_privilege`). 기본 유닛은 capability를 전부 버리므로 설치기가
`sentinel.service.d/restart.conf`로 `CAP_SYS_ADMIN` 하나만 돌려줌.
`RECOVER_ENABLED=0`으로 두고 설치기를 다시 돌리면 이 drop-in을 지우고 알림만 하는 모드가 됨.

## 3옵션 `docker` 동작

- 5분 주기, 대상별 사건, 크래시 루프 알림 합산, 주간 요약은 2옵션과 같음
- `/etc/sentinel/targets`에 `container <이름 또는 ID>`를 한 줄에 하나씩 등록
- docker CLI 없이 `/var/run/docker.sock`의 Engine API(`GET /containers/<name>/json`)를 직접 부름. 소켓이 root 소유라서 추가 권한 필요 없음
- `Status`가 `running`이 아니거나 healthcheck가 `unhealthy`면 실패. 컨테이너가 없으면 `container not found`
- 재시작 감지는 `RestartCount` 증가 (restart policy에 의한 재시작만 셈)

### 3옵션 자동복구

같은 `RECOVER_*` 설정과 방어 장치를 대상별로 씀.

- 크래시(`exited`이고 종료 코드가 0, 137, 143이 아니거나 OOM으로 죽음): `POST /containers/<name>/start`
- `unhealthy`: `POST /containers/<name>/restart`. Docker는 unhealthy 컨테이너를 스스로 재시작하지 않음
- `docker stop`으로 멈춘 컨테이너(0, 143, grace 초과 137)와 `restarting`, `paused`는 건드리지 않음

## 4옵션 `resource` 동작

- 대상은 targets 파일이 아니라 `sentinel.conf`의 기준값으로 정해짐. 기준이 `0`이면 그 대상은 없음
- 측정값이 기준을 **넘으면** 실패. 2회 연속이면 장애 알림, 지속되면 12시간마다 재알림, 내려가면 복구 알림. 대상마다 따로 돌아감
- 자동복구는 없고 알림만 함
- 기준을 고치면 `sudo /usr/local/sbin/sentinel check-config`로 지금 값과 적용된 기준(`limit=`)을 바로 확인

| 대상 | 설정 (기본값) | 측정 |
| --- | --- | --- |
| `resource:cpu` | `RESOURCE_CPU_MAX=90` | 전체 vCPU 대비 %, 직전 실행 이후 평균. nice 프로세스 제외 |
| `resource:memory` | `RESOURCE_MEMORY_MAX=90` | 사용 %, `MemAvailable` 기준 |
| `resource:disk:<경로>` | `RESOURCE_DISK_MAX=90`, `RESOURCE_DISK_PATHS=/` | `df`의 Use%와 같은 계산. 경로는 쉼표로 여러 개 |
| `resource:tx-rate` | `RESOURCE_NET_TX_MBPS=30` | 송신 Mbps, 직전 실행 이후 평균 |
| `resource:tx-month` | `RESOURCE_NET_MONTH_TX_GB=8000` | 이번 달(UTC) 누적 송신 GB |

- 평균 구간은 timer 주기와 같음. `boinc`와 같이 쓰면 15분, 아니면 5분. 그보다 짧은 스파이크는 평균에 묻힘
- CPU: `/proc/stat`의 user, system, irq, softirq만 사용량으로 셈. BOINC task는 nice 19로 돌면서 남는 CPU를 일부러 다 쓰므로 nice를 넣으면 늘 100%가 됨. idle, iowait, steal도 뺌
- 송신: `/proc/net/dev`의 인터페이스 하나만 셈. `RESOURCE_NET_INTERFACE`가 비어 있으면 IPv4 기본 경로의 인터페이스. Tailscale 트래픽도 결국 그 인터페이스로 나가므로 `tailscale0`을 따로 더하지 않음
- 직전 실행의 커널 카운터를 state에 두고 차이로 평균을 냄. 첫 실행, 재부팅 직후, 직전 실행이 1시간 넘게 지났을 때는 그 실행 안에서 5초간 재서 대신함
- 이번 달 누적은 설치한 뒤부터 Sentinel이 센 값임. 재부팅하면 부팅 뒤 보낸 양을 그대로 더하므로 빠지는 건 재부팅 직전 한 주기뿐
- 주간 요약 끝에 `이번 달 송신=12.3GB/기준 8000GB`가 붙음
- `/home`, `/root`, `/run/user` 아래 경로는 `RESOURCE_DISK_PATHS`에 못 넣음. 유닛의 `ProtectHome=yes`가 그 자리를 빈 tmpfs로 가려서 엉뚱한 값이 나옴

### 4옵션 기본값과 Oracle 무료분량

기본값은 Oracle Cloud Always Free 기준에 맞춰둠. 다른 서버라면 숫자만 바꾸면 됨.

- 송신은 월 10TB까지 무료. `RESOURCE_NET_MONTH_TX_GB=8000`은 그 80%
- `RESOURCE_NET_TX_MBPS=30`은 한 달 내내 유지하면 약 10TB가 되는 속도. 이 속도가 이어지면 그 달 한도를 넘김
- 누적은 이 서버 것만 셈. 무료분량은 계정에 주어지는 것이라 인스턴스가 여럿이면 기준을 그만큼 낮출 것
- 유휴 회수(7일간 CPU 95퍼센타일, 네트워크, 메모리가 모두 20% 미만)는 "미만" 쪽 위험이라 여기서 안 봄. CPU를 30% 위로 유지하는지는 1옵션이 감시함

## 설치

Ubuntu 24.04의 root 셸에서 저장소 기준

저장소에는 실제 설정 대신 `config/sentinel.conf.example`과
`config/telegram-token.example`만 포함함. 실제 `sentinel.conf`,
`telegram-token`, `.env` 파일은 Git에서 제외됨.

```sh
sudo ./install.sh                     # 새 설치면 선택 메뉴 (4번이 BOINC+서비스/프로세스)
sudo ./install.sh --monitor boinc
sudo ./install.sh --monitor process
sudo ./install.sh --monitor docker
sudo ./install.sh --monitor resource
sudo ./install.sh --monitor boinc,process,resource   # 조합
```

인스톨러는 기존 상태와 로컬 설정을 덮어쓰지 않음.  
BOINC를 재시작하지 않고 `systemctl daemon-reload`만 수행한 뒤 timer를 활성화.

- 옵션은 `--monitor`, 기존 `sentinel.conf`의 `SENTINEL_MONITOR` 순으로 정함. 기존 conf에 값이 없으면 업그레이드로 보고 `boinc`
- 기존 conf와 다른 옵션을 주면 중단함. 바꾸려면 conf의 `SENTINEL_MONITOR`를 먼저 고칠 것
- `boinc`: `boinc` 그룹이 없으면 중단. BOINC 전용 설정(`SupplementaryGroups=boinc` 등)은 `sentinel.service.d/boinc.conf` drop-in으로만 설치되므로 BOINC 없는 서버에서도 기본 유닛이 뜸
- 조합에 `boinc`가 있으면 timer는 15분 그대로 둠. 5분 주기는 task 사이의 짧은 공백을 일감 고갈로 잡아 파괴적인 sync를 부를 가능성을 높이기 때문
- `process`, `docker`: targets 파일이 없으면 대상을 입력받아 만들고 `check-config`가 실패하면 timer를 켜지 않고 중단
- `resource`: 추가 권한이나 drop-in 없음. `boinc`가 없으면 5분 timer. 이미 설치된 서버에 더하려면 설치기로 새 버전을 먼저 올린 뒤 conf의 `SENTINEL_MONITOR`에 `resource`를 더하고 `check-config`로 확인. 순서를 바꾸면 그 사이 timer가 옛 버전으로 돌아 모르는 옵션이라며 한 번 실패함

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

- 부팅 ID 변경: 대상마다 연속 실패 횟수, 장애당 복구 시도 횟수, 재시작 기준값을 초기화. 쿨다운은 재부팅으로 풀리지 않음. 4옵션의 CPU·송신 카운터도 새로 시작하고 이번 달 누적은 유지
- 주 변경: 지난 카운터를 고정 크기 pending summary로 옮김
- 손상된 JSON: `state.json.corrupt-<UTC>`로 보존, 초기화 알림을 재시도
- schema 0, 1, 2: BOINC 장애 이력과 자동복구 기록을 `targets.boinc`로 옮기고 카운터는 보존한 채 schema 4로 마이그레이션
- schema 3: 4옵션의 카운터 자리(`resource`)만 더해 schema 4로 마이그레이션. 대상과 이력은 그대로
- targets 파일에서 빠진 대상: 상태에서 지우고 journal에 남김
- 더 새로운 schema: 파일을 수정하지 않고 서비스가 오류로 종료. schema 4를 쓴 뒤에는 이전 버전으로 되돌릴 수 없으므로 올리기 전에 `state.json`을 백업해 둘 것

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
