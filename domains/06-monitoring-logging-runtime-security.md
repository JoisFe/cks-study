# Domain 6. Monitoring, Logging and Runtime Security (20%)

런타임에서 벌어지는 일을 탐지(Falco)·기록(Audit Log)·조사(crictl, /proc)하고, 애초에 변조가 불가능한 컨테이너(immutability)를 만드는 도메인이다.

> **📌 시험 비중: 20% — Supply Chain Security와 함께 공동 1위 가중치.**
> 16문제 기준 3~4문제가 이 도메인에서 나오며, **Falco 룰 수정/작성과 Audit Policy 구성은 사실상 고정 출제**다. 두 유형만 완벽히 잡아도 합격선(67%)에 크게 다가선다. 시험 중 [falco.org/docs](https://falco.org/docs)와 [kubernetes.io/docs의 Auditing 페이지](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)를 열람할 수 있으니 문법은 복사해서 쓰되, **어디에 무엇이 있는지**는 몸에 익혀 가야 한다.

## 목차

1. [Falco 완전 정복](#1-falco-완전-정복)
   - [1.1 아키텍처와 설치 형태](#11-아키텍처와-설치-형태)
   - [1.2 설정 파일 구조](#12-설정-파일-구조)
   - [1.3 룰 문법: rule / macro / list](#13-룰-문법-rule--macro--list)
   - [1.4 최다 빈출: 기존 룰 출력 포맷 오버라이드](#14-최다-빈출-기존-룰-출력-포맷-오버라이드)
   - [1.5 실행·수집·제출](#15-실행수집제출)
2. [공격 단계 조사 (Incident Investigation)](#2-공격-단계-조사-incident-investigation)
3. [컨테이너 불변성 보장 (Immutability)](#3-컨테이너-불변성-보장-immutability)
4. [Kubernetes Audit Logs](#4-kubernetes-audit-logs)
   - [4.1 아키텍처](#41-아키텍처)
   - [4.2 Audit Policy 문법](#42-audit-policy-문법)
   - [4.3 apiserver 플래그와 volume mount 함정](#43-apiserver-플래그와-volume-mount-함정)
   - [4.4 로그 분석 jq 레시피](#44-로그-분석-jq-레시피)
5. [실전 연습문제 12제](#5-실전-연습문제-12제)
6. [🎯 시험 직전 체크리스트](#6--시험-직전-체크리스트)
7. [핵심 명령어 치트시트](#7-핵심-명령어-치트시트)

---

## 1. Falco 완전 정복

### 1.1 아키텍처와 설치 형태

> **📖 오픈북 — 문서에서 찾기** — `falco.org/docs`에서 **`install host`** 검색 → **"Install on a host (DEB, RPM)"** → 시험 표준인 systemd 서비스 설치 형태·유닛명 확인.

Falco는 **커널 이벤트(syscall) 기반 런타임 위협 탐지 도구**다. 커널 모듈 또는 eBPF(extended Berkeley Packet Filter — 커널 안에서 안전하게 프로그램을 실행시키는 기술) probe가 노드에서 발생하는 모든 syscall 스트림을 가로채고, 유저스페이스의 Falco 데몬이 이를 **룰(rule)의 condition과 대조**해 매칭되면 output 포맷대로 알림을 낸다. 컨테이너 런타임(containerd)과 Kubernetes 메타데이터를 결합해 "어느 네임스페이스의 어느 pod에서" 일어났는지까지 붙여준다.

시험에서 중요한 사실:

- **시험 표준 설치 형태는 노드의 호스트에 systemd 서비스로 설치된 Falco**다. Helm/DaemonSet이 아니라 `ssh 노드명`으로 들어가 작업한다.
- 애플리케이션이 아니라 **노드 단위**로 동작한다. 문제에 명시된 노드로 ssh 하는 것이 항상 첫 단계다.

```bash
# 문제에 지정된 노드로 진입
ssh cluster3-node1

# Falco 서비스 상태 확인 (환경에 따라 유닛명이 falco 또는 falco-modern-bpf)
systemctl list-units --type=service | grep -i falco
systemctl status falco

# 버전 확인
falco --version
```

> **💡 시험 팁**: Falco 문제는 "ssh → 룰 파일 수정 → 재시작/실행 → 로그 확인 → 파일 제출" 흐름이 전부다. 이 5단계를 손이 기억하게 만들어라.

### 1.2 설정 파일 구조

> **📖 오픈북 — 문서에서 찾기** — `falco.org/docs`에서 **`configuration options`** 검색 → **"Falco Configuration Options"** → `rules_files`·`json_output`·`*_output` 채널 키 확인.

설정 디렉토리는 `/etc/falco/`다. 시험장에서 가장 먼저 `ls /etc/falco/`를 실행하라.

| 파일 | 역할 | 시험에서의 취급 |
|---|---|---|
| `/etc/falco/falco.yaml` | 데몬 전역 설정: 로드할 룰 파일 목록, 출력 채널(stdout/file/syslog), `json_output` 등 | 출력 형식·채널 변경 시에만 손댐 |
| `/etc/falco/falco_rules.yaml` | 기본 제공 룰 세트 | **직접 수정 금지** (업그레이드 시 덮어써짐) |
| `/etc/falco/falco_rules.local.yaml` | 커스텀 룰과 오버라이드 | **모든 신규/수정 룰은 여기에** |
| `/etc/falco/rules.d/` | 추가 룰 디렉토리 | 존재하면 함께 로드됨 |

룰 파일은 `falco.yaml`에 나열된 **순서대로 로드**되며, **같은 이름의 rule을 나중에 로드되는 파일에서 다시 정의하면 앞의 정의를 완전히 대체**한다. 이것이 오버라이드의 원리다.

```yaml
# /etc/falco/falco.yaml 발췌 (버전에 따라 키 이름이 rules_file 또는 rules_files)
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/rules.d

json_output: false        # true로 바꾸면 이벤트가 JSON 한 줄로 출력됨

stdout_output:
  enabled: true

file_output:
  enabled: false
  filename: /var/log/falco/events.txt

syslog_output:
  enabled: true            # journalctl -u falco / /var/log/syslog 로 보이는 이유
```

> **📌 암기 포인트**: "기본 룰은 `falco_rules.yaml`, 내 룰은 `falco_rules.local.yaml`, 같은 이름이면 나중 것이 이긴다."

### 1.3 룰 문법: rule / macro / list

> **📖 오픈북 — 문서에서 찾기** — `falco.org/docs`에서 **`rules basic elements`** 검색 → **"Basic Elements of Falco Rules"** → rule/macro/list 필수 키와 예제 복사.

룰 파일은 YAML 리스트이며 세 가지 요소로 구성된다.

| 요소 | 필수 키 | 설명 |
|---|---|---|
| `rule` | `rule`, `desc`, `condition`, `output`, `priority` | 탐지 단위. `enabled: false`로 끌 수 있음 |
| `macro` | `macro`, `condition` | condition 조각의 재사용 (함수처럼) |
| `list` | `list`, `items` | 값 목록의 재사용 (`in (list이름)`으로 참조) |

`priority`는 높은 순으로 `EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL, DEBUG`.

> **🛠 만드는 법** — Falco 룰은 kubectl 리소스가 아니라 노드의 설정 파일이다. 생성 명령(dry-run)이 없으니 [falco.org/docs](https://falco.org/docs)의 rule/macro/list 예제를 복사해 `condition`·`output`만 요구사항대로 채운다.

```yaml
# /etc/falco/falco_rules.local.yaml 예시 — list + macro + rule 풀 세트
- list: my_shell_binaries
  items: [bash, sh, zsh, ash, ksh]

- macro: my_spawned_process
  condition: evt.type in (execve, execveat) and evt.dir = <

- rule: Shell Spawned in Container
  desc: A shell process was launched inside a container
  condition: >
    my_spawned_process and container and proc.name in (my_shell_binaries)
  output: >
    Shell in container (time=%evt.time pod=%k8s.pod.name ns=%k8s.ns.name
    user=%user.name command=%proc.cmdline)
  priority: WARNING
```

condition에서 자주 쓰는 연산자: `=`, `!=`, `in (...)`, `contains`, `startswith`, `and`, `or`, `not`. 기본 룰 세트가 이미 `container`(컨테이너 안에서 발생), `spawned_process`, `open_read`, `open_write` 같은 macro를 제공하므로 **직접 만들기 전에 grep으로 있는지 먼저 확인**하라.

**주요 출력 필드 표** — output 문자열에 `%필드명`으로 삽입한다.

| 필드 | 의미 |
|---|---|
| `%evt.time` | 이벤트 시각 (나노초 포함) |
| `%container.id` | 컨테이너 ID (12자리 축약) |
| `%container.name` | 컨테이너 이름 |
| `%container.image.repository` | 이미지 저장소 이름 (태그 제외) |
| `%proc.name` | 프로세스 이름 |
| `%proc.cmdline` | 전체 커맨드라인 |
| `%user.name` | 사용자 이름 |
| `%user.uid` | 사용자 UID |
| `%k8s.pod.name` | Pod 이름 |
| `%k8s.ns.name` | 네임스페이스 이름 |

> **⚠️ 함정**: 출력 필드를 문제가 요구한 **순서와 구분자 그대로** 써야 한다. "time,container-id,user-name을 콤마로"라고 했으면 `%evt.time,%container.id,%user.name` — 공백 하나도 채점에 영향을 줄 수 있다.

#### 📝 문제로 이해하기

```bash
kubectl config use-context cluster3-admin
ssh cluster3-node1
```

**Task (mini):** Create a new Falco rule in `/etc/falco/falco_rules.local.yaml`:

- Rule name: `Netcat Launched in Container`
- Trigger: the program `nc` or `ncat` is started inside a container
- Output must contain: time, namespace, pod name, full command line
- Priority: `WARNING`

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 기본 macro `spawned_process`(execve 완료)와 `container`를 재사용하고, 바이너리 목록은 list로 뺀다.

**2) 단계별**:

```yaml
# /etc/falco/falco_rules.local.yaml 에 추가
- list: netcat_binaries
  items: [nc, ncat]

- rule: Netcat Launched in Container
  desc: netcat was executed inside a container
  condition: spawned_process and container and proc.name in (netcat_binaries)
  output: >
    Netcat run in container (time=%evt.time ns=%k8s.ns.name
    pod=%k8s.pod.name cmd=%proc.cmdline)
  priority: WARNING
```

**3) 검증**:

```bash
# 기본 macro(spawned_process 등)를 참조하므로 기본 룰 파일을 먼저 -V로 함께 지정
falco -V /etc/falco/falco_rules.yaml -V /etc/falco/falco_rules.local.yaml
systemctl restart falco
# 아무 pod에서 nc 실행 후:
journalctl -u falco --since "2 min ago" | grep -i netcat
```

**⚠️ 함정 포인트**

- `priority: WARNING`처럼 값은 대문자 관례. 소문자도 동작하지만 문서 예시를 따르는 게 안전.
- `falco_rules.yaml`(기본 룰 파일)에 추가하면 안 된다 — 문제는 거의 항상 `local.yaml`을 지정한다.

</details>

### 1.4 최다 빈출: 기존 룰 출력 포맷 오버라이드

> **📖 오픈북 — 문서에서 찾기** — `falco.org/docs`에서 **`overriding rules`** 검색 → **"Overriding Rules"** → 같은 rule 이름 재정의로 기존 룰을 override하는 방식 확인.

**CKS에서 가장 많이 보고되는 Falco 유형**: "특정 행위(예: 컨테이너 안 쉘 실행)를 탐지하는 기존 룰을 찾아, 출력 형식을 지정된 필드로 바꿔라." 순서화된 워크플로우로 익혀라.

```bash
# ① 키워드로 기존 룰 찾기 — 룰 이름이나 관련 단어로 grep
grep -r "Terminal shell" /etc/falco/
grep -ri "package management" /etc/falco/

# ② 해당 rule 블록 전체를 확인 (condition이 macro를 참조하면 macro도 grep)
grep -rA 10 "rule: Terminal shell in container" /etc/falco/
```

```yaml
# ③ rule 블록 전체를 /etc/falco/falco_rules.local.yaml 로 복사한 뒤
#    "같은 rule 이름"을 유지한 채 output만 수정 → 기본 룰을 대체(override)
- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
  output: "%evt.time,%container.id,%container.name,%user.name"
  priority: NOTICE
```

```bash
# ④ 검증 후 반영 — local 룰이 기본 macro를 참조하므로 기본 룰 파일도 함께 -V
falco -V /etc/falco/falco_rules.yaml -V /etc/falco/falco_rules.local.yaml
systemctl restart falco

# ⑤ 트리거 & 확인
kubectl exec -it 아무pod -- sh   # (다른 터미널에서)
journalctl -u falco -f
```

> **⚠️ 함정**: condition은 **한 글자도 바꾸지 말고 그대로 복사**하라. condition이 참조하는 macro(`shell_procs`, `container_entrypoint` 등)는 기본 룰 파일에 이미 로드되어 있으므로 복사할 필요 없다. rule 이름을 오타 내면 override가 아니라 **새 룰 추가**가 되어 이벤트가 두 번 찍힌다.

> **💡 시험 팁**: 과거 문법인 `append: true`는 deprecated. 시험에서는 "동일 rule 이름으로 전체 재정의" 한 가지 방법만 기억하면 충분하다.

#### 📝 문제로 이해하기

```bash
kubectl config use-context cluster3-admin
ssh cluster3-node1
```

**Task (mini):** Falco ships a default rule that detects when a package management process (`apt`, `yum`, ...) is launched in a container. Without editing the default rules file, change this rule's priority to `CRITICAL` and keep everything else identical.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 룰을 grep으로 찾고, 블록 전체를 `local.yaml`에 복사해 `priority`만 수정.

**2) 단계별**:

```bash
grep -rB 2 -A 12 "Launch Package Management Process in Container" /etc/falco/falco_rules.yaml
```

찾은 블록 전체(rule/desc/condition/output/priority)를 `/etc/falco/falco_rules.local.yaml`에 붙여넣고 마지막 줄만 변경:

```yaml
  priority: CRITICAL
```

**3) 검증**:

```bash
falco -V /etc/falco/falco_rules.yaml -V /etc/falco/falco_rules.local.yaml && systemctl restart falco
kubectl exec 아무pod -- apk add curl   # 또는 apt-get update
journalctl -u falco --since "1 min ago" | grep -i critical
```

**⚠️ 함정 포인트**

- rule 이름 문자열이 정확히 일치해야 override 성립.
- condition 안의 멀티라인 `>` 블록 들여쓰기가 깨지면 `falco -V`에서 잡힌다 — 반드시 검증 후 재시작.

</details>

### 1.5 실행·수집·제출

> **📖 오픈북 — 문서에서 찾기** — `falco.org/docs`에서 **`daemon arguments`** 검색 → **"Falco Daemon Arguments"** → `-M`(수집 시간)·`-o`(일회성 오버라이드) 등 CLI 플래그 확인.

Falco 이벤트를 "일정 시간 수집해서 파일로 제출"하는 유형. 두 가지 실행 모드를 구분하라.

```bash
# A. systemd 서비스로 이미 돌고 있는 경우 — 저널에서 시간 범위로 추출
journalctl -u falco --since "10 min ago" --no-pager
journalctl -u falco --since "2026-07-21 09:00:00" --until "2026-07-21 09:05:00" --no-pager
# syslog_output이 켜져 있으면 /var/log/syslog 에서도 grep 가능
grep falco /var/log/syslog

# B. 포그라운드로 정해진 시간만 실행 (-M 초 = 그 시간 후 자동 종료)
falco -M 30                       # 30초 수집 후 종료
timeout 30s falco                 # 동일 효과
falco -M 45 > /opt/course/2/falco.log   # 파일로 저장하며 45초 수집
```

수집한 원본에서 요구 필드만 추출해 제출 파일을 만드는 것까지가 한 문제다.

```bash
# 예: 이벤트 라인에서 컨테이너 ID(공백 구분 몇 번째 필드)만 뽑기
grep "Package management" /opt/course/2/falco.log | awk '{print $9}' > /opt/course/2/ids.txt

# json_output: true 로 켰다면 jq가 훨씬 안전
falco -M 30 -o json_output=true | jq -r '.output_fields."container.id"'
```

> **💡 시험 팁**: `-o 키=값`으로 falco.yaml을 편집하지 않고도 설정을 일회성 오버라이드할 수 있다(`falco -o json_output=true`). 파일 수정 → 원복을 잊는 실수를 원천 차단한다.

> **⚠️ 함정**: 포그라운드 `falco`와 systemd 서비스를 동시에 돌리면 드라이버 충돌로 실패할 수 있다. 포그라운드 실행 전 `systemctl stop falco`, 끝나면 `systemctl start falco` — **원상복구까지가 답안**이다.

#### 📝 문제로 이해하기

```bash
kubectl config use-context cluster3-admin
ssh cluster3-node1
```

**Task (mini):** Run Falco in the foreground for exactly 30 seconds and save its complete output to `/opt/course/m3/falco.out`. The Falco systemd service must be running again afterwards.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 서비스 정지 → `-M 30`으로 수집 → 서비스 재기동.

**2) 단계별**:

```bash
mkdir -p /opt/course/m3
systemctl stop falco
falco -M 30 > /opt/course/m3/falco.out
systemctl start falco
```

**3) 검증**:

```bash
wc -l /opt/course/m3/falco.out
systemctl is-active falco    # active 여야 함
```

**⚠️ 함정 포인트**

- 서비스 재기동 누락이 최다 감점 요인.
- 출력이 비어 있으면 30초 동안 트리거될 행위가 없었던 것 — 다른 터미널에서 `kubectl exec`로 쉘을 열어 이벤트를 만들어라.

</details>

---

## 2. 공격 단계 조사 (Incident Investigation)

공격 킬체인 관점에서 Kubernetes 침해는 대개 이 순서로 흔적을 남긴다: **침투(취약 이미지/노출된 대시보드) → 실행(컨테이너 안 쉘, 악성 바이너리) → 권한 상승(privileged, hostPath) → 지속화(새 워크로드/CronJob, ServiceAccount 토큰 탈취 — ServiceAccount는 파드가 API에 인증할 때 쓰는 쿠버네티스 신원) → 탐색·유출(metadata endpoint, 네트워크 스캔)**. 시험에서는 이 중 한 장면을 주고 "찾아서, 증거를 보존하고, 격리/제거하라"고 한다.

### 의심 워크로드 식별 (kubectl 레벨)

```bash
# 전체 조망: 낯선 네임스페이스, 낯선 이미지, 이상한 이름
kubectl get pods -A -o wide
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'

# 의심 pod 심층: command/args, securityContext(privileged?), SA, hostPath
kubectl get pod 의심pod -n ns -o yaml | less
kubectl get events -n ns --sort-by=.lastTimestamp
```

### 컨테이너 폭로 (노드에서 crictl)

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`crictl`** 검색 → **"Debugging Kubernetes nodes with crictl"** → `crictl ps`·`inspect`·`logs` 사용 예제 확인.

containerd 환경이므로 노드에서는 `crictl`이 표준 도구다.

```bash
ssh 해당노드
crictl ps                          # 실행 중 컨테이너
crictl ps -a                       # 종료된 것 포함
crictl pods --name 의심pod         # pod sandbox 확인
crictl ps --pod <POD_SANDBOX_ID>   # 그 pod의 컨테이너들

crictl inspect <CONTAINER_ID>                    # 전체 스펙
crictl inspect <CONTAINER_ID> | jq '.info.pid'   # 호스트에서 본 프로세스 PID
crictl logs <CONTAINER_ID> > /opt/course/8/logs.txt   # 증거 보존
```

### 프로세스 해부 (/proc/PID)

> **📖 오픈북** — `/proc/PID/{exe,cwd,environ,fd}`·`ps`·`readlink`는 허용 문서 8개에 없다 → 명령을 미리 암기.

crictl inspect로 얻은 PID로 호스트에서 프로세스의 실체를 확인한다.

```bash
ls -l /proc/<PID>/exe              # 실제 실행 바이너리 경로 (삭제됐어도 (deleted) 표기)
ls -l /proc/<PID>/cwd              # 작업 디렉토리
cat /proc/<PID>/environ | tr '\0' '\n'   # 환경변수 (탈취된 토큰/크리덴셜 단서)
ls -l /proc/<PID>/fd               # 열린 파일/소켓
cat /proc/<PID>/cmdline | tr '\0' ' '; echo
```

### 대응: 격리 → 보존 → 제거

> **📖 오픈북 — 문서에서 찾기** — 네트워크 격리용 deny-all은 `kubernetes.io/docs`에서 **`network policy`** 검색 → **"Network Policies"** → ingress+egress를 모두 막는 예제 YAML 복사(scale·label·crictl은 암기).

| 조치 | 명령 | 용도 |
|---|---|---|
| 스케일 0 | `kubectl scale deploy 이름 -n ns --replicas 0` | 관리형 워크로드 중지 |
| 라벨 제거 격리 | `kubectl label pod 이름 -n ns app-` | Service 트래픽에서 분리하되 pod은 조사용으로 유지 |
| 네트워크 격리 | deny-all `NetworkPolicy` 적용 | 유출/횡이동 차단 |
| 증거 보존 | `crictl logs`, `kubectl get pod -o yaml`, environ 덤프를 파일로 | **삭제 전에 반드시** |
| 제거 | `kubectl delete pod ...` | 문제 지시가 있을 때만 |

> **⚠️ 함정**: 문제가 "증거를 파일로 저장한 뒤 pod을 삭제하라"면 **순서가 채점 대상**이다. pod을 먼저 지우면 컨테이너 로그도 함께 사라져 복구할 수 없다.

#### 📝 문제로 이해하기

```bash
kubectl config use-context cluster2-admin
ssh cluster2-node1
```

**Task (mini):** A container on this node is running a process named `kdevtmpfsi`. Using `crictl` and `/proc`, find the host PID of that process and write the absolute path of its binary (the `exe` link target) to `/opt/course/m4/exe.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 호스트 ps로 PID 확보 → `/proc/PID/exe` 확인. (crictl로 컨테이너를 먼저 찾고 inspect의 `.info.pid`로 가도 동일.)

**2) 단계별**:

```bash
mkdir -p /opt/course/m4
ps aux | grep -i kdevtmpfsi        # PID 확인
ls -l /proc/<PID>/exe               # -> /usr/bin/kdevtmpfsi 형태
readlink -f /proc/<PID>/exe > /opt/course/m4/exe.txt
```

**3) 검증**: `cat /opt/course/m4/exe.txt` 내용이 절대경로 한 줄인지 확인.

**⚠️ 함정 포인트**

- `readlink -f`가 링크 대상을 그대로 뽑는 가장 안전한 방법.
- 컨테이너 안 경로가 아니라 **호스트에서 본 /proc 경로**임을 혼동하지 말 것.

</details>

---

## 3. 컨테이너 불변성 보장 (Immutability)

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`security context`** 검색 → **"Configure a Security Context for a Pod or Container"** → `readOnlyRootFilesystem`·`allowPrivilegeEscalation` 등 container 레벨 필드 복사.

불변 컨테이너는 **실행 중 파일시스템 변조가 불가능**하므로, 공격자가 쉘을 얻어도 악성 바이너리 다운로드·설치·지속화가 어렵다. 즉 immutability는 그 자체가 런타임 방어선이다. 핵심 패턴:

> **🛠 만드는 법** — Deployment는 생성기가 있다: `k create deploy immutable-app --image=nginx:1.27.1 $do > deploy.yaml` 로 뼈대를 뽑고 container 레벨 `securityContext`(readOnlyRootFilesystem 등)와 emptyDir volume을 채워 `k apply -f`. (`$do`=`--dry-run=client -o yaml`, 시험 세팅 변수)

```yaml
# 불변 컨테이너 표준 securityContext + 쓰기 경로만 emptyDir
apiVersion: apps/v1
kind: Deployment
metadata:
  name: immutable-app
  namespace: team-orange
spec:
  replicas: 1
  selector:
    matchLabels:
      app: immutable-app
  template:
    metadata:
      labels:
        app: immutable-app
    spec:
      containers:
        - name: app
          image: nginx:1.27.1
          securityContext:
            readOnlyRootFilesystem: true      # 핵심: 루트 FS 읽기 전용
            allowPrivilegeEscalation: false
            privileged: false
          volumeMounts:                        # 앱이 반드시 써야 하는 경로만 예외 처리
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /var/cache/nginx
            - name: run
              mountPath: /var/run
      volumes:
        - name: tmp
          emptyDir: {}
        - name: cache
          emptyDir: {}
        - name: run
          emptyDir: {}
```

**빈출 유형**: 기존 Deployment에 `readOnlyRootFilesystem: true`를 넣으면 컨테이너가 CrashLoopBackOff에 빠진다. 로그에서 "Read-only file system" 에러가 난 **경로를 찾아 그 경로만 emptyDir로 마운트**하는 것이 정답 흐름이다.

```bash
kubectl -n team-orange logs deploy/immutable-app
# nginx: [emerg] open() "/var/cache/nginx/..." failed (30: Read-only file system)
# -> /var/cache/nginx 를 emptyDir로 마운트
```

`hostPID: false`, `hostIPC: false`, `hostNetwork: false`(모두 기본값)도 함께 요구될 수 있다 — 명시돼 있으면 제거하거나 false로.

### 변형: probe로 쉘 제거/감시

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`liveness readiness startup probes`** 검색 → **"Configure Liveness, Readiness and Startup Probes"** → `startupProbe`/`livenessProbe`의 `exec` 예제 복사.

이미지를 다시 빌드할 수 없을 때 probe를 방어 수단으로 쓰는 변형이 있다.

```yaml
containers:
  - name: app
    image: some-legacy:1.0
    startupProbe:               # 기동 직후 쉘 바이너리 제거 (rootfs가 쓰기 가능할 때만 유효)
      exec:
        command: ["rm", "-f", "/bin/bash", "/bin/sh"]
      initialDelaySeconds: 1
      periodSeconds: 5
    livenessProbe:              # 쉘이 되살아나면 컨테이너 재시작
      exec:
        command: ["test", "!", "-e", "/bin/bash"]
      periodSeconds: 10
```

> **⚠️ 함정**: `startupProbe`로 쉘을 지우는 방식은 `readOnlyRootFilesystem: true`와 **양립 불가**(지울 수 없으니 probe 실패 → 재시작 루프). 문제가 어느 쪽을 요구하는지 정확히 읽어라.

> **💡 시험 팁**: 기존 리소스 수정은 `kubectl -n ns edit deploy 이름`보다 `kubectl get deploy 이름 -o yaml > f.yaml` 후 수정·`kubectl apply`가 실수 복구에 유리하다. 시험에서는 둘 다 허용된다.

#### 📝 문제로 이해하기

```bash
kubectl config use-context cluster1-admin
```

**Task (mini):** Pod `writer` in namespace `dev` crashes after you set `readOnlyRootFilesystem: true` because the app writes to `/data/tmp`. Fix the pod so the root filesystem stays read-only but the app still works.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 쓰기 경로 `/data/tmp`만 emptyDir 마운트로 예외 처리.

**2) 단계별**:

```yaml
    volumeMounts:
      - name: data-tmp
        mountPath: /data/tmp
  volumes:
    - name: data-tmp
      emptyDir: {}
```

pod은 spec 대부분이 불변이므로 `kubectl -n dev get pod writer -o yaml > w.yaml` → 수정 → `kubectl delete pod writer -n dev` → `kubectl apply -f w.yaml` (delete 후 재생성).

**3) 검증**:

```bash
kubectl -n dev get pod writer          # Running
kubectl -n dev exec writer -- touch /data/tmp/ok      # 성공
kubectl -n dev exec writer -- touch /etc/x            # Read-only 에러가 정상
```

**⚠️ 함정 포인트**

- standalone pod은 in-place 수정 불가 필드가 많다 — 삭제 후 재생성이 정석.
- emptyDir은 pod 재시작 시 초기화된다. 영속이 필요하면 문제에서 PVC를 지시할 것이므로 임의로 바꾸지 말 것.

</details>

---

## 4. Kubernetes Audit Logs

### 4.1 아키텍처

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`auditing`** 검색 → **"Auditing"**(Audit stages 섹션) → RequestReceived/ResponseComplete 등 stage 정의 확인.

Audit 로그는 **kube-apiserver가 기록**한다. API 서버를 지나는 모든 요청은 단계(stage)를 거치며, 각 단계에서 policy에 따라 이벤트가 남는다.

| Stage | 시점 |
|---|---|
| `RequestReceived` | 요청 수신 직후 (처리 전) |
| `ResponseStarted` | 응답 헤더 전송 시 (watch 같은 장기 요청에만) |
| `ResponseComplete` | 응답 완료 |
| `Panic` | 패닉 발생 시 |

같은 요청이 stage마다 중복 기록될 수 있으므로 보통 `omitStages: ["RequestReceived"]`로 잡음을 줄인다.

### 4.2 Audit Policy 문법

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`auditing`** 검색 → **"Auditing"**(Audit policy 섹션) → Policy YAML·level 4종 예제 복사.

> **🛠 만드는 법** — Audit Policy는 kubectl 리소스가 아니라 apiserver가 읽는 설정 파일이다. 생성기가 없으니 [kubernetes.io/docs의 Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) 예제 Policy를 복사해 `rules` 순서만 요구사항대로 채운다.

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - "RequestReceived"
rules:
  # 룰은 위에서부터 평가되어 "첫 번째로 매칭되는 룰"이 적용된다 — 순서가 전부다
  - level: Metadata
    resources:
      - group: ""                 # core API group
        resources: ["secrets"]
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods"]
    verbs: ["create", "update", "patch", "delete"]
    namespaces: ["prod"]
  - level: None                   # 나머지는 기록하지 않음 (최소화)
```

**Level 4종 — 각각 무엇을 남기는가**

| Level | 남기는 내용 |
|---|---|
| `None` | 아무것도 기록하지 않음 |
| `Metadata` | 요청 메타데이터만: 누가(user), 언제, 어떤 리소스에 어떤 verb. **본문 없음** |
| `Request` | Metadata + **요청 본문**. 응답 본문은 없음 |
| `RequestResponse` | Metadata + 요청 본문 + **응답 본문** (가장 상세, 가장 큼) |

> **📌 암기 포인트**: Secret은 본문에 민감정보가 있으므로 **Metadata가 관례**. "변경을 전부 추적하라"는 요구는 RequestResponse. "로그 최소화"는 마지막에 `level: None` 캐치올.

> **⚠️ 함정**: 첫 매칭 룰 적용 원칙 때문에 **`level: None` 캐치올을 맨 위에 쓰면 아무것도 기록되지 않는다**. 구체적인 룰 → 일반적인 룰 순서로 배치하라. 또한 `group: ""`(core group)은 빈 문자열이며 생략하면 모든 group을 뜻하지 않으니 명시하라.

### 4.3 apiserver 플래그와 volume mount 함정

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`auditing`** 검색 → **"Auditing"**(Log backend 섹션) → `--audit-policy-file`·`--audit-log-*` 플래그 확인.

policy 파일을 만들었으면 `/etc/kubernetes/manifests/kube-apiserver.yaml`(static pod)에 반영한다. **플래그 4~5종 + hostPath 마운트 2개**가 한 세트다.

> **🛠 만드는 법** — 이건 kubectl로 만드는 리소스가 아니라 노드의 static pod manifest다. dry-run 대상이 아니며, 백업 후 `/etc/kubernetes/manifests/kube-apiserver.yaml`을 직접 편집하면 kubelet이 apiserver를 자동 재생성한다.

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml 에 추가
spec:
  containers:
    - command:
        - kube-apiserver
        # ... 기존 플래그 유지 ...
        - --audit-policy-file=/etc/kubernetes/audit/policy.yaml
        - --audit-log-path=/etc/kubernetes/audit/audit.log
        - --audit-log-maxage=30        # 로그 보관 일수
        - --audit-log-maxbackup=10     # 보관할 로그 파일 개수
        - --audit-log-maxsize=100      # 파일당 최대 크기(MB), 초과 시 로테이트
      volumeMounts:
        - name: audit-policy
          mountPath: /etc/kubernetes/audit/policy.yaml
          readOnly: true
        - name: audit-logs
          mountPath: /etc/kubernetes/audit
  volumes:
    - name: audit-policy
      hostPath:
        path: /etc/kubernetes/audit/policy.yaml
        type: File
    - name: audit-logs
      hostPath:
        path: /etc/kubernetes/audit
        type: DirectoryOrCreate
```

저장하면 kubelet이 apiserver를 자동 재생성한다(30초~1분 대기). 안 뜨면:

```bash
watch crictl ps                         # apiserver 컨테이너 재기동 관찰
crictl ps -a | grep apiserver           # Exited 상태 확인
journalctl -u kubelet -f                # kubelet 에러
ls /var/log/pods/kube-system_kube-apiserver-*/   # 컨테이너 로그 직접 확인
```

> **⚠️ 함정 (자주 빠뜨리는 것)**: 플래그만 넣고 **volumeMounts/volumes를 빼먹으면** apiserver가 policy 파일을 못 읽어 기동 실패한다. 이 유형 오답의 절대다수가 이 마운트 누락이다. policy 파일 마운트(File)와 로그 디렉토리 마운트(DirectoryOrCreate) **두 개 모두** 필요하다.

### 4.4 로그 분석 jq 레시피

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`auditing`** 검색 → **"Auditing"**의 샘플 audit 이벤트에서 `objectRef`·`user.username`·`verb` 필드명 확인(jq 쿼리 자체는 암기).

audit 로그는 JSON Lines(한 줄에 이벤트 하나씩 담는 JSON) 형식이다. 한 이벤트의 주요 필드: `.user.username`, `.verb`, `.objectRef.resource/.namespace/.name/.subresource`, `.responseStatus.code`, `.requestReceivedTimestamp`, `.sourceIPs`.

```bash
LOG=/etc/kubernetes/audit/audit.log

# 특정 Secret을 삭제한 사람
jq 'select(.objectRef.resource == "secrets" and .verb == "delete"
    and .objectRef.name == "database-creds")' $LOG

# 특정 ServiceAccount가 한 모든 행위
jq 'select(.user.username == "system:serviceaccount:dev:deployer")' $LOG

# Secret에 접근(get/list/watch)한 사용자 빈도
jq -r 'select(.objectRef.resource == "secrets"
    and (.verb == "get" or .verb == "list" or .verb == "watch"))
    | .user.username' $LOG | sort | uniq -c | sort -rn

# 누가 pod에 exec 했는가 (subresource가 핵심)
jq 'select(.objectRef.resource == "pods" and .objectRef.subresource == "exec")
    | {user: .user.username, pod: .objectRef.name, ns: .objectRef.namespace}' $LOG
```

> **💡 시험 팁**: 침해 조사 문제에서 "누가 언제 무엇을 했나"는 거의 항상 audit log + jq(또는 grep) 조합이다. `kubectl exec`은 `pods` 리소스의 `exec` **subresource**로 기록된다는 것을 기억하라.

#### 📝 문제로 이해하기

```bash
kubectl config use-context cluster2-admin
ssh cluster2-controlplane1
```

**Task (mini):** Audit logging is already enabled with log file `/etc/kubernetes/audit/audit.log`. Find out which user read (`get`) the Secret `api-key` in namespace `security`, and write only the username to `/opt/course/m7/user.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: objectRef 세 필드(resource/name/namespace)와 verb로 select, username만 -r 출력.

**2) 단계별**:

```bash
mkdir -p /opt/course/m7
jq -r 'select(.objectRef.resource == "secrets"
    and .objectRef.name == "api-key"
    and .objectRef.namespace == "security"
    and .verb == "get")
    | .user.username' /etc/kubernetes/audit/audit.log | sort -u > /opt/course/m7/user.txt
```

**3) 검증**: `cat /opt/course/m7/user.txt` — 사용자명 한 줄.

**⚠️ 함정 포인트**

- policy가 Metadata 레벨이어도 user/verb/objectRef는 남는다 — 조사에 충분하다.
- 로그가 로테이트됐다면 `audit.log.1` 등 이전 파일도 확인.

</details>

---

## 5. 실전 연습문제 12제

### Q1. Falco — 신규 커스텀 룰 작성

> **📖 오픈북 — 문서에서 찾기** — `falco.org/docs`에서 **`supported fields`** 검색 → **"Supported Fields for Conditions and Outputs"** → `fd.name`·`open_read`·`%k8s.ns.name` 등 필드명 확인.

```bash
kubectl config use-context cluster3-admin
ssh cluster3-node1
```

**Task:** Falco is installed as a systemd service on node `cluster3-node1`.

Create a new Falco rule with the following specification and add it to `/etc/falco/falco_rules.local.yaml`:

- Rule name: `Sensitive File Read in Container`
- Condition: any process inside a container opens `/etc/shadow` for reading
- Output format, exactly these fields in this order: time, namespace, pod name, full process command line
- Priority: `WARNING`

Make sure Falco loads the rule without errors. Verify the rule fires by reading `/etc/shadow` inside any running container.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 기본 macro `open_read`(읽기 목적 open 계열 syscall)와 `container`를 조합하고 `fd.name`으로 파일 경로를 지정한다.

**2) 단계별 명령어/YAML**:

```yaml
# /etc/falco/falco_rules.local.yaml 에 추가
- rule: Sensitive File Read in Container
  desc: Detect any read of /etc/shadow inside a container
  condition: open_read and container and fd.name = /etc/shadow
  output: >
    Sensitive file read (time=%evt.time ns=%k8s.ns.name
    pod=%k8s.pod.name cmd=%proc.cmdline)
  priority: WARNING
```

```bash
falco -V /etc/falco/falco_rules.yaml -V /etc/falco/falco_rules.local.yaml
systemctl restart falco
```

**3) 검증 방법**:

```bash
# 다른 터미널(원래 student 터미널)에서
kubectl exec -it 아무pod -- cat /etc/shadow
# 노드에서
journalctl -u falco --since "2 min ago" | grep "Sensitive file read"
```

**⚠️ 함정 포인트**

- `fd.name`은 열린 파일 디스크립터의 전체 경로다. `proc.name = cat` 같은 조건은 요구사항(모든 프로세스)보다 좁아 오답.
- 검증 없이 재시작하면 문법 오류 시 Falco 서비스가 죽은 채로 남는다 — `falco -V` 습관화.
- `output`의 필드 순서는 문제 지시 그대로.

</details>

### Q2. Falco — 기존 룰 출력 포맷 오버라이드 (최다 빈출)

> **📖 오픈북 — 문서에서 찾기** — `falco.org/docs`에서 **`overriding rules`** 검색 → **"Overriding Rules"** → 같은 rule 이름으로 output만 재정의(override)하는 방법 확인.

```bash
kubectl config use-context cluster3-admin
ssh cluster3-node1
```

**Task:** Falco ships a default rule that fires when a terminal shell is spawned inside a container.

1. Find that rule in the installed rules files.
2. Without modifying `/etc/falco/falco_rules.yaml`, change the rule so that its output is exactly the following comma-separated format and nothing else:

```
%evt.time,%container.id,%container.name,%user.name
```

3. Restart Falco, trigger the rule by starting a shell in any container, and save one resulting log line to `/opt/course/2/shell.log`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: grep으로 룰 위치 확인 → 블록 전체를 `local.yaml`에 복사(같은 이름 유지) → output만 교체 → 재시작 → 트리거 → journalctl에서 한 줄 저장.

**2) 단계별 명령어/YAML**:

```bash
grep -rB 2 -A 10 "Terminal shell in container" /etc/falco/
```

찾은 rule 블록을 `/etc/falco/falco_rules.local.yaml`에 복사하고 output만 수정:

```yaml
- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
  output: "%evt.time,%container.id,%container.name,%user.name"
  priority: NOTICE
```

(condition/desc/priority는 설치된 기본 룰의 것을 **그대로** 복사 — 위는 예시이며 시험장 파일 기준이 정답이다.)

```bash
falco -V /etc/falco/falco_rules.yaml -V /etc/falco/falco_rules.local.yaml
systemctl restart falco
```

**3) 검증 방법**:

```bash
# student 터미널에서
kubectl exec -it 아무pod -- sh -c 'exit'
# 노드에서
mkdir -p /opt/course/2
journalctl -u falco --since "2 min ago" | grep "Notice" | tail -n 1 > /opt/course/2/shell.log
cat /opt/course/2/shell.log   # 콤마 구분 4개 필드 확인
```

**⚠️ 함정 포인트**

- rule 이름이 한 글자라도 다르면 override가 아니라 별개 룰 추가가 된다.
- condition 안의 macro들은 기본 파일에서 이미 로드되므로 복사 불필요. condition 자체는 절대 변형 금지.
- output을 따옴표로 감싸면 YAML 특수문자(%) 걱정이 없다.

</details>

### Q3. Falco — 일정 시간 수집 후 필드 추출 제출

> **📖 오픈북 — 문서에서 찾기** — `falco.org/docs`에서 **`daemon arguments`** 검색 → **"Falco Daemon Arguments"** → `-M`(N초 후 종료)·`-o json_output=true` 확인(추출용 jq는 암기).

```bash
kubectl config use-context cluster3-admin
ssh cluster3-node2
```

**Task:** A workload on node `cluster3-node2` periodically runs package management tools inside a container, which triggers the default Falco rule about package management processes.

1. Run Falco from the command line for exactly 45 seconds and store the raw output at `/opt/course/3/raw.log`.
2. From that output, extract the container id of every event generated by the package management rule and write the unique ids, one per line, to `/opt/course/3/ids.txt`.
3. Ensure the Falco systemd service is running again when you are done.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 서비스 정지 → `falco -M 45`로 수집 → grep + 필드 추출 → 서비스 재기동. json_output을 켜면 추출이 정확해진다.

**2) 단계별 명령어/YAML**:

```bash
mkdir -p /opt/course/3
systemctl stop falco
falco -M 45 -o json_output=true > /opt/course/3/raw.log
systemctl start falco

jq -r 'select(.rule | test("Package Management"; "i"))
    | .output_fields."container.id"' /opt/course/3/raw.log | sort -u > /opt/course/3/ids.txt
```

json 없이 텍스트로 받았다면 필드 위치를 눈으로 확인 후 awk:

```bash
grep -i "package management" /opt/course/3/raw.log
# 라인을 보고 container_id=xxxx 또는 N번째 필드를 확인해서
grep -i "package management" /opt/course/3/raw.log | awk '{print $NF}' | sort -u > /opt/course/3/ids.txt
```

**3) 검증 방법**:

```bash
cat /opt/course/3/ids.txt        # 12자리 hex id, 중복 없음
systemctl is-active falco        # active
```

**⚠️ 함정 포인트**

- 45초 안에 이벤트가 안 잡히면 한 번 더 돌려라 — 주기 실행 워크로드는 타이밍 운이 있다.
- `-o json_output=true`는 falco.yaml을 건드리지 않는 일회성 오버라이드 — 원복 부담이 없다.
- 서비스 재기동(`systemctl start falco`)까지가 답안이다.

</details>

### Q4. Falco — 룰을 트리거한 Pod 찾아 조치

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`crictl`** 검색 → **"Debugging Kubernetes nodes with crictl"** → `crictl inspect`의 labels로 container id → pod/namespace 역추적.

```bash
kubectl config use-context cluster3-admin
ssh cluster3-node1
```

**Task:** The Falco service on `cluster3-node1` has been logging `Terminal shell in container` events for the last hour, all coming from the same container.

1. Using the Falco logs, identify the offending container and find out which Pod and namespace it belongs to.
2. Write `<namespace>/<pod-name>` to `/opt/course/4/pod.txt`.
3. The Pod is managed by a Deployment. Scale that Deployment to 0 replicas.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: journalctl에서 container id 확보 → `crictl`로 pod 이름/네임스페이스 역추적(라벨 `io.kubernetes.pod.name` 등) → 소유 Deployment 확인 → scale 0.

**2) 단계별 명령어/YAML**:

```bash
journalctl -u falco --since "1 hour ago" | grep "Terminal shell" | tail -n 5
# 출력에서 container id (예: 4a8b9c0d1e2f) 확보

crictl ps --id 4a8b9c0d1e2f
crictl inspect 4a8b9c0d1e2f | jq -r '.status.labels'
# io.kubernetes.pod.name / io.kubernetes.pod.namespace 확인

mkdir -p /opt/course/4
echo "team-purple/webapp-6c7d8e9f-abcde" > /opt/course/4/pod.txt
```

```bash
# student 터미널에서 소유자 추적 후 스케일 다운
kubectl -n team-purple get pod webapp-6c7d8e9f-abcde -o jsonpath='{.metadata.ownerReferences[0].name}'
kubectl -n team-purple get rs <rs이름> -o jsonpath='{.metadata.ownerReferences[0].name}'
kubectl -n team-purple scale deploy webapp --replicas 0
```

**3) 검증 방법**:

```bash
kubectl -n team-purple get deploy,pod
journalctl -u falco -f     # 새 이벤트가 더 이상 없음
```

**⚠️ 함정 포인트**

- Falco 기본 출력에 pod 이름이 없을 수 있다(포맷에 따라 container id만). crictl 역추적 경로를 몸에 익혀라.
- pod 이름에서 Deployment 이름을 어림짐작하지 말고 ownerReferences로 확인 — ReplicaSet 해시가 낀 이름이 함정이다.
- `pod.txt` 형식(`ns/pod`)을 문제 지시 그대로.

</details>

### Q5. Audit — 요구사항을 Policy로 번역

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`auditing`** 검색 → **"Auditing"** → omitStages·rules 순서·level 예제 Policy 복사.

```bash
kubectl config use-context cluster2-admin
ssh cluster2-controlplane1
```

**Task:** Create an audit policy file at `/etc/kubernetes/audit/policy.yaml` on the control plane node which implements exactly these requirements:

1. Nothing from stage `RequestReceived` should be recorded.
2. Requests to `secrets` (all namespaces) are recorded at `Metadata` level.
3. `create`, `update`, `patch` and `delete` of `pods` in namespace `prod` are recorded at `RequestResponse` level.
4. Everything else is not recorded at all.

Audit logging itself will be enabled in the next task; only the policy file is graded here.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 요구 1 → `omitStages`. 요구 2, 3 → 구체 룰 두 개. 요구 4 → 마지막 `level: None` 캐치올. **순서: 구체 → 일반**.

**2) 단계별 명령어/YAML**:

```yaml
# /etc/kubernetes/audit/policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - "RequestReceived"
rules:
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods"]
    verbs: ["create", "update", "patch", "delete"]
    namespaces: ["prod"]
  - level: None
```

**3) 검증 방법**: 다음 문제에서 apiserver에 연결한 뒤 `kubectl -n prod run test --image nginx` 후 로그에 RequestResponse 이벤트가, `kubectl get secrets -A` 후 Metadata 이벤트가 남는지 확인. 정적 검증은 YAML 문법(`yq`나 눈)으로.

**⚠️ 함정 포인트**

- `level: None` 캐치올을 **맨 위에** 두면 전부 무기록 — 첫 매칭 룰 적용 원칙.
- core group은 `group: ""` — 생략이 아니라 빈 문자열 명시.
- pods 룰에 `namespaces: ["prod"]`와 `verbs`를 빼먹으면 요구사항 3의 범위가 달라져 감점.

</details>

### Q6. Audit — apiserver 플래그 + 마운트 구성

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`auditing`** 검색 → **"Auditing"**(Log backend) → `--audit-policy-file`·`--audit-log-*` 플래그 확인(hostPath 마운트는 static pod에 직접 추가).

```bash
kubectl config use-context cluster2-admin
ssh cluster2-controlplane1
```

**Task:** Enable audit logging on the apiserver of `cluster2` using the existing policy file `/etc/kubernetes/audit/policy.yaml`:

- Log file: `/etc/kubernetes/audit/audit.log`
- Keep logs for a maximum of `30` days
- Keep at most `10` rotated log files
- Rotate a log file when it reaches `100` MB

Make sure the apiserver comes back up and events are written to the log file.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: static pod manifest에 플래그 5개 + hostPath volume/volumeMount 2세트 추가. 수정 전 백업.

**2) 단계별 명령어/YAML**:

```bash
cp /etc/kubernetes/manifests/kube-apiserver.yaml /root/kube-apiserver.yaml.bak  # manifests 밖에 백업
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

```yaml
# command 에 추가
    - --audit-policy-file=/etc/kubernetes/audit/policy.yaml
    - --audit-log-path=/etc/kubernetes/audit/audit.log
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
    - --audit-log-maxsize=100
# containers[0].volumeMounts 에 추가
    - name: audit-policy
      mountPath: /etc/kubernetes/audit/policy.yaml
      readOnly: true
    - name: audit-logs
      mountPath: /etc/kubernetes/audit
# spec.volumes 에 추가
  - name: audit-policy
    hostPath:
      path: /etc/kubernetes/audit/policy.yaml
      type: File
  - name: audit-logs
    hostPath:
      path: /etc/kubernetes/audit
      type: DirectoryOrCreate
```

**3) 검증 방법**:

```bash
watch crictl ps                    # kube-apiserver 재기동 대기 (30초~1분)
kubectl get ns                     # API 응답 확인
kubectl -n prod get pods
tail -f /etc/kubernetes/audit/audit.log | jq .
```

기동 실패 시: `crictl ps -a | grep apiserver`, `journalctl -u kubelet | tail`, `/var/log/pods/kube-system_kube-apiserver-*/` 로그 확인.

**⚠️ 함정 포인트**

- **volumeMounts/volumes 누락이 이 유형 오답의 대부분** — 플래그만 넣으면 apiserver가 policy를 못 읽고 죽는다.
- 백업은 `/etc/kubernetes/manifests/` **밖에** 둘 것 — 그 안에 두면 kubelet이 백업본까지 static pod으로 띄우려 한다.
- maxage/maxbackup/maxsize 값을 서로 바꿔 넣는 단순 실수 주의(일수/개수/MB).

</details>

### Q7. Audit — 로그 분석으로 삭제 범인 찾기

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`auditing`** 검색 → **"Auditing"**의 샘플 이벤트에서 `objectRef`·`verb`·`user.username` 필드명 확인(jq/grep 쿼리는 암기).

```bash
kubectl config use-context cluster2-admin
ssh cluster2-controlplane1
```

**Task:** Someone deleted the Secret `database-creds` in namespace `security`. Audit logging was enabled at the time, log file: `/etc/kubernetes/audit/audit.log`.

1. Find the audit event of that deletion and save the full JSON event to `/opt/course/7/event.json`.
2. Write only the username that performed the deletion to `/opt/course/7/user.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: `objectRef.resource/name/namespace` + `verb: delete`로 select. stage 중복이 있으면 `ResponseComplete` 이벤트를 택한다.

**2) 단계별 명령어/YAML**:

```bash
mkdir -p /opt/course/7
LOG=/etc/kubernetes/audit/audit.log

jq 'select(.objectRef.resource == "secrets"
    and .objectRef.name == "database-creds"
    and .objectRef.namespace == "security"
    and .verb == "delete")' $LOG > /opt/course/7/event.json

jq -r 'select(.objectRef.resource == "secrets"
    and .objectRef.name == "database-creds"
    and .objectRef.namespace == "security"
    and .verb == "delete")
    | .user.username' $LOG | sort -u > /opt/course/7/user.txt
```

**3) 검증 방법**: `jq .verb /opt/course/7/event.json` → `"delete"`, `cat /opt/course/7/user.txt` → 사용자명 한 줄.

**⚠️ 함정 포인트**

- jq 문법이 막히면 무식하게 `grep database-creds $LOG | grep '"verb":"delete"'`도 통한다 — 시간이 점수다.
- 로테이트된 `audit.log.1` 등도 검색 범위에 포함할 것.
- `deletecollection` verb로 지워졌을 가능성도 열어두라(안 나오면 delete 확정).

</details>

### Q8. 침해 조사 — crictl로 악성 컨테이너 폭로

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`crictl`** 검색 → **"Debugging Kubernetes nodes with crictl"** → `crictl ps`·`inspect`·`logs`로 컨테이너 폭로(ps로 PID 매칭은 암기 병행).

```bash
kubectl config use-context cluster2-admin
ssh cluster2-node1
```

**Task:** Node `cluster2-node1` shows constant high CPU usage caused by a crypto-mining process called `xmrig` running inside a container.

1. Using `crictl`, identify the container. Write its container id to `/opt/course/8/id.txt`.
2. Save the container logs to `/opt/course/8/logs.txt`.
3. Write the Pod name and its namespace as `<namespace>/<pod-name>` to `/opt/course/8/pod.txt`.
4. Afterwards delete the offending Pod. It is not managed by a controller.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 호스트 ps로 PID 확인 → crictl 전수 조사로 매칭(또는 inspect의 pid 비교) → 증거 저장 → 마지막에 삭제.

**2) 단계별 명령어/YAML**:

```bash
mkdir -p /opt/course/8
ps aux | grep xmrig                      # 호스트 PID 확인

# 각 컨테이너의 pid와 대조
for c in $(crictl ps -q); do
  echo "$c $(crictl inspect $c | jq -r '.info.pid')"
done
# 매칭된 컨테이너 id로:
crictl ps --id <ID>                      # 이름/pod 확인
echo "<ID>" > /opt/course/8/id.txt
crictl logs <ID> > /opt/course/8/logs.txt 2>&1
crictl inspect <ID> | jq -r '.status.labels["io.kubernetes.pod.namespace"] + "/" + .status.labels["io.kubernetes.pod.name"]' > /opt/course/8/pod.txt
```

```bash
# student 터미널에서
kubectl delete pod <pod이름> -n <ns>
```

**3) 검증 방법**: 세 파일 내용 확인, `ps aux | grep xmrig` 결과 없음, `crictl ps`에 컨테이너 없음.

**⚠️ 함정 포인트**

- **증거(로그) 저장 전에 pod을 지우면 복구 불가** — 순서가 채점이다.
- `crictl logs`는 stderr에도 출력이 있을 수 있으니 `2>&1` 붙이는 습관.
- pod 이름만 쓰라는지 `ns/pod` 형식인지 문제 지시를 그대로 따르라.

</details>

### Q9. 침해 조사 — /proc과 audit log 교차 분석

> **📖 오픈북** — `ss`·`/proc/PID/environ`·JWT 디코드는 허용 문서 8개에 없다 → 명령을 미리 암기. audit 조회 부분만 `kubernetes.io/docs` **"Auditing"** 참고.

```bash
kubectl config use-context cluster2-admin
ssh cluster2-node1
```

**Task:** A suspicious process is listening on port `2222` on node `cluster2-node1`.

1. Find the process and write its PID to `/opt/course/9/pid.txt`.
2. Save its full environment variables, one per line, to `/opt/course/9/environ.txt`.
3. The environment contains a ServiceAccount token. Using the audit log on `cluster2-controlplane1` (`/etc/kubernetes/audit/audit.log`), determine which resources that ServiceAccount accessed and write the distinct resource names to `/opt/course/9/resources.txt`.
4. Kill the process.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 포트 → PID(`ss -tlnp`) → `/proc/PID/environ` 덤프 → 토큰에서 SA 신원 파악(environ의 네임스페이스/SA명 또는 토큰 payload 디코드) → audit log에서 그 username으로 조회.

**2) 단계별 명령어/YAML**:

```bash
mkdir -p /opt/course/9
ss -tlnp | grep 2222                     # pid=XXXX 확인
echo "XXXX" > /opt/course/9/pid.txt
cat /proc/XXXX/environ | tr '\0' '\n' > /opt/course/9/environ.txt
grep -i -e token -e service /opt/course/9/environ.txt
# JWT payload 디코드로 SA 확인 (sub: system:serviceaccount:ns:name)
echo "<토큰 가운데 조각>" | base64 -d
```

```bash
# controlplane에서
ssh cluster2-controlplane1
jq -r 'select(.user.username == "system:serviceaccount:<ns>:<sa>")
    | .objectRef.resource' /etc/kubernetes/audit/audit.log | sort -u > /opt/course/9/resources.txt
```

```bash
# 노드로 돌아와 프로세스 제거
kill -9 XXXX
```

**3) 검증 방법**: `ss -tlnp | grep 2222` 결과 없음, 세 파일 내용 확인.

**⚠️ 함정 포인트**

- environ은 NUL(`\0`) 구분이므로 `tr '\0' '\n'` 없이는 한 줄 덩어리로 보인다.
- 파일 저장 경로가 노드마다 다르다 — `/opt/course/9`가 어느 호스트 기준인지 문제 지문을 확인하고, 필요하면 scp로 옮겨라.
- kill은 **증거 수집이 끝난 뒤** 마지막에.

</details>

### Q10. 불변성 — 기존 Deployment 리팩터링

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`security context`** 검색 → **"Configure a Security Context for a Pod or Container"** → container 레벨 `readOnlyRootFilesystem`·`allowPrivilegeEscalation` 필드 복사.

```bash
kubectl config use-context cluster1-admin
```

**Task:** Deployment `legacy-app` in namespace `team-orange` should be made immutable:

- The container's root filesystem must be read-only.
- Privilege escalation and privileged mode must be disabled.
- The application needs write access to `/tmp` only; make sure it keeps working.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: securityContext 3종 + `/tmp` emptyDir 마운트. 적용 후 CrashLoop 여부와 로그 확인.

**2) 단계별 명령어/YAML**:

```bash
kubectl -n team-orange edit deploy legacy-app
```

```yaml
# spec.template.spec.containers[0] 에
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          privileged: false
        volumeMounts:
          - name: tmp
            mountPath: /tmp
# spec.template.spec 에
      volumes:
        - name: tmp
          emptyDir: {}
```

**3) 검증 방법**:

```bash
kubectl -n team-orange rollout status deploy legacy-app
kubectl -n team-orange exec deploy/legacy-app -- touch /tmp/ok     # 성공
kubectl -n team-orange exec deploy/legacy-app -- touch /usr/x     # Read-only 에러
```

**⚠️ 함정 포인트**

- securityContext를 **pod 레벨에 두면 `readOnlyRootFilesystem`/`privileged`는 적용되지 않는다**(컨테이너 전용 필드). 반드시 container 레벨.
- 적용 후 로그에 다른 경로의 Read-only 에러가 나오면 그 경로도 emptyDir 추가.
- 새 ReplicaSet 롤아웃이 끝나야 채점 대상 pod이 바뀐다 — `rollout status`로 확인.

</details>

### Q11. 불변성 — probe로 쉘 제거·감시

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`liveness readiness startup probes`** 검색 → **"Configure Liveness, Readiness and Startup Probes"** → `exec` 커맨드형 `startupProbe`/`livenessProbe` 예제 복사.

```bash
kubectl config use-context cluster1-admin
```

**Task:** The image of Deployment `web-tier` in namespace `team-blue` cannot be rebuilt, but shells inside the running container must be prevented:

1. Add a `startupProbe` that deletes `/bin/bash` and `/bin/sh` right after the container starts.
2. Add a `livenessProbe` that makes the container restart if `/bin/bash` ever exists again. Check every 10 seconds.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: exec probe 두 개. 삭제는 startupProbe(1회성 통과), 감시는 livenessProbe(주기적).

**2) 단계별 명령어/YAML**:

```yaml
# spec.template.spec.containers[0] 에
        startupProbe:
          exec:
            command: ["rm", "-f", "/bin/bash", "/bin/sh"]
          initialDelaySeconds: 1
          periodSeconds: 5
        livenessProbe:
          exec:
            command: ["test", "!", "-e", "/bin/bash"]
          periodSeconds: 10
```

**3) 검증 방법**:

```bash
kubectl -n team-blue rollout status deploy web-tier
kubectl -n team-blue exec deploy/web-tier -- /bin/bash -c 'id'   # 실패해야 정상
kubectl -n team-blue get pod -l app=web-tier   # RESTARTS 증가 없이 Running
```

**⚠️ 함정 포인트**

- 이 패턴은 rootfs가 **쓰기 가능**해야 성립 — `readOnlyRootFilesystem: true`와 함께 쓰면 rm이 실패해 재시작 루프에 빠진다.
- livenessProbe 커맨드에 `sh -c`를 쓰면 안 된다(쉘을 지웠으므로). `test` 바이너리를 직접 exec.
- `rm -f`의 `-f`가 없으면 파일 부재 시 비0 종료로 startupProbe가 실패한다.

</details>

### Q12. 복합 — Falco 탐지 → Audit 추적 → 격리

> **📖 오픈북 — 문서에서 찾기** — 격리용 NetworkPolicy는 `kubernetes.io/docs`에서 **`network policy`** 검색 → **"Network Policies"** → ingress+egress 양방향 deny-all 뼈대 복사(falco·audit는 앞 절 참고).

```bash
kubectl config use-context cluster3-admin
ssh cluster3-node1
```

**Task:** Falco on `cluster3-node1` keeps logging `Terminal shell in container` events for a container that belongs to Pod `payment-api` in namespace `prod`.

1. Save one Falco log line proving the activity to `/opt/course/12/falco.txt`.
2. On `cluster3-controlplane1`, use the audit log `/etc/kubernetes/audit/audit.log` to find out which user opened an exec session into that Pod, and write the username to `/opt/course/12/attacker.txt`.
3. Isolate the Pod from all network traffic with a NetworkPolicy named `quarantine` in namespace `prod` (the Pod has label `app: payment-api`). Do not delete the Pod.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: ① journalctl에서 증거 라인 저장 → ② `pods/exec` subresource 이벤트에서 username 추출 → ③ ingress+egress 모두 막는 deny-all NetworkPolicy를 해당 라벨에만 적용.

**2) 단계별 명령어/YAML**:

```bash
mkdir -p /opt/course/12
journalctl -u falco | grep "Terminal shell" | tail -n 1 > /opt/course/12/falco.txt
```

```bash
ssh cluster3-controlplane1
jq -r 'select(.objectRef.resource == "pods"
    and .objectRef.subresource == "exec"
    and .objectRef.name == "payment-api"
    and .objectRef.namespace == "prod")
    | .user.username' /etc/kubernetes/audit/audit.log | sort -u > /opt/course/12/attacker.txt
```

> **🛠 만드는 법** — NetworkPolicy는 생성 명령(생성기)이 없다. [kubernetes.io/docs](https://kubernetes.io/docs/concepts/services-networking/network-policies/)의 최소 뼈대를 복사해 `podSelector`와 `policyTypes`만 채운다(dry-run으로 뽑을 수 없음).

```yaml
# quarantine.yaml — student 터미널에서 apply
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: payment-api
  policyTypes:
    - Ingress
    - Egress
```

```bash
kubectl apply -f quarantine.yaml
```

**3) 검증 방법**:

```bash
kubectl -n prod describe netpol quarantine     # 양방향 차단, 대상 pod 확인
kubectl -n prod exec payment-api -- wget -T 3 -qO- http://kubernetes.default   # 타임아웃이 정상
```

**⚠️ 함정 포인트**

- `policyTypes`에 `Egress`를 빼면 유출 경로가 열려 있다 — 격리는 **양방향**.
- ingress/egress 항목을 아예 정의하지 않으면 deny-all — 빈 리스트 `- {}`를 넣으면 반대로 allow-all이 되는 함정.
- podSelector를 `{}`로 두면 네임스페이스 전체가 격리돼 다른 워크로드까지 죽는다 — 라벨로 한정.
- 증거 파일 경로가 노드/컨트롤플레인 어느 쪽 기준인지 지문대로. 필요 시 scp.

</details>

---

## 6. 🎯 시험 직전 체크리스트

- [ ] `ls /etc/falco/` 구조가 머릿속에 있다: `falco.yaml` / `falco_rules.yaml`(수정 금지) / `falco_rules.local.yaml`(내 작업 공간)
- [ ] 기존 룰 오버라이드 = **같은 rule 이름으로 local.yaml에 전체 재정의**, condition은 그대로 복사
- [ ] `grep -r "키워드" /etc/falco/` → 룰 찾기가 3초 안에 나온다
- [ ] 출력 필드 10종(`%evt.time`, `%container.id`, `%container.name`, `%container.image.repository`, `%proc.cmdline`, `%proc.name`, `%user.name`, `%user.uid`, `%k8s.pod.name`, `%k8s.ns.name`)을 문제 지시 순서·구분자대로 쓸 수 있다
- [ ] `falco -V 기본룰파일 -V local룰파일` 검증(기본 macro 참조 시 기본 룰 파일 먼저) → `systemctl restart falco` → `journalctl -u falco` 확인 루틴
- [ ] 시간 수집: `falco -M 30` / `timeout 30s falco`, 포그라운드 실행 전후 `systemctl stop/start falco`
- [ ] crictl 4종: `ps -a` / `pods` / `inspect | jq '.info.pid'` / `logs`
- [ ] `/proc/PID/`의 `exe`, `cwd`, `environ`(`tr '\0' '\n'`), `fd`를 읽을 수 있다
- [ ] 조사 순서: **증거 보존(로그/yaml/environ) → 격리(스케일 0·라벨 제거·NetworkPolicy) → 제거**
- [ ] 불변성 = container 레벨 `readOnlyRootFilesystem: true` + 쓰기 경로만 `emptyDir` + `allowPrivilegeEscalation: false` + `privileged: false`
- [ ] Audit level 4종 차이를 말할 수 있다: None / Metadata(본문 없음) / Request(요청 본문) / RequestResponse(요청+응답 본문)
- [ ] Policy는 **첫 매칭 룰 적용** — 구체 룰 먼저, `level: None` 캐치올은 맨 마지막
- [ ] apiserver 플래그 5종 + **hostPath 마운트 2개(File / DirectoryOrCreate)** 세트로 외웠다
- [ ] apiserver 수정 후 `watch crictl ps`로 재기동 확인, 실패 시 `/var/log/pods/`·`journalctl -u kubelet`
- [ ] `kubectl exec`은 audit log에 `pods` + subresource `exec`으로 남는다
- [ ] 답안 파일은 `/opt/course/문제번호/`에, 지시된 파일명·형식 그대로

## 7. 핵심 명령어 치트시트

```bash
### Falco
systemctl status falco                          # 서비스 확인
grep -r "Terminal shell" /etc/falco/            # 룰 위치 찾기
vim /etc/falco/falco_rules.local.yaml           # 커스텀/오버라이드는 항상 여기
falco -V /etc/falco/falco_rules.yaml -V /etc/falco/falco_rules.local.yaml   # 룰 문법 검증 (기본 macro 참조 시 기본 룰 파일 먼저)
systemctl restart falco                         # 반영
journalctl -u falco --since "10 min ago"        # 이벤트 확인 (또는 /var/log/syslog)
systemctl stop falco && falco -M 30 > out.log && systemctl start falco   # 30초 수집
falco -M 30 -o json_output=true | jq -r '.output_fields."container.id"'  # JSON 수집

### 침해 조사
kubectl get pods -A -o wide                     # 낯선 워크로드 조망
crictl ps -a                                    # 노드의 컨테이너 (종료 포함)
crictl inspect <ID> | jq '.info.pid'            # 호스트 PID
crictl logs <ID> > /opt/course/N/logs.txt 2>&1  # 증거 보존
ls -l /proc/<PID>/exe /proc/<PID>/cwd           # 실행 파일/작업 디렉토리
cat /proc/<PID>/environ | tr '\0' '\n'          # 환경변수
kubectl scale deploy <이름> -n <ns> --replicas 0     # 중지
kubectl label pod <이름> -n <ns> app-                # Service에서 분리

### Audit
vim /etc/kubernetes/audit/policy.yaml           # apiVersion: audit.k8s.io/v1, kind: Policy
vim /etc/kubernetes/manifests/kube-apiserver.yaml
# --audit-policy-file= --audit-log-path= --audit-log-maxage= --audit-log-maxbackup= --audit-log-maxsize=
# + volumeMounts/volumes (policy: File, 로그 디렉토리: DirectoryOrCreate)
watch crictl ps                                 # apiserver 재기동 대기
tail -f /etc/kubernetes/audit/audit.log | jq .  # 기록 확인
jq 'select(.objectRef.resource=="secrets" and .verb=="delete")' audit.log
jq 'select(.objectRef.subresource=="exec") | .user.username' audit.log

### 불변성 핵심 스니펫 (container 레벨)
#   securityContext: {readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, privileged: false}
#   + 쓰기 경로만 emptyDir 마운트
```
