# Domain 3 — System Hardening (시스템 하드닝)

클러스터 노드(호스트 OS) 레벨의 공격면을 줄이는 도메인이다. 서비스/포트/패키지 정리, SSH(Secure Shell — 암호화된 원격 접속 프로토콜)·sudo 최소화, 방화벽, 그리고 CKS의 단골 주제인 **AppArmor**(강제접근제어 프로파일 — 프로세스별 파일·기능 접근을 제한)와 **seccomp**(시스템콜 필터 — 프로세스가 호출 가능한 시스템콜을 제한) 프로파일 적용까지를 다룬다.

> **📌 시험 비중: 10%** — 16문제 기준 대략 1~2문제. 비중은 작지만 AppArmor/seccomp는 매 시험 거의 빠지지 않고 출제되며, 절차가 정형화되어 있어 **연습만 해두면 확실히 점수를 가져가는 도메인**이다. 노드에 `ssh`로 들어가서 작업하는 문제가 대부분이므로, "노드 작업 → `exit` → base 터미널 복귀" 흐름에 익숙해져야 한다.

## 목차

1. [시험 개요와 전략](#1-시험-개요와-전략)
2. [호스트 OS 공격면 축소](#2-호스트-os-공격면-축소)
3. [최소권한 IAM과 SSH 하드닝](#3-최소권한-iam과-ssh-하드닝)
4. [네트워크 접근 최소화](#4-네트워크-접근-최소화)
5. [AppArmor 심화](#5-apparmor-심화)
6. [seccomp 심화](#6-seccomp-심화)
7. [커널 하드닝 보조](#7-커널-하드닝-보조)
8. [연습문제](#8-연습문제)
9. [시험 직전 체크리스트](#-시험-직전-체크리스트)
10. [핵심 명령어 치트시트](#핵심-명령어-치트시트)

---

## 1. 시험 개요와 전략

System Hardening 문제의 전형적인 패턴은 다음 세 가지다.

| 패턴 | 예시 | 작업 위치 |
|---|---|---|
| 호스트 정리 | 수상한 포트/서비스/패키지 찾아 제거, SSH 하드닝, 커널 모듈 차단 | 노드 (ssh) |
| AppArmor | 프로파일을 노드에 로드하고 Pod의 `securityContext.appArmorProfile`로 적용 | 노드 + base |
| seccomp | 프로파일 JSON을 `/var/lib/kubelet/seccomp/`에 배치하고 Pod에 적용 | 노드 + base |

> **💡 시험 팁**: 노드 작업 문제는 `ssh 노드명`으로 들어간 뒤 대부분 root 권한이 필요하다. 프롬프트가 일반 사용자라면 `sudo -i`부터 실행하자. 작업이 끝나면 반드시 `exit`(필요 시 두 번)로 base 터미널에 돌아와야 다음 문제의 `kubectl`이 정상 동작한다.

> **⚠️ 함정**: AppArmor/seccomp 프로파일은 **Pod가 스케줄될 바로 그 노드**에 있어야 한다. base 노드에만 프로파일을 만들어 두고 Pod를 띄우면 `CreateContainerError`가 난다. 문제에서 지정한 노드가 어디인지 항상 먼저 확인하라.

---

## 2. 호스트 OS 공격면 축소

노드에는 Kubernetes 구성요소(kubelet, containerd)와 꼭 필요한 시스템 서비스만 있어야 한다. 시험에서는 "수상한 서비스/프로세스/패키지를 찾아 제거하라"는 형태로 나온다.

### 2.1 실행 중인 서비스 찾기와 끄기

```bash
# 실행 중인 서비스 나열
systemctl list-units --type=service --state=running

# 이름으로 검색 (중지된 것 포함)
systemctl list-units --type=service --all | grep -i suspicious

# 부팅 시 자동 시작되도록 등록된 유닛 확인
systemctl list-unit-files --type=service --state=enabled

# 상세 확인 (실행 파일 경로, PID 표시)
systemctl status suspicious.service

# 중지 + 자동시작 해제를 한 번에
systemctl disable --now suspicious.service
```

> **📌 암기 포인트**: `systemctl disable --now 서비스` = `stop` + `disable`. 문제에서 "stop and disable"이라고 하면 이 한 줄이면 된다. `mask`까지 요구하면 `systemctl mask 서비스`.

### 2.2 불필요 패키지 제거

```bash
# 설치된 패키지 검색
apt list --installed 2>/dev/null | grep -i nginx

# 패키지 정보 확인
apt show nginx

# 어떤 패키지가 이 파일(바이너리)을 설치했는지 역추적
dpkg -S /usr/sbin/nginx

# 제거 (설정 파일 포함)
apt remove --purge -y nginx
apt autoremove -y
```

### 2.3 열린 포트와 프로세스 식별

```bash
# LISTEN 중인 TCP 포트 + 프로세스 (가장 많이 쓰는 명령)
ss -tlpn

# 특정 포트만
ss -tlpn | grep 6666
lsof -i :6666

# 프로세스의 실제 바이너리 경로 추적
ls -l /proc/<PID>/exe
ps aux | grep <PID>
```

프로세스를 찾았으면 처리 순서는 **① 어떤 서비스/패키지 소속인지 확인 → ② systemd 서비스면 `disable --now` → ③ 패키지면 `apt remove --purge` → ④ 고아 프로세스면 `kill`**이다. 무작정 `kill`만 하면 서비스가 재시작되거나 재부팅 후 되살아난다.

### 📝 문제로 이해하기

```
ssh wk8s-node-1
```

Task: A process is listening on port `8080` on node `wk8s-node-1`. Identify the systemd service that owns this process, stop it, and make sure it does not start again on boot. Write the service name into `/opt/course/m1/service.txt` on the node.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: `ss -tlpn`으로 포트 → PID → `systemctl status PID 역추적` 순서.

2) **단계별 명령어**:

```bash
ssh wk8s-node-1
sudo -i

ss -tlpn | grep 8080
# LISTEN 0 4096 *:8080  users:(("evil-app",pid=1234,fd=3))

# PID가 속한 systemd 유닛 확인
systemctl status 1234
# → evil-app.service

systemctl disable --now evil-app.service

mkdir -p /opt/course/m1
echo "evil-app.service" > /opt/course/m1/service.txt
```

3) **검증**: `ss -tlpn | grep 8080` 출력이 비어 있고, `systemctl is-enabled evil-app.service`가 `disabled`.

4) **⚠️ 함정 포인트**:
- `kill -9`만 하면 systemd가 `Restart=always`로 되살릴 수 있다. 반드시 `disable --now`.
- 답안 파일을 base가 아니라 **노드의** `/opt/course/m1/`에 쓰라고 했는지 문제를 정확히 읽을 것.

</details>

---

## 3. 최소권한 IAM과 SSH 하드닝

### 3.1 리눅스 사용자/그룹 최소화

```bash
# 사용자 확인
id jane
getent passwd jane

# 로그인 잠금 / 셸 제거
passwd -l jane                        # 패스워드 잠금
usermod -s /usr/sbin/nologin jane     # 로그인 셸 제거

# 그룹에서 제거 (Ubuntu)
deluser jane sudo
# 또는
gpasswd -d jane sudo

# 사용자 삭제
userdel -r attacker
```

### 3.2 sudo 최소화

```bash
# sudo 그룹 멤버 확인
getent group sudo

# 특정 사용자의 sudo 권한 나열
sudo -l -U jane

# sudoers 편집은 반드시 visudo (문법 오류 방지)
visudo
# 개별 파일은 /etc/sudoers.d/ 아래도 확인
ls /etc/sudoers.d/
```

> **⚠️ 함정**: sudo 권한은 `sudo` 그룹 멤버십뿐 아니라 `/etc/sudoers`와 `/etc/sudoers.d/*`의 개별 항목으로도 부여된다. "jane이 sudo를 못 쓰게 하라"는 문제면 **세 군데를 모두** 확인해야 한다.

### 3.3 SSH 하드닝

`/etc/ssh/sshd_config`에서 최소 두 가지는 암기 대상이다.

```bash
# /etc/ssh/sshd_config 에서 다음 설정 (주석 해제 후 수정)
# PermitRootLogin no
# PasswordAuthentication no

# 문법 검증 후 재시작
sshd -t
systemctl restart sshd    # Ubuntu에서 안 되면: systemctl restart ssh
```

| 설정 | 값 | 의미 |
|---|---|---|
| `PermitRootLogin` | `no` | root 직접 로그인 차단 |
| `PasswordAuthentication` | `no` | 패스워드 로그인 차단(키 인증만) |

> **💡 시험 팁**: 같은 지시어가 파일에 여러 번 있으면 **첫 번째 항목이 적용**된다. 파일 끝에 추가하지 말고 `grep -n PermitRootLogin /etc/ssh/sshd_config`로 기존 줄을 찾아 수정하는 편이 안전하다. `/etc/ssh/sshd_config.d/*.conf`가 include되는 배포판도 있으니 함께 확인.

### 📝 문제로 이해하기

```
ssh cks-node-2
```

Task: On node `cks-node-2`, configure the SSH daemon so that the root user cannot log in via SSH and password authentication is disabled. Restart the SSH daemon afterwards.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: `sshd_config` 두 줄 수정 → `sshd -t` 검증 → 재시작.

2) **단계별 명령어**:

```bash
ssh cks-node-2
sudo -i

vim /etc/ssh/sshd_config
# PermitRootLogin no
# PasswordAuthentication no

sshd -t && systemctl restart sshd
```

3) **검증**:

```bash
sshd -T | grep -E 'permitrootlogin|passwordauthentication'
# permitrootlogin no
# passwordauthentication no
```

4) **⚠️ 함정 포인트**:
- `PermitRootLogin prohibit-password`(기본값)는 "no"가 아니다. 명시적으로 `no`로 바꿔야 한다.
- 주석(`#PermitRootLogin ...`)을 해제하지 않고 그 아래 새 줄만 추가했다가 위쪽에 활성 줄이 이미 있으면 무시될 수 있다 — 첫 매칭이 이긴다.
- 재시작을 잊으면 설정이 반영되지 않는다.

</details>

---

## 4. 네트워크 접근 최소화

### 4.1 ufw 기초

Ubuntu 노드에서는 `ufw`(Uncomplicated Firewall)로 간단히 처리한다.

```bash
ufw status verbose

# 필수 포트 먼저 허용 (잠금 방지!)
ufw allow 22/tcp
ufw allow 6443/tcp     # kube-apiserver (컨트롤플레인)
ufw allow 10250/tcp    # kubelet

# 차단 규칙
ufw deny 8080/tcp
ufw deny from 172.16.0.0/16

ufw enable
ufw status numbered
ufw delete <번호>       # 규칙 삭제
```

> **⚠️ 함정**: `ufw enable` 전에 반드시 `ufw allow 22/tcp`를 먼저 넣어라. 순서를 바꾸면 시험 환경에서 노드 접속이 끊길 수 있다. 또한 컨트롤플레인 노드라면 6443, etcd(2379-2380), kubelet(10250)을 막지 않도록 주의.

### 4.2 iptables 최소 지식

```bash
iptables -L INPUT -n --line-numbers

# 특정 포트로 들어오는 트래픽 차단
iptables -A INPUT -p tcp --dport 8080 -j DROP

# 규칙 삭제
iptables -D INPUT <라인번호>
```

### 4.3 바인딩 인터페이스 점검

서비스가 `0.0.0.0`(모든 인터페이스)에 열려 있는지, `127.0.0.1`(로컬 전용)에만 열려 있는지 확인하는 습관을 들이자.

```bash
ss -tlpn
# 127.0.0.1:10248  → kubelet healthz, 로컬 전용 (정상)
# 0.0.0.0:22       → 모든 인터페이스 (외부 노출)
```

외부 노출이 불필요한 서비스는 해당 데몬 설정에서 바인드 주소를 `127.0.0.1`로 좁히거나 방화벽으로 차단한다.

### 📝 문제로 이해하기

```
ssh wk8s-node-1
```

Task: On node `wk8s-node-1`, use `ufw` to allow incoming traffic on ports `22/tcp` and `10250/tcp`, deny incoming traffic on port `9091/tcp`, then enable the firewall.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: allow 규칙(특히 22) → deny 규칙 → enable 순서.

2) **단계별 명령어**:

```bash
ssh wk8s-node-1
sudo -i

ufw allow 22/tcp
ufw allow 10250/tcp
ufw deny 9091/tcp
ufw enable
```

3) **검증**: `ufw status verbose` 출력에서 세 규칙과 `Status: active` 확인.

4) **⚠️ 함정 포인트**:
- 22 허용 전에 enable하면 SSH 세션이 끊길 수 있다.
- `ufw enable` 실행 시 "may disrupt existing ssh connections" 프롬프트에 `y` 입력 필요.

</details>

---

## 5. AppArmor 심화

### 5.1 개념

AppArmor는 리눅스 LSM(Linux Security Module) 기반의 MAC(강제 접근 제어)로, **프로파일** 단위로 프로세스의 파일 접근/기능을 제한한다. Ubuntu 노드에서 기본 활성화되어 있으며, CKS에서는 "주어진 프로파일을 노드에 로드하고 Pod에 적용"하는 문제가 정형적으로 나온다.

프로파일 모드:

| 모드 | 의미 |
|---|---|
| `enforce` | 규칙 위반을 실제로 차단 |
| `complain` | 차단하지 않고 로그만 남김 |
| `unconfined` | 프로파일 미적용 |

### 5.2 프로파일 문법 기초

시험에서는 프로파일을 직접 작성하기보다 **주어진 파일을 읽고 로드**하는 수준이면 충분하지만, 핵심 문법은 알아야 한다.

> **🛠 만드는 법** — AppArmor 프로파일은 kubectl 리소스가 아니다(dry-run 대상 아님). 노드의 `/etc/apparmor.d/`에 두는 설정 파일 — kubernetes.io(AppArmor 튜토리얼) 등 허용 문서의 예제를 복사해 편집한다.

```text
#include <tunables/global>

profile k8s-deny-write flags=(attach_disconnected) {
  #include <abstractions/base>

  file,            # 모든 파일 접근 허용 (기본)

  deny /** w,      # 단, 모든 경로에 대한 쓰기(w)는 거부
}
```

- `deny 경로 권한,` — 명시적 거부. 권한 문자는 `r`(읽기) `w`(쓰기) `x`(실행) `k`(잠금) `l`(링크).
- `audit 경로 권한,` — 허용하되 로그 기록.
- `/**` — 하위 모든 경로 재귀 매칭.
- 프로파일 이름(`k8s-deny-write`)이 Pod에서 참조하는 이름이다. 파일명이 아니라 **`profile` 뒤에 오는 이름**임에 주의.

### 5.3 호스트에서 로드/확인

```bash
# 현재 로드된 프로파일과 모드 확인
aa-status

# 프로파일 로드 (프로파일 파일은 관례상 /etc/apparmor.d/ 에 배치)
apparmor_parser -q /etc/apparmor.d/k8s-deny-write

# 이미 로드된 프로파일 수정 후 재로드
apparmor_parser -r /etc/apparmor.d/k8s-deny-write

# 확인
aa-status | grep k8s-deny-write
```

> **📌 암기 포인트**: 프로파일은 **Pod가 뜰 노드마다** 로드되어 있어야 한다. `/etc/apparmor.d/`에 두면 부팅 시 자동 로드된다.

### 5.4 Pod 적용 — GA 방식 (v1.30+)

v1.30부터 AppArmor는 GA(General Availability — 정식 안정화 단계)가 되어 `securityContext.appArmorProfile` **필드**를 사용한다. Pod 레벨(모든 컨테이너 적용) 또는 컨테이너 레벨 모두 가능하다.

> **🛠 만드는 법** — Pod는 생성기가 있다: `k run secured-pod --image=busybox:1.36 $do > pod.yaml` 로 뼈대를 뽑고 `securityContext.appArmorProfile`(type/localhostProfile)을 채워 `k apply -f`. (`$do`=`--dry-run=client -o yaml`, 시험 세팅 변수)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secured-pod
  namespace: moon
spec:
  containers:
  - name: app
    image: busybox:1.36
    command: ["sh", "-c", "sleep 1d"]
    securityContext:
      appArmorProfile:
        type: Localhost
        localhostProfile: k8s-deny-write
```

| `type` | 의미 |
|---|---|
| `RuntimeDefault` | 컨테이너 런타임 기본 프로파일 |
| `Localhost` | 노드에 로드된 프로파일 사용 (`localhostProfile`에 프로파일 이름) |
| `Unconfined` | AppArmor 미적용 |

> **⚠️ 함정**: 과거의 annotation 방식 `container.apparmor.security.beta.kubernetes.io/<컨테이너명>: localhost/<프로파일>`은 **deprecated**다. 기존 매니페스트에서 발견하면 GA 필드로 마이그레이션하는 문제가 나올 수 있다. 새로 작성할 때는 반드시 `securityContext.appArmorProfile`을 쓰자.

### 5.5 검증

```bash
# 프로파일이 동작하면 쓰기 시도 시 Permission denied
kubectl -n moon exec secured-pod -- touch /tmp/test
# touch: /tmp/test: Permission denied

# 프로파일이 노드에 없으면 컨테이너 생성 실패
kubectl -n moon get pod secured-pod
kubectl -n moon describe pod secured-pod   # 이벤트에서 원인 확인
```

### 📝 문제로 이해하기

```
kubectl config use-context wk8s
ssh wk8s-node-1
```

Task: The AppArmor profile file `/home/candidate/profiles/k8s-deny-write` exists on node `wk8s-node-1`. Load it into AppArmor on that node and verify it is loaded. Then, from the main terminal, create a Pod named `aa-test` in namespace `default` using image `busybox:1.36` running command `sleep 1d` that uses this AppArmor profile for its container.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: 노드에서 `apparmor_parser`로 로드 → `aa-status` 확인 → base로 나와 GA 필드로 Pod 작성.

2) **단계별 명령어**:

```bash
ssh wk8s-node-1
sudo -i
cp /home/candidate/profiles/k8s-deny-write /etc/apparmor.d/
apparmor_parser -q /etc/apparmor.d/k8s-deny-write
aa-status | grep k8s-deny-write
exit
exit
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: aa-test
spec:
  containers:
  - name: aa-test
    image: busybox:1.36
    command: ["sh", "-c", "sleep 1d"]
    securityContext:
      appArmorProfile:
        type: Localhost
        localhostProfile: k8s-deny-write
```

```bash
kubectl apply -f aa-test.yaml
```

3) **검증**: `kubectl get pod aa-test`가 Running, `kubectl exec aa-test -- touch /root/x`가 Permission denied.

4) **⚠️ 함정 포인트**:
- `localhostProfile`에는 파일 경로가 아니라 **프로파일 이름**(파일 안 `profile` 키워드 뒤)을 쓴다.
- Pod가 다른 노드에 스케줄되면 프로파일이 없어 실패한다. 필요 시 `nodeName: wk8s-node-1`로 고정.
- annotation 방식으로 쓰면 감점/오답 가능 — GA 필드를 사용하라.

</details>

---

## 6. seccomp 심화

### 6.1 개념과 프로파일 구조

seccomp(secure computing mode)은 프로세스가 호출할 수 있는 **syscall을 필터링**한다. 프로파일은 JSON이다.

> **🛠 만드는 법** — seccomp 프로파일(JSON)도 kubectl 리소스가 아니다(dry-run 대상 아님). 노드의 `/var/lib/kubelet/seccomp/`에 두는 설정 파일 — kubernetes.io 문서의 예제 JSON을 복사해 syscall 목록을 채운다.

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "openat", "close", "execve", "exit_group", "futex", "nanosleep"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

| Action | 의미 |
|---|---|
| `SCMP_ACT_ALLOW` | 허용 |
| `SCMP_ACT_ERRNO` | 차단(에러 반환) — 프로세스에 "Operation not permitted" |
| `SCMP_ACT_LOG` | 허용하되 로그 기록 (감사용) |

`defaultAction: SCMP_ACT_ERRNO` + 허용 목록(화이트리스트) 방식이 가장 안전하고, `defaultAction: SCMP_ACT_LOG`는 감사(audit) 프로파일로 쓰인다.

### 6.2 프로파일 배치 경로

kubelet은 seccomp 프로파일을 **`/var/lib/kubelet/seccomp/`** 아래에서 찾는다. Pod의 `localhostProfile`은 이 디렉토리 기준 **상대경로**다.

```bash
# 노드에서
mkdir -p /var/lib/kubelet/seccomp/profiles
cp /home/candidate/audit.json /var/lib/kubelet/seccomp/profiles/audit.json
```

### 6.3 Pod 적용

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-pod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json   # /var/lib/kubelet/seccomp/ 기준 상대경로
  containers:
  - name: app
    image: nginx:1.27
```

`RuntimeDefault`는 런타임(containerd) 기본 프로파일을 쓴다. 커스텀 파일이 필요 없어 가장 자주 쓰는 형태다.

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

### 6.4 검증과 위반 시 증상

```bash
# 컨테이너 프로세스의 seccomp 상태 (0=off, 1=strict, 2=filter)
kubectl exec seccomp-pod -- grep Seccomp /proc/1/status
# Seccomp:  2

# 차단된 syscall을 호출하면
# → "Operation not permitted" 에러

# 프로파일 파일이 노드에 없으면
kubectl describe pod seccomp-pod
# → CreateContainerError / "cannot load seccomp profile" 이벤트
```

> **⚠️ 함정**: `localhostProfile: /var/lib/kubelet/seccomp/profiles/audit.json`처럼 **절대경로를 쓰면 안 된다**. 반드시 `profiles/audit.json` 같은 상대경로. 그리고 AppArmor와 마찬가지로 파일은 Pod가 뜨는 노드에 있어야 한다.

### 📝 문제로 이해하기

```
kubectl config use-context wk8s
```

Task: Update the existing Deployment `api` in namespace `prod` so that all its containers run with the `RuntimeDefault` seccomp profile. Verify the rollout succeeds.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: Pod 템플릿의 `spec.securityContext`에 `seccompProfile` 추가(Pod 레벨이면 전 컨테이너 적용).

2) **단계별 명령어**:

```bash
kubectl -n prod edit deploy api
```

```yaml
# spec.template.spec 아래
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
```

3) **검증**:

```bash
kubectl -n prod rollout status deploy api
kubectl -n prod get pod -l app=api -o yaml | grep -A2 seccompProfile
```

4) **⚠️ 함정 포인트**:
- Deployment 최상위 `spec.securityContext`가 아니라 **`spec.template.spec.securityContext`**에 넣어야 한다.
- 컨테이너 레벨에 다른 seccompProfile이 이미 있으면 컨테이너 레벨이 우선한다 — 있으면 제거하거나 함께 수정.

</details>

---

## 7. 커널 하드닝 보조

### 7.1 커널 모듈 블랙리스트

사용하지 않는 프로토콜 모듈(sctp, dccp 등)은 로드를 차단한다.

```bash
# 현재 로드 여부 확인
lsmod | grep -E 'sctp|dccp'

# 블랙리스트 파일 작성
cat <<EOF > /etc/modprobe.d/blacklist-cks.conf
blacklist sctp
blacklist dccp
install sctp /bin/true
install dccp /bin/true
EOF

# 이미 로드되어 있으면 언로드
modprobe -r sctp
modprobe -r dccp
```

> **📌 암기 포인트**: `blacklist 모듈`은 **별칭에 의한 자동 로드**만 막는다. `modprobe 모듈` 명시 호출까지 막으려면 `install 모듈 /bin/true` 줄을 함께 넣는다. 두 줄 다 쓰는 것이 정석.

### 7.2 위험 sysctl 정리

노드의 커널 파라미터는 `/etc/sysctl.d/*.conf`로 영구 설정하고 `sysctl --system`으로 적용한다.

```bash
# 조회
sysctl kernel.dmesg_restrict
sysctl -a 2>/dev/null | grep protected

# 즉시 적용 (휘발성)
sysctl -w kernel.dmesg_restrict=1

# 영구 적용
echo "kernel.dmesg_restrict=1" >> /etc/sysctl.d/99-cks.conf
sysctl --system
```

대표적인 하드닝 파라미터:

| sysctl | 권장값 | 의미 |
|---|---|---|
| `kernel.dmesg_restrict` | 1 | 일반 사용자의 dmesg 열람 차단 |
| `kernel.kptr_restrict` | 1 | 커널 포인터 주소 노출 제한 |
| `fs.protected_symlinks` | 1 | 심볼릭 링크 공격 완화 |
| `fs.protected_hardlinks` | 1 | 하드 링크 공격 완화 |
| `net.ipv4.conf.all.accept_redirects` | 0 | ICMP 리다이렉트 수신 차단 |
| `net.ipv4.conf.all.send_redirects` | 0 | ICMP 리다이렉트 발신 차단 |

> **⚠️ 함정**: Kubernetes 노드에서 `net.ipv4.ip_forward`는 **1이어야 한다**(Pod 네트워킹 필수). `net.bridge.bridge-nf-call-iptables=1`도 마찬가지. 하드닝한다고 이 값들을 0으로 바꾸면 클러스터 네트워크가 망가진다.

### 📝 문제로 이해하기

```
ssh cks-node-2
```

Task: On node `cks-node-2`, prevent the kernel module `dccp` from being loaded, both automatically and manually, and make the setting persistent across reboots. Unload the module if it is currently loaded.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: `/etc/modprobe.d/` 파일에 blacklist + install 두 줄, 로드 상태면 `modprobe -r`.

2) **단계별 명령어**:

```bash
ssh cks-node-2
sudo -i

lsmod | grep dccp

cat <<EOF > /etc/modprobe.d/blacklist-dccp.conf
blacklist dccp
install dccp /bin/true
EOF

modprobe -r dccp 2>/dev/null || true
```

3) **검증**: `modprobe dccp` 실행 후 `lsmod | grep dccp` 출력이 비어 있으면 성공(`install ... /bin/true`가 동작).

4) **⚠️ 함정 포인트**:
- `blacklist`만 쓰면 `modprobe dccp` 명시 호출은 여전히 성공한다 — "manually"까지 막으려면 `install` 줄 필수.
- 파일 확장자는 `.conf`여야 modprobe가 읽는다.

</details>

---

## 8. 연습문제

실제 시험과 동일한 형식의 8문제다. 문제당 목표 시간은 5~7분.

### Question 1 — AppArmor 프로파일 로드와 적용 (AppArmor)

```
kubectl config use-context wk8s
ssh wk8s-node-1
```

Task: A file `/home/candidate/profiles/very-secure` containing an AppArmor profile named `very-secure` exists on node `wk8s-node-1`.

1. Load the profile into AppArmor on node `wk8s-node-1` so that it survives a reboot.
2. Create a Pod named `q1-pod` in namespace `apparmor-test` (create the namespace if needed) with image `busybox:1.36` running command `sleep 1d`, and enforce the `very-secure` profile on its container using the GA `securityContext` field.
3. Verify the Pod is running.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: 프로파일을 `/etc/apparmor.d/`로 복사(재부팅 대응) 후 `apparmor_parser` 로드 → base에서 Pod 작성.

2) **단계별 명령어**:

```bash
ssh wk8s-node-1
sudo -i
cp /home/candidate/profiles/very-secure /etc/apparmor.d/
apparmor_parser -q /etc/apparmor.d/very-secure
aa-status | grep very-secure
exit
exit
```

```bash
kubectl create ns apparmor-test
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: q1-pod
  namespace: apparmor-test
spec:
  containers:
  - name: q1-pod
    image: busybox:1.36
    command: ["sh", "-c", "sleep 1d"]
    securityContext:
      appArmorProfile:
        type: Localhost
        localhostProfile: very-secure
```

```bash
kubectl apply -f q1.yaml
```

3) **검증**:

```bash
kubectl -n apparmor-test get pod q1-pod    # Running
kubectl -n apparmor-test describe pod q1-pod | grep -i apparmor
```

4) **⚠️ 함정 포인트**:
- "survives a reboot" 요구 → `/etc/apparmor.d/`에 복사해 두어야 부팅 시 자동 로드된다.
- `localhostProfile`은 파일 경로가 아니라 프로파일 이름.
- 워커 노드가 여러 개면 Pod가 프로파일 없는 노드에 갈 수 있다. 문제가 노드를 지정하면 `nodeName`으로 고정.

</details>

### Question 2 — Deprecated annotation 마이그레이션 (AppArmor)

```
kubectl config use-context wk8s
```

Task: The Deployment `legacy-app` in namespace `legacy` uses the deprecated AppArmor annotation to apply the profile `k8s-deny-write` to its container `main`. Migrate the Deployment to the GA `securityContext.appArmorProfile` field, keeping the same profile, and remove the deprecated annotation. Make sure the new Pods run successfully.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: 현재 매니페스트에서 annotation을 확인 → 삭제 → 컨테이너 `main`의 securityContext에 GA 필드 추가.

2) **단계별 명령어**:

```bash
kubectl -n legacy get deploy legacy-app -o yaml | grep -B2 apparmor
# spec.template.metadata.annotations:
#   container.apparmor.security.beta.kubernetes.io/main: localhost/k8s-deny-write

kubectl -n legacy edit deploy legacy-app
```

편집 내용:

```yaml
# 1) spec.template.metadata.annotations 에서 아래 줄 삭제
#    container.apparmor.security.beta.kubernetes.io/main: localhost/k8s-deny-write
# 2) main 컨테이너에 추가
      containers:
      - name: main
        image: nginx:1.27
        securityContext:
          appArmorProfile:
            type: Localhost
            localhostProfile: k8s-deny-write
```

3) **검증**:

```bash
kubectl -n legacy rollout status deploy legacy-app
kubectl -n legacy get pod -l app=legacy-app -o yaml | grep -A2 appArmorProfile
```

4) **⚠️ 함정 포인트**:
- annotation의 값 형식은 `localhost/프로파일명`이지만 GA 필드에서는 `type: Localhost` + `localhostProfile: 프로파일명`으로 나눠 쓴다. `localhost/` 접두어를 그대로 옮겨 적으면 안 된다.
- annotation은 `spec.template.metadata.annotations`에 있다. 최상위 `metadata.annotations`가 아니다.

</details>

### Question 3 — 커스텀 seccomp 프로파일 적용 (seccomp)

```
kubectl config use-context wk8s
ssh wk8s-node-1
```

Task: A seccomp profile file exists at `/home/candidate/audit.json` on node `wk8s-node-1`.

1. Place the profile in the kubelet seccomp directory on that node as `profiles/audit.json`.
2. Create a Pod named `q3-pod` in namespace `default` with image `nginx:1.27` that uses this profile via `Localhost` type, scheduled on `wk8s-node-1`.
3. Verify the container is running with seccomp filtering enabled.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: `/var/lib/kubelet/seccomp/profiles/`에 배치 → `localhostProfile`에 상대경로 지정 → `nodeName`으로 노드 고정.

2) **단계별 명령어**:

```bash
ssh wk8s-node-1
sudo -i
mkdir -p /var/lib/kubelet/seccomp/profiles
cp /home/candidate/audit.json /var/lib/kubelet/seccomp/profiles/audit.json
exit
exit
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: q3-pod
spec:
  nodeName: wk8s-node-1
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json
  containers:
  - name: q3-pod
    image: nginx:1.27
```

```bash
kubectl apply -f q3.yaml
```

3) **검증**:

```bash
kubectl get pod q3-pod                                # Running
kubectl exec q3-pod -- grep Seccomp /proc/1/status    # Seccomp: 2 (filter)
```

4) **⚠️ 함정 포인트**:
- `localhostProfile`은 `/var/lib/kubelet/seccomp/` 기준 **상대경로**. 절대경로를 쓰면 안 된다.
- 프로파일이 없는 노드에 스케줄되면 `CreateContainerError` — `kubectl describe pod`의 "cannot load seccomp profile" 이벤트로 진단.
- kubelet 재시작은 필요 없다. 파일만 있으면 된다.

</details>

### Question 4 — RuntimeDefault 전환과 증거 수집 (seccomp)

```
kubectl config use-context prod-cluster
```

Task: The Deployment `web` in namespace `frontend` currently runs its containers with seccomp `Unconfined`.

1. Change the Deployment so all containers use the `RuntimeDefault` seccomp profile.
2. After the rollout, run `grep Seccomp /proc/1/status` inside one of the new Pods and save the output to `/opt/course/4/seccomp.txt` on the main terminal.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: Pod 템플릿의 seccompProfile을 교체 → rollout 완료 후 exec로 증거 수집.

2) **단계별 명령어**:

```bash
kubectl -n frontend edit deploy web
```

```yaml
# spec.template.spec.securityContext 를 다음으로 변경
      securityContext:
        seccompProfile:
          type: RuntimeDefault
# 컨테이너 레벨에 seccompProfile(type: Unconfined)이 있으면 그것도 제거/변경
```

```bash
kubectl -n frontend rollout status deploy web
mkdir -p /opt/course/4
POD=$(kubectl -n frontend get pod -l app=web -o jsonpath='{.items[0].metadata.name}')
kubectl -n frontend exec $POD -- grep Seccomp /proc/1/status > /opt/course/4/seccomp.txt
cat /opt/course/4/seccomp.txt   # Seccomp: 2
```

3) **검증**: 파일 내용이 `Seccomp:\t2`(filter 모드)면 RuntimeDefault가 적용된 것이다. 0이면 여전히 unconfined.

4) **⚠️ 함정 포인트**:
- 컨테이너 레벨 securityContext가 Pod 레벨을 **덮어쓴다**. Unconfined가 컨테이너 레벨에 있으면 Pod 레벨만 고쳐서는 안 바뀐다.
- 옛 Pod가 아직 Terminating일 때 exec하면 이전 값이 나온다. rollout 완료 후 새 Pod에서 실행할 것.

</details>

### Question 5 — 수상한 포트의 서비스 제거 (포트/서비스)

```
kubectl config use-context wk8s
ssh wk8s-node-1
```

Task: On node `wk8s-node-1` something is listening on port `6666`.

1. Find the process and write the full path of its binary to `/opt/course/5/binary.txt` on the node.
2. Stop the process and ensure it cannot start again on boot.
3. Write the name of the systemd service that started it to `/opt/course/5/service.txt` on the node.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: `ss -tlpn` → PID → `/proc/PID/exe` → `systemctl status PID` 순으로 역추적.

2) **단계별 명령어**:

```bash
ssh wk8s-node-1
sudo -i
mkdir -p /opt/course/5

ss -tlpn | grep 6666
# users:(("backdoor",pid=2345,fd=3))

ls -l /proc/2345/exe
# /proc/2345/exe -> /usr/local/bin/backdoor
echo "/usr/local/bin/backdoor" > /opt/course/5/binary.txt

systemctl status 2345
# → backdoor.service

systemctl disable --now backdoor.service
echo "backdoor.service" > /opt/course/5/service.txt
```

3) **검증**: `ss -tlpn | grep 6666` 출력 없음, `systemctl is-enabled backdoor.service` → `disabled`.

4) **⚠️ 함정 포인트**:
- `systemctl status PID`에 PID를 넘기면 그 PID가 속한 유닛을 바로 찾아준다 — 시간 절약 팁.
- `kill`만 하고 disable을 빼먹으면 재부팅/자동재시작 시 되살아난다.
- 바이너리가 삭제된 채 실행 중이면 `/proc/PID/exe` 링크에 `(deleted)`가 붙는다. 경로는 링크가 가리키는 원래 경로를 적는다.

</details>

### Question 6 — 불필요 패키지와 열린 포트 정리 (포트/서비스)

```
kubectl config use-context cks
ssh cks-node-2
```

Task: On node `cks-node-2` an unnecessary package is running a web server listening on port `80`.

1. Identify which package owns the listening process and write the package name to `/opt/course/6/pkg.txt` on the node.
2. Stop and disable the corresponding service, then remove the package completely including its configuration files.
3. Confirm nothing is listening on port `80` anymore.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: 포트 → 프로세스 바이너리 → `dpkg -S`로 패키지 역추적 → 서비스 중지 → `apt remove --purge`.

2) **단계별 명령어**:

```bash
ssh cks-node-2
sudo -i
mkdir -p /opt/course/6

ss -tlpn | grep :80
# users:(("nginx",pid=3456,...))

ls -l /proc/3456/exe        # /usr/sbin/nginx
dpkg -S /usr/sbin/nginx     # nginx-core: /usr/sbin/nginx → 패키지 확인
echo "nginx" > /opt/course/6/pkg.txt

systemctl disable --now nginx
apt remove --purge -y nginx nginx-core
apt autoremove -y
```

3) **검증**: `ss -tlpn | grep :80` 출력이 비어 있음. `apt list --installed 2>/dev/null | grep nginx` 결과 없음.

4) **⚠️ 함정 포인트**:
- "completely including its configuration files" → `remove`가 아니라 `--purge` 필수.
- 패키지를 지워도 이미 떠 있는 프로세스가 남을 수 있다. 서비스 중지 → 패키지 제거 순서가 안전.
- kubelet의 10250, NodePort 범위(30000-32767) 등 Kubernetes가 쓰는 포트를 건드리지 않도록 대상 확인.

</details>

### Question 7 — SSH 하드닝과 sudo 회수 (SSH/sudo)

```
kubectl config use-context wk8s
ssh wk8s-node-1
```

Task: On node `wk8s-node-1`:

1. Configure the SSH daemon to disallow root login and password authentication, then restart it.
2. The user `jane` currently has sudo privileges. Remove her ability to use sudo, but keep the user account itself.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: `sshd_config` 두 줄 수정 + 재시작, jane의 sudo 경로 3곳(sudo 그룹 / sudoers / sudoers.d) 점검 후 제거.

2) **단계별 명령어**:

```bash
ssh wk8s-node-1
sudo -i

# --- SSH ---
vim /etc/ssh/sshd_config
# PermitRootLogin no
# PasswordAuthentication no
sshd -t && systemctl restart sshd

# --- sudo ---
sudo -l -U jane                 # 현재 권한 확인
getent group sudo               # sudo 그룹 멤버 확인
deluser jane sudo               # 그룹에서 제거
grep -r jane /etc/sudoers /etc/sudoers.d/ 2>/dev/null
# 개별 항목이 있으면 visudo 또는 visudo -f /etc/sudoers.d/파일 로 제거
```

3) **검증**:

```bash
sshd -T | grep -E 'permitrootlogin|passwordauthentication'
sudo -l -U jane    # "not allowed to run sudo" 계열 출력이면 성공
id jane            # 계정은 존재, sudo 그룹 없음
```

4) **⚠️ 함정 포인트**:
- sudo 권한은 그룹 멤버십 외에 `/etc/sudoers`, `/etc/sudoers.d/*`에도 있을 수 있다. `sudo -l -U jane`이 최종 확인 수단.
- 계정 삭제(`userdel`)를 하면 안 된다 — "keep the user account itself".
- sudoers 직접 편집은 반드시 `visudo`로 (문법 깨지면 sudo 전체 마비).

</details>

### Question 8 — 커널 모듈 차단 (커널 모듈)

```
kubectl config use-context cks
ssh cks-node-2
```

Task: On node `cks-node-2`, the kernel modules `sctp` and `dccp` must never be loaded.

1. Unload them if currently loaded.
2. Make sure they cannot be loaded automatically or manually, persistent across reboots.
3. Save the list of currently loaded kernel modules to `/opt/course/8/lsmod.txt` on the node.

<details>
<summary>✅ 정답 및 해설</summary>

1) **접근 방법**: `lsmod` 확인 → `modprobe -r` 언로드 → `/etc/modprobe.d/`에 blacklist + install 등록 → 증거 저장.

2) **단계별 명령어**:

```bash
ssh cks-node-2
sudo -i
mkdir -p /opt/course/8

lsmod | grep -E 'sctp|dccp'
modprobe -r sctp 2>/dev/null || true
modprobe -r dccp 2>/dev/null || true

cat <<EOF > /etc/modprobe.d/blacklist-cks.conf
blacklist sctp
blacklist dccp
install sctp /bin/true
install dccp /bin/true
EOF

lsmod > /opt/course/8/lsmod.txt
```

3) **검증**:

```bash
modprobe sctp          # 에러 없이 종료되지만 실제로는 /bin/true 실행
lsmod | grep sctp      # 출력 없음 → 차단 성공
```

4) **⚠️ 함정 포인트**:
- "manually"까지 차단 → `install 모듈 /bin/true` 줄이 반드시 필요. `blacklist`만으로는 부족.
- 다른 모듈이 의존 중이면 `modprobe -r`이 실패할 수 있다. 그 경우 의존 모듈부터 정리.
- `/etc/modprobe.d/` 파일은 `.conf` 확장자여야 읽힌다.

</details>

---

## 🎯 시험 직전 체크리스트

- [ ] `ss -tlpn` → PID → `/proc/PID/exe` → `systemctl status PID` → `dpkg -S` 역추적 체인을 손이 기억하는가
- [ ] `systemctl disable --now`가 stop+disable 한 방인 것을 아는가
- [ ] "설정 파일까지 제거" = `apt remove --purge` + `apt autoremove`
- [ ] sshd_config: `PermitRootLogin no`, `PasswordAuthentication no` → `sshd -t` → `systemctl restart sshd`
- [ ] sudo 회수는 그룹(`deluser 사용자 sudo`) + `/etc/sudoers` + `/etc/sudoers.d/` 3곳 확인
- [ ] `ufw enable` 전에 22/tcp allow 먼저
- [ ] AppArmor: 프로파일은 `/etc/apparmor.d/`에, 로드는 `apparmor_parser -q`, 확인은 `aa-status`
- [ ] Pod AppArmor는 GA 필드 `securityContext.appArmorProfile`(type: Localhost + localhostProfile: 프로파일이름) — annotation 방식은 deprecated
- [ ] seccomp 프로파일 위치는 `/var/lib/kubelet/seccomp/`, `localhostProfile`은 그 기준 상대경로
- [ ] seccomp 적용 확인: `grep Seccomp /proc/1/status` → 2(filter)
- [ ] 프로파일(AppArmor/seccomp)은 Pod가 스케줄될 노드에 있어야 함 — 없으면 CreateContainerError
- [ ] 커널 모듈 차단은 `blacklist` + `install 모듈 /bin/true` 두 줄, `.conf` 파일로
- [ ] K8s 노드에서 `net.ipv4.ip_forward=1`은 건드리지 않는다
- [ ] 노드 작업 후 `exit`로 base 터미널 복귀했는가

## 핵심 명령어 치트시트

```bash
# ---------- 포트/서비스/패키지 ----------
ss -tlpn                                   # LISTEN 포트 + 프로세스
lsof -i :6666                              # 특정 포트 사용 프로세스
ls -l /proc/<PID>/exe                      # 바이너리 경로 추적
systemctl status <PID>                     # PID → systemd 유닛 역추적
systemctl list-units --type=service --state=running
systemctl disable --now <svc>              # 중지 + 자동시작 해제
dpkg -S /usr/sbin/nginx                    # 파일 → 패키지 역추적
apt remove --purge -y <pkg> && apt autoremove -y

# ---------- IAM / SSH ----------
sudo -l -U jane                            # 사용자 sudo 권한 나열
deluser jane sudo                          # sudo 그룹에서 제거
sshd -t && systemctl restart sshd          # sshd_config 검증 + 재시작
sshd -T | grep -E 'permitrootlogin|passwordauthentication'

# ---------- 방화벽 ----------
ufw allow 22/tcp && ufw deny 8080/tcp && ufw enable
ufw status numbered
iptables -A INPUT -p tcp --dport 8080 -j DROP

# ---------- AppArmor ----------
aa-status                                  # 로드된 프로파일/모드
apparmor_parser -q /etc/apparmor.d/<profile>   # 로드
apparmor_parser -r /etc/apparmor.d/<profile>   # 재로드
# Pod: securityContext.appArmorProfile:
#   type: Localhost / localhostProfile: <프로파일이름>

# ---------- seccomp ----------
mkdir -p /var/lib/kubelet/seccomp/profiles
cp audit.json /var/lib/kubelet/seccomp/profiles/
# Pod: securityContext.seccompProfile:
#   type: Localhost / localhostProfile: profiles/audit.json
kubectl exec <pod> -- grep Seccomp /proc/1/status   # 2 = filter

# ---------- 커널 ----------
lsmod | grep sctp
modprobe -r sctp
printf 'blacklist sctp\ninstall sctp /bin/true\n' > /etc/modprobe.d/blacklist-cks.conf
sysctl -w kernel.dmesg_restrict=1
echo 'kernel.dmesg_restrict=1' >> /etc/sysctl.d/99-cks.conf && sysctl --system
```
