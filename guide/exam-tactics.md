# CKS 실전 조작 플레이북 — 터미널·kubectl·Mac 접속 팁

"무엇을 아느냐"가 아니라 **"제한시간 안에 손으로 어떻게 해내느냐"** 를 다루는 문서다. 시험 규칙·전략·환경 개요·시간 관리는 [00-exam-guide.md](00-exam-guide.md)에 있으니 여기서는 반복하지 않고, **손으로 하는 조작**(특히 Mac에서 접속할 때)을 더 깊게 파고든다. 모든 명령은 Kubernetes v1.35 기준 복붙 실행 가능.

## 목차

1. [시작 직후 60초 세팅](#1-시작-직후-60초-세팅)
2. [⭐ Mac으로 리눅스 시험 환경 접속 — 복사·붙여넣기·키보드](#2--mac으로-리눅스-시험-환경-접속--복사붙여넣기키보드)
3. [dry-run으로 YAML 뼈대 뽑기 → 편집 → apply](#3-dry-run으로-yaml-뼈대-뽑기--편집--apply)
4. [context·namespace 명확히 (0점 방지 1순위)](#4-contextnamespace-명확히-0점-방지-1순위)
5. [잘못했을 때 되돌리기·복구](#5-잘못했을-때-되돌리기복구)
6. [자동완성·alias 확인](#6-자동완성alias-확인)
7. [답안 저장 경로 규칙](#7-답안-저장-경로-규칙)
8. [vim 최소 생존술](#8-vim-최소-생존술)
9. [흔한 사고 체크리스트](#9-흔한-사고-체크리스트)

---

## 1. 시작 직후 60초 세팅

시험이 열리면 문제부터 읽지 말고 **60초만** 아래를 세팅한다. 투자 대비 효과가 가장 크다.

```bash
# YAML(YAML Ain't Markup Language — 사람이 읽는 설정 표기) 생성 단축 변수
export do="--dry-run=client -o yaml"    # k run web --image=nginx $do > pod.yaml
export now="--force --grace-period=0"   # k delete pod web $now  (즉시 삭제)

# vim: YAML 들여쓰기 2칸, 탭을 스페이스로 (붙여넣기 계단현상 방지 겸용)
printf 'set ts=2 sw=2 et\nset ai\n' >> ~/.vimrc

# k alias·자동완성은 대개 이미 되어 있다. 안 되어 있으면 (6장 참고):
alias k=kubectl
source <(kubectl completion bash); complete -o default -F __start_kubectl k
```

> **📌 핵심** — `do`/`now` 변수와 vimrc 두 줄이면 충분하다. tmux 같은 평소 안 쓰던 도구는 시험장에서 쓰지 마라. **세팅에 2분 이상 쓰지 마라.**

---

## 2. ⭐ Mac으로 리눅스 시험 환경 접속 — 복사·붙여넣기·키보드

시험은 PSI(Secure Browser) 안에 **리눅스 XFCE 원격 데스크톱**이 통째로 스트리밍된다. **당신의 MacBook은 화면과 키 입력을 원격으로 "전달"만** 하고, 실제로 도는 것은 리눅스다. 그래서 Mac 습관 그대로 하면 복사·붙여넣기가 안 먹혀 당황한다. 이 절이 이 문서에서 가장 중요하다.

### 2.1 가장 큰 함정 — Cmd ≠ Ctrl

- Mac의 물리 **⌘(Cmd) 키는 리눅스의 Ctrl로 자동 매핑되지 않는다.** 원격 리눅스 안에서는 **왼쪽 아래 `Ctrl`(⌃) 키**를 써야 한다.
- 즉 `⌘C`·`⌘V`(Mac 복사/붙여넣기 근육기억)는 원격 안에서 대개 아무것도 안 하거나 엉뚱하게 동작한다. **⌘이 아니라 `Ctrl`을 눌러라.** Mac은 `Ctrl`이 맨 왼쪽 아래 구석에 있고 엄지로 누르던 `⌘` 바로 옆이라, 시작 직후 손에 익혀둬야 한다.

> **💡 대안 — ⌘을 Ctrl로 리매핑 (많은 합격 후기의 1순위)** — macOS `시스템 설정 → 키보드 → 키보드 단축키 → 보조 키(Modifier Keys)`에서 **⌘(Command)를 Control로** 바꾸면 로컬 OS 레벨에서 변환돼 PSI로 전달되므로 ⌘ 근육기억을 그대로 쓸 수 있다. 단 ⓐ 리매핑해도 터미널 복사는 여전히 `Shift`가 필요하고(리매핑 후 기준 `⌘+Shift+C`), `⌘+C` 단독은 여전히 SIGINT다. ⓑ 로컬 Mac 전체 단축키에 영향을 주니 **시험용으로만 켰다 끄는 것**을 권한다.

### 2.2 어디서 무엇으로 복사·붙여넣기 하나

| 상황 | 복사 | 붙여넣기 | 비고 |
|---|---|---|---|
| 터미널 안 → 터미널 | `Ctrl+Shift+C` | `Ctrl+Shift+V` | 터미널에서 `Ctrl+C`는 **복사 아님 = 실행 중 프로세스 중단(SIGINT)** |
| Firefox(허용 문서) → 터미널 | Firefox에서 `Ctrl+C` | 터미널에서 `Ctrl+Shift+V` | 같은 원격 데스크톱 안이라 클립보드 공유됨 |
| 문제 지문 → 터미널 | 드래그 선택 후 `Ctrl+C` | `Ctrl+Shift+V` | 리소스명·경로는 **반드시 복사**(오타 = 0점) |
| 어디서든 | 텍스트 드래그 선택 후 **마우스 우클릭 → Copy/Paste** | 우클릭 메뉴 | 단축키가 헷갈리면 우클릭이 가장 확실 |

> **⚠️ 로컬 Mac ↔ 원격 클립보드는 원칙적으로 안 넘어간다**(보안 격리). 그럴 필요도 없다 — 허용 문서(kubernetes.io 등)가 전부 원격 데스크톱 안 Firefox에 있으므로, 복사는 항상 "원격 안 → 원격 안"이다. 로컬 메모장에 미리 답을 적어두고 붙여넣는 전략은 통하지 않는다.

> **💡 터미널 설정 팁** — XFCE 터미널 환경설정에서 **'Copy on Select'(드래그 선택만 하면 복사)** 와 **'Paste on Right Click'(우클릭 붙여넣기)** 를 켜면 단축키 없이도 빠르다. 시작 직후 켜두면 손이 편하다.

### 2.3 Mac 특유의 조용한 사고 — 스마트 따옴표·대시

2.2대로 클립보드가 격리돼 있으면 이 문제는 대개 안 생긴다. 하지만 환경에 따라 클립보드 브리지가 열려 있거나 어떤 경로로든 로컬 텍스트가 들어오면, macOS가 자동 변환한 문자 때문에 명령/YAML이 깨진다. 로컬 앱(메모, TextEdit 등, 스마트 치환이 켜진 표준 텍스트 앱)에서 타이핑한 뒤 옮기면 특히 그렇다:

- 곧은 따옴표 `"` `'` → 굽은 따옴표 `"` `"` `'` (YAML·bash에서 문법 오류)
- 하이픈 두 개 `--` → em-dash `—` (`--dry-run`이 `—dry-run`으로 바뀜)

→ **원격 데스크톱 안에서 직접 타이핑·편집**하면 이 문제가 없다. 굳이 로컬에서 준비하지 마라. (로컬에서 준비할 수밖에 없다면 "설정 → 키보드 → 스마트 따옴표/대시 끄기".)

### 2.4 vim에 여러 줄 붙여넣을 때 — 계단현상

여러 줄 YAML을 vim에 그냥 붙여넣으면 자동 들여쓰기가 누적돼 계단처럼 밀린다. **붙여넣기 전에 `:set paste`**, 붙여넣고 `:set nopaste`. (1장 vimrc의 `set ai`를 쓸 때 특히.)

### 2.5 시작 30초 안에 이걸 테스트하라

```bash
echo hello                    # 이 줄을 드래그 선택 → Ctrl+Shift+C
                              # 새 줄에서 Ctrl+Shift+V 로 붙여지는지 확인
kubectl get ns                # Firefox 문서에서 한 단어 복사 → 여기 붙여넣기 테스트
```

- **복사 후 1~2초 기다렸다 붙여넣어라.** 원격 데스크톱은 클립보드 반영에 약간의 지연이 있어, 복사하자마자 붙여넣으면 **이전 클립보드 내용**이 붙는 사고가 잦다.

> **⚠️ 환경 주의** — PSI 버전·연도에 따라 클립보드 동작이 조금씩 다르다(별도 "클립보드" 패널이 뜨는 버전도 있었다). **위 테스트를 시작 직후 반드시 직접 해보고** 내 손에 맞는 방법을 확정하라. 시험 도중에 처음 시도하면 시간을 잃는다.

---

## 3. dry-run으로 YAML 뼈대 뽑기 → 편집 → apply

처음부터 YAML을 손으로 치지 않는다. **명령형(imperative)으로 뼈대를 뽑고 → 필요한 것만 편집 → 선언형(declarative)으로 apply** 가 표준 동선이다.

```bash
# 1) 뼈대 생성 (파일로 저장)
k run web --image=nginx $do > web.yaml
# 2) 편집 (securityContext, resources, volume 등 문제 요구사항 추가)
vim web.yaml
# 3) 적용
k apply -f web.yaml
# 4) 확인
k get pod web -o wide
```

### 리소스별 뼈대 생성 명령

| 리소스 | 명령 (뒤에 `$do` 붙여 파일로) |
|---|---|
| Pod | `k run web --image=nginx` |
| Deployment | `k create deploy web --image=nginx --replicas=3` |
| Job / CronJob | `k create job j --image=busybox -- sleep 1` / `k create cronjob c --image=busybox --schedule="*/1 * * * *" -- date` |
| Service(ClusterIP) | `k expose deploy web --port=80` 또는 `k create service clusterip web --tcp=80:80` |
| ConfigMap / Secret | `k create configmap cm --from-literal=k=v` / `k create secret generic s --from-literal=pw=1234` |
| Role / RoleBinding | `k create role r --verb=get,list --resource=pods` / `k create rolebinding rb --role=r --serviceaccount=ns:sa` |
| ServiceAccount | `k create sa build-sa` |
| Namespace | `k create ns team-a` |

> **📌 생성 명령이 없는 리소스**(NetworkPolicy, PersistentVolume, EncryptionConfiguration, RuntimeClass, PeerAuthentication 등)는 dry-run으로 못 뽑는다 → **허용 문서(kubernetes.io/docs)에서 예제 YAML을 복사**해 수정하는 것이 정석이다. 그래서 2장의 복사·붙여넣기가 중요하다.

> **💡 서버 사이드 dry-run** — `--dry-run=server`는 실제 admission(예: Pod Security Admission)까지 거쳐 **거부 여부를 미리** 보여준다. restricted 네임스페이스에 Pod가 통과할지 배포 전에 확인할 때 유용하다.

---

## 4. context·namespace 명확히 (0점 방지 1순위)

**틀린 클러스터에서 작업하면 그 문제는 통째로 0점**이다. CKS에서 가장 억울한 실점이 이것이다.

```bash
# 매 문제 첫 줄 — 문제 지문에 적힌 context로 전환 (거의 항상 지문에 주어진다)
k config use-context <문제가 준 이름>

# 지금 어느 클러스터인지 확인
k config current-context
k config get-contexts          # 전체 목록·현재(*) 표시

# 이 문제 내내 쓸 namespace 고정 (매번 -n 치기 싫으면)
k config set-context --current --namespace=<ns>
# 그러면 이후 -n 생략 가능. 확인:  k config view --minify | grep namespace
```

- namespace를 고정하기 애매하면 **모든 명령에 `-n <ns>`를 명시**하는 편이 더 안전하다(잘못된 기본 ns에서 리소스를 못 찾아 헤매는 사고 방지).
- **노드에 `ssh`로 들어갔다 나와도 context는 그대로**다. 단, ssh 세션 안에서는 1장 세팅(alias·변수)이 없다 — 노드에선 짧게 작업하고 바로 `exit`.
- 프롬프트에 현재 context를 띄우고 싶으면 `kubectl config current-context`를 한 번 눈으로 확인하는 습관이 더 빠르다(굳이 프롬프트 커스터마이즈에 시간 쓰지 마라).

---

## 5. 잘못했을 때 되돌리기·복구

시험은 **최종 상태로 채점**하므로, 손댄 게 잘못됐으면 원복이 곧 점수다. 핵심은 **건드리기 전에 백업**.

### 5.1 백업 먼저 (특히 시스템 파일)

```bash
# 리소스는 손대기 전에 현재 상태를 파일로
k get deploy web -o yaml > web.bak.yaml

# static pod·시스템 설정은 반드시 복사본 (노드에서 sudo)
sudo cp /etc/kubernetes/manifests/kube-apiserver.yaml ~/kube-apiserver.yaml.bak
sudo cp /var/lib/kubelet/config.yaml ~/kubelet-config.yaml.bak
```

### 5.2 흔한 되돌리기

| 상황 | 되돌리기 |
|---|---|
| Deployment를 잘못 바꿈 | `k rollout undo deploy/web` (이전 리비전으로) · `k rollout history deploy/web` |
| 리소스를 원하는 형태로 갈아끼우기 | `k replace --force -f web.yaml` (지우고 재생성) |
| 방금 만든 걸 지우기 | `k delete -f web.yaml` 또는 `k delete <종류> <이름>` |
| `k edit` 잘못 저장 | 백업본을 `k apply -f *.bak.yaml`로 덮어쓰기 |
| NetworkPolicy로 통신이 다 막힘 | `k delete netpol <이름>` 후 다시 작성 |

### 5.3 apiserver를 깨뜨렸을 때 (가장 무서운 상황)

`kube-apiserver.yaml`(static pod)에 오타·잘못된 플래그를 넣으면 apiserver가 CrashLoop에 빠지고 **`kubectl` 자체가 먹통**이 된다. 침착하게:

```bash
# 노드(control plane)에서, root로
sudo crictl ps -a | grep apiserver          # 컨테이너가 죽어 있는지/재시작 반복인지 확인
sudo crictl logs <apiserver_container_id>    # 실패 원인 로그

# 응급 복구: manifest를 폴더 밖으로 빼면 kubelet이 apiserver를 내린다
sudo mv /etc/kubernetes/manifests/kube-apiserver.yaml /tmp/
# → 백업본으로 되돌리거나(권장) /tmp/에서 오타를 고친 뒤
sudo cp ~/kube-apiserver.yaml.bak /etc/kubernetes/manifests/kube-apiserver.yaml
# kubelet이 새 manifest를 감지해 apiserver를 다시 띄운다 (30초~1분)
watch "sudo crictl ps | grep apiserver"      # Running 될 때까지 (파이프 전체를 watch가 실행하도록 따옴표)
```

> **📌 원리** — control plane 구성요소는 **static pod**라 Deployment처럼 롤백이 없다. kubelet이 `/etc/kubernetes/manifests/`를 감시하다가 파일이 있으면 띄우고 없으면 내린다. 그래서 "파일을 빼고 → 고치고 → 다시 넣기"가 복구의 전부다.

### 5.4 kubelet을 깨뜨렸을 때

`/var/lib/kubelet/config.yaml`을 잘못 고쳐 노드가 NotReady가 되면: 백업 복원 후 서비스 재시작. **kubelet은 static pod가 아니므로 반드시 재시작해야 반영된다.**

```bash
sudo cp ~/kubelet-config.yaml.bak /var/lib/kubelet/config.yaml
sudo systemctl restart kubelet
sudo systemctl status kubelet          # active (running) 확인
```

---

## 6. 자동완성·alias 확인

- 최근 CKS/CKA 환경은 **`alias k=kubectl`과 자동완성이 대개 미리 설정**돼 있다. 시작하자마자 `k get ns` 입력 후 `Tab`을 눌러 완성되는지 확인하라.
- 안 되어 있으면 아래 3줄(1장에도 포함):

```bash
alias k=kubectl
source <(kubectl completion bash)
complete -o default -F __start_kubectl k     # alias 'k'에도 완성 붙이기
```

- 자동완성은 **리소스 이름까지** 완성해준다(`k get pod <Tab>`). 오타로 인한 0점을 줄이는 실질적 도구다.
- ssh로 들어간 노드에는 이 설정이 없다. 노드 작업은 완성 없이 짧게.

---

## 7. 답안 저장 경로 규칙

- 문제가 "파일을 `/opt/course/<번호>/...`에 저장하라"고 하면 **그 경로·파일명 그대로** 저장한다. 경로/이름이 틀리면 채점 스크립트가 못 찾아 **0점**이다.
- 저장 직후 확인: `ls -l /opt/course/<번호>/` 로 파일이 정확한 이름·위치인지 눈으로 본다.
- 출력을 파일로 뽑는 문제(예: `trivy` 스캔 결과, 취약 이미지 목록)는 리다이렉트 경로를 특히 조심하라: `trivy image nginx:1.19 > /opt/course/3/scan.txt`.

---

## 8. vim 최소 생존술

빈 파일에서 YAML을 만들고 고칠 최소한만:

| 하고 싶은 것 | 키 |
|---|---|
| 입력 모드 / 빠져나오기 | `i` / `Esc` |
| 저장 후 종료 / 강제 종료 | `:wq` / `:q!` |
| 방금 동작 취소 / 다시 | `u` / `Ctrl+r` |
| 한 줄 삭제 / 복사 / 붙여넣기 | `dd` / `yy` / `p` |
| 검색 / 치환(전체) | `/문자열` 후 `n` / `:%s/old/new/g` |
| 줄 번호 표시 | `:set number` |
| 여러 줄 붙여넣기 전 (2.4 참고) | `:set paste` → 붙여넣기 → `:set nopaste` |

> **📌 YAML은 들여쓰기가 생명** — 1장 vimrc의 `set ts=2 sw=2 et`로 탭을 2칸 스페이스로 강제하라. 들여쓰기 한 칸이 틀리면 `apply`가 조용히 다른 의미로 먹거나 거부된다.

---

## 9. 흔한 사고 체크리스트

문제를 넘기기 전에 이 목록을 30초 안에 훑어라(상세 검증 루틴은 [00-exam-guide.md](00-exam-guide.md)의 "30초 검증 루틴" 참고).

- [ ] **context를 바꿨는가?** (`k config current-context`) — 안 바꾸면 0점
- [ ] **namespace가 맞는가?** (`-n` 또는 set-context)
- [ ] 만들기만 하고 **`apply`를 안 한 리소스**는 없는가?
- [ ] 파일을 **지시된 경로·이름**(`/opt/course/...`)에 저장했는가?
- [ ] apiserver/kubelet 설정을 바꿨으면 **재기동·반영**됐는가? (static pod는 자동, kubelet은 `systemctl restart`)
- [ ] 리소스 이름·라벨에 **오타**는 없는가? (복사해서 쓰기)
- [ ] Mac에서 붙여넣은 명령에 **스마트 따옴표/em-dash**가 섞이지 않았는가? (2.3)
- [ ] 문제에 지정된 **호스트 외에 ssh**로 들어가지 않았는가? (규정)

---

> 이 문서는 조작 요령에 집중한다. 시험 규정·시간 배분·도메인별 지식은 [00-exam-guide.md](00-exam-guide.md)와 [../domains/](../domains/) 개념서를, 명령 요약은 `/cheatsheet` 스킬을 함께 쓰라.
