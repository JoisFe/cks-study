# CKS Domain 1 — Cluster Setup

클러스터를 처음부터 안전하게 구성하는 도메인으로, NetworkPolicy, CIS Benchmark(kube-bench), Ingress TLS, 노드 메타데이터 보호, 플랫폼 바이너리 검증을 다룬다.

> 📌 **시험 비중: 15%** — 16문제 기준 약 2~3문제가 출제된다. 특히 NetworkPolicy는 Domain 1뿐 아니라 메타데이터 차단, 마이크로서비스 격리 등 다른 도메인 문제에도 반복 등장하므로 CKS 전체에서 투자 대비 효율이 가장 높은 주제다. 시험은 2시간 / 15~20개 hands-on 과제 / 합격선 67% / Kubernetes v1.35 환경(containerd, Ubuntu 노드)이다.

## 목차

1. [NetworkPolicy 완전 정복](#1-networkpolicy-완전-정복)
2. [CIS Benchmark와 kube-bench](#2-cis-benchmark와-kube-bench)
3. [Ingress TLS](#3-ingress-tls)
4. [노드 메타데이터 보호](#4-노드-메타데이터-보호)
5. [플랫폼 바이너리 검증](#5-플랫폼-바이너리-검증)
6. [실전 연습문제 10제](#6-실전-연습문제-10제)
7. [🎯 시험 직전 체크리스트](#7--시험-직전-체크리스트)
8. [핵심 명령어 치트시트](#8-핵심-명령어-치트시트)

---

## 1. NetworkPolicy 완전 정복

> **📖 오픈북 — 공식 문서에서 찾기** — 시험 중 `kubernetes.io/docs`를 볼 수 있다. 검색창에 **`network policy`** 입력 → **"Network Policies"** 개념 페이지(`concepts/services-networking/network-policies`)로 간다. 페이지 안에 **default-deny 스니펫**과 `podSelector`/`ingress`·`egress`/`ports`가 다 들어간 **full 예제 YAML**이 있으니, 이걸 복사해 라벨·포트만 문제에 맞게 바꾸는 게 가장 빠르다. `ipBlock` 예시도 같은 페이지에서 `Ctrl+F ipBlock`으로 바로 찾는다. (단 DNS 53 egress 허용 블록은 이 페이지에 없으니 §1.6 패턴으로 직접 작성한다.)

### 1.1 동작 원리 — CNI가 시행한다

NetworkPolicy는 Kubernetes API 오브젝트(원하는 상태를 선언해 두는 설정)일 뿐이며, 실제 트래픽 차단은 **CNI**(Container Network Interface — 파드 간 네트워크를 실제로 구현하는 플러그인 규격, Calico·Cilium 등)가 수행한다. NetworkPolicy를 지원하지 않는 CNI(예: flannel 단독)에서는 정책을 만들어도 아무 효과가 없다. 시험 클러스터는 항상 시행 가능한 CNI를 사용하므로 걱정할 필요는 없지만, "왜 정책이 안 먹히지?"라는 상황의 첫 번째 원인이 CNI라는 점은 알아두자.

동작 규칙 세 가지가 모든 문제의 출발점이다.

1. **화이트리스트 모델**: 어떤 Pod가 NetworkPolicy에 의해 select되면(셀렉터로 정책의 적용 대상이 되면), 해당 `policyTypes` 방향(**Ingress**=파드로 들어오는 트래픽, **Egress**=파드에서 나가는 트래픽)의 트래픽은 기본 차단되고 정책에 나열된 규칙만 허용된다.
2. **합집합(additive)**: 같은 Pod를 select하는 정책이 여러 개면 허용 규칙은 모두 합쳐진다(OR). "차단 규칙"이라는 것은 존재하지 않는다 — 허용을 좁게 정의해서 차단을 만든다.
3. **select되지 않은 Pod는 모든 트래픽 허용**: 정책이 하나도 걸리지 않은 Pod는 기본적으로 완전 개방 상태다.

> **📌 암기 포인트** — `policyTypes`를 명시하지 않으면 `egress` 섹션이 있어도 Egress가 시행되지 않는 실수가 나온다. **항상 `policyTypes`를 명시**하라.

### 1.2 default-deny 3종 세트

가장 빈출되는 기본형이다. 세 가지 모두 안 보고 쓸 수 있어야 한다.

```yaml
# 1) 네임스페이스 내 모든 Pod의 ingress 차단
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: team-a
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

```yaml
# 2) 네임스페이스 내 모든 Pod의 egress 차단
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: team-a
spec:
  podSelector: {}
  policyTypes:
    - Egress
```

```yaml
# 3) ingress + egress 모두 차단
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: team-a
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

> **💡 시험 팁** — `podSelector: {}`(빈 셀렉터)는 "해당 네임스페이스의 **모든** Pod"를 의미한다. `spec`에 `ingress`/`egress` 섹션이 아예 없으면 해당 방향은 "아무것도 허용하지 않음" = 전면 차단이다.

### 1.3 허용 규칙 작성 기본형

frontend → backend:8080만 허용하는 전형적인 형태다. 완성본을 통째로 외우지 말고 **뼈대에서 필드를 채워나가는 순서**로 익히면 실전에서 빠르게 재현할 수 있다.

> **🛠 실전에서 이 YAML 만드는 법** — NetworkPolicy는 Pod·Deployment와 달리 `kubectl create`로 뽑는 **생성 명령이 없다**(dry-run 생성 불가). 그래서 **최소 뼈대에서 채운다**: 1.2의 default-deny를 복사하거나 kubernetes.io/docs의 "Network Policies" 예제를 복사해, 아래 `①→⑤` 순서로 채운 뒤 `k apply -f backend-allow.yaml`로 적용한다.

```yaml
apiVersion: networking.k8s.io/v1        # ① 뼈대: apiVersion / kind 는 고정값
kind: NetworkPolicy
metadata:
  name: backend-allow
  namespace: moon                       #    (대상 네임스페이스)
spec:
  podSelector:                          # ② 정책 대상 = 트래픽을 받는 backend
    matchLabels:
      app: backend
  policyTypes:                          # ③ 제어할 방향 (여기선 들어오는 Ingress)
    - Ingress
  ingress:                              # ④ '허용 규칙' 시작 — 이 블록이 없으면 전면 차단
    - from:
        - podSelector:                  #    상대방(peer) = frontend
            matchLabels:
              app: frontend
      ports:                            # ⑤ 허용 포트 (from 과 형제 레벨!)
        - protocol: TCP
          port: 8080
```

- `spec.podSelector`: 정책이 **적용되는 대상**(트래픽을 받는/보내는 쪽).
- `from`/`to`: 상대방(peer). `podSelector`가 단독으로 오면 **정책과 같은 네임스페이스**의 Pod만 의미한다.
- `ports`는 `from`/`to`와 **형제 레벨**(같은 규칙 항목 안)이다. 들여쓰기를 틀리면 의미가 완전히 달라진다.

### 1.4 최다 빈출 함정 — namespaceSelector와 podSelector의 AND vs OR

**대시(`-`) 하나 차이로 의미가 완전히 달라진다.** CKS에서 가장 많이 틀리는 지점이므로 두 예시를 나란히 비교해서 외우자.

**예시 A — AND (한 peer 항목 안에 두 셀렉터):** "라벨 `env=prod`가 붙은 네임스페이스에 있으면서 **동시에** 라벨 `role=api`가 붙은 Pod"만 허용.

```yaml
ingress:
  - from:
      - namespaceSelector:
          matchLabels:
            env: prod
        podSelector:          # 앞에 대시 없음 → 위 namespaceSelector와 한 항목 = AND
          matchLabels:
            role: api
```

**예시 B — OR (별개 peer 항목 두 개):** "`env=prod` 네임스페이스의 **모든** Pod" **또는** "**현재 네임스페이스**의 `role=api` Pod" 허용.

```yaml
ingress:
  - from:
      - namespaceSelector:
          matchLabels:
            env: prod
      - podSelector:          # 대시 있음 → 별개 항목 = OR
          matchLabels:
            role: api
```

| 구분 | 예시 A (AND) | 예시 B (OR) |
|------|--------------|-------------|
| YAML 구조 | peer 1개 안에 selector 2개 | peer 2개 |
| `role=api`인데 dev 네임스페이스의 Pod | ❌ 차단 | ❌ 차단 (단독 `podSelector`는 정책 네임스페이스만 해당) |
| prod 네임스페이스의 `role=web` Pod | ❌ 차단 | ✅ 허용 |
| prod 네임스페이스의 `role=api` Pod | ✅ 허용 | ✅ 허용 |

> **⚠️ 함정** — 예시 B의 단독 `podSelector`는 "모든 네임스페이스의 role=api"가 아니라 "**정책이 있는 네임스페이스**의 role=api"다. 다른 네임스페이스의 특정 Pod만 허용하려면 반드시 AND 형태(예시 A)를 써야 한다.

> **💡 시험 팁** — 특정 네임스페이스 하나를 지목할 때는 자동 생성 라벨 `kubernetes.io/metadata.name: <네임스페이스명>`을 쓰면 라벨을 따로 붙일 필요가 없다. `kubectl get ns --show-labels`로 확인.

### 1.5 ipBlock과 except

CIDR(Classless Inter-Domain Routing — IP 대역을 접두 길이로 표기하는 방식, 예: 10.0.0.0/16) 기반 허용에 예외 대역을 뚫는 패턴. 메타데이터 차단(4장)의 핵심이기도 하다.

```yaml
egress:
  - to:
      - ipBlock:
          cidr: 10.0.0.0/16
          except:
            - 10.0.5.0/24
```

"10.0.0.0/16 전체로 나가는 것은 허용하되 10.0.5.0/24만 제외"라는 뜻이다. `except`는 반드시 `cidr`의 부분집합이어야 한다.

### 1.6 egress 정책의 필수 동반자 — DNS 허용

egress를 잠그는 순간 DNS(Domain Name System — 서비스·도메인 이름을 IP 주소로 해석) 질의(UDP/TCP 53)도 함께 막혀서 서비스명 해석이 실패한다. **egress 정책에는 거의 항상 DNS 허용을 추가**해야 한다.

```yaml
# 간단형: 모든 목적지로 53 포트 허용 (to 생략 = 목적지 무제한, 포트만 제한)
egress:
  - ports:
      - protocol: UDP
        port: 53
      - protocol: TCP
        port: 53
```

```yaml
# 엄격형: kube-system의 kube-dns Pod로만 53 허용
egress:
  - to:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: kube-system
        podSelector:
          matchLabels:
            k8s-app: kube-dns
    ports:
      - protocol: UDP
        port: 53
      - protocol: TCP
        port: 53
```

> **⚠️ 함정** — 문제에서 "DNS는 계속 동작해야 한다(DNS resolution must still work)"는 문구가 나오면 위 블록을 추가하라는 신호다. 문구가 없어도 egress 정책 때문에 검증 단계에서 서비스명 접근이 실패하면 DNS부터 의심하라.

### 1.7 빈출 시나리오 요약

| 시나리오 | 핵심 구성 |
|----------|-----------|
| 네임스페이스 격리(default deny) | `podSelector: {}` + `policyTypes` |
| 특정 앱 간 통신만 허용 | 대상 `podSelector` + `from.podSelector` + `ports` |
| 다른 네임스페이스의 특정 Pod만 허용 | AND 형태(한 peer에 ns+pod selector) |
| 여러 출처 허용 | OR 형태(peer 여러 개) |
| 외부 CIDR 제한 | `ipBlock.cidr` + `except` |
| 메타데이터 서버 차단 | `cidr: 0.0.0.0/0` + `except: 169.254.169.254/32` |
| egress 잠금 | default-deny egress + DNS 53 허용 |

검증에 쓰는 명령:

```bash
kubectl -n moon describe networkpolicy backend-allow
# 임시 Pod로 연결 테스트 (성공/타임아웃 확인)
kubectl -n moon run tmp --rm -it --restart=Never --image=busybox:1.36 -- \
  wget -qO- --timeout=2 http://backend:8080
```

### 📝 문제로 이해하기

> Solve this task on: `kubectl config use-context cluster1`
>
> In namespace `mars` there are pods labeled `app=web` listening on TCP port 80. Create a NetworkPolicy named `allow-app` in namespace `mars` that allows incoming traffic to the `app=web` pods **only** from pods labeled `app=frontend` in the same namespace, and **only** on TCP port 80. All other ingress traffic to the `app=web` pods must be denied. Save the manifest to `/opt/course/m1/allow-app.yaml` and apply it.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — 대상은 `app=web`(spec.podSelector), 허용 peer는 같은 네임스페이스이므로 단독 `podSelector`면 충분하다. `policyTypes: [Ingress]`를 명시하면 나열된 규칙 외 ingress는 자동 차단된다.

**2) 단계별 명령어/YAML**

```bash
kubectl config use-context cluster1
mkdir -p /opt/course/m1
cat > /opt/course/m1/allow-app.yaml <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app
  namespace: mars
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 80
EOF
kubectl apply -f /opt/course/m1/allow-app.yaml
```

**3) 검증 방법**

```bash
kubectl -n mars describe netpol allow-app
# frontend 라벨 Pod에서는 성공해야 함
kubectl -n mars run test-ok --rm -it --restart=Never \
  --labels=app=frontend --image=busybox:1.36 -- wget -qO- --timeout=2 http://<web-pod-ip>
# 라벨 없는 Pod에서는 타임아웃이어야 함
kubectl -n mars run test-deny --rm -it --restart=Never \
  --image=busybox:1.36 -- wget -qO- --timeout=2 http://<web-pod-ip>
```

**4) ⚠️ 함정 포인트**

- `ports`를 `from`의 하위(peer 안)로 들여쓰면 API가 거부하거나 의도와 다른 정책이 된다. `- from:`과 같은 레벨에 `ports:`를 두어야 한다.
- `policyTypes`를 빼먹으면 ingress 섹션이 있으니 이 경우엔 동작하지만, 습관적으로 항상 명시하는 편이 안전하다.
- 문제에서 파일 저장 경로를 지정하면 **적용까지** 해야 채점된다. 저장만 하고 apply를 잊지 말 것.

</details>

---

## 2. CIS Benchmark와 kube-bench

### 2.1 개념

> **📖 오픈북** — kube-bench(Aqua Security)와 CIS Benchmark 원문 사이트는 허용 문서 8개에 없다 → 실행 옵션(`--targets`, `--check`)·결과 읽는 법·빈출 Remediation을 미리 암기한다(수정 근거가 되는 플래그·설정은 kubernetes.io/docs·etcd.io/docs에서 확인 가능).

CIS(Center for Internet Security) Kubernetes Benchmark는 컨트롤 플레인/노드 컴포넌트의 보안 설정 기준 문서다. **kube-bench**(Aqua Security)는 이 기준으로 클러스터를 자동 점검하는 도구로, 시험에서는 "kube-bench를 실행해 실패 항목을 찾아 수정하라"는 형태로 출제된다. **실패 항목의 번호를 찾아 Remediation 섹션의 지시를 그대로 적용하는 것**이 풀이의 전부다.

### 2.2 실행 방법

시험 환경에서는 보통 노드에 kube-bench 바이너리가 미리 설치되어 있다.

```bash
# 컨트롤 플레인 노드에서 (ssh 후 root 권한)
kube-bench run --targets=master

# 워커 노드에서
kube-bench run --targets=node

# 특정 체크만 다시 실행 (수정 후 확인용)
kube-bench run --targets=master --check 1.2.18

# FAIL만 빠르게 추리기
kube-bench run --targets=master | grep -A1 '\[FAIL\]'
```

바이너리가 없다면 Job 방식으로도 실행할 수 있다(인터넷이 되는 연습 환경용).

```bash
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl wait --for=condition=complete job/kube-bench --timeout=120s
kubectl logs job/kube-bench
```

### 2.3 결과 읽는 법

출력은 `[PASS]/[FAIL]/[WARN]/[INFO]` + 체크 번호 + 설명으로 구성되고, 마지막에 `== Remediations ==` 섹션이 번호별 수정 방법을 알려준다.

```text
[FAIL] 1.2.18 Ensure that the --profiling argument is set to false (Automated)

== Remediations master ==
1.2.18 Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml
on the control plane node and set the below parameter.
--profiling=false
```

> **💡 시험 팁** — 체크 번호는 벤치마크 버전에 따라 달라질 수 있으므로 번호 자체를 외우지 말고, **FAIL 번호를 grep → 같은 번호의 Remediation을 읽고 그대로 적용**하는 절차를 몸에 익혀라.

### 2.4 빈출 수정 항목 총정리

> **📖 오픈북 — 문서에서 찾기** — kubelet 항목(anonymous/webhook/authorization/readOnlyPort)은 `kubernetes.io/docs`에서 **`kubelet authentication authorization`** 검색 → **"Kubelet authentication/authorization"** 레퍼런스에서 각 플래그 근거를 확인한다. etcd `--client-cert-auth`는 `etcd.io/docs`에서 **`transport security`** 검색 → **"Transport security model"**. apiserver/cm/scheduler 플래그는 kubernetes.io/docs의 각 컴포넌트 레퍼런스에서 플래그명으로 검색.

| 컴포넌트 | 점검 항목 | 수정 내용 | 파일 |
|----------|-----------|-----------|------|
| kube-apiserver | anonymous-auth | `--anonymous-auth=false` | `/etc/kubernetes/manifests/kube-apiserver.yaml` |
| kube-apiserver | profiling | `--profiling=false` | 위와 동일 |
| kube-apiserver | admission plugins | `--enable-admission-plugins=NodeRestriction` | 위와 동일 |
| kube-apiserver | SA lookup | `--service-account-lookup=true` | 위와 동일 |
| etcd | client cert auth | `--client-cert-auth=true` | `/etc/kubernetes/manifests/etcd.yaml` |
| kubelet | anonymous auth | `authentication.anonymous.enabled: false` | `/var/lib/kubelet/config.yaml` |
| kubelet | webhook auth | `authentication.webhook.enabled: true` | 위와 동일 |
| kubelet | authorization | `authorization.mode: Webhook` (AlwaysAllow 금지) | 위와 동일 |
| kubelet | read-only port | `readOnlyPort: 0` | 위와 동일 |
| controller-manager | profiling | `--profiling=false` | `/etc/kubernetes/manifests/kube-controller-manager.yaml` |
| controller-manager | bind address | `--bind-address=127.0.0.1` | 위와 동일 |
| scheduler | profiling / bind | `--profiling=false`, `--bind-address=127.0.0.1` | `/etc/kubernetes/manifests/kube-scheduler.yaml` |

kubelet 하드닝 후의 config.yaml 핵심 부분:

> **🛠 만드는 법** — 이건 `kubectl create`로 뽑는 API 리소스가 아니라 노드의 kubelet 설정 파일(`/var/lib/kubelet/config.yaml`)이다. 새로 생성하지 말고 이미 있는 파일에서 아래 키만 편집한다(스키마는 kubernetes.io의 KubeletConfiguration 문서 참고).

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
readOnlyPort: 0
```

```bash
# kubelet은 static pod가 아니므로 반드시 서비스 재시작
systemctl restart kubelet
systemctl status kubelet
```

### 2.5 static pod 수정 절차와 디버깅

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`static pod`** 검색 → **"Create static Pods"** → static pod manifest 경로(`/etc/kubernetes/manifests/`)와 kubelet 자동 재생성 동작을 확인한다(`crictl`/`journalctl` 디버깅 명령 자체는 허용 문서에 없으니 암기).

`/etc/kubernetes/manifests/`의 매니페스트를 저장하면 kubelet이 해당 static pod를 자동으로 재생성한다(**30초~1분 대기**). 조급하게 여러 번 수정하지 말고 기다렸다가 확인하라.

```bash
# 수정 전 백업은 manifests 디렉토리 밖에!
cp /etc/kubernetes/manifests/kube-apiserver.yaml /root/kube-apiserver.yaml.bak
vim /etc/kubernetes/manifests/kube-apiserver.yaml

# 재기동 확인
watch crictl ps          # kube-apiserver 컨테이너가 새로 뜨는지
kubectl get nodes        # API 응답 확인
```

apiserver가 다시 안 뜰 때의 디버깅 순서:

```bash
crictl ps -a                            # Exited 상태의 apiserver 컨테이너 확인
crictl logs <container-id>              # 에러 메시지 (플래그 오타가 대부분)
journalctl -u kubelet | tail -50        # kubelet이 manifest 파싱에 실패한 경우
ls /var/log/pods/                       # 컨테이너 로그 파일 직접 확인
```

> **⚠️ 함정** — 백업 파일을 `/etc/kubernetes/manifests/` 안에 두면 kubelet이 백업본까지 static pod로 띄우려 해서 충돌한다. 백업은 반드시 다른 디렉토리에 저장하라.

> **⚠️ 함정** — `--anonymous-auth=false` 적용 후 apiserver 헬스 프로브가 익명 접근에 의존하는 구성이라면 재시작 루프가 생길 수 있다. 적용 후 `crictl ps`로 안정적으로 Running인지 반드시 확인하고, 문제가 생기면 로그를 보고 원복/재조정하라.

### 📝 문제로 이해하기

> Solve this task on: `kubectl config use-context cluster2`
>
> Connect to the worker node with `ssh cluster2-node1`. Run kube-bench against the node target. Fix the following failed checks by editing the kubelet configuration: anonymous authentication must be disabled, authorization mode must not be AlwaysAllow, and the read-only port must be disabled. Restart the kubelet afterwards and confirm the node stays `Ready`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — kubelet 관련 3대 하드닝(anonymous / authorization / readOnlyPort)은 모두 `/var/lib/kubelet/config.yaml` 한 파일에서 수정하고 `systemctl restart kubelet`으로 반영한다.

**2) 단계별 명령어/YAML**

```bash
ssh cluster2-node1
sudo -i
kube-bench run --targets=node | grep -A1 '\[FAIL\]'

vim /var/lib/kubelet/config.yaml
```

```yaml
# /var/lib/kubelet/config.yaml 에서 해당 키를 아래 값으로
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
readOnlyPort: 0
```

```bash
systemctl restart kubelet
systemctl status kubelet --no-pager
```

**3) 검증 방법**

```bash
kube-bench run --targets=node | grep -E 'anonymous|authorization|read-only' -i
curl -sk https://localhost:10250/pods    # 401 Unauthorized 이어야 정상
curl -s http://localhost:10255/pods      # connection refused 이어야 정상 (readOnlyPort 0)
exit; exit                                # 노드에서 빠져나와서
kubectl get nodes                         # cluster2-node1 Ready 확인
```

**4) ⚠️ 함정 포인트**

- `readOnlyPort` 키가 파일에 아예 없을 수 있다 — 없으면 **추가**해야 한다(기본값에 의존하지 말 것).
- `authorization.mode`를 `Webhook`으로 바꿀 때 `authentication.webhook.enabled: true`도 함께 확인하라.
- kubelet 재시작을 잊으면 파일만 바뀌고 동작은 그대로다. kube-bench 재실행으로 PASS를 확인하는 습관을 들이자.
- 노드 작업이 끝나면 반드시 `exit`로 메인 터미널에 돌아와야 다음 문제에서 kubectl 컨텍스트가 꼬이지 않는다.

</details>

---

## 3. Ingress TLS

### 3.1 개념

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`ingress`** 검색 → **"Ingress"**(TLS 섹션) → `kubernetes.io/tls` 타입 Secret과 `spec.tls`(hosts·secretName) 예제를 복사해 호스트·Secret 이름만 바꾼다.

Ingress에서 TLS(Transport Layer Security)를 종료(terminate)하려면 두 가지가 필요하다: ① `kubernetes.io/tls` 타입 Secret(`tls.crt` + `tls.key`), ② Ingress의 `spec.tls` 블록. 시험에서는 인증서/키 파일이 주어지거나 self-signed 인증서를 직접 만들게 한다.

### 3.2 TLS Secret 생성

```bash
# 인증서가 주어진 경우
kubectl -n world create secret tls tls-secret \
  --cert=/opt/course/x/cert.pem --key=/opt/course/x/key.pem

# self-signed 인증서를 직접 만들어야 하는 경우
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=world.universe.mine"
```

### 3.3 Ingress에 TLS 연결

> **📖 오픈북 — 문서에서 찾기** — 컨트롤러별 TLS 동작(기본 HTTPS 443 리다이렉트, `--default-ssl-certificate`, self-signed 대체 등)은 `kubernetes.github.io/ingress-nginx`에서 **`TLS`** 검색 → **"TLS/HTTPS"** 사용자 가이드에서 확인한다.

> **🛠 만드는 법** — Ingress는 생성기가 있다: `k create ingress web --rule="world.universe.mine/*=web:80" $do > ing.yaml` 로 뼈대를 뽑아 `spec.tls`만 채운 뒤 `k apply -f`(여기서 `$do`=`--dry-run=client -o yaml`). TLS Secret은 YAML로 쓰지 말고 3.2처럼 `k create secret tls`로 바로 생성한다.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: world
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - world.universe.mine
      secretName: tls-secret
  rules:
    - host: world.universe.mine
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web
                port:
                  number: 80
```

- `spec.tls.hosts`의 호스트명은 `rules.host`와 일치해야 한다.
- `ingressClassName`을 빼먹으면 컨트롤러가 Ingress를 처리하지 않는다. 기존 Ingress를 수정하는 문제라면 이미 있는 값을 유지하라(`kubectl get ingressclass`로 확인 가능).
- 기존 Ingress에 TLS만 추가하는 경우 `kubectl -n world edit ingress web`으로 `tls` 블록만 삽입하면 된다.

### 3.4 검증

```bash
# Ingress controller의 HTTPS NodePort 확인
kubectl -n ingress-nginx get svc ingress-nginx-controller

# self-signed이므로 -k 필수. /etc/hosts에 호스트가 등록되어 있지 않으면 --resolve 사용
curl -k https://world.universe.mine:<https-nodeport>/
curl -kv --resolve world.universe.mine:443:<node-ip> https://world.universe.mine/ 2>&1 | grep -E 'subject|HTTP'
```

`curl -kv` 출력의 `subject: CN=...`이 내 인증서면 성공, `Kubernetes Ingress Controller Fake Certificate`가 보이면 Secret 이름 오타·네임스페이스 불일치·hosts 불일치 중 하나다.

> **⚠️ 함정** — Secret은 반드시 **Ingress와 같은 네임스페이스**에 있어야 한다. Fake Certificate가 나오면 십중팔구 이 문제다.

### 📝 문제로 이해하기

> Solve this task on: `kubectl config use-context cluster1`
>
> Namespace `space` contains a working Ingress named `api` for host `api.space.local` (HTTP only). Create a TLS Secret named `api-tls` in namespace `space` from the files `/opt/course/m3/cert.pem` and `/opt/course/m3/key.pem`, then configure the Ingress to serve HTTPS for `api.space.local` using that Secret. Verify with curl that the certificate served for the host is the provided one.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — Secret 생성 → 기존 Ingress에 `spec.tls` 블록 추가 → curl로 인증서 subject 확인. 새로 만들 필요 없이 `kubectl edit`이 가장 빠르다.

**2) 단계별 명령어/YAML**

```bash
kubectl config use-context cluster1
kubectl -n space create secret tls api-tls \
  --cert=/opt/course/m3/cert.pem --key=/opt/course/m3/key.pem
kubectl -n space edit ingress api
```

```yaml
# spec: 아래에 추가 (rules와 같은 레벨)
  tls:
    - hosts:
        - api.space.local
      secretName: api-tls
```

**3) 검증 방법**

```bash
kubectl -n ingress-nginx get svc ingress-nginx-controller   # HTTPS NodePort 확인
curl -kv https://api.space.local:<nodeport>/ 2>&1 | grep subject
# subject에 제공된 인증서의 CN이 보여야 함 (Fake Certificate가 아니어야 함)
openssl x509 -in /opt/course/m3/cert.pem -noout -subject     # 비교용
```

**4) ⚠️ 함정 포인트**

- `tls.hosts`와 `rules.host`의 철자가 다르면 Fake Certificate가 서빙된다.
- Secret 생성 시 `--cert`/`--key` 순서는 상관없지만 파일을 바꿔 넣으면 생성 자체가 실패한다 — 에러 메시지를 읽어라.
- 시험 환경 노드의 `/etc/hosts`에 호스트가 이미 등록된 경우가 많다. 안 되면 `--resolve`를 쓰자.

</details>

---

## 4. 노드 메타데이터 보호

### 4.1 왜 위험한가

클라우드 노드는 링크로컬 주소 `169.254.169.254`에서 **인스턴스 메타데이터 서비스**(AWS IMDS, GCP/Azure metadata server)를 제공한다. 여기에는 노드 IAM(Identity and Access Management — 클라우드의 자격·권한 관리 체계) 역할의 임시 자격 증명, 부트스트랩 토큰, 사용자 데이터 스크립트 등이 들어 있다. 기본 상태에서는 **모든 Pod가 이 주소에 접근 가능**하므로, 컨테이너 하나만 침해되어도(예: SSRF — Server-Side Request Forgery, 서버가 공격자 의도대로 내부 주소로 요청하게 만드는 취약점) 공격자가 다음 한 줄로 클라우드 계정 자격 증명을 탈취할 수 있다.

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### 4.2 egress NetworkPolicy로 차단

> **📖 오픈북 — 문서에서 찾기** — `kubernetes.io/docs`에서 **`network policy`** 검색 → **"Network Policies"** → `ipBlock` egress 예제(⌘/Ctrl+F `ipBlock`)를 복사해 `cidr: 0.0.0.0/0` + `except: 169.254.169.254/32`로 바꾼다(메타데이터 서비스 자체는 클라우드 문서라 허용 목록에 없음).

"모든 곳으로의 egress는 허용하되 메타데이터 주소만 차단" = `ipBlock 0.0.0.0/0` + `except`.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
```

변형 문제: "라벨 `metadata-access=true`가 붙은 Pod**만** 메타데이터 접근 허용" — 두 정책 조합으로 푼다.

```yaml
# 1) 전체 차단 (위의 deny-metadata) + 2) 예외 Pod에게만 허용
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-metadata
  namespace: production
spec:
  podSelector:
    matchLabels:
      metadata-access: "true"
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 169.254.169.254/32
```

NetworkPolicy는 합집합이므로 라벨이 붙은 Pod는 두 정책의 허용 규칙을 모두 갖게 되어 메타데이터에 접근할 수 있고, 나머지 Pod는 except에 걸려 차단된다.

> **📌 암기 포인트** — `169.254.169.254/32`. `/32`를 빼먹으면 CIDR로 인정되지 않는다. 검증은 Pod 안에서 `curl -m 2 http://169.254.169.254/` 타임아웃 확인.

### 📝 문제로 이해하기

> Solve this task on: `kubectl config use-context cluster2`
>
> The cluster runs on a cloud provider whose metadata service listens on `169.254.169.254`. Create a NetworkPolicy named `metadata-deny` in namespace `apps` that denies **all** pods in the namespace egress access to `169.254.169.254`, while still permitting egress to every other destination.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — 전체 Pod(`podSelector: {}`)에 Egress 정책을 걸고, 허용 대역을 `0.0.0.0/0`로 열되 `except`로 메타데이터 IP만 뺀다.

**2) 단계별 명령어/YAML**

```bash
kubectl config use-context cluster2
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: metadata-deny
  namespace: apps
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
EOF
```

**3) 검증 방법**

```bash
kubectl -n apps run tmp --rm -it --restart=Never --image=busybox:1.36 -- \
  wget -qO- --timeout=2 http://169.254.169.254/   # 타임아웃이어야 정상
kubectl -n apps run tmp2 --rm -it --restart=Never --image=busybox:1.36 -- \
  wget -qO- --timeout=2 http://1.1.1.1/           # 다른 외부는 응답이 와야 정상
```

**4) ⚠️ 함정 포인트**

- 이 정책은 IP 기반이라 DNS 문제는 없지만(0.0.0.0/0 허용), default-deny egress와 **함께** 요구되는 변형에서는 DNS 53 허용을 추가해야 한다.
- `except` 값은 리스트다 — `except: 169.254.169.254/32`처럼 스칼라로 쓰면 스키마 오류.

</details>

---

## 5. 플랫폼 바이너리 검증

### 5.1 개념

> **📖 오픈북** — `sha512sum`/`sha512sum --check`는 셸 명령이라 암기 대상이다. 체크섬 대조 형식이 헷갈리면 `kubernetes.io/docs`에서 **`install kubectl linux`** 검색 → **"Install and Set Up kubectl on Linux"**의 바이너리 검증(Validate) 단계에서 `echo "<hash>  kubectl" | sha256sum --check` 예시를 확인한다(sha256→sha512만 치환). cosign 등 서명 검증 도구는 허용 문서 8개에 없다.

공급망 공격의 1차 방어선: 다운로드하거나 이미 설치된 Kubernetes 바이너리(kubelet, kubectl, kubeadm, 서버 tarball)가 공식 릴리스와 동일한지 **sha512 체크섬**으로 확인한다. 공식 릴리스는 각 바이너리에 대해 `.sha256`/`.sha512` 체크섬 파일을 함께 배포한다(체크섬 파일에는 해시 문자열만 들어 있다).

### 5.2 다운로드한 파일 검증

```bash
# 체크섬 파일과 대상 파일이 주어졌을 때의 표준 패턴
echo "$(cat kubectl.sha512)  kubectl" | sha512sum --check
# 출력: kubectl: OK  (변조 시: FAILED)
```

`sha512sum --check`는 "해시  파일명" 형식의 입력을 받는다(구분 공백 2칸). 체크섬 파일이 이미 "해시  파일명" 형식이라면 그대로 `sha512sum -c 체크섬파일`.

### 5.3 설치된 바이너리 검증 (빈출 시나리오)

노드에서 실제로 돌고 있는 kubelet이 공식 바이너리인지 확인하는 문제. 같은 버전의 공식 해시와 비교한다.

```bash
ssh cluster1-node1
kubelet --version                        # v1.35.0 → 비교 대상 버전 확인
which kubelet                            # /usr/bin/kubelet

# 방법 1: 해시 문자열끼리 diff (시험에서는 공식 해시가 파일로 제공되는 경우가 많다)
sha512sum /usr/bin/kubelet | cut -d ' ' -f1 > /tmp/actual
diff /tmp/actual /opt/course/x/kubelet.sha512   # 출력 없음 = 일치

# 방법 2: 인터넷이 되는 연습 환경이라면 공식 릴리스에서 직접 수령
curl -sSL -o /tmp/official.sha512 \
  "https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubelet.sha512"
echo "$(cat /tmp/official.sha512)  /usr/bin/kubelet" | sha512sum --check
```

> **💡 시험 팁** — 시험에서는 보통 비교용 체크섬(또는 정상 바이너리)이 로컬 경로로 제공된다. 해시 검증 절차는 kubernetes.io/docs의 설치 페이지(예: "Install and Set Up kubectl on Linux")에도 나오므로 막히면 문서를 열어라.

> **⚠️ 함정** — 해시 비교는 대소문자·개행까지 정확해야 한다. 눈으로 비교하지 말고 `diff`나 `sha512sum --check`로 기계적으로 비교하라. 또한 tarball 내부의 바이너리와 노드에 설치된 바이너리를 비교하라는 변형(`tar xzf` 후 개별 파일 해시 비교)도 나온다.

### 📝 문제로 이해하기

> Solve this task on: `kubectl config use-context cluster1`
>
> The file `/opt/course/m5/kubectl` claims to be the official kubectl v1.35.0 binary. The official sha512 checksum is stored in `/opt/course/m5/kubectl.sha512` (hash only). Determine whether the binary is genuine and write either `genuine` or `tampered` into `/opt/course/m5/result.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — 대상 파일의 sha512 해시를 계산해 제공된 공식 해시와 기계적으로 비교한다.

**2) 단계별 명령어/YAML**

```bash
cd /opt/course/m5
echo "$(cat kubectl.sha512)  kubectl" | sha512sum --check
# kubectl: OK        → genuine
# kubectl: FAILED    → tampered

# 결과 기록 (예: FAILED가 나온 경우)
echo tampered > /opt/course/m5/result.txt
```

**3) 검증 방법**

```bash
# 교차 확인: 해시 문자열 직접 비교
sha512sum kubectl | cut -d ' ' -f1
cat kubectl.sha512
cat /opt/course/m5/result.txt
```

**4) ⚠️ 함정 포인트**

- `echo "해시  파일명"`에서 해시와 파일명 사이 공백은 **2칸**이다. 1칸이면 포맷 에러가 날 수 있다.
- sha256과 sha512를 혼동하지 말 것 — 문제와 체크섬 파일 확장자를 확인하라.
- 답 파일에 요구된 단어만 정확히 쓰기(`genuine`/`tampered`). 여분의 문장을 덧붙이면 자동 채점에서 틀릴 수 있다.

</details>

---

## 6. 실전 연습문제 10제

> **💡 시험 팁** — 각 문제는 실제 시험처럼 지정된 컨텍스트로 전환한 뒤 시작하라. 노드 작업 후에는 반드시 `exit`로 메인 터미널에 복귀할 것. 파일 답안은 killer.sh 관례에 따라 `/opt/course/문제번호/`에 저장한다.

### Question 1 — default deny (NetworkPolicy 기초)

```bash
kubectl config use-context cluster1
```

Namespace `project-a` currently allows all pod-to-pod traffic. Create a NetworkPolicy named `default-deny` in namespace `project-a` that denies **all incoming** traffic to **all** pods in the namespace. Outgoing traffic must not be affected. Save your manifest to `/opt/course/1/np.yaml` and apply it.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — 빈 `podSelector`로 전체 Pod를 select하고 `policyTypes`에 `Ingress`만 넣는다. `ingress` 섹션을 아예 두지 않으면 허용 규칙이 0개 = 전면 차단. Egress는 policyTypes에 넣지 않았으므로 영향 없음.

**2) 단계별 명령어/YAML**

```bash
mkdir -p /opt/course/1
cat > /opt/course/1/np.yaml <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: project-a
spec:
  podSelector: {}
  policyTypes:
    - Ingress
EOF
kubectl apply -f /opt/course/1/np.yaml
```

**3) 검증 방법**

```bash
kubectl -n project-a describe netpol default-deny
# "Allowing ingress traffic: <none> (Selected pods are isolated for ingress)" 확인
kubectl -n project-a run probe --rm -it --restart=Never --image=busybox:1.36 -- \
  wget -qO- --timeout=2 http://<임의-pod-ip>    # 타임아웃이어야 정상
```

**4) ⚠️ 함정 포인트**

- `policyTypes`에 `Egress`까지 넣으면 문제 요구("outgoing must not be affected")를 위반한다.
- `ingress: []`를 명시해도 결과는 같지만, 섹션 자체를 생략하는 쪽이 실수 여지가 적다.

</details>

### Question 2 — 허용 규칙과 OR 조합

```bash
kubectl config use-context cluster1
```

Namespace `moon` contains pods labeled `app=backend` listening on TCP port 8080. Create a NetworkPolicy named `backend-policy` in namespace `moon` that allows ingress to the `app=backend` pods on TCP 8080 **only** from:

- pods labeled `app=frontend` in namespace `moon`, **or**
- any pod running in a namespace labeled `team=monitoring`

All other ingress to the backend pods must be denied.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — "또는(or)"이므로 `from` 아래에 **peer를 두 개**(대시 두 개) 나열한다. 단독 `podSelector`는 같은 네임스페이스, 단독 `namespaceSelector`는 해당 네임스페이스의 모든 Pod를 의미한다.

**2) 단계별 명령어/YAML**

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-policy
  namespace: moon
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
        - namespaceSelector:
            matchLabels:
              team: monitoring
      ports:
        - protocol: TCP
          port: 8080
EOF
```

**3) 검증 방법**

```bash
kubectl -n moon describe netpol backend-policy
# From 항목이 "PodSelector: app=frontend" 와 "NamespaceSelector: team=monitoring"
# 두 개의 별개 항목으로 표시되는지 확인
kubectl get ns -l team=monitoring    # 라벨이 실제로 있는지 확인
```

**4) ⚠️ 함정 포인트**

- 두 번째 peer 앞의 대시를 빠뜨리면 AND가 되어 "monitoring 네임스페이스의 frontend Pod만" 허용하는 전혀 다른 정책이 된다. **describe 출력으로 peer가 2개인지 반드시 확인**하라.
- 8080 외 포트도 막아야 하므로 `ports`를 생략하면 안 된다(생략 = 모든 포트 허용).

</details>

### Question 3 — AND 조합 (최다 빈출 함정)

```bash
kubectl config use-context cluster2
```

Namespace `mercury` contains database pods labeled `app=db` listening on TCP 5432. Create a NetworkPolicy named `db-allow` in namespace `mercury` that allows ingress to the `app=db` pods on TCP 5432 **only from pods labeled `role=api` that run in namespaces labeled `env=prod`**.

Pods labeled `role=api` in namespaces without the `env=prod` label, and pods without the `role=api` label in `env=prod` namespaces, must **not** be able to connect.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — "prod 네임스페이스 **의** api Pod"라는 교집합 조건이므로 **한 peer 항목 안에** `namespaceSelector`와 `podSelector`를 함께 쓴다(AND). 대시는 `namespaceSelector` 앞에 하나만.

**2) 단계별 명령어/YAML**

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-allow
  namespace: mercury
spec:
  podSelector:
    matchLabels:
      app: db
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              env: prod
          podSelector:
            matchLabels:
              role: api
      ports:
        - protocol: TCP
          port: 5432
EOF
```

**3) 검증 방법**

```bash
kubectl -n mercury describe netpol db-allow
# From 이 "NamespaceSelector: env=prod AND PodSelector: role=api" 처럼
# 하나의 항목으로 묶여 표시되어야 함 (항목이 2개로 갈라져 있으면 OR로 잘못 쓴 것)
# prod 네임스페이스에서 role=api 라벨로 테스트 → 성공해야 함
kubectl -n <prod-ns> run t1 --rm -it --restart=Never --labels=role=api \
  --image=busybox:1.36 -- nc -zv -w 2 <db-pod-ip> 5432
# 같은 네임스페이스에서 라벨 없이 테스트 → 실패해야 함
kubectl -n <prod-ns> run t2 --rm -it --restart=Never \
  --image=busybox:1.36 -- nc -zv -w 2 <db-pod-ip> 5432
```

**4) ⚠️ 함정 포인트**

- `podSelector:` 앞에 대시를 붙이는 순간 OR이 되어 채점에서 탈락한다. 이 문제 유형의 채점 포인트가 바로 그 대시 하나다.
- `podSelector`의 들여쓰기는 `namespaceSelector`와 **같은 열**이어야 한다(그 하위가 아님).
- 네임스페이스에 `env=prod` 라벨이 실제로 있는지 `kubectl get ns --show-labels`로 먼저 확인하라. 문제에 따라 라벨을 직접 붙여야 할 수도 있다.

</details>

### Question 4 — egress 제한 + DNS (난이도 상)

```bash
kubectl config use-context cluster2
```

In namespace `venus` the pods labeled `app=crawler` must only be able to:

1. open connections to IP addresses within `10.0.0.0/16`, **except** the subnet `10.0.5.0/24`, and
2. resolve DNS names (port 53 UDP and TCP).

Create a NetworkPolicy named `crawler-egress` in namespace `venus` enforcing this. All other egress traffic of the `app=crawler` pods must be blocked.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — `policyTypes: [Egress]`로 egress를 잠그고 규칙 두 개를 나열한다: ① `ipBlock` + `except`, ② DNS 53(UDP/TCP). 규칙끼리는 합집합이므로 둘 다 허용된다.

**2) 단계별 명령어/YAML**

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: crawler-egress
  namespace: venus
spec:
  podSelector:
    matchLabels:
      app: crawler
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/16
            except:
              - 10.0.5.0/24
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
EOF
```

**3) 검증 방법**

```bash
kubectl -n venus describe netpol crawler-egress
# crawler Pod 안에서:
kubectl -n venus exec <crawler-pod> -- nslookup kubernetes.default   # 성공해야 함
kubectl -n venus exec <crawler-pod> -- nc -zv -w 2 10.0.3.10 80      # 성공(대역 내)
kubectl -n venus exec <crawler-pod> -- nc -zv -w 2 10.0.5.10 80      # 실패(except)
kubectl -n venus exec <crawler-pod> -- nc -zv -w 2 8.8.8.8 443       # 실패(대역 외)
```

**4) ⚠️ 함정 포인트**

- DNS 규칙을 첫 번째 규칙의 `ports`에 합쳐 쓰면 "10.0.0.0/16으로 가는 53 포트만 허용"이 되어 클러스터 DNS가 대역 밖이면 해석이 실패한다. **별개 규칙**(대시 별도)으로 분리하라.
- `except` 항목은 리스트이며 `cidr` 하위가 아닌 `ipBlock` 하위 키다 — 들여쓰기 주의.
- UDP만 열고 TCP 53을 빼먹는 실수가 흔하다. 문제에서 둘 다 요구하면 둘 다.

</details>

### Question 5 — kube-bench: kube-apiserver 하드닝

```bash
kubectl config use-context cluster3
```

Connect to the control plane node with `ssh cluster3-controlplane1`. Run kube-bench against the master components. Among the results, fix the following failed checks on the kube-apiserver:

1. anonymous requests must be rejected
2. profiling must be disabled

Afterwards ensure the kube-apiserver comes back up and the fixed checks pass.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — kube-bench 실행 → FAIL 항목의 Remediation 확인 → static pod manifest에 플래그 추가 → kubelet의 자동 재생성 대기 → 재점검.

**2) 단계별 명령어/YAML**

```bash
ssh cluster3-controlplane1
sudo -i
kube-bench run --targets=master | grep -B1 -A5 -i -E 'anonymous|profiling'

cp /etc/kubernetes/manifests/kube-apiserver.yaml /root/kube-apiserver.yaml.bak
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

```yaml
# spec.containers[0].command 에 추가/수정
    - --anonymous-auth=false
    - --profiling=false
```

```bash
# kubelet이 apiserver를 재생성할 때까지 30초~1분 대기
watch crictl ps
kubectl get nodes    # API 응답 복구 확인
```

**3) 검증 방법**

```bash
kube-bench run --targets=master | grep -i -E 'anonymous|profiling'
# 해당 체크가 [PASS] 로 바뀌었는지 확인
ps aux | grep kube-apiserver | tr ' ' '\n' | grep -E 'anonymous|profiling'
```

**4) ⚠️ 함정 포인트**

- 같은 플래그가 이미 다른 값으로 존재할 수 있다 — **중복 추가하지 말고 기존 라인을 수정**하라. 플래그가 중복되면 뒤의 값이 이기지만 kube-bench가 혼동할 수 있다.
- 백업 파일을 manifests 디렉토리 안에 두지 말 것(kubelet이 static pod로 취급).
- apiserver가 안 돌아오면 `crictl ps -a`로 Exited 컨테이너를 찾고 `crictl logs`로 오타를 확인. `journalctl -u kubelet`과 `/var/log/pods/`도 함께 본다.
- 수정 직후 `kubectl` 명령이 잠시 실패하는 것은 정상이다 — 당황하지 말고 기다려라.

</details>

### Question 6 — kube-bench: kubelet과 etcd 하드닝

```bash
kubectl config use-context cluster3
```

kube-bench reported failures on node `cluster3-node1` (connect with `ssh cluster3-node1`) and on the etcd component of the control plane (`ssh cluster3-controlplane1`). Fix all of the following:

1. On `cluster3-node1`: the kubelet accepts anonymous requests, uses `AlwaysAllow` authorization and exposes the read-only port. Correct the kubelet configuration and restart the kubelet.
2. On the control plane: ensure etcd requires client certificate authentication.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — kubelet 3종 세트는 `/var/lib/kubelet/config.yaml` + `systemctl restart kubelet`, etcd는 static pod manifest의 `--client-cert-auth=true` 확인/수정.

**2) 단계별 명령어/YAML**

```bash
# --- 워커 노드 ---
ssh cluster3-node1
sudo -i
vim /var/lib/kubelet/config.yaml
```

```yaml
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
readOnlyPort: 0
```

```bash
systemctl restart kubelet
systemctl status kubelet --no-pager
exit; exit

# --- 컨트롤 플레인 ---
ssh cluster3-controlplane1
sudo -i
vim /etc/kubernetes/manifests/etcd.yaml
# command 에서 확인/수정:
#   - --client-cert-auth=true
watch crictl ps    # etcd 재생성 대기
exit; exit
```

**3) 검증 방법**

```bash
# 노드에서
kube-bench run --targets=node | grep -i -E 'anonymous|authorization|read-only'
curl -sk https://localhost:10250/pods   # 401 Unauthorized
curl -s http://localhost:10255/pods     # connection refused
# 컨트롤 플레인에서
kube-bench run --targets=master | grep -i 'client-cert-auth'
kubectl get nodes                        # 모두 Ready
```

**4) ⚠️ 함정 포인트**

- kubelet 플래그로 지정하는 방식(deprecated)과 config.yaml 방식이 섞여 있을 수 있다. `/var/lib/kubelet/config.yaml`이 정답 경로이며, systemd drop-in에 같은 항목의 플래그가 있으면 그쪽이 우선하므로 확인이 필요하다.
- etcd manifest를 고치면 etcd가 재시작되는 동안 apiserver도 잠시 불안정해진다 — `kubectl` 실패에 당황하지 말 것.
- 두 노드를 오가는 문제에서는 **지금 어느 셸에 있는지** 프롬프트를 항상 확인하라.

</details>

### Question 7 — Ingress TLS

```bash
kubectl config use-context cluster1
```

In namespace `world` an Ingress named `web` already routes host `world.universe.mine` to Service `web` on port 80 (HTTP only). The certificate and key are provided at `/opt/course/7/cert.pem` and `/opt/course/7/key.pem`.

1. Create a TLS Secret named `tls-secret` in namespace `world` using the provided files.
2. Extend the Ingress so that TLS is terminated for host `world.universe.mine` using that Secret.
3. Verify with curl over HTTPS that the served certificate is the provided one.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — `kubectl create secret tls` → `kubectl edit ingress`로 `spec.tls` 블록 추가 → `curl -kv`로 subject 확인.

**2) 단계별 명령어/YAML**

```bash
kubectl -n world create secret tls tls-secret \
  --cert=/opt/course/7/cert.pem --key=/opt/course/7/key.pem
kubectl -n world edit ingress web
```

```yaml
# spec: 아래, rules: 와 같은 레벨에 추가
  tls:
    - hosts:
        - world.universe.mine
      secretName: tls-secret
```

**3) 검증 방법**

```bash
kubectl -n world get ingress web -o yaml | grep -A4 'tls:'
kubectl -n ingress-nginx get svc ingress-nginx-controller   # HTTPS NodePort
curl -kv https://world.universe.mine:<nodeport>/ 2>&1 | grep -E 'subject|HTTP/'
openssl x509 -in /opt/course/7/cert.pem -noout -subject      # CN 대조
```

**4) ⚠️ 함정 포인트**

- `subject`에 `Kubernetes Ingress Controller Fake Certificate`가 보이면 실패: Secret 이름/네임스페이스/hosts 철자를 재확인.
- 기존 Ingress를 삭제 후 재생성하지 말 것 — annotations나 ingressClassName 같은 기존 설정이 사라지면 라우팅 자체가 깨질 수 있다. `edit`으로 tls 블록만 추가하는 것이 안전하다.

</details>

### Question 8 — 메타데이터 서버 차단

```bash
kubectl config use-context cluster2
```

The cloud metadata service is reachable from pods at `169.254.169.254`. Create a NetworkPolicy named `metadata-deny` in namespace `production` that prevents **all** pods in the namespace from accessing `169.254.169.254`, while still allowing all other egress traffic. Save the manifest to `/opt/course/8/np.yaml` and apply it.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — 4장의 표준 패턴: `podSelector: {}` + Egress + `ipBlock 0.0.0.0/0` + `except 169.254.169.254/32`.

**2) 단계별 명령어/YAML**

```bash
mkdir -p /opt/course/8
cat > /opt/course/8/np.yaml <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: metadata-deny
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
EOF
kubectl apply -f /opt/course/8/np.yaml
```

**3) 검증 방법**

```bash
kubectl -n production run probe --rm -it --restart=Never --image=busybox:1.36 -- \
  wget -qO- --timeout=2 http://169.254.169.254/    # 타임아웃
kubectl -n production run probe2 --rm -it --restart=Never --image=busybox:1.36 -- \
  nslookup kubernetes.default                       # 정상 (0.0.0.0/0 허용 덕분)
```

**4) ⚠️ 함정 포인트**

- `/32` 누락, `except`를 리스트가 아닌 스칼라로 쓰는 실수가 대부분이다.
- 이 정책이 있는 네임스페이스에 **다른 egress 정책**이 이미 있으면 합집합으로 평가된다. 기존 정책이 metadata IP를 허용하고 있으면 차단되지 않으므로 `kubectl -n production get netpol`로 먼저 살펴라.

</details>

### Question 9 — 바이너리 무결성 검증

```bash
kubectl config use-context cluster1
```

The directory `/opt/course/9/binaries` on your main terminal contains the files `kube-apiserver`, `kube-controller-manager`, `kubelet` and `kubectl`, all claiming to be official v1.35.0 binaries. The file `/opt/course/9/checksums.txt` contains the official sha512 checksums in the format `<hash>  <filename>`. Identify every binary that does **not** match its official checksum and write its filename (one per line) into `/opt/course/9/compromised.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — 체크섬 파일이 `sha512sum --check` 표준 형식이므로 그대로 `-c`로 돌리고 FAILED 라인만 추린다.

**2) 단계별 명령어/YAML**

```bash
cd /opt/course/9/binaries
sha512sum -c ../checksums.txt
# 예시 출력:
# kube-apiserver: OK
# kube-controller-manager: OK
# kubelet: FAILED
# kubectl: OK

sha512sum -c ../checksums.txt 2>/dev/null | awk -F: '/FAILED/{print $1}' \
  > /opt/course/9/compromised.txt
cat /opt/course/9/compromised.txt
```

**3) 검증 방법**

```bash
# 수동 교차 확인: FAILED로 나온 파일의 해시를 직접 대조
sha512sum kubelet | cut -d ' ' -f1
grep kubelet ../checksums.txt
```

**4) ⚠️ 함정 포인트**

- `sha512sum -c`는 체크섬 파일에 적힌 **파일명 기준 상대 경로**로 대상을 찾는다. 반드시 바이너리가 있는 디렉토리로 `cd`한 뒤 실행하라.
- 답 파일에는 파일명만, 한 줄에 하나씩. `kubelet: FAILED` 같은 원본 라인을 그대로 쓰면 오답 처리될 수 있다.
- sha256 체크섬 파일이 주어지는 변형도 있다 — 명령을 `sha256sum`으로 바꾸기만 하면 된다.

</details>

### Question 10 — 복합: 감사 결과 일괄 조치

```bash
kubectl config use-context cluster3
```

A security audit of `cluster3` produced the following findings. Fix all of them:

1. The kube-apiserver has profiling enabled and does not enable the `NodeRestriction` admission plugin. Fix both. (`ssh cluster3-controlplane1`)
2. On `cluster3-node1` the kubelet still serves the read-only port. Disable it. (`ssh cluster3-node1`)
3. Namespace `finance` allows unrestricted traffic. Create a NetworkPolicy named `default-deny` in namespace `finance` that blocks all ingress **and** egress for all pods, but still allows DNS resolution on port 53 (UDP and TCP).

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법** — 세 개의 독립 작업: ① apiserver 플래그 2개, ② kubelet readOnlyPort, ③ default-deny + DNS 예외. 순서대로 처리하고 각각 검증한다.

**2) 단계별 명령어/YAML**

```bash
# --- 1) apiserver ---
ssh cluster3-controlplane1
sudo -i
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

```yaml
# command 에서 수정/추가:
    - --profiling=false
    - --enable-admission-plugins=NodeRestriction
```

```bash
watch crictl ps       # apiserver 재생성 대기
kubectl get nodes
exit; exit

# --- 2) kubelet ---
ssh cluster3-node1
sudo -i
vim /var/lib/kubelet/config.yaml     # readOnlyPort: 0 (없으면 추가)
systemctl restart kubelet
curl -s http://localhost:10255/pods  # connection refused 확인
exit; exit

# --- 3) NetworkPolicy ---
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: finance
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  egress:
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
EOF
```

**3) 검증 방법**

```bash
ps aux | grep kube-apiserver | tr ' ' '\n' | grep -E 'profiling|admission'  # (컨트롤 플레인에서)
kubectl -n finance describe netpol default-deny
kubectl -n finance run probe --rm -it --restart=Never --image=busybox:1.36 -- \
  nslookup kubernetes.default          # DNS는 성공
kubectl -n finance run probe2 --rm -it --restart=Never --image=busybox:1.36 -- \
  wget -qO- --timeout=2 http://1.1.1.1 # 그 외 egress는 타임아웃
```

**4) ⚠️ 함정 포인트**

- `--enable-admission-plugins`가 이미 존재하면(예: 다른 플러그인 나열) 값을 **덮어쓰지 말고 콤마로 추가**하라: `--enable-admission-plugins=NodeRestriction,기존값`.
- 3번에서 `ingress` 섹션은 아예 없어야 전면 차단이다. DNS 예외는 egress에만 붙는다.
- 복합 문제는 부분 점수가 있다. 한 항목이 막히면 매달리지 말고 나머지를 먼저 끝내라.

</details>

---

## 7. 🎯 시험 직전 체크리스트

- [ ] default-deny NetworkPolicy 3종(ingress/egress/모두)을 문서 없이 작성할 수 있다
- [ ] `namespaceSelector`+`podSelector`의 AND(대시 1개)와 OR(대시 2개) 차이를 describe 출력으로 검증할 수 있다
- [ ] egress 정책을 만들 때 DNS 53(UDP/TCP) 허용을 반사적으로 추가한다
- [ ] `ipBlock` + `except`로 `169.254.169.254/32` 차단 패턴을 쓸 수 있다
- [ ] 네임스페이스 지목용 라벨 `kubernetes.io/metadata.name`을 기억한다
- [ ] kube-bench 실행 → FAIL 번호 → Remediation 적용 → 재실행 확인 사이클이 손에 익었다
- [ ] kubelet 하드닝 4항목(anonymous/webhook/authorization/readOnlyPort)의 파일 경로와 재시작 명령을 안다
- [ ] static pod 수정 후 30초~1분 대기, 안 뜨면 `crictl ps -a` → `crictl logs` → `journalctl -u kubelet` 순서로 디버깅한다
- [ ] 백업 파일을 `/etc/kubernetes/manifests/` 밖에 둔다
- [ ] `kubectl create secret tls` + Ingress `spec.tls` + `curl -kv`의 subject 확인 흐름을 안다
- [ ] `sha512sum --check`와 해시 `diff` 비교를 할 수 있다 (공백 2칸 형식 포함)
- [ ] 노드 ssh 작업 후 `exit`로 복귀, 문제 시작 시 `kubectl config use-context` 전환을 빠뜨리지 않는다
- [ ] 파일 답안은 `/opt/course/문제번호/`에 저장하고, 저장 후 **apply까지** 완료한다

## 8. 핵심 명령어 치트시트

```bash
# ===== NetworkPolicy =====
kubectl -n NS get netpol
kubectl -n NS describe netpol NAME                  # AND/OR 구조 검증
kubectl get ns --show-labels                        # kubernetes.io/metadata.name 확인
kubectl -n NS run tmp --rm -it --restart=Never --image=busybox:1.36 -- \
  wget -qO- --timeout=2 http://TARGET:PORT          # 연결 테스트
kubectl -n NS exec POD -- nc -zv -w 2 IP PORT       # 포트 테스트
kubectl -n NS exec POD -- nslookup kubernetes.default  # DNS 테스트

# ===== kube-bench =====
kube-bench run --targets=master                     # 컨트롤 플레인 점검
kube-bench run --targets=node                       # 워커 점검
kube-bench run --targets=master --check 1.2.18      # 특정 체크 재확인
kube-bench run --targets=master | grep -A1 '\[FAIL\]'

# ===== static pod / kubelet 운영 =====
vim /etc/kubernetes/manifests/kube-apiserver.yaml   # 저장 시 자동 재생성(30s-1m)
vim /var/lib/kubelet/config.yaml && systemctl restart kubelet
watch crictl ps                                     # 재기동 관찰
crictl ps -a && crictl logs CONTAINER_ID            # 안 뜰 때 디버깅
journalctl -u kubelet | tail -50
ls /var/log/pods/

# ===== 하드닝 핵심 값 =====
# apiserver : --anonymous-auth=false --profiling=false
#             --enable-admission-plugins=NodeRestriction --service-account-lookup=true
# etcd      : --client-cert-auth=true
# kubelet   : authentication.anonymous.enabled=false, authentication.webhook.enabled=true,
#             authorization.mode=Webhook, readOnlyPort=0
# cm/sched  : --profiling=false --bind-address=127.0.0.1

# ===== Ingress TLS =====
kubectl -n NS create secret tls SECRET --cert=cert.pem --key=key.pem
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=HOST"
kubectl -n NS edit ingress NAME                     # spec.tls 블록 추가
curl -kv https://HOST:NODEPORT/ 2>&1 | grep subject
openssl x509 -in cert.pem -noout -subject

# ===== 바이너리 검증 =====
sha512sum FILE
sha512sum -c checksums.txt                          # "<hash>  <file>" 형식
echo "$(cat file.sha512)  FILE" | sha512sum --check # 해시만 있는 체크섬 파일
sha512sum FILE | cut -d ' ' -f1 > /tmp/a && diff /tmp/a official.sha512

# ===== 메타데이터 차단 검증 =====
kubectl -n NS run probe --rm -it --restart=Never --image=busybox:1.36 -- \
  wget -qO- --timeout=2 http://169.254.169.254/     # 타임아웃이면 성공
```



