# Domain 2 — Cluster Hardening (15%)

클러스터에 들어오는 모든 요청의 통로인 Kubernetes API를 잠그는 도메인 — RBAC 최소권한, ServiceAccount 보안, API/kubelet 접근 제한, 인증서 사용자 관리, 그리고 CVE 대응을 위한 클러스터 업그레이드를 다룬다.

> **📌 시험 비중: 15% (16문제 기준 약 2~3문제).** RBAC와 ServiceAccount는 CKS 전 도메인을 통틀어 가장 확실하게 점수를 챙길 수 있는 영역이다. CKA에서 이미 익힌 내용의 "보안 관점 심화"이므로, 이 도메인에서 시간을 아껴 다른 도메인에 투자하는 전략이 유효하다.

## 목차

1. [RBAC 최소권한 설계](#1-rbac-최소권한-설계)
2. [ServiceAccount 보안](#2-serviceaccount-보안)
3. [Kubernetes API 접근 제한](#3-kubernetes-api-접근-제한)
4. [인증서 기반 사용자 생성 워크플로우](#4-인증서-기반-사용자-생성-워크플로우)
5. [Kubernetes 업그레이드](#5-kubernetes-업그레이드)
6. [실전 연습문제 10제](#6-실전-연습문제-10제)
7. [🎯 시험 직전 체크리스트](#7--시험-직전-체크리스트)
8. [핵심 명령어 치트시트](#8-핵심-명령어-치트시트)

---

## 1. RBAC 최소권한 설계

### 1.1 Role vs ClusterRole, Binding 조합 4가지

RBAC의 리소스는 딱 4종류다. **권한을 정의하는 것**(Role/ClusterRole)과 **권한을 주체(subject)에 연결하는 것**(RoleBinding/ClusterRoleBinding)으로 나뉜다.

| 조합 | 권한 범위 | 용도 |
|---|---|---|
| Role + RoleBinding | 해당 네임스페이스 안에서만 | 가장 일반적. 특정 네임스페이스의 최소권한 부여 |
| ClusterRole + ClusterRoleBinding | 클러스터 전체 (모든 네임스페이스 + 클러스터 스코프 리소스) | 노드/PV 조회, 관리자 권한 등 |
| ClusterRole + RoleBinding | **RoleBinding이 있는 네임스페이스 안에서만** | 공통 권한 정의(ClusterRole)를 여러 네임스페이스에 재사용 |
| Role + ClusterRoleBinding | **불가능한 조합** | ClusterRoleBinding의 roleRef는 ClusterRole만 참조 가능 |

> **📌 암기 포인트**: RoleBinding은 Role과 ClusterRole 둘 다 참조할 수 있지만, ClusterRoleBinding은 오직 ClusterRole만 참조할 수 있다. 그리고 **roleRef는 생성 후 변경 불가(immutable)** — 참조 대상을 바꾸려면 Binding을 삭제 후 재생성해야 한다.

```bash
# 명령형 생성 — 시험에서는 YAML을 직접 쓰기보다 이걸 쓰는 게 압도적으로 빠르다
kubectl create role pod-reader --verb=get,list,watch --resource=pods -n dev
kubectl create rolebinding pod-reader-binding -n dev \
  --role=pod-reader --serviceaccount=dev:app-sa

kubectl create clusterrole node-viewer --verb=get,list --resource=nodes
kubectl create clusterrolebinding node-viewer-binding \
  --clusterrole=node-viewer --user=alice

# ClusterRole을 특정 네임스페이스에만 부여 (재사용 패턴)
kubectl create rolebinding view-dev -n dev --clusterrole=view --serviceaccount=dev:app-sa
```

동일한 내용의 YAML 형태(시험에서 기존 리소스를 수정할 때 필요):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: dev
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-reader-binding
  namespace: dev
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: dev
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

### 1.2 위험한 verb와 와일드카드

CKS는 "이 ClusterRole에서 위험한 권한을 찾아 제거하라"는 식으로 출제된다. 다음 4가지를 보면 즉시 의심하라.

| 위험 요소 | 무엇이 가능해지나 |
|---|---|
| `escalate` | 자신이 가진 것보다 **더 많은 권한을 담은 Role/ClusterRole을 생성·수정** 가능 → 권한 상승 |
| `bind` | 자신이 갖지 않은 Role/ClusterRole을 **다른 주체(또는 자신)에게 바인딩** 가능 → 권한 상승 |
| `impersonate` | 다른 user/group/serviceaccount로 **가장(sudo처럼)하여 API 호출** 가능 |
| `*` (verbs/resources/apiGroups) | 와일드카드 — 향후 추가되는 리소스/동작까지 전부 포함. 최소권한 원칙 위반 |

> **⚠️ 함정**: `create` + `pods/exec`, `create` + `pods` (임의 이미지·hostPath 마운트 가능), `get` + `secrets` 도 사실상 클러스터 장악으로 이어지는 준-위험 권한이다. 문제에서 "권한을 최소화하라"고 하면 secrets에 대한 `list`/`get`, 와일드카드부터 걷어내라.

### 1.3 기존 권한 감사

```bash
# 특정 SA가 가진 모든 권한 나열 (해당 네임스페이스 기준)
kubectl auth can-i --list --as=system:serviceaccount:dev:app-sa -n dev

# 특정 행위 가능 여부 (yes/no)
kubectl auth can-i delete pods --as=system:serviceaccount:dev:app-sa -n dev
kubectl auth can-i '*' '*' --as=system:serviceaccount:dev:app-sa   # 관리자급인지 즉시 확인

# 사용자/그룹으로도 가능
kubectl auth can-i list secrets --as=alice -n prod

# 어떤 Binding이 이 SA를 참조하는지 역추적
kubectl get rolebindings,clusterrolebindings -A -o wide | grep app-sa

# Role/ClusterRole 내용 확인
kubectl describe clusterrole suspicious-role
```

### 1.4 과도한 권한 축소 리팩터링 패턴

시험 단골 시나리오: "이 SA는 secrets 전체 조회가 가능하다. pods의 get/list만 가능하도록 수정하라."

1. `kubectl auth can-i --list --as=system:serviceaccount:...` 로 현재 권한 확인
2. 그 SA를 참조하는 RoleBinding/ClusterRoleBinding을 찾는다
3. Binding이 참조하는 Role/ClusterRole을 `kubectl edit`으로 열어 rules를 최소권한으로 교체 — 또는 새 Role을 만들고 Binding의 roleRef를 바꾸는 대신 **Binding을 삭제 후 재생성**(roleRef는 immutable)
4. 다시 `auth can-i` 로 검증 — 줄인 권한은 no, 남긴 권한은 yes

> **💡 시험 팁**: ClusterRoleBinding으로 과도하게 열려 있는 경우, ClusterRole은 그대로 두고 ClusterRoleBinding을 삭제한 뒤 필요한 네임스페이스에만 RoleBinding으로 다시 연결하는 것도 유효한 축소 패턴이다.

### 📝 문제로 이해하기

```
kubectl config use-context wk8s
```

Task (mini): In namespace `finance` there is a ServiceAccount `report-sa`. Create a Role `report-role` that only allows `get` and `list` on `configmaps`, and bind it to the ServiceAccount with a RoleBinding `report-rb`. Verify that the ServiceAccount cannot delete configmaps.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 명령형 커맨드 3줄이면 끝나는 전형적 RBAC 문제. 검증까지 `auth can-i`로 마무리한다.

**2) 단계별 명령어**:

```bash
kubectl create role report-role -n finance --verb=get,list --resource=configmaps
kubectl create rolebinding report-rb -n finance \
  --role=report-role --serviceaccount=finance:report-sa
```

**3) 검증**:

```bash
kubectl auth can-i get configmaps -n finance \
  --as=system:serviceaccount:finance:report-sa      # yes
kubectl auth can-i delete configmaps -n finance \
  --as=system:serviceaccount:finance:report-sa      # no
```

**4) ⚠️ 함정 포인트**:
- `--serviceaccount`는 반드시 `네임스페이스:SA명` 형식. `finance:report-sa`에서 네임스페이스를 빠뜨리면 안 됨.
- `--as=system:serviceaccount:finance:report-sa` — 접두어 `system:serviceaccount:`를 정확히 기억할 것.
- RoleBinding 자체의 네임스페이스(`-n finance`)를 빠뜨리면 default에 생성되어 동작하지 않는다.

</details>

---

## 2. ServiceAccount 보안

### 2.1 기본 ServiceAccount의 문제

- 모든 네임스페이스에는 `default` SA가 자동 생성되고, `serviceAccountName`을 지정하지 않은 Pod에 자동 연결된다.
- 기본 동작으로 SA 토큰이 Pod의 `/var/run/secrets/kubernetes.io/serviceaccount/token` 경로에 **자동 마운트**된다.
- 컨테이너가 탈취되면 공격자는 이 토큰으로 API 서버에 인증할 수 있다. 토큰에 붙은 RBAC 권한이 곧 공격자의 권한이 된다.

**보안 원칙**: ① 앱이 API를 쓰지 않으면 토큰 마운트 차단, ② API를 쓴다면 default가 아닌 전용 SA + 최소 RBAC.

### 2.2 automountServiceAccountToken: false — SA 레벨 vs Pod 레벨

```yaml
# SA 레벨 — 이 SA를 쓰는 모든 Pod에 기본 적용
apiVersion: v1
kind: ServiceAccount
metadata:
  name: no-token-sa
  namespace: dev
automountServiceAccountToken: false
```

```yaml
# Pod 레벨 — SA 설정보다 우선한다
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: dev
spec:
  serviceAccountName: no-token-sa
  automountServiceAccountToken: false
  containers:
  - name: app
    image: nginx:1.27
```

> **📌 암기 포인트**: `automountServiceAccountToken` 필드의 위치 — SA에서는 **최상위 필드**(spec 아님), Pod에서는 **spec 아래**. 둘 다 설정된 경우 **Pod 레벨이 우선**한다.

> **⚠️ 함정**: 이미 실행 중인 Pod에는 적용되지 않는다. Pod spec은 대부분 immutable이므로 `kubectl delete` 후 재생성(또는 Deployment면 template 수정)이 필요하다. 검증은 `kubectl exec app -n dev -- ls /var/run/secrets/kubernetes.io/serviceaccount` 가 "No such file or directory"를 반환하는지로 한다.

### 2.3 최소권한 SA 생성 → Pod 연결 → 토큰 수동 발급

```bash
# 1) 전용 SA 생성
kubectl create serviceaccount app-sa -n dev

# 2) 최소 RBAC 연결
kubectl create role cm-reader -n dev --verb=get,list --resource=configmaps
kubectl create rolebinding cm-reader-rb -n dev --role=cm-reader --serviceaccount=dev:app-sa

# 3) Pod에 연결 (spec.serviceAccountName)
kubectl patch deployment web -n dev -p '{"spec":{"template":{"spec":{"serviceAccountName":"app-sa"}}}}'

# 4) 필요 시 단기 토큰 수동 발급 (v1.24+ 표준 방식, 기본 1시간)
kubectl create token app-sa -n dev --duration=10m
```

> **💡 시험 팁**: v1.24부터 SA를 만들어도 Secret 기반 장기 토큰은 자동 생성되지 않는다. 토큰이 필요하면 `kubectl create token`으로 만료 기한이 있는 토큰을 발급하는 것이 현행 표준이다.

### 2.4 미사용/위험 SA 탐지

```bash
# 네임스페이스의 모든 SA 나열
kubectl get sa -n dev

# 실제 Pod들이 어떤 SA를 쓰는지 수집
kubectl get pods -n dev -o jsonpath='{range .items[*]}{.spec.serviceAccountName}{"\n"}{end}' | sort -u

# 위 목록에 없는 SA = 미사용 후보 → 문제 지시에 따라 삭제
kubectl delete sa unused-sa -n dev

# 각 SA의 권한 수준 점검 (과도한 권한 SA 탐지)
kubectl auth can-i --list --as=system:serviceaccount:dev:app-sa -n dev
```

### 📝 문제로 이해하기

```
kubectl config use-context wk8s
```

Task (mini): In namespace `payment`, create a ServiceAccount named `batch-sa` that does not automount its API token. Then update the existing Pod `batch-runner` in the same namespace to use this ServiceAccount.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: SA를 YAML로 만들어 `automountServiceAccountToken: false`를 최상위에 넣고, Pod는 spec이 immutable이므로 YAML을 덤프해 수정 후 재생성한다.

**2) 단계별 명령어**:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: batch-sa
  namespace: payment
automountServiceAccountToken: false
EOF

kubectl get pod batch-runner -n payment -o yaml > /tmp/batch-runner.yaml
# spec: 아래에 serviceAccountName: batch-sa 추가/수정 (기존 serviceAccountName 줄이 있으면 교체)
vim /tmp/batch-runner.yaml
kubectl delete pod batch-runner -n payment
kubectl apply -f /tmp/batch-runner.yaml
```

**3) 검증**:

```bash
kubectl get pod batch-runner -n payment -o jsonpath='{.spec.serviceAccountName}'   # batch-sa
kubectl exec batch-runner -n payment -- ls /var/run/secrets/kubernetes.io/serviceaccount
# ls: ... No such file or directory 이면 성공
```

**4) ⚠️ 함정 포인트**:
- `automountServiceAccountToken`을 SA의 `metadata`나 `spec` 아래에 쓰면 안 된다. SA에는 spec이 없고 **최상위 필드**다.
- serviceAccountName 변경은 재생성 필수 — `kubectl edit`으로는 수정이 거부된다.
- 덤프한 YAML의 `status`, `nodeName` 등은 지워도 되지만 그대로 둬도 재생성에 문제없다. 시간 절약이 우선.

</details>

---

## 3. Kubernetes API 접근 제한

### 3.1 요청 처리 흐름: 인증 → 인가 → 어드미션

모든 API 요청은 세 관문을 통과한다.

| 단계 | 질문 | 메커니즘 |
|---|---|---|
| 1. Authentication | 너는 누구인가? | 클라이언트 인증서, SA 토큰(Bearer), OIDC 등 |
| 2. Authorization | 그 행동이 허용되는가? | RBAC, Node, Webhook |
| 3. Admission Control | 요청을 변형/검증할까? | NodeRestriction, PSA, ValidatingAdmissionPolicy 등 |

인증 실패 = **401 Unauthorized**, 인가 실패 = **403 Forbidden**. 이 구분이 익명 접근 테스트 해석의 핵심이다.

### 3.2 kube-apiserver 하드닝 플래그

수정 대상: `/etc/kubernetes/manifests/kube-apiserver.yaml` (static pod — 저장하면 kubelet이 자동 재생성, 30초~1분 대기).

| 플래그 | 권장값 | 의미 |
|---|---|---|
| `--anonymous-auth` | `false` | 익명(system:anonymous) 요청 차단 |
| `--enable-admission-plugins` | `NodeRestriction` 포함 | kubelet의 API 오남용 차단 |
| `--authorization-mode` | `Node,RBAC` | `AlwaysAllow`는 절대 금지 |
| `--profiling` | `false` | 디버그 프로파일링 엔드포인트 비활성화 |
| `--service-account-lookup` | `true` | 토큰의 원본 SA가 실제 존재하는지 검증(삭제된 SA 토큰 거부) |
| `--insecure-port` | (레거시) `0` | 구버전의 비인증 HTTP 포트. 최신 버전에서는 제거됨 |

```bash
# 익명 접근 테스트 — 하드닝 전/후 비교
curl -k https://<apiserver>:6443/api
# --anonymous-auth=true  → 403 Forbidden ("system:anonymous" 사용자로 인증은 됐지만 RBAC에서 거부)
# --anonymous-auth=false → 401 Unauthorized (인증 자체가 거부)
```

> **⚠️ 함정**: `--anonymous-auth=false`를 설정하면 apiserver의 livez/healthz 익명 프로브 등 익명 접근에 의존하는 요소가 영향을 받을 수 있다. 시험에서는 지시대로 설정하면 되지만, **manifest 저장 후 apiserver가 다시 뜰 때까지 `kubectl`이 잠시 먹통이 되는 것은 정상**이다. 안 뜨면 `crictl ps -a`로 컨테이너 상태, `journalctl -u kubelet` 또는 `/var/log/pods/`에서 오류(대부분 플래그 오타)를 확인하라.

### 3.3 kubelet 하드닝 — /var/lib/kubelet/config.yaml

kubelet API(포트 10250)는 컨테이너 exec/log 접근이 가능한 강력한 API다. 익명 접근을 막고 apiserver를 통한 위임 인증/인가만 허용해야 한다.

```yaml
# /var/lib/kubelet/config.yaml 에서 확인/수정할 4개 필드
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false          # 익명 요청 차단
  webhook:
    enabled: true           # Bearer 토큰을 apiserver의 TokenReview로 검증
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook             # AlwaysAllow 금지 — apiserver의 SubjectAccessReview로 위임
readOnlyPort: 0             # 비인증 read-only 포트(10255) 비활성화
```

```bash
# 수정 후 반드시 재시작
sudo systemctl restart kubelet
sudo systemctl status kubelet

# 검증: 익명으로 kubelet API 접근이 거부되는지
curl -sk https://localhost:10250/pods    # Unauthorized 이면 성공
curl -s  http://localhost:10255/pods     # readOnlyPort: 0 이면 연결 실패가 정상
```

> **📌 암기 포인트**: kubelet 하드닝 4종 세트 — `anonymous.enabled: false`, `webhook.enabled: true`, `authorization.mode: Webhook`, `readOnlyPort: 0`. 그리고 **`systemctl restart kubelet`을 잊으면 0점**이다. kubelet 실행 플래그(`--config` 경로 확인)는 `ps aux | grep kubelet`으로 확인할 수 있다.

### 3.4 NodeRestriction admission plugin

`--enable-admission-plugins=NodeRestriction` 활성화 시 kubelet(`system:node:<노드명>` 자격증명)이 할 수 있는 일이 제한된다.

- **자기 자신의 Node 객체**와 **자기 노드에서 실행 중인 Pod**만 수정 가능
- 다른 노드의 라벨/상태 변경 불가 → 탈취된 워커 노드가 다른 노드를 조작하는 것을 차단
- `node-restriction.kubernetes.io/` 접두어 라벨은 kubelet 스스로 설정/수정 불가 → 이 라벨로 민감 워크로드 스케줄링을 통제해도 노드가 위조할 수 없음

```bash
# 검증 예시 (워커 노드에서 kubelet kubeconfig로 시도)
ssh wk8s-node-1
sudo kubectl --kubeconfig /etc/kubernetes/kubelet.conf label node cks-controlplane foo=bar
# → Forbidden (NodeRestriction이 차단)
sudo kubectl --kubeconfig /etc/kubernetes/kubelet.conf label node wk8s-node-1 foo=bar
# → 자기 노드는 성공 (단, node-restriction.kubernetes.io/* 라벨은 거부됨)
```

### 📝 문제로 이해하기

```
kubectl config use-context wk8s
ssh wk8s-node-1
```

Task (mini): The kubelet on node `wk8s-node-1` currently allows anonymous requests and exposes the read-only port. Fix the kubelet configuration so that anonymous authentication is disabled, authorization uses `Webhook` mode, and the read-only port is disabled. Restart the kubelet afterwards.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 노드에 SSH 접속 → `/var/lib/kubelet/config.yaml`의 3개 지점 수정 → kubelet 재시작 → curl로 검증.

**2) 단계별 명령어**:

```bash
ssh wk8s-node-1
sudo vim /var/lib/kubelet/config.yaml
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
sudo systemctl restart kubelet
```

**3) 검증**:

```bash
sudo systemctl status kubelet                # active (running)
curl -sk https://localhost:10250/pods        # Unauthorized
curl -s  http://localhost:10255/pods         # connection refused (정상)
kubectl get node wk8s-node-1                 # Ready 유지 확인 (컨트롤플레인에서)
```

**4) ⚠️ 함정 포인트**:
- `authorization.mode`의 `Webhook`은 대문자 W. `webhook`으로 쓰면 kubelet이 기동 실패한다.
- `readOnlyPort: 0`은 최상위 필드 — authentication/authorization 블록 안이 아니다.
- 재시작 누락이 최다 실수. 수정만 하고 넘어가면 반영되지 않는다.
- kubelet이 안 뜨면 `journalctl -u kubelet -f`로 YAML 문법 오류부터 확인.

</details>

---

## 4. 인증서 기반 사용자 생성 워크플로우

Kubernetes에는 User 객체가 없다. 클러스터 CA가 서명한 클라이언트 인증서의 **CN(Common Name)이 사용자명, O(Organization)가 그룹**으로 해석된다. "새 개발자 alice에게 dev 네임스페이스 접근 권한을 부여하라"는 문제는 아래 6단계를 한 번에 수행하는 문제다.

### 4.1 전체 흐름 (6단계)

```bash
# 1) 개인키 + CSR 파일 생성
openssl genrsa -out alice.key 2048
openssl req -new -key alice.key -out alice.csr -subj "/CN=alice/O=dev-team"

# 2) CertificateSigningRequest 리소스 생성 (request는 CSR 파일의 base64 한 줄)
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: alice
spec:
  request: $(cat alice.csr | base64 -w0)
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400
  usages:
  - client auth
EOF

# 3) 승인 및 서명된 인증서 추출
kubectl get csr                       # Pending 확인
kubectl certificate approve alice     # Approved,Issued
kubectl get csr alice -o jsonpath='{.status.certificate}' | base64 -d > alice.crt

# 4) kubeconfig에 자격증명 등록
kubectl config set-credentials alice \
  --client-certificate=alice.crt --client-key=alice.key --embed-certs=true

# 5) 컨텍스트 생성
kubectl config set-context alice@kubernetes --cluster=kubernetes --user=alice

# 6) RBAC 연결 (인증서만으로는 아무 권한도 없다)
kubectl create role dev-role -n dev --verb=get,list,watch --resource=pods
kubectl create rolebinding alice-rb -n dev --role=dev-role --user=alice

# 검증
kubectl config use-context alice@kubernetes
kubectl get pods -n dev               # 성공
kubectl get pods -n kube-system       # Forbidden 이면 정상
kubectl config use-context kubernetes-admin@kubernetes   # 원래 컨텍스트 복귀!
```

> **📌 암기 포인트**: `signerName: kubernetes.io/kube-apiserver-client` — 사용자용 클라이언트 인증서 서명자. kubelet serving 인증서용 `kubernetes.io/kubelet-serving`과 혼동하지 말 것. `usages`는 `client auth` 하나면 된다.

> **⚠️ 함정**:
> - `request` 필드에는 **CSR 파일**(.csr)의 base64를 넣는다. key나 crt를 넣으면 안 된다. `base64 -w0`으로 줄바꿈 없이.
> - 승인 전 상태는 Pending — `kubectl certificate approve`를 잊으면 `.status.certificate`가 비어 있다.
> - RBAC의 `--user=alice`는 인증서의 CN과 정확히 일치해야 한다.
> - 검증 후 **관리자 컨텍스트로 복귀**하지 않으면 다음 문제를 권한 없는 사용자로 풀게 된다.

### 4.2 인증서 내용 확인 / 사용자 접근 차단

```bash
# 발급된 인증서의 CN/O/만료일 확인
openssl x509 -in alice.crt -noout -text | grep -A1 Subject

# 사용자 접근을 "차단"하려면: 인증서는 회수(revoke)가 불가능하므로
# 1) 해당 사용자에 대한 모든 RoleBinding/ClusterRoleBinding 제거 (실질적 권한 박탈)
kubectl get rolebindings,clusterrolebindings -A -o wide | grep alice
kubectl delete rolebinding alice-rb -n dev
# 2) 아직 서명 전이라면 CSR 거부/삭제
kubectl certificate deny alice
kubectl delete csr alice
```

### 📝 문제로 이해하기

```
kubectl config use-context cks
```

Task (mini): A CertificateSigningRequest for user `dev-bob` is already present in the cluster and is in `Pending` state. Approve it, extract the signed certificate to `/opt/course/m4/bob.crt`, and grant the user permission to `get` and `list` pods in namespace `sandbox`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 이미 CSR 리소스가 있으므로 approve → 인증서 추출 → RBAC 연결 3단계만 수행.

**2) 단계별 명령어**:

```bash
kubectl get csr                                  # dev-bob Pending 확인
kubectl certificate approve dev-bob
kubectl get csr dev-bob -o jsonpath='{.status.certificate}' | base64 -d > /opt/course/m4/bob.crt

kubectl create role bob-role -n sandbox --verb=get,list --resource=pods
kubectl create rolebinding bob-rb -n sandbox --role=bob-role --user=dev-bob
```

**3) 검증**:

```bash
kubectl get csr dev-bob                          # Approved,Issued
openssl x509 -in /opt/course/m4/bob.crt -noout -subject   # CN=dev-bob 확인
kubectl auth can-i list pods -n sandbox --as=dev-bob      # yes
kubectl auth can-i delete pods -n sandbox --as=dev-bob    # no
```

**4) ⚠️ 함정 포인트**:
- `.status.certificate`는 base64 인코딩 상태 — `base64 -d`를 거치지 않으면 PEM이 아닌 쓰레기 파일이 저장된다.
- RBAC 주체는 `--user=dev-bob` (CSR 리소스명이 아니라 인증서 CN 기준 — 보통 문제에서 동일하게 출제).
- 저장 경로 디렉토리가 없으면 `mkdir -p /opt/course/m4` 먼저.

</details>

---

## 5. Kubernetes 업그레이드

### 5.1 왜 업그레이드가 보안 도메인인가

- Kubernetes는 최신 3개 마이너 버전만 패치를 지원한다. 구버전 방치 = 공개된 CVE에 무방비.
- CKS 커리큘럼의 "Update Kubernetes frequently" 항목이 이것. 시험에서는 kubeadm으로 컨트롤플레인 또는 워커 노드를 한 단계 마이너 버전 업그레이드하는 형태로 출제된다.
- 시험 환경은 Kubernetes v1.35 기반(시험 환경은 최신 마이너 버전을 릴리스 후 4~8주 내 반영)이므로, 버전 숫자는 문제 지문이 지정하는 값을 그대로 쓰면 된다.

### 5.2 버전 스큐 정책 (핵심만)

| 컴포넌트 | 허용 스큐 |
|---|---|
| kube-apiserver | 기준점 — HA 구성 간에는 1 마이너 차이까지 |
| kubelet | apiserver보다 **최대 3 마이너 낮게** 허용 (높으면 안 됨) |
| kubectl | apiserver ±1 마이너 |
| controller-manager/scheduler | apiserver보다 높으면 안 됨 |

> **📌 암기 포인트**: 업그레이드 순서는 항상 **컨트롤플레인 먼저, 워커는 나중**. 컴포넌트 중에서는 apiserver가 가장 먼저 올라간다(kubeadm이 순서를 처리해 준다).

### 5.3 컨트롤플레인 업그레이드 절차 (Ubuntu / kubeadm)

```bash
ssh cks-controlplane

# 0) 패키지 저장소의 마이너 버전 라인 갱신 (pkgs.k8s.io는 마이너별 저장소)
sudo sed -i 's/v1.34/v1.35/' /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update

# 1) kubeadm 업그레이드
sudo apt-mark unhold kubeadm
sudo apt-get install -y kubeadm=1.35.1-*
sudo apt-mark hold kubeadm
kubeadm version

# 2) 업그레이드 계획 확인 후 적용
sudo kubeadm upgrade plan
sudo kubeadm upgrade apply v1.35.1

# 3) 노드 비우기
kubectl drain cks-controlplane --ignore-daemonsets

# 4) kubelet/kubectl 업그레이드
sudo apt-mark unhold kubelet kubectl
sudo apt-get install -y kubelet=1.35.1-* kubectl=1.35.1-*
sudo apt-mark hold kubelet kubectl
sudo systemctl daemon-reload && sudo systemctl restart kubelet

# 5) 복귀
kubectl uncordon cks-controlplane
kubectl get nodes    # VERSION 이 v1.35.1 인지 확인
```

### 5.4 워커 노드 업그레이드 절차

```bash
# 컨트롤플레인(또는 점프 호스트)에서 먼저 drain
kubectl drain wk8s-node-1 --ignore-daemonsets --delete-emptydir-data

ssh wk8s-node-1
sudo sed -i 's/v1.34/v1.35/' /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-mark unhold kubeadm
sudo apt-get install -y kubeadm=1.35.1-*
sudo apt-mark hold kubeadm

sudo kubeadm upgrade node        # 워커는 apply가 아니라 node!

sudo apt-mark unhold kubelet kubectl
sudo apt-get install -y kubelet=1.35.1-* kubectl=1.35.1-*
sudo apt-mark hold kubelet kubectl
sudo systemctl daemon-reload && sudo systemctl restart kubelet
exit

kubectl uncordon wk8s-node-1
kubectl get nodes
```

> **⚠️ 함정**:
> - 워커에서 `kubeadm upgrade apply`를 치면 안 된다. 워커는 `kubeadm upgrade node`.
> - drain 시 `--ignore-daemonsets` 없이는 진행이 막힌다. emptyDir을 쓰는 Pod가 있으면 `--delete-emptydir-data`도 필요.
> - `apt-get install kubeadm=1.35.1-*` 처럼 패키지 버전 뒤 `-*` 접미어를 붙여야 매칭된다. 정확한 버전 문자열은 `apt-cache madison kubeadm`으로 확인.
> - 마지막에 `uncordon`을 잊으면 노드가 SchedulingDisabled로 남아 감점.

### 📝 문제로 이해하기

```
kubectl config use-context cks
ssh cks-controlplane
```

Task (mini): The control plane node `cks-controlplane` is running an outdated Kubernetes version. Upgrade kubeadm, the control plane components, kubelet and kubectl on this node to version `1.35.1`. Make the node schedulable again afterwards. Do not upgrade any worker nodes.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 5.3의 표준 절차 그대로 — kubeadm → upgrade apply → drain → kubelet/kubectl → uncordon.

**2) 단계별 명령어**: 위 5.3 코드블록과 동일 (버전 1.35.1). 순서만 정확히:

```bash
sudo apt-mark unhold kubeadm && sudo apt-get update
sudo apt-get install -y kubeadm=1.35.1-* && sudo apt-mark hold kubeadm
sudo kubeadm upgrade plan
sudo kubeadm upgrade apply v1.35.1
kubectl drain cks-controlplane --ignore-daemonsets
sudo apt-mark unhold kubelet kubectl
sudo apt-get install -y kubelet=1.35.1-* kubectl=1.35.1-*
sudo apt-mark hold kubelet kubectl
sudo systemctl daemon-reload && sudo systemctl restart kubelet
kubectl uncordon cks-controlplane
```

**3) 검증**:

```bash
kubectl get nodes
# cks-controlplane   Ready   control-plane   ...   v1.35.1  (SchedulingDisabled 없어야 함)
```

**4) ⚠️ 함정 포인트**:
- `kubeadm upgrade apply v1.35.1` — 버전 앞에 `v`가 붙는다. apt 패키지 버전(`1.35.1-*`)에는 `v`가 없다.
- 저장소 라인이 구 마이너 버전을 가리키면 새 패키지가 보이지 않는다. `/etc/apt/sources.list.d/kubernetes.list` 확인.
- drain을 upgrade apply 전에 해도 되지만, 그 경우 컨트롤플레인 static pod는 어차피 남아 있으므로 결과는 같다. 공식 문서 순서(apply 후 drain)를 따르는 게 안전.
- "워커는 건드리지 말라"는 지시를 놓치고 전체 업그레이드를 하면 시간 낭비 + 채점 리스크.

</details>

---

## 6. 실전 연습문제 10제

> **💡 시험 팁**: 각 문제의 첫 줄 `kubectl config use-context ...`를 실행하는 습관을 들여라. 실제 시험에서 컨텍스트를 바꾸지 않고 푸는 것이 가장 흔한 0점 사유다. 노드 작업 후에는 반드시 `exit`로 점프 호스트에 복귀할 것.

### Q1. [RBAC] Role/RoleBinding 신규 생성

```
kubectl config use-context wk8s
```

Create a ServiceAccount `ci-bot` in namespace `pipeline`. Create a Role `ci-role` in the same namespace that allows only `get`, `list` and `watch` on `pods` and `pods/log`. Bind the Role to the ServiceAccount using a RoleBinding named `ci-rb`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 전부 명령형 커맨드로 해결. 서브리소스 `pods/log`는 `--resource=pods/log`로 그대로 쓸 수 있다.

**2) 단계별 명령어**:

```bash
kubectl create serviceaccount ci-bot -n pipeline
kubectl create role ci-role -n pipeline \
  --verb=get,list,watch --resource=pods,pods/log
kubectl create rolebinding ci-rb -n pipeline \
  --role=ci-role --serviceaccount=pipeline:ci-bot
```

생성된 Role의 rules는 다음과 같다:

```yaml
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
```

**3) 검증**:

```bash
kubectl auth can-i watch pods -n pipeline --as=system:serviceaccount:pipeline:ci-bot   # yes
kubectl auth can-i get pods --subresource=log -n pipeline --as=system:serviceaccount:pipeline:ci-bot # yes
kubectl auth can-i create pods -n pipeline --as=system:serviceaccount:pipeline:ci-bot  # no
```

**4) ⚠️ 함정 포인트**:
- `pods/log` 같은 서브리소스는 별도 리소스로 취급된다 — `pods` 권한만으로 로그 조회는 불가.
- 세 리소스(SA, Role, RoleBinding) 모두 `-n pipeline` 필수.

</details>

### Q2. [RBAC] 와일드카드 권한 제거

```
kubectl config use-context wk8s
```

In namespace `stage` there is a Role `stage-admin` bound to ServiceAccount `stage-sa`. The Role currently uses wildcards. Edit the Role so that the ServiceAccount can only `get`, `list` and `watch` resources `pods` and `services`. Do not delete the Role or the RoleBinding.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: Binding은 그대로 두고 Role의 rules만 교체하면 된다. `kubectl edit role`이 가장 빠르다.

**2) 단계별 명령어**:

```bash
kubectl get role stage-admin -n stage -o yaml   # 현재 상태 확인 (verbs: ["*"] 등)
kubectl edit role stage-admin -n stage
```

rules 블록을 다음으로 교체:

```yaml
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
```

**3) 검증**:

```bash
kubectl auth can-i list services -n stage --as=system:serviceaccount:stage:stage-sa   # yes
kubectl auth can-i delete pods -n stage --as=system:serviceaccount:stage:stage-sa     # no
kubectl auth can-i get secrets -n stage --as=system:serviceaccount:stage:stage-sa     # no
kubectl auth can-i --list -n stage --as=system:serviceaccount:stage:stage-sa          # 전체 재확인
```

**4) ⚠️ 함정 포인트**:
- `apiGroups: ["*"]`가 남아 있으면 안 된다. pods/services는 core 그룹이므로 `[""]`.
- Role 이름을 바꾸거나 삭제 후 재생성하면 "Do not delete" 지시 위반. rules만 수정.
- 와일드카드 제거 후에도 `--list`로 잔여 권한을 한 번 훑어 다른 rule이 남아 있지 않은지 확인.

</details>

### Q3. [RBAC] 위험 verb(escalate/bind/impersonate) 감사 및 제거

```
kubectl config use-context cks
```

The ClusterRole `ops-role` grants dangerous permissions. Identify any rules using the verbs `escalate`, `bind` or `impersonate` and remove those rules from the ClusterRole. Write the names of the dangerous verbs you removed to `/opt/course/3/verbs.txt`, one per line. Keep all other rules unchanged.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: ClusterRole을 덤프해 위험 verb가 포함된 rule을 찾고, 해당 rule만 삭제한다. 기록 파일도 잊지 말 것.

**2) 단계별 명령어**:

```bash
kubectl get clusterrole ops-role -o yaml | grep -nE 'escalate|bind|impersonate'
kubectl edit clusterrole ops-role
# 예: 아래와 같은 rule 블록들을 통째로 삭제
#  - apiGroups: ["rbac.authorization.k8s.io"]
#    resources: ["clusterroles"]
#    verbs: ["escalate", "bind"]
#  - apiGroups: [""]
#    resources: ["users", "groups", "serviceaccounts"]
#    verbs: ["impersonate"]

mkdir -p /opt/course/3
printf 'escalate\nbind\nimpersonate\n' > /opt/course/3/verbs.txt
```

**3) 검증**:

```bash
kubectl get clusterrole ops-role -o yaml | grep -E 'escalate|bind|impersonate'   # 출력 없어야 함
cat /opt/course/3/verbs.txt
```

**4) ⚠️ 함정 포인트**:
- `bind`라는 단어는 RoleBinding 리소스명에도 등장할 수 있다 — verbs 배열 안의 `bind`만 제거 대상이다.
- rule 하나에 정상 verb와 위험 verb가 섞여 있으면(예: `["get", "impersonate"]`) rule 전체 삭제가 아니라 위험 verb만 배열에서 빼는 것이 "Keep all other rules unchanged"에 부합한다. 지문을 그대로 따르라.
- 실제로 제거된 verb만 파일에 기록하라 — 예를 들어 impersonate가 없었다면 두 줄만 쓴다.

</details>

### Q4. [SA] 토큰 자동 마운트 차단

```
kubectl config use-context wk8s
```

In namespace `web` the Deployment `frontend` runs with the `default` ServiceAccount and mounts its API token. Create a new ServiceAccount `frontend-sa` with token automounting disabled at the ServiceAccount level, and configure the Deployment to use it. The Pods of the Deployment must not have a ServiceAccount token mounted.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: SA를 automount false로 생성 → Deployment의 pod template에 serviceAccountName 지정. Deployment는 template 수정만으로 롤링 재생성되므로 Pod 삭제가 필요 없다.

**2) 단계별 명령어**:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: frontend-sa
  namespace: web
automountServiceAccountToken: false
EOF

kubectl patch deployment frontend -n web \
  -p '{"spec":{"template":{"spec":{"serviceAccountName":"frontend-sa"}}}}'
kubectl rollout status deployment frontend -n web
```

**3) 검증**:

```bash
POD=$(kubectl get pods -n web -l app=frontend -o jsonpath='{.items[0].metadata.name}')
kubectl get pod $POD -n web -o jsonpath='{.spec.serviceAccountName}'   # frontend-sa
kubectl exec $POD -n web -- ls /var/run/secrets/kubernetes.io/serviceaccount
# No such file or directory 이면 성공
```

**4) ⚠️ 함정 포인트**:
- pod template의 `automountServiceAccountToken`이 true로 명시돼 있으면 **Pod 레벨이 SA 레벨보다 우선**하므로 토큰이 계속 마운트된다. `kubectl get deploy frontend -n web -o yaml | grep automount`로 확인하고, 있으면 제거하거나 false로 바꿔라.
- patch 후 이전 ReplicaSet의 Pod를 보고 검증하면 안 된다. `rollout status`로 새 Pod가 뜬 뒤 검증.

</details>

### Q5. [SA] 미사용 SA 정리 + 토큰 발급

```
kubectl config use-context wk8s
```

Namespace `ops` contains several ServiceAccounts. Find all ServiceAccounts that are not used by any Pod in the namespace and delete them, except the `default` ServiceAccount. Then create a token for the remaining non-default ServiceAccount with a validity of 30 minutes and save it to `/opt/course/5/token`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: SA 목록과 Pod들이 실제 사용하는 SA 목록을 비교 → 차집합 삭제(default 제외) → 남은 SA로 `kubectl create token`.

**2) 단계별 명령어**:

```bash
kubectl get sa -n ops
kubectl get pods -n ops -o jsonpath='{range .items[*]}{.spec.serviceAccountName}{"\n"}{end}' | sort -u
# 예: 사용 중 = app-sa / 전체 = default, app-sa, old-sa, temp-sa
kubectl delete sa old-sa temp-sa -n ops

mkdir -p /opt/course/5
kubectl create token app-sa -n ops --duration=30m > /opt/course/5/token
```

**3) 검증**:

```bash
kubectl get sa -n ops            # default, app-sa 만 남음
cat /opt/course/5/token          # eyJ... 형태의 JWT
```

**4) ⚠️ 함정 포인트**:
- `default` SA는 삭제 대상에서 제외하라는 지시를 놓치기 쉽다(삭제해도 자동 재생성되지만 지시 위반).
- Pod가 `serviceAccountName`을 명시하지 않으면 jsonpath 출력이 `default`로 나온다(빈 줄이 아니라). 목록 비교 시 참고.
- `--duration=30m` 누락 시 기본 1시간 토큰이 발급된다 — 지문 요구사항과 다르다.
- 토큰 값 뒤에 개행 외 다른 문자열이 붙지 않도록 리다이렉션(`>`)으로 바로 저장.

</details>

### Q6. [API 하드닝] kube-apiserver 익명 접근 차단

```
kubectl config use-context cks
ssh cks-controlplane
```

The kube-apiserver of this cluster accepts anonymous requests and profiling is enabled. Reconfigure the apiserver so that anonymous authentication is disabled, profiling is disabled, and the `NodeRestriction` admission plugin is enabled. Verify that an anonymous request to the API server is rejected with HTTP 401.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: static pod manifest `/etc/kubernetes/manifests/kube-apiserver.yaml`의 command 플래그 3개를 수정하고, kubelet이 apiserver를 재생성할 때까지 기다린 뒤 curl로 검증.

**2) 단계별 명령어**:

```bash
ssh cks-controlplane
sudo cp /etc/kubernetes/manifests/kube-apiserver.yaml /root/kube-apiserver.yaml.bak  # 백업은 manifests 밖에!
sudo vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

command 배열에서 다음을 설정(기존 플래그가 있으면 값 수정, 없으면 추가):

```yaml
    - --anonymous-auth=false
    - --profiling=false
    - --enable-admission-plugins=NodeRestriction
```

```bash
# kubelet이 static pod를 재생성할 때까지 30초~1분 대기
watch crictl ps   # kube-apiserver 컨테이너가 새로 Running 되는지 확인
```

**3) 검증**:

```bash
kubectl get nodes    # apiserver 복귀 확인
curl -k https://localhost:6443/api -o /dev/null -w '%{http_code}\n'   # 401
kubectl -n kube-system get pod -l component=kube-apiserver \
  -o jsonpath='{.items[0].spec.containers[0].command}' | tr ',' '\n' | grep -E 'anonymous|profiling|admission'
```

**4) ⚠️ 함정 포인트**:
- 백업 파일을 `/etc/kubernetes/manifests/` 안에 두면 kubelet이 그것도 static pod로 띄우려 한다. 반드시 디렉토리 밖에 백업.
- `--enable-admission-plugins`가 이미 있으면 새 줄을 추가하지 말고 기존 값에 `NodeRestriction`을 포함시켜라(쉼표 구분). 같은 플래그 중복 시 마지막 값만 적용되어 의도가 깨질 수 있다.
- apiserver가 안 뜨면: `crictl ps -a`로 Exited 컨테이너 확인 → `crictl logs <ID>` 또는 `/var/log/pods/kube-system_kube-apiserver-*/` 로그에서 플래그 오타 확인. `journalctl -u kubelet | tail`도 유용.
- 수정 직후 몇십 초간 `kubectl`이 connection refused를 뱉는 것은 정상. 당황하지 말 것.

</details>

### Q7. [kubelet 하드닝] 워커 노드 kubelet 잠그기

```
kubectl config use-context wk8s
ssh wk8s-node-1
```

A security scan reported that the kubelet on `wk8s-node-1` accepts anonymous requests on port 10250 and serves an unauthenticated read-only API on port 10255. Harden the kubelet configuration to close both findings and make sure requests are authorized via the API server. Restart the kubelet and verify your changes.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: kubelet 하드닝 4종 세트를 `/var/lib/kubelet/config.yaml`에 적용 — anonymous 차단, webhook 인증, Webhook 인가, readOnlyPort 0.

**2) 단계별 명령어**:

```bash
ssh wk8s-node-1
ps aux | grep kubelet | grep -o '\-\-config=[^ ]*'   # config 경로 확인 (보통 /var/lib/kubelet/config.yaml)
sudo vim /var/lib/kubelet/config.yaml
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
sudo systemctl restart kubelet
sudo systemctl status kubelet
```

**3) 검증**:

```bash
curl -sk https://localhost:10250/pods     # Unauthorized
curl -s  http://localhost:10255/pods      # 연결 거부(출력 없음/refused)가 정상
exit
kubectl get node wk8s-node-1              # Ready 유지
```

**4) ⚠️ 함정 포인트**:
- `readOnlyPort` 필드가 파일에 아예 없을 수 있다 — 없으면 최상위에 `readOnlyPort: 0`을 **추가**해야 한다(기본값이 0인 배포판도 있지만 지문이 요구하면 명시).
- `authorization.mode: AlwaysAllow`로 남겨두면 익명 인증만 막힐 뿐 토큰만 있으면 모든 요청이 허용된다. 반드시 `Webhook`.
- YAML 들여쓰기 오류로 kubelet이 죽으면 노드가 NotReady가 된다. `journalctl -u kubelet -f`로 즉시 확인.

</details>

### Q8. [CSR] 인증서 사용자 생성 전체 워크플로우

```
kubectl config use-context cks
```

Create a new user `jane` who can authenticate to the cluster with a client certificate:

1. A private key and CSR file are already provided at `/opt/course/8/jane.key` and `/opt/course/8/jane.csr` (CN=jane).
2. Create a CertificateSigningRequest object named `jane`, approve it, and save the issued certificate to `/opt/course/8/jane.crt`.
3. Add credentials and a context `jane@kubernetes` to the default kubeconfig.
4. Allow user `jane` to `get`, `list` and `watch` Deployments in namespace `apps` only.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 4.1의 6단계 중 key/CSR 생성은 이미 되어 있으므로 CSR 리소스 생성부터 시작한다.

**2) 단계별 명령어**:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: jane
spec:
  request: $(cat /opt/course/8/jane.csr | base64 -w0)
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
EOF

kubectl certificate approve jane
kubectl get csr jane -o jsonpath='{.status.certificate}' | base64 -d > /opt/course/8/jane.crt

kubectl config set-credentials jane \
  --client-certificate=/opt/course/8/jane.crt \
  --client-key=/opt/course/8/jane.key --embed-certs=true
kubectl config set-context jane@kubernetes --cluster=kubernetes --user=jane

kubectl create role deploy-viewer -n apps --verb=get,list,watch --resource=deployments
kubectl create rolebinding jane-rb -n apps --role=deploy-viewer --user=jane
```

**3) 검증**:

```bash
kubectl config use-context jane@kubernetes
kubectl get deployments -n apps        # 성공
kubectl get pods -n apps               # Forbidden (deployments만 허용했으므로)
kubectl config use-context cks         # 반드시 원래 컨텍스트로 복귀
```

**4) ⚠️ 함정 포인트**:
- `request:`에 base64 인코딩된 **CSR 파일** 내용이 들어가야 한다. heredoc의 `$(...)`가 실행되도록 위 블록을 그대로 셸에 붙여넣으면 된다.
- `signerName`을 빠뜨리면 생성이 거부된다. 사용자용은 `kubernetes.io/kube-apiserver-client`.
- 클러스터 이름이 `kubernetes`가 아닐 수 있다 — `kubectl config get-clusters`로 확인 후 `--cluster=` 값 지정.
- Deployments는 `apps` API 그룹이지만 `kubectl create role --resource=deployments`가 자동으로 처리한다.
- 검증 후 관리자 컨텍스트 복귀를 잊지 말 것.

</details>

### Q9. [업그레이드] 워커 노드 업그레이드

```
kubectl config use-context wk8s
ssh wk8s-node-1
```

Worker node `wk8s-node-1` is running Kubernetes `1.34.x` while the control plane has already been upgraded to `1.35.1`. Upgrade kubeadm, kubelet and kubectl on the worker node to version `1.35.1`. Drain the node before the upgrade and make it schedulable again afterwards.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: drain(점프 호스트에서) → 노드에서 kubeadm 업그레이드 → `kubeadm upgrade node` → kubelet/kubectl 업그레이드 + 재시작 → uncordon.

**2) 단계별 명령어**:

```bash
kubectl drain wk8s-node-1 --ignore-daemonsets --delete-emptydir-data

ssh wk8s-node-1
sudo sed -i 's/v1.34/v1.35/' /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-mark unhold kubeadm
sudo apt-get install -y kubeadm=1.35.1-*
sudo apt-mark hold kubeadm
sudo kubeadm upgrade node

sudo apt-mark unhold kubelet kubectl
sudo apt-get install -y kubelet=1.35.1-* kubectl=1.35.1-*
sudo apt-mark hold kubelet kubectl
sudo systemctl daemon-reload && sudo systemctl restart kubelet
exit

kubectl uncordon wk8s-node-1
```

**3) 검증**:

```bash
kubectl get nodes
# wk8s-node-1   Ready   <none>   ...   v1.35.1   (SchedulingDisabled 없음)
```

**4) ⚠️ 함정 포인트**:
- 워커에서는 `kubeadm upgrade node` — `apply`는 컨트롤플레인 전용이다.
- drain은 워커 자신이 아니라 **kubectl이 동작하는 점프 호스트/컨트롤플레인에서** 실행한다(워커에는 관리자 kubeconfig가 없는 경우가 많다).
- 저장소 파일의 마이너 버전 갱신을 잊으면 `apt-get install kubeadm=1.35.1-*`가 패키지를 찾지 못한다. `apt-cache madison kubeadm`으로 후보 확인.
- `systemctl daemon-reload` 없이 restart만 하면 유닛 파일 갱신이 반영되지 않을 수 있다. 두 명령을 세트로 외워라.
- 마지막 uncordon 누락 주의.

</details>

### Q10. [복합] 권한 감사 후 최소권한으로 축소

```
kubectl config use-context cks
```

The ServiceAccount `deploy-bot` in namespace `prod` is reported to have far more permissions than needed. The application only needs to `get`, `list` and `update` Deployments in namespace `prod`.

1. Write the full list of current permissions of the ServiceAccount in namespace `prod` to `/opt/course/10/before.txt`.
2. Find and remove the binding that grants excessive permissions (it may be cluster-wide).
3. Create a Role `deploy-bot-role` and RoleBinding `deploy-bot-rb` in namespace `prod` granting exactly the required permissions.
4. Write the new permission list to `/opt/course/10/after.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**: 감사(`auth can-i --list`) → 역추적(어떤 Binding이 SA를 참조하나) → 과도한 Binding 제거 → 최소권한 Role/RoleBinding 신설 → 재감사. 실전 복합 문제의 정석 흐름이다.

**2) 단계별 명령어**:

```bash
mkdir -p /opt/course/10
kubectl auth can-i --list -n prod \
  --as=system:serviceaccount:prod:deploy-bot > /opt/course/10/before.txt
# 예: *.* [*] [*] 같은 관리자급 권한이 보임

# SA를 참조하는 Binding 역추적 (cluster-admin류 ClusterRoleBinding이 범인인 경우가 많다)
kubectl get clusterrolebindings -o wide | grep deploy-bot
kubectl get rolebindings -A -o wide | grep deploy-bot
# 예: crb 'deploy-bot-admin'이 cluster-admin을 SA에 바인딩하고 있음
kubectl delete clusterrolebinding deploy-bot-admin

# 최소권한으로 재구성
kubectl create role deploy-bot-role -n prod \
  --verb=get,list,update --resource=deployments
kubectl create rolebinding deploy-bot-rb -n prod \
  --role=deploy-bot-role --serviceaccount=prod:deploy-bot

kubectl auth can-i --list -n prod \
  --as=system:serviceaccount:prod:deploy-bot > /opt/course/10/after.txt
```

**3) 검증**:

```bash
kubectl auth can-i update deployments -n prod --as=system:serviceaccount:prod:deploy-bot  # yes
kubectl auth can-i delete deployments -n prod --as=system:serviceaccount:prod:deploy-bot  # no
kubectl auth can-i get secrets -n prod --as=system:serviceaccount:prod:deploy-bot         # no
diff /opt/course/10/before.txt /opt/course/10/after.txt   # 권한 축소가 눈에 보임
```

**4) ⚠️ 함정 포인트**:
- 과도한 권한의 근원이 **ClusterRoleBinding**이면 네임스페이스 검색(`-n prod`)만으로는 찾을 수 없다. clusterrolebindings를 반드시 함께 뒤져라.
- ClusterRole 자체(예: cluster-admin)를 수정/삭제하면 안 된다 — 다른 주체들이 쓰고 있다. **Binding만 제거**한다.
- `auth can-i --list` 출력에는 모든 인증 사용자에게 부여되는 기본 권한(selfsubjectreviews 생성 등)이 항상 포함된다. after.txt에 이런 항목이 남아 있는 것은 정상이다.
- before.txt를 Binding 제거 **전에** 저장해야 한다. 순서가 바뀌면 복구 불가.

</details>

---

## 7. 🎯 시험 직전 체크리스트

- [ ] RBAC 조합 4가지 표를 말로 설명할 수 있다 (Role+CRB는 불가능한 조합, roleRef는 immutable)
- [ ] `kubectl create role/clusterrole/rolebinding/clusterrolebinding` 명령형 문법이 손에 붙어 있다
- [ ] 위험 verb 3개(escalate, bind, impersonate)와 와일드카드의 의미를 즉시 설명할 수 있다
- [ ] `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa> -n <ns>` 를 오타 없이 칠 수 있다
- [ ] `automountServiceAccountToken: false`의 위치(SA 최상위 vs Pod spec)와 우선순위(Pod 우선)를 안다
- [ ] `kubectl create token <sa> --duration=...` 으로 단기 토큰을 발급할 수 있다
- [ ] apiserver 하드닝 플래그: `--anonymous-auth=false`, `--profiling=false`, `--enable-admission-plugins=NodeRestriction`, `--service-account-lookup=true`
- [ ] 익명 curl 결과 해석: 401 = 익명 차단됨, 403 = 익명 인증은 되지만 RBAC 거부
- [ ] kubelet 하드닝 4종: anonymous false / webhook true / mode Webhook / readOnlyPort 0 + `systemctl restart kubelet`
- [ ] static pod manifest 수정 후 안 뜰 때: `crictl ps -a` → `journalctl -u kubelet` → `/var/log/pods/` 순서로 디버깅
- [ ] CSR 워크플로우 6단계(key→CSR→CSR객체→approve→kubeconfig→RBAC)를 문서 없이 재현할 수 있다
- [ ] `signerName: kubernetes.io/kube-apiserver-client` 를 외우고 있다
- [ ] kubeadm 업그레이드: 컨트롤플레인 `upgrade apply`, 워커 `upgrade node`, drain→업그레이드→uncordon 순서
- [ ] 답안 파일은 항상 `/opt/course/<번호>/` 아래, 디렉토리 없으면 `mkdir -p` 먼저
- [ ] 문제마다 첫 줄의 `kubectl config use-context`를 실행했고, 사용자 컨텍스트 테스트 후 관리자로 복귀했다

## 8. 핵심 명령어 치트시트

```bash
### RBAC
kubectl create role r1 -n ns1 --verb=get,list,watch --resource=pods,pods/log
kubectl create rolebinding rb1 -n ns1 --role=r1 --serviceaccount=ns1:sa1
kubectl create clusterrole cr1 --verb=get,list --resource=nodes
kubectl create clusterrolebinding crb1 --clusterrole=cr1 --user=alice
kubectl create rolebinding rb2 -n ns1 --clusterrole=view --serviceaccount=ns1:sa1   # CR 재사용
kubectl auth can-i --list --as=system:serviceaccount:ns1:sa1 -n ns1
kubectl auth can-i delete pods --as=system:serviceaccount:ns1:sa1 -n ns1
kubectl get rolebindings,clusterrolebindings -A -o wide | grep sa1

### ServiceAccount
kubectl create serviceaccount sa1 -n ns1
kubectl create token sa1 -n ns1 --duration=30m
kubectl get pods -n ns1 -o jsonpath='{range .items[*]}{.spec.serviceAccountName}{"\n"}{end}' | sort -u
# SA 최상위: automountServiceAccountToken: false / Pod spec에도 동일 필드(Pod 우선)

### apiserver 하드닝 (/etc/kubernetes/manifests/kube-apiserver.yaml)
# --anonymous-auth=false --profiling=false
# --enable-admission-plugins=NodeRestriction --service-account-lookup=true
curl -k https://localhost:6443/api -o /dev/null -w '%{http_code}\n'   # 401 기대
crictl ps -a && journalctl -u kubelet | tail                          # 안 뜰 때

### kubelet 하드닝 (/var/lib/kubelet/config.yaml)
# authentication.anonymous.enabled: false / authentication.webhook.enabled: true
# authorization.mode: Webhook / readOnlyPort: 0
sudo systemctl restart kubelet
curl -sk https://localhost:10250/pods     # Unauthorized 기대

### CSR 사용자
openssl genrsa -out u.key 2048
openssl req -new -key u.key -out u.csr -subj "/CN=user1/O=team1"
cat u.csr | base64 -w0                    # CSR 객체 spec.request 값
kubectl certificate approve user1
kubectl get csr user1 -o jsonpath='{.status.certificate}' | base64 -d > u.crt
kubectl config set-credentials user1 --client-certificate=u.crt --client-key=u.key --embed-certs=true
kubectl config set-context user1@kubernetes --cluster=kubernetes --user=user1

### kubeadm 업그레이드
sudo apt-mark unhold kubeadm && sudo apt-get update
sudo apt-get install -y kubeadm=1.35.1-* && sudo apt-mark hold kubeadm
sudo kubeadm upgrade plan && sudo kubeadm upgrade apply v1.35.1   # 컨트롤플레인
sudo kubeadm upgrade node                                          # 워커
kubectl drain <node> --ignore-daemonsets --delete-emptydir-data
sudo apt-mark unhold kubelet kubectl
sudo apt-get install -y kubelet=1.35.1-* kubectl=1.35.1-* && sudo apt-mark hold kubelet kubectl
sudo systemctl daemon-reload && sudo systemctl restart kubelet
kubectl uncordon <node>
```
