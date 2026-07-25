# Domain 4. Minimize Microservice Vulnerabilities (20%)

Pod Security Admission, securityContext, Secrets와 Encryption at Rest, gVisor 샌드박스 격리, Cilium/Istio pod-to-pod 암호화까지 — 마이크로서비스 워크로드의 공격 표면을 줄이는 모든 기법을 다루는 최고 가중치 도메인이다.

> **📌 시험 비중 20%** — Supply Chain Security와 함께 CKS에서 가장 비중이 큰 도메인이다. 16문제 기준 3~4문제가 이 도메인에서 출제된다. 특히 PSA 라벨링, restricted 통과 pod 수정, Encryption at Rest 설정, RuntimeClass는 거의 매 시험 등장하는 단골 유형이므로 손이 자동으로 움직일 때까지 반복하라. 2024-10 커리큘럼 개편으로 Cilium/Istio pod-to-pod 암호화가 신규 추가되었다.

## 목차

- [1. Pod Security Standards와 Pod Security Admission](#1-pod-security-standards와-pod-security-admission)
- [2. securityContext 총정리](#2-securitycontext-총정리)
- [3. Kubernetes Secrets 심층](#3-kubernetes-secrets-심층)
- [4. Encryption at Rest](#4-encryption-at-rest)
- [5. 격리 기법 - gVisor와 RuntimeClass](#5-격리-기법---gvisor와-runtimeclass)
- [6. Pod-to-Pod 암호화 - Cilium과 Istio](#6-pod-to-pod-암호화---cilium과-istio)
- [연습문제 (실전 12문제)](#연습문제-실전-12문제)
- [🎯 시험 직전 체크리스트](#-시험-직전-체크리스트)
- [핵심 명령어 치트시트](#핵심-명령어-치트시트)

---

## 1. Pod Security Standards와 Pod Security Admission

### 1.1 PSP는 죽었다, PSA가 현행이다

PodSecurityPolicy(PSP)는 **v1.25에서 완전히 제거**되었다. 2024-10 커리큘럼 개편에서도 PSP는 삭제되었으므로 시험에 나오지 않는다. 현행 메커니즘은 **Pod Security Admission(PSA)** — kube-apiserver에 내장된 admission controller(=파드 생성·수정 등 API 요청을 승인 전에 검증하거나 바꾸는 관문)로, **네임스페이스 라벨**만으로 동작한다. 별도 설치나 CRD(Custom Resource Definition — 쿠버네티스 API에 사용자 정의 리소스 타입을 추가하는 확장)가 필요 없다.

PSA는 **Pod Security Standards(PSS)** 라는 3단계 보안 프로파일을 검사 기준으로 사용한다.

### 1.2 3레벨 비교 — 각 레벨이 금지하는 것

| 레벨 | 성격 | 주요 금지/요구 사항 |
|------|------|---------------------|
| `privileged` | 무제한 | 아무것도 금지하지 않음. 모든 것 허용 (kube-system 류 시스템 워크로드용) |
| `baseline` | 알려진 권한 상승 차단 | `privileged: true` 금지, `hostNetwork`/`hostPID`/`hostIPC` 금지, `hostPath` volume 금지, `hostPort` 금지, 허용 목록 밖의 capabilities 추가 금지, unsafe sysctls 금지, AppArmor/SELinux를 Unconfined 등으로 완화 금지 |
| `restricted` | 강력 제한 (baseline 포함 + 추가 요구) | `runAsNonRoot: true` 필수, `allowPrivilegeEscalation: false` 필수, `capabilities.drop: ["ALL"]` 필수 (추가는 `NET_BIND_SERVICE`만 허용), `seccompProfile.type`이 `RuntimeDefault` 또는 `Localhost`여야 함, volume 타입 제한 (`configMap`, `secret`, `emptyDir`, `projected`, `downwardAPI`, `csi`, `ephemeral`, `persistentVolumeClaim`만 허용) |

> **📌 암기 포인트** — restricted 4종 세트: **runAsNonRoot true / allowPrivilegeEscalation false / drop ALL / seccomp RuntimeDefault**. 이 4개만 컨테이너에 넣으면 대부분의 restricted 위반이 해결된다.

### 1.3 3모드 — enforce / audit / warn

| 모드 | 라벨 | 동작 |
|------|------|------|
| `enforce` | `pod-security.kubernetes.io/enforce` | 위반 pod **생성 거부** |
| `audit` | `pod-security.kubernetes.io/audit` | 생성은 허용, audit 로그에 annotation 기록 |
| `warn` | `pod-security.kubernetes.io/warn` | 생성은 허용, kubectl 사용자에게 warning 출력 |

버전 고정 라벨도 존재한다: `pod-security.kubernetes.io/enforce-version=v1.35` (모드별로 `audit-version`, `warn-version`도 가능). 지정하지 않으면 `latest`로 동작한다.

```bash
# 네임스페이스에 restricted 강제 + baseline 경고
kubectl label ns team-red \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.35 \
  pod-security.kubernetes.io/warn=baseline

# 라벨 확인
kubectl get ns team-red --show-labels

# 라벨을 실제로 붙이기 전에, 기존 pod 중 위반이 있는지 서버측 dry-run으로 미리 확인
kubectl label --dry-run=server --overwrite ns team-red \
  pod-security.kubernetes.io/enforce=restricted
```

> **⚠️ 함정** — `enforce`는 **새로 생성되는 pod에만** 적용된다. 라벨을 붙여도 이미 떠 있는 pod는 죽지 않는다. 또한 Deployment로 배포하면 거부 이벤트는 Deployment가 아니라 **ReplicaSet의 events**에 남는다. `kubectl describe rs -n <ns>` 또는 `kubectl get events -n <ns>`로 확인하라.

### 1.4 restricted를 통과하는 표준 pod 템플릿

시험에서 "이 pod가 restricted 네임스페이스에서 뜨도록 고쳐라"가 나오면 아래 템플릿을 그대로 적용한다.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: team-red
spec:
  securityContext:                # pod 레벨: seccomp은 여기 둬도 전 컨테이너에 적용됨
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: nginxinc/nginx-unprivileged:1.27   # 비루트 이미지(8080 포트)
    securityContext:              # container 레벨
      runAsNonRoot: true
      runAsUser: 101              # 이미지가 root로 시작하면 명시적 UID 필요
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
```

> **⚠️ 함정** — `runAsNonRoot: true`만 넣고 이미지가 root(UID 0)로 시작하면 admission은 통과해도 **런타임에 `CreateContainerConfigError`** 가 난다. 이미지가 root 기반이면 `runAsUser`에 0이 아닌 UID를 명시하거나 비루트 이미지를 쓰라. 반대로 nginx 정식 이미지는 80 포트 바인딩에 root가 필요하므로, 비루트 강제 시 `nginxinc/nginx-unprivileged` 같은 비루트 이미지(8080 포트)로 교체하는 것이 안전하다.

### 1.5 위반 pod 수정 워크플로우

1. 증상 확인: Deployment는 있는데 pod 개수가 0 → `kubectl -n <ns> describe rs <rs명>` 으로 거부 사유 확인. 에러 메시지에 위반 필드가 그대로 나온다 (예: `violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false, ...`).
2. `kubectl -n <ns> edit deploy <이름>` 으로 pod template의 securityContext를 1.4 템플릿대로 수정.
3. 저장 후 ReplicaSet이 pod를 새로 만들면 `kubectl -n <ns> get pods` 로 Running 확인.

### 1.6 클러스터 전역 기본값과 exemptions — AdmissionConfiguration

네임스페이스 라벨 없이도 클러스터 전체 기본 레벨을 걸고, 특정 네임스페이스/사용자를 면제(exempt)할 수 있다. kube-apiserver의 `--admission-control-config-file` 로 지정하는 AdmissionConfiguration 파일을 쓴다.

```yaml
# /etc/kubernetes/psa/admission-config.yaml (control plane 노드에 저장)
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "baseline"
      enforce-version: "latest"
      audit: "restricted"
      audit-version: "latest"
      warn: "restricted"
      warn-version: "latest"
    exemptions:
      usernames: []
      runtimeClasses: []
      namespaces: ["kube-system", "legacy"]
```

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml 수정 사항
spec:
  containers:
  - command:
    - kube-apiserver
    - --admission-control-config-file=/etc/kubernetes/psa/admission-config.yaml
    # ... 기존 플래그 유지 ...
    volumeMounts:
    - name: psa-config
      mountPath: /etc/kubernetes/psa
      readOnly: true
  volumes:
  - name: psa-config
    hostPath:
      path: /etc/kubernetes/psa
      type: DirectoryOrCreate
```

> **💡 시험 팁** — static pod manifest를 저장하면 kubelet이 apiserver를 자동 재생성한다(30초~1분 대기). 안 뜨면 `crictl ps -a`, `journalctl -u kubelet`, `/var/log/pods/` 순으로 디버깅. **volume mount를 빠뜨리면 apiserver가 파일을 못 읽어 기동 실패**하는 것이 최다 실수다.

### 📝 문제로 이해하기

```bash
kubectl config use-context cluster1
```

**Task**: Namespace `magpie` exists in the cluster. Configure it so that:

- Pods violating the `restricted` Pod Security Standard are **rejected**.
- Pods violating the `restricted` standard also generate a **warning**.

Then try to create a Pod named `test-priv` in namespace `magpie` using image `nginx:1.27` with `privileged: true`, and write the full error message returned by the API server to `/opt/course/psa/error.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

네임스페이스 라벨 2개(enforce, warn)를 붙이고, 위반 pod 생성을 시도해 거부 메시지를 파일로 저장한다.

**2) 단계별 풀이**

```bash
kubectl label ns magpie \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted

mkdir -p /opt/course/psa

# 위반 pod 생성 시도 → 에러 메시지를 파일로 저장 (stderr 리다이렉트 주의)
kubectl run test-priv -n magpie --image=nginx:1.27 \
  --overrides='{"apiVersion":"v1","spec":{"containers":[{"name":"test-priv","image":"nginx:1.27","securityContext":{"privileged":true}}]}}' \
  &> /opt/course/psa/error.txt

cat /opt/course/psa/error.txt
# Error from server (Forbidden): pods "test-priv" is forbidden: violates PodSecurity "restricted:latest": privileged ...
```

**3) 검증**

```bash
kubectl get ns magpie --show-labels
kubectl get pods -n magpie   # test-priv가 없어야 정상
```

**⚠️ 함정 포인트**

- 에러는 **stderr**로 나온다. `>`만 쓰면 빈 파일이 저장된다. 반드시 `&>` 또는 `2>`를 쓰라.
- `kubectl run`의 `--privileged` 같은 플래그는 없다. `--overrides` JSON을 쓰거나 YAML 파일을 만들어 apply 하라.

</details>

---

## 2. securityContext 총정리

### 2.1 pod 레벨 vs container 레벨

securityContext는 pod 레벨(`spec.securityContext`)과 container 레벨(`spec.containers[].securityContext`) 두 곳에 존재하며, **겹치는 필드는 container 레벨이 우선**한다.

| 필드 | Pod 레벨 | Container 레벨 | 설명 |
|------|:---:|:---:|------|
| `runAsUser` / `runAsGroup` | ✅ | ✅ | 프로세스 UID/GID |
| `runAsNonRoot` | ✅ | ✅ | UID 0이면 기동 거부 |
| `fsGroup` | ✅ | ❌ | volume 파일의 그룹 소유권 |
| `supplementalGroups` | ✅ | ❌ | 추가 그룹 |
| `sysctls` | ✅ | ❌ | 커널 파라미터 |
| `seccompProfile` | ✅ | ✅ | syscall 필터 |
| `appArmorProfile` | ✅ | ✅ | AppArmor 프로파일 (v1.30+ GA 필드) |
| `privileged` | ❌ | ✅ | 호스트 커널 전권 — 사실상 컨테이너 격리 해제 |
| `allowPrivilegeEscalation` | ❌ | ✅ | setuid 바이너리 등을 통한 권한 상승 차단 |
| `capabilities` | ❌ | ✅ | Linux capability 추가/제거 |
| `readOnlyRootFilesystem` | ❌ | ✅ | 루트 파일시스템 읽기 전용 |
| `procMount` | ❌ | ✅ | /proc 마스킹 제어 |

> **📌 암기 포인트** — `fsGroup`은 **pod 레벨 전용**, `privileged`/`capabilities`/`readOnlyRootFilesystem`/`allowPrivilegeEscalation`은 **container 레벨 전용**. 시험에서 이걸 반대 위치에 쓰면 apply 자체가 실패하며 시간을 잃는다.

### 2.2 privileged가 왜 위험한가

`privileged: true`는 컨테이너에 호스트의 **모든 device 접근 + 모든 capability**를 부여한다. 컨테이너 안에서 호스트 디스크를 마운트해 파일시스템 전체를 읽고 쓸 수 있고, 커널 모듈을 로드할 수 있으며, 사실상 **노드 root 탈취와 동일**하다. baseline PSS 레벨부터 금지되는 이유다. 시험에서는 "이 워크로드에서 privileged를 제거하고 필요한 최소 권한만 남겨라" 유형이 나온다 — 대부분 `privileged: true` 삭제 + 필요한 capability만 `capabilities.add`로 남기는 식이다.

### 2.3 빈출 조합

```yaml
# ① 비루트 강제 (가장 흔한 요구)
securityContext:
  runAsUser: 1000
  runAsGroup: 3000
  runAsNonRoot: true
---
# ② 컨테이너 불변성(immutability) — 루트FS 읽기전용 + 쓰기 경로만 emptyDir
securityContext:
  readOnlyRootFilesystem: true
  privileged: false
  allowPrivilegeEscalation: false
---
# ③ capability 최소화 — 전부 버리고 꼭 필요한 것만 추가
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]
```

컨테이너 불변성 요구 시 애플리케이션이 쓰기해야 하는 경로(`/tmp`, `/var/run`, 캐시 디렉토리 등)는 emptyDir로 마운트한다.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: immutable-app
spec:
  containers:
  - name: app
    image: nginx:1.27-alpine
    securityContext:
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
    volumeMounts:
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

적용 후 불변성 검증:

```bash
kubectl exec immutable-app -- touch /test
# touch: /test: Read-only file system   ← 루트FS가 읽기 전용
kubectl exec immutable-app -- touch /tmp/ok
# 성공 — emptyDir로 마운트한 경로만 쓰기 가능
```

> **💡 시험 팁** — `readOnlyRootFilesystem: true`를 넣은 뒤 pod가 CrashLoopBackOff이면 십중팔구 앱이 쓰던 경로가 막힌 것이다. `kubectl logs`에서 "Read-only file system" 에러가 난 경로를 찾아 그 경로만 emptyDir로 뚫어주면 된다.

### 📝 문제로 이해하기

```bash
kubectl config use-context cluster1
```

**Task**: In namespace `lion` there is a Deployment `web-api`. Update it so that all containers:

- run with user ID `3000` and group ID `3000`
- cannot run as root
- do not allow privilege escalation

Do not change anything else. Verify the running process UID inside the pod.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`kubectl edit deploy`로 pod template의 securityContext를 수정한다. UID/GID는 pod 레벨에 한 번만 써도 전 컨테이너에 적용되지만, `allowPrivilegeEscalation`은 container 레벨 전용이므로 container에 써야 한다.

**2) 단계별 풀이**

```bash
kubectl -n lion edit deploy web-api
```

```yaml
spec:
  template:
    spec:
      securityContext:            # pod 레벨
        runAsUser: 3000
        runAsGroup: 3000
        runAsNonRoot: true
      containers:
      - name: web-api
        securityContext:          # container 레벨
          allowPrivilegeEscalation: false
```

**3) 검증**

```bash
kubectl -n lion rollout status deploy web-api
kubectl -n lion exec deploy/web-api -- id
# uid=3000 gid=3000 groups=3000
```

**4) ⚠️ 함정 포인트**

- `allowPrivilegeEscalation`을 pod 레벨에 쓰면 필드가 없다며 저장이 거부된다.
- 이미지가 root 전제(예: 80 포트 바인딩)라면 rollout 후 CrashLoop이 날 수 있다 — 문제에서 이미지 교체를 허용하는지 지시문을 다시 읽으라.
- Deployment 수정은 pod template(`spec.template.spec`) 아래를 고쳐야 한다. 최상위 `spec`에 쓰면 에러.

</details>

---

## 3. Kubernetes Secrets 심층

### 3.1 base64는 암호화가 아니다

Secret의 `data` 필드는 **base64 인코딩**일 뿐 암호화가 아니다. `kubectl get secret -o yaml` 권한이 있는 사람, etcd(클러스터 전체 상태를 저장하는 키-값 저장소)에 접근할 수 있는 사람, etcd 백업 파일을 손에 넣은 사람은 모두 값을 평문으로 복원할 수 있다. 그래서 CKS는 (1) RBAC(Role-Based Access Control — 역할에 권한을 묶어 사용자·서비스어카운트에 부여하는 접근 제어)로 secret 읽기 권한 최소화, (2) Encryption at Rest(4장)를 요구한다.

### 3.2 생성과 사용

```bash
# 생성
kubectl -n moon create secret generic db-cred \
  --from-literal=username=admin \
  --from-literal=password='S3cret!'

# 값 읽기 (빈출: 이미 있는 secret 값을 디코드해 파일로 제출)
kubectl -n moon get secret db-cred -o jsonpath='{.data.username}' | base64 -d
kubectl -n moon get secret db-cred -o jsonpath='{.data.password}' | base64 -d
```

```yaml
# env로 주입 + volume으로 마운트하는 pod
apiVersion: v1
kind: Pod
metadata:
  name: secret-consumer
  namespace: moon
spec:
  containers:
  - name: app
    image: busybox:1.36
    command: ["sh", "-c", "sleep 1d"]
    env:
    - name: DB_USER
      valueFrom:
        secretKeyRef:
          name: db-cred
          key: username
    volumeMounts:
    - name: cred
      mountPath: /etc/cred
      readOnly: true
  volumes:
  - name: cred
    secret:
      secretName: db-cred
```

```bash
# 마운트 검증
kubectl -n moon exec secret-consumer -- cat /etc/cred/password
kubectl -n moon exec secret-consumer -- env | grep DB_USER
```

> **💡 시험 팁** — "secret의 username을 `/opt/course/N/username` 파일에 저장하라" 유형은 반드시 **디코드된 값**을 저장해야 한다. base64 문자열을 그대로 내면 오답이다. `| base64 -d` 를 붙였는지, 파일 끝에 개행이 섞이지 않았는지 확인하라.

### 3.3 etcd에서 평문 확인 실습

Encryption at Rest가 없는 클러스터에서 secret은 etcd에 **평문에 가까운 형태**로 저장된다. control plane 노드에서 직접 확인할 수 있다.

```bash
ssh cluster1-controlplane1

ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/moon/db-cred
# 출력에 admin, S3cret! 같은 값이 그대로 보인다
```

> **📌 암기 포인트** — etcd 키 경로는 `/registry/secrets/<네임스페이스>/<secret이름>`. 인증서 3종은 모두 `/etc/kubernetes/pki/etcd/` 아래의 `ca.crt`, `server.crt`, `server.key`. 시험장에서 헷갈리면 `kubectl -n kube-system get pod etcd-<노드명> -o yaml` 에서 etcd가 쓰는 플래그를 컨닝하면 된다.

### 3.4 RBAC로 secret 접근 제한

```bash
# 어떤 SA가 secret을 읽을 수 있는지 점검
kubectl auth can-i get secrets --as=system:serviceaccount:moon:app-sa -n moon
kubectl auth can-i --list --as=system:serviceaccount:moon:app-sa -n moon

# 특정 secret 하나만 읽게 최소 권한 Role
kubectl -n moon create role secret-reader \
  --verb=get --resource=secrets --resource-name=db-cred
kubectl -n moon create rolebinding secret-reader-binding \
  --role=secret-reader --serviceaccount=moon:app-sa
```

또한 pod가 API 토큰이 필요 없다면 ServiceAccount 토큰 자동 마운트를 꺼서 탈취 표면을 줄인다 (`automountServiceAccountToken: false`, Pod 레벨 설정이 SA 레벨보다 우선).

### 📝 문제로 이해하기

```bash
kubectl config use-context cluster1
```

**Task**: Namespace `moon` contains a Secret named `db-cred`.

1. Decode the values of keys `username` and `password` and write them into `/opt/course/sec/username` and `/opt/course/sec/password`.
2. Create a Pod named `secret-reader` (image `busybox:1.36`, command `sleep 1d`) in namespace `moon` that mounts the Secret read-only at `/etc/db`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

jsonpath + base64 -d 로 값 추출, 마운트는 3.2의 volume 패턴을 그대로 쓴다.

**2) 단계별 풀이**

```bash
mkdir -p /opt/course/sec
kubectl -n moon get secret db-cred -o jsonpath='{.data.username}' | base64 -d > /opt/course/sec/username
kubectl -n moon get secret db-cred -o jsonpath='{.data.password}' | base64 -d > /opt/course/sec/password
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secret-reader
  namespace: moon
spec:
  containers:
  - name: secret-reader
    image: busybox:1.36
    command: ["sh", "-c", "sleep 1d"]
    volumeMounts:
    - name: db
      mountPath: /etc/db
      readOnly: true
  volumes:
  - name: db
    secret:
      secretName: db-cred
```

**3) 검증**

```bash
cat /opt/course/sec/username /opt/course/sec/password
kubectl -n moon exec secret-reader -- ls /etc/db
kubectl -n moon exec secret-reader -- cat /etc/db/username
```

**⚠️ 함정 포인트**

- `base64 -d`를 빼먹고 인코딩된 값을 저장하는 것이 최다 실수.
- jsonpath 키 이름에 점(`.`)이 들어간 경우(예: `token.id`)는 `{.data.token\.id}` 처럼 이스케이프해야 한다.
- 파일 경로 디렉토리가 없으면 `mkdir -p` 먼저.

</details>

---

## 4. Encryption at Rest

### 4.1 EncryptionConfiguration — providers 순서가 전부다

etcd에 저장되는 secret을 암호화하려면 kube-apiserver에 `EncryptionConfiguration` 파일을 물린다. 핵심 규칙 두 가지:

- **쓰기(암호화)는 첫 번째 provider**로 수행된다.
- **읽기(복호화)는 목록의 provider를 순서대로 시도**한다. 따라서 `identity: {}`(평문)가 목록에 있어야 아직 암호화되지 않은 기존 데이터를 읽을 수 있다.

| providers 순서 | 새 secret | 기존 평문 secret |
|----------------|-----------|------------------|
| `aescbc` → `identity` | 암호화되어 저장 | 읽기 가능 (마이그레이션 표준 구성) |
| `identity` → `aescbc` | **평문으로 저장** | 읽기 가능 (암호화 해제 시 구성) |

```bash
# 32바이트 랜덤 키 생성 (aescbc는 32바이트 base64 키)
head -c 32 /dev/urandom | base64
```

```yaml
# /etc/kubernetes/enc/enc.yaml (control plane 노드에 저장)
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: WKgVDFbAoLh7lU2LEsF6zau5AwGjeVLGWDIBEDSKGVA=   # 예시: 32바이트 base64
      - identity: {}
```

provider 종류: `aescbc`(시험 표준), `secretbox`, `kms`(v2, 외부 KMS 연동). `aesgcm`도 존재하지만 키 로테이션 요건 때문에 시험에선 aescbc가 기본이다.

### 4.2 kube-apiserver에 연결

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml 수정 사항
spec:
  containers:
  - command:
    - kube-apiserver
    - --encryption-provider-config=/etc/kubernetes/enc/enc.yaml
    # ... 기존 플래그 유지 ...
    volumeMounts:
    - name: enc
      mountPath: /etc/kubernetes/enc
      readOnly: true
  volumes:
  - name: enc
    hostPath:
      path: /etc/kubernetes/enc
      type: DirectoryOrCreate
```

저장하면 kubelet이 apiserver를 재생성한다. `kubectl get pods -n kube-system` 이 응답할 때까지 30초~1분 대기.

```bash
# apiserver가 안 뜰 때 디버깅 3종 세트
crictl ps -a | grep apiserver
journalctl -u kubelet | tail -30
ls /var/log/pods/kube-system_kube-apiserver-*/
```

### 4.3 기존 secret 일괄 재암호화

설정을 적용해도 **기존 secret은 여전히 평문**이다. 전부 다시 써서(re-write) 암호화를 트리거한다.

```bash
kubectl get secrets -A -o json | kubectl replace -f -
```

### 4.4 etcd에서 암호화 확인

```bash
ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/moon/db-cred | hexdump -C | head -8
# 값 앞에 k8s:enc:aescbc:v1:key1: 접두어가 보이고 본문은 바이너리면 성공
```

> **⚠️ 함정** — (1) volume mount 누락 → apiserver 기동 실패. (2) 키가 32바이트가 아님 → 기동 실패. (3) `identity: {}`를 **첫 번째**에 두면 새 secret이 계속 평문으로 저장된다. (4) 재암호화(`kubectl replace`)를 빼먹으면 기존 secret은 평문 그대로다. (5) EncryptionConfiguration은 클러스터 리소스가 아니라 **디스크의 파일**이다 — `kubectl apply` 대상이 아니다.

### 📝 문제로 이해하기

```bash
kubectl config use-context cluster1
ssh cluster1-controlplane1
```

**Task**: Encryption at rest is already configured on this cluster via `/etc/kubernetes/enc/enc.yaml`, but newly created Secrets are still stored unencrypted in etcd. Find the misconfiguration, fix it so new Secrets are encrypted with `aescbc`, and ensure all existing Secrets in the cluster become encrypted as well.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

"설정은 있는데 평문 저장" = 십중팔구 `identity: {}` 가 providers 첫 번째에 있는 경우다. 순서를 바꾸고 apiserver 재기동 후 일괄 재암호화한다.

**2) 단계별 풀이**

```bash
cat /etc/kubernetes/enc/enc.yaml
# providers:
#   - identity: {}        ← 이게 첫 번째라서 평문 저장
#   - aescbc: ...
```

`aescbc`를 첫 번째로, `identity: {}`를 두 번째로 순서 교체 후 저장. 그리고 apiserver를 재기동시킨다(static pod manifest를 touch 하거나 잠깐 밖으로 옮겼다 되돌리기).

```bash
# manifest 수정이 없다면 파일 이동으로 강제 재기동
mv /etc/kubernetes/manifests/kube-apiserver.yaml /tmp/ && sleep 5 && \
mv /tmp/kube-apiserver.yaml /etc/kubernetes/manifests/

# apiserver 복귀 확인 후 일괄 재암호화
kubectl get secrets -A -o json | kubectl replace -f -
```

**3) 검증**

```bash
ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/<아무 secret> | hexdump -C | head
# k8s:enc:aescbc:v1: 접두어 확인
```

**⚠️ 함정 포인트**

- EncryptionConfiguration 파일만 고치면 apiserver는 모른다 — **재기동이 필요**하다(파일 변경 자동 감지는 보장되지 않으므로 시험에선 재기동이 안전).
- `kubectl replace` 는 apiserver가 완전히 뜬 다음 실행. 안 떠 있으면 connection refused.
- 순서를 바꾸되 `identity: {}` 를 **지우면 안 된다** — 아직 평문인 기존 secret을 읽지 못해 클러스터가 이상 동작한다. 재암호화가 끝난 뒤에야 제거 가능.

</details>

---

## 5. 격리 기법 - gVisor와 RuntimeClass

### 5.1 왜 커널 격리가 필요한가 — 멀티테넌시

일반 컨테이너는 격리처럼 보이지만 **호스트 커널을 모든 컨테이너가 공유**한다. namespace/cgroup은 뷰를 나눌 뿐이어서, 커널 취약점 하나면 컨테이너 탈출(container escape)로 이어진다. 서로 신뢰하지 않는 테넌트(멀티테넌시)나 신뢰할 수 없는 코드(외부 제출 코드, 서드파티 플러그인)를 돌릴 때는 **커널 수준의 추가 격리 계층**이 필요하다. Kubernetes에서 이를 선택하는 표준 인터페이스가 **RuntimeClass**다.

### 5.2 gVisor(runsc) 동작 원리

gVisor는 구글이 만든 **user-space 애플리케이션 커널**이다. 컨테이너의 syscall을 호스트 커널로 직접 보내지 않고, Sentry라는 유저스페이스 컴포넌트가 가로채 자체 구현한 커널 로직으로 처리한다. 호스트 커널에 도달하는 syscall 종류가 크게 줄어들어 커널 공격 표면이 대폭 축소된다. containerd에서의 핸들러 이름은 `runsc`. 트레이드오프는 성능(특히 syscall 집약적 워크로드)과 일부 호환성이다. 비슷한 목적의 **Kata Containers**는 경량 VM 안에서 컨테이너를 실행하는 방식으로, 핸들러 이름은 `kata`다.

### 5.3 RuntimeClass 생성 / 적용 / 검증

```yaml
# RuntimeClass 생성 (클러스터 리소스, 네임스페이스 없음)
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc          # 노드의 containerd에 설정된 런타임 핸들러 이름
```

```yaml
# pod에 적용
apiVersion: v1
kind: Pod
metadata:
  name: sandboxed
  namespace: sandbox
spec:
  runtimeClassName: gvisor      # spec 바로 아래, containers와 같은 레벨
  containers:
  - name: app
    image: nginx:1.27-alpine
```

```bash
# 검증 1: gVisor pod 안의 dmesg에는 gVisor 부팅 메시지가 보인다
kubectl -n sandbox exec sandboxed -- dmesg
# [    0.000000] Starting gVisor...

# 검증 2: 커널 버전이 호스트와 다르게 보인다
kubectl -n sandbox exec sandboxed -- uname -r
```

> **⚠️ 함정** — (1) `runtimeClassName`을 container 레벨에 쓰는 실수 — **pod spec 레벨**이다. (2) RuntimeClass의 `handler`는 `spec` 아래가 아니라 **최상위 필드**다. (3) gVisor가 설치된 노드가 일부뿐이면 pod가 Pending이 될 수 있다 — 문제에서 nodeSelector나 특정 노드를 지정했는지 확인. (4) Deployment에 적용할 때는 `spec.template.spec.runtimeClassName`.

### 📝 문제로 이해하기

```bash
kubectl config use-context cluster2
```

**Task**: The node `cluster2-node1` has gVisor installed with the containerd handler `runsc`. Create a RuntimeClass named `gvisor` for this handler. Then create a Pod named `sandbox-test` (image `busybox:1.36`, command `sleep 1d`) in namespace `default` that uses this RuntimeClass. Verify it runs inside gVisor and write the output of `dmesg` from inside the Pod to `/opt/course/rc/dmesg.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

RuntimeClass 리소스 생성 → pod에 `runtimeClassName` 지정 → `dmesg`로 검증.

**2) 단계별 풀이**

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
---
apiVersion: v1
kind: Pod
metadata:
  name: sandbox-test
spec:
  runtimeClassName: gvisor
  containers:
  - name: sandbox-test
    image: busybox:1.36
    command: ["sh", "-c", "sleep 1d"]
```

```bash
kubectl apply -f rc.yaml
mkdir -p /opt/course/rc
kubectl exec sandbox-test -- dmesg > /opt/course/rc/dmesg.txt
grep -i gvisor /opt/course/rc/dmesg.txt   # Starting gVisor...
```

**3) 검증**

```bash
kubectl get runtimeclass gvisor
kubectl get pod sandbox-test -o jsonpath='{.spec.runtimeClassName}'
```

**⚠️ 함정 포인트**

- kubernetes.io/docs에서 "RuntimeClass"를 검색하면 위 YAML을 그대로 복사할 수 있다 — 외우지 말고 찾는 연습을 하라.
- pod가 Pending이면 `kubectl describe pod`로 확인 — runsc 핸들러가 없는 노드에 스케줄되려 하는 경우다. 필요 시 `nodeName: cluster2-node1` 지정.

</details>

---

## 6. Pod-to-Pod 암호화 - Cilium과 Istio

2024-10 커리큘럼 개편에서 신규 추가된 주제다. 클러스터 내부 트래픽(pod-to-pod)은 기본적으로 **평문**이며, 이를 암호화하는 대표 수단이 Cilium의 투명 암호화와 Istio의 mTLS다. 시험 중 `docs.cilium.io/en/stable`과 `istio.io/latest/docs` 열람이 허용된다.

### 6.1 Cilium 투명 암호화 — WireGuard / IPsec

Cilium CNI(Container Network Interface — 파드 간 네트워크를 구현하는 플러그인 규격, Calico·Cilium 등)는 노드 간 pod 트래픽을 **네트워크 계층에서 투명하게 암호화**할 수 있다. 애플리케이션이나 pod spec 수정이 전혀 필요 없다.

- **WireGuard**: 노드마다 키가 자동 생성/교환되어 설정이 단순. 시험 환경에서 만날 가능성이 높은 쪽.
- **IPsec**: 키를 Kubernetes secret(`cilium-ipsec-keys`)으로 관리, 키 로테이션 지원.

```bash
# 상태 확인 (Cilium CLI가 호스트에 설치된 경우)
cilium status

# cilium agent pod에서 직접 확인 — Encryption 줄을 본다
kubectl -n kube-system exec ds/cilium -- cilium status | grep -i encryption
# Encryption:    Wireguard   [NodeEncryption: Disabled, cilium_wg0 (Pubkey: ..., Port: 51871, Peers: 2)]

# 어떤 모드로 설정되어 있는지 ConfigMap에서도 확인 가능
kubectl -n kube-system get cm cilium-config -o yaml | grep -i -E "enable-wireguard|enable-ipsec"
```

CiliumNetworkPolicy(참고: L7/FQDN 정책도 가능)는 `apiVersion: cilium.io/v2`, `endpointSelector`, `fromEndpoints`/`toEndpoints`, `toPorts`, `toFQDNs`를 쓴다. 암호화 문제와 별개로 Cilium이 깔린 클러스터에서는 NetworkPolicy 문제가 CiliumNetworkPolicy로 변형되어 나올 수 있다.

### 6.2 Istio mTLS — PeerAuthentication STRICT

Istio는 서비스 메시 계층에서 워크로드 간 **mTLS(상호 TLS)** 를 제공한다. 전통 모드에서는 각 pod에 Envoy **sidecar**가 주입되어 트래픽을 프록시하고, 최신 **ambient 모드**에서는 sidecar 없이 노드 레벨 프록시(ztunnel)가 같은 역할을 한다. 시험 기준으로는 sidecar 방식 + PeerAuthentication이 핵심이다.

```bash
# 1) 네임스페이스에 sidecar 자동 주입 라벨
kubectl label ns team-blue istio-injection=enabled

# 2) 라벨 이후에 뜬 pod에만 sidecar가 붙는다 → 기존 워크로드는 재시작 필요
kubectl -n team-blue rollout restart deploy

# 3) sidecar 확인: READY가 2/2 (앱 + istio-proxy)
kubectl -n team-blue get pods
```

```yaml
# 네임스페이스 전체에 mTLS 강제
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: team-blue
spec:
  mtls:
    mode: STRICT      # STRICT: mTLS 아닌 평문 연결 거부 / PERMISSIVE: 둘 다 허용(기본)
```

```bash
kubectl apply -f peer-auth.yaml
kubectl -n team-blue get peerauthentication
```

> **⚠️ 함정** — (1) `istio-injection=enabled` 라벨을 붙여도 **기존 pod에는 sidecar가 안 생긴다**. `rollout restart`를 잊으면 mTLS가 적용되지 않는다. (2) STRICT를 걸었는데 메시 밖(사이드카 없는) pod가 해당 서비스를 호출하면 연결이 거부된다 — 의도된 동작이다. (3) PeerAuthentication을 `istio-system`에 만들면 메시 전체에 적용된다. 문제의 요구 범위(네임스페이스 vs 전체)를 정확히 읽으라.

### 6.3 Cilium vs Istio 비교

| 항목 | Cilium 암호화 | Istio mTLS |
|------|---------------|------------|
| 동작 계층 | L3/L4 네트워크 계층 (eBPF) | L7 서비스 메시 (프록시) |
| 기술 | WireGuard 또는 IPsec 터널 | X.509 인증서 기반 mTLS (SPIFFE ID) |
| 적용 단위 | 클러스터 전체 노드 간 트래픽 | 네임스페이스/워크로드 단위 세밀 제어 |
| pod 변경 | 불필요 (완전 투명) | sidecar 주입 필요 (ambient는 불필요) |
| 워크로드 신원 인증 | 없음 (전송 암호화만) | 있음 (상호 인증 + 암호화) |
| 확인 명령 | `cilium status` | `kubectl get peerauthentication`, pod READY 2/2 |

### 📝 문제로 이해하기

```bash
kubectl config use-context cluster3
```

**Task**: Istio is installed on this cluster. Namespace `pay` contains Deployment `checkout`. Enable automatic sidecar injection for namespace `pay`, make sure all existing workloads receive the sidecar, and enforce STRICT mTLS for all workloads in the namespace using a PeerAuthentication named `default`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

라벨 → rollout restart → PeerAuthentication STRICT, 3단계 그대로.

**2) 단계별 풀이**

```bash
kubectl label ns pay istio-injection=enabled
kubectl -n pay rollout restart deploy checkout
```

```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: pay
spec:
  mtls:
    mode: STRICT
```

**3) 검증**

```bash
kubectl -n pay get pods          # READY 2/2 확인
kubectl -n pay get peerauthentication default -o yaml
```

**⚠️ 함정 포인트**

- rollout restart를 빼먹으면 sidecar 없는 pod가 남고, STRICT 적용 시 그 pod로의 mTLS 통신이 성립하지 않는다.
- 리소스 이름을 `default`로 지정하라는 요구를 놓치기 쉽다 — 네임스페이스 기본 정책의 관례적 이름이다.

</details>

---

## 연습문제 (실전 12문제)

> **💡 시험 팁** — 실제 시험처럼 문제마다 첫 줄의 `kubectl config use-context`를 반드시 먼저 실행하는 습관을 들이라. 컨텍스트를 안 바꾸고 다른 클러스터를 조작하는 것이 실전 최악의 실수다. 파일 답안은 killer.sh 관례대로 `/opt/course/<문제번호>/`에 저장한다.

### Q1. PSA — 네임스페이스에 적용하고 차단 확인

```bash
kubectl config use-context cluster1
```

**Task**:

1. Configure the existing namespace `gamma` so that Pods violating the `baseline` Pod Security Standard are **rejected**, and Pods violating the `restricted` standard produce a **warning** and an **audit** log entry.
2. Attempt to create a Pod named `hostpid-pod` (image `nginx:1.27`, `hostPID: true`) in namespace `gamma`. Save the complete error message to `/opt/course/1/error.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

enforce=baseline, warn=restricted, audit=restricted 라벨 3개. hostPID는 baseline 위반이므로 거부된다.

**2) 단계별 풀이**

```bash
kubectl label ns gamma \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

mkdir -p /opt/course/1

cat << 'EOF' > /opt/course/1/hostpid-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: hostpid-pod
  namespace: gamma
spec:
  hostPID: true
  containers:
  - name: hostpid-pod
    image: nginx:1.27
EOF

kubectl apply -f /opt/course/1/hostpid-pod.yaml &> /opt/course/1/error.txt
cat /opt/course/1/error.txt
# Error from server (Forbidden): ... violates PodSecurity "baseline:latest": host namespaces (hostPID=true)
```

**3) 검증**

```bash
kubectl get ns gamma --show-labels     # 라벨 3개 확인
kubectl -n gamma get pod hostpid-pod   # NotFound여야 정상
```

**⚠️ 함정 포인트**

- 모드별 레벨이 다르게 요구되는 문제다. enforce에 restricted를 걸면 요구사항과 다르다 — 지시문의 레벨-모드 매핑을 표로 그려보고 시작하라.
- 에러 메시지는 stderr → `&>` 필수.

</details>

### Q2. PSA — restricted 위반 Deployment 수정

```bash
kubectl config use-context cluster1
```

**Task**: Namespace `sec-app` enforces the `restricted` Pod Security Standard. Deployment `web` in that namespace should run 2 replicas but currently has 0 Pods running. Find out why the Pods are not being created and adjust the Deployment so that its Pods comply with the `restricted` standard. Do not remove functionality that is not related to the violation.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

ReplicaSet events에서 위반 항목을 읽고, restricted 4종 세트를 pod template에 넣는다.

**2) 단계별 풀이**

```bash
kubectl -n sec-app get deploy,rs,pods
kubectl -n sec-app describe rs -l app=web | grep -A3 Events
# Error creating: pods "web-..." is forbidden: violates PodSecurity "restricted:latest":
#   allowPrivilegeEscalation != false, unrestricted capabilities, runAsNonRoot != true, seccompProfile

kubectl -n sec-app edit deploy web
```

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: web
        # ... image 등 기존 필드 유지 ...
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
```

**3) 검증**

```bash
kubectl -n sec-app get pods    # 2/2 Running
kubectl -n sec-app describe rs -l app=web | tail -5   # 새 RS에 에러 없음
```

**⚠️ 함정 포인트**

- Deployment의 events에는 아무것도 안 나온다. **ReplicaSet**을 봐야 한다.
- `runAsNonRoot: true`만 넣으면 admission은 통과해도 root 이미지면 `CreateContainerConfigError` — `kubectl get pods`가 Running까지 가는지 반드시 확인.
- 기존 securityContext에 `privileged: true` 같은 위반 필드가 이미 있으면 제거해야 한다.

</details>

### Q3. PSA — AdmissionConfiguration으로 전역 기본값과 exemption

```bash
kubectl config use-context cluster1
ssh cluster1-controlplane1
```

**Task**: Configure the PodSecurity admission plugin cluster-wide:

1. Create an AdmissionConfiguration file at `/etc/kubernetes/psa/admission-config.yaml` that sets a default `enforce` level of `baseline` and a default `warn` level of `restricted` for all namespaces.
2. Exempt the namespace `legacy` from all Pod Security checks.
3. Configure the kube-apiserver to use this file.
4. Verify that a privileged Pod can still be created in namespace `legacy` but not in namespace `default`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

AdmissionConfiguration + PodSecurityConfiguration 작성 → apiserver 플래그 + hostPath mount 추가 → 재기동 대기 → 두 네임스페이스에서 교차 검증.

**2) 단계별 풀이**

```bash
mkdir -p /etc/kubernetes/psa
cat << 'EOF' > /etc/kubernetes/psa/admission-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "baseline"
      enforce-version: "latest"
      warn: "restricted"
      warn-version: "latest"
    exemptions:
      usernames: []
      runtimeClasses: []
      namespaces: ["legacy"]
EOF

vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

```yaml
# command에 추가
    - --admission-control-config-file=/etc/kubernetes/psa/admission-config.yaml
# volumeMounts에 추가
    - name: psa-config
      mountPath: /etc/kubernetes/psa
      readOnly: true
# volumes에 추가
  - name: psa-config
    hostPath:
      path: /etc/kubernetes/psa
      type: DirectoryOrCreate
```

**3) 검증**

```bash
# apiserver 재기동 대기 후
kubectl get pods -n kube-system | grep apiserver

kubectl run priv-test -n legacy --image=nginx:1.27 \
  --overrides='{"apiVersion":"v1","spec":{"containers":[{"name":"priv-test","image":"nginx:1.27","securityContext":{"privileged":true}}]}}'
# 성공해야 함 (exempt)

kubectl run priv-test -n default --image=nginx:1.27 \
  --overrides='{"apiVersion":"v1","spec":{"containers":[{"name":"priv-test","image":"nginx:1.27","securityContext":{"privileged":true}}]}}'
# Forbidden이어야 함 (baseline 기본 적용)
```

**⚠️ 함정 포인트**

- volume mount 누락 = apiserver 기동 실패. `crictl ps -a`와 `journalctl -u kubelet`으로 디버깅.
- AdmissionConfiguration의 defaults는 **라벨이 없는 네임스페이스에만** 적용된다. 네임스페이스에 PSA 라벨이 이미 있으면 라벨이 이긴다.
- 검증 후 테스트 pod(`priv-test`)는 삭제해 흔적을 남기지 않는 것이 좋다.

</details>

### Q4. securityContext — 비루트 + capability 최소화

```bash
kubectl config use-context cluster1
```

**Task**: In namespace `app-team` there is a Deployment `tokyo`. Modify it so that:

- containers run as user `30000` and group `30000`
- running as root is not allowed
- all Linux capabilities are dropped, and only `NET_BIND_SERVICE` is added
- privilege escalation is not allowed

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

UID/GID/runAsNonRoot는 pod 레벨, capabilities/allowPrivilegeEscalation은 container 레벨.

**2) 단계별 풀이**

```bash
kubectl -n app-team edit deploy tokyo
```

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsUser: 30000
        runAsGroup: 30000
        runAsNonRoot: true
      containers:
      - name: tokyo
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
            add: ["NET_BIND_SERVICE"]
```

**3) 검증**

```bash
kubectl -n app-team rollout status deploy tokyo
kubectl -n app-team exec deploy/tokyo -- id     # uid=30000 gid=30000
kubectl -n app-team get pods                    # Running 확인
```

**⚠️ 함정 포인트**

- capability 이름에 `CAP_` 접두어를 붙이지 않는다 (`CAP_NET_BIND_SERVICE` ✗ → `NET_BIND_SERVICE` ✓).
- drop과 add를 동시에 쓸 수 있다 — "모두 버리고 하나만 추가"가 전형 패턴.
- 컨테이너가 여러 개면 **모든 컨테이너**에 container 레벨 필드를 넣어야 한다 (initContainers 포함 여부도 지시문 확인).

</details>

### Q5. securityContext — 컨테이너 불변성 만들기

```bash
kubectl config use-context cluster1
```

**Task**: Namespace `world` contains a Deployment `logger` whose container currently runs with `privileged: true` and writes temporary data to `/tmp`. Harden it:

- remove privileged mode
- make the container's root filesystem read-only
- ensure the application can still write to `/tmp` (use an `emptyDir` volume)
- disallow privilege escalation

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

privileged 삭제 + readOnlyRootFilesystem + /tmp emptyDir 마운트.

**2) 단계별 풀이**

```bash
kubectl -n world edit deploy logger
```

```yaml
spec:
  template:
    spec:
      containers:
      - name: logger
        securityContext:
          privileged: false               # 또는 해당 줄 삭제
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir: {}
```

**3) 검증**

```bash
kubectl -n world get pods                              # Running/CrashLoop 확인
kubectl -n world exec deploy/logger -- touch /tmp/ok   # 성공해야 함
kubectl -n world exec deploy/logger -- touch /etc/x    # Read-only file system 에러여야 함
```

**⚠️ 함정 포인트**

- `privileged: true`를 지우기만 해도 되지만, 명시적으로 `false`를 쓰면 의도가 분명해진다.
- readOnlyRootFilesystem 적용 후 CrashLoop이면 `kubectl logs`에서 막힌 쓰기 경로를 찾아 emptyDir을 추가 — /tmp 외에 `/var/run` 등이 더 필요할 수 있다.
- `allowPrivilegeEscalation: false`는 privileged와 함께 쓸 수 없다(privileged는 escalation을 전제로 함). privileged를 먼저 제거해야 한다.

</details>

### Q6. Secrets — 값 추출과 신규 secret 사용

```bash
kubectl config use-context cluster1
```

**Task**:

1. Namespace `venus` contains a Secret `database-access`. Decode the value of its key `password` and write it to `/opt/course/6/db-password`.
2. Create a new generic Secret `api-token` in namespace `venus` with key `token` and value `superSecret123`.
3. Create a Pod `token-pod` (image `busybox:1.36`, command `sleep 1d`) in namespace `venus` that exposes the new Secret's `token` key as environment variable `API_TOKEN` and mounts Secret `database-access` read-only at `/etc/db`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

jsonpath+base64 → create secret generic → env(secretKeyRef) + volume(secret) 조합 pod.

**2) 단계별 풀이**

```bash
mkdir -p /opt/course/6
kubectl -n venus get secret database-access \
  -o jsonpath='{.data.password}' | base64 -d > /opt/course/6/db-password

kubectl -n venus create secret generic api-token --from-literal=token=superSecret123
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: token-pod
  namespace: venus
spec:
  containers:
  - name: token-pod
    image: busybox:1.36
    command: ["sh", "-c", "sleep 1d"]
    env:
    - name: API_TOKEN
      valueFrom:
        secretKeyRef:
          name: api-token
          key: token
    volumeMounts:
    - name: db
      mountPath: /etc/db
      readOnly: true
  volumes:
  - name: db
    secret:
      secretName: database-access
```

**3) 검증**

```bash
cat /opt/course/6/db-password
kubectl -n venus exec token-pod -- sh -c 'echo $API_TOKEN'   # superSecret123
kubectl -n venus exec token-pod -- ls /etc/db
```

**⚠️ 함정 포인트**

- env 이름(`API_TOKEN`)과 secret 키 이름(`token`)을 혼동하기 쉽다 — `name`은 컨테이너에 보이는 변수명, `key`는 secret 안의 키.
- `kubectl exec pod -- echo $API_TOKEN` 은 **로컬 셸**에서 변수가 확장되어 빈 값이 나온다. `sh -c '...'` 로 감싸야 컨테이너 안에서 확장된다.

</details>

### Q7. Secrets — etcd에서 직접 조회

```bash
kubectl config use-context cluster1
ssh cluster1-controlplane1
```

**Task**: Using `etcdctl` on the control plane node, read the raw data of Secret `database-access` in namespace `venus` directly from etcd. Save the complete command you used to `/opt/course/7/command.txt` and the raw output to `/opt/course/7/etcd-output.txt`. State whether the Secret is stored encrypted by writing `encrypted` or `plaintext` to `/opt/course/7/state.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

etcd 인증서 3종으로 `/registry/secrets/venus/database-access` 키를 읽는다. 이 클러스터에 Encryption at Rest가 없다면 값이 그대로 보인다.

**2) 단계별 풀이**

```bash
mkdir -p /opt/course/7

ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/venus/database-access > /opt/course/7/etcd-output.txt

cat > /opt/course/7/command.txt << 'EOF'
ETCDCTL_API=3 etcdctl --cacert /etc/kubernetes/pki/etcd/ca.crt --cert /etc/kubernetes/pki/etcd/server.crt --key /etc/kubernetes/pki/etcd/server.key get /registry/secrets/venus/database-access
EOF

# 출력에서 password 값이 사람이 읽을 수 있게 보이면 평문
grep -a password /opt/course/7/etcd-output.txt
echo "plaintext" > /opt/course/7/state.txt
```

**3) 검증**

출력에 `k8s:enc:` 접두어가 없고 secret 값 문자열이 그대로 보이면 `plaintext`가 정답. `k8s:enc:aescbc:v1:` 접두어가 보이면 `encrypted`.

**⚠️ 함정 포인트**

- 인증서 경로를 못 외웠으면 `kubectl -n kube-system describe pod etcd-cluster1-controlplane1` 에서 etcd 플래그(`--cert-file` 등)를 보고 그대로 쓰면 된다.
- 키 경로는 복수형 `secrets`다: `/registry/secrets/<ns>/<name>`. `/registry/secret/...`은 빈 결과.
- 바이너리가 섞인 출력을 grep 할 때는 `-a` 옵션.

</details>

### Q8. Encryption at Rest — 신규 구성

```bash
kubectl config use-context cluster1
ssh cluster1-controlplane1
```

**Task**:

1. Create an `EncryptionConfiguration` at `/etc/kubernetes/enc/enc.yaml` that encrypts Secrets using the `aescbc` provider with a key named `key1` (generate a proper 32-byte key yourself). Unencrypted reads must remain possible.
2. Configure the kube-apiserver to use it.
3. Ensure all already-existing Secrets in the cluster are encrypted in etcd.
4. Verify that Secret `database-access` in namespace `venus` is now stored encrypted.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

키 생성 → EncryptionConfiguration(aescbc 첫 번째, identity 두 번째) → apiserver 플래그+마운트 → 재암호화 → etcd 확인.

**2) 단계별 풀이**

```bash
mkdir -p /etc/kubernetes/enc
head -c 32 /dev/urandom | base64    # 출력을 secret 필드에 사용

cat > /etc/kubernetes/enc/enc.yaml << EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: $(head -c 32 /dev/urandom | base64)
      - identity: {}
EOF

vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

```yaml
# command에 추가
    - --encryption-provider-config=/etc/kubernetes/enc/enc.yaml
# volumeMounts에 추가
    - name: enc
      mountPath: /etc/kubernetes/enc
      readOnly: true
# volumes에 추가
  - name: enc
    hostPath:
      path: /etc/kubernetes/enc
      type: DirectoryOrCreate
```

```bash
# apiserver 복귀 대기 후 일괄 재암호화
kubectl get pods -n kube-system | grep apiserver
kubectl get secrets -A -o json | kubectl replace -f -
```

**3) 검증**

```bash
ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/venus/database-access | hexdump -C | head -5
# k8s:enc:aescbc:v1:key1 접두어 확인
```

**⚠️ 함정 포인트**

- "Unencrypted reads must remain possible" = `identity: {}`를 **두 번째**에 두라는 뜻. 빼면 기존 평문 secret을 못 읽는다.
- 키는 반드시 32바이트 base64. `echo somekey | base64` 같은 짧은 키는 apiserver 기동 실패.
- volume mount 누락이 이 유형 최다 탈락 사유. manifest 저장 전 3군데(command/volumeMounts/volumes)를 모두 확인.
- 재암호화 단계(3번 요구사항)를 잊으면 부분 점수만 받는다.

</details>

### Q9. Encryption at Rest — 잘못된 provider 순서 수정

```bash
kubectl config use-context cluster2
ssh cluster2-controlplane1
```

**Task**: Encryption at rest was configured on this cluster, but a colleague reports that newly created Secrets still appear unencrypted in etcd. The configuration file is at `/etc/kubernetes/enc/enc.yaml`. Identify and fix the problem, then make sure every Secret in the cluster is stored encrypted. Do not delete any provider from the configuration.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

증상(새 secret이 평문) = `identity`가 첫 번째 provider. `aescbc`를 첫 번째로 올리고 apiserver 재기동, 전체 재암호화.

**2) 단계별 풀이**

```bash
cat /etc/kubernetes/enc/enc.yaml   # providers 순서 확인: identity가 첫 번째임을 발견
vim /etc/kubernetes/enc/enc.yaml   # aescbc를 첫 번째로, identity: {}를 두 번째로

# apiserver 재기동 (manifest 임시 이동)
mv /etc/kubernetes/manifests/kube-apiserver.yaml /tmp/ && sleep 5 && \
mv /tmp/kube-apiserver.yaml /etc/kubernetes/manifests/

kubectl get pods -n kube-system | grep apiserver   # 복귀 확인
kubectl get secrets -A -o json | kubectl replace -f -
```

**3) 검증**

```bash
ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/<임의 secret> | hexdump -C | head -5
# k8s:enc:aescbc:v1: 접두어 확인
```

**⚠️ 함정 포인트**

- 설정 파일 수정만으로는 반영되지 않는다 — apiserver **재기동** 필수.
- "Do not delete any provider" = identity를 지우지 말라는 힌트. 순서만 바꾼다.
- 재암호화 전에 apiserver가 완전히 떠 있어야 한다. `kubectl get --raw /readyz` 로 확인 가능.

</details>

### Q10. RuntimeClass — gVisor 샌드박스 적용

```bash
kubectl config use-context cluster2
```

**Task**: gVisor is installed on node `cluster2-node1` with containerd handler `runsc`.

1. Create a RuntimeClass named `gvisor` for handler `runsc`.
2. Update Deployment `untrusted` in namespace `sandbox` to run all its Pods with this RuntimeClass.
3. Verify the Pods run inside gVisor and write the output of `dmesg` from one of them to `/opt/course/10/dmesg.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

RuntimeClass 생성 → Deployment pod template에 `runtimeClassName` → dmesg 검증.

**2) 단계별 풀이**

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```

```bash
kubectl apply -f runtimeclass.yaml
kubectl -n sandbox edit deploy untrusted
```

```yaml
spec:
  template:
    spec:
      runtimeClassName: gvisor      # containers와 같은 레벨
      # 필요 시 해당 노드로 스케줄 보장:
      # nodeSelector:
      #   kubernetes.io/hostname: cluster2-node1
```

```bash
mkdir -p /opt/course/10
kubectl -n sandbox get pods -l app=untrusted
kubectl -n sandbox exec <pod명> -- dmesg > /opt/course/10/dmesg.txt
grep -i gvisor /opt/course/10/dmesg.txt   # Starting gVisor...
```

**3) 검증**

```bash
kubectl -n sandbox get pod <pod명> -o jsonpath='{.spec.runtimeClassName}'   # gvisor
kubectl -n sandbox exec <pod명> -- uname -r    # 호스트 커널 버전과 다름
```

**⚠️ 함정 포인트**

- `handler`는 RuntimeClass 최상위 필드다. `spec.handler`로 쓰면 apply 실패.
- runsc가 특정 노드에만 설치된 환경이면 nodeSelector 없이는 Pending pod가 생길 수 있다.
- rollout이 완료되기 전의 옛 pod에서 dmesg를 뜨면 gVisor 메시지가 없다 — `rollout status`로 새 pod 확인 후 실행.

</details>

### Q11. Cilium — pod-to-pod 암호화 상태 확인

```bash
kubectl config use-context cluster3
```

**Task**: Cluster3 uses Cilium as its CNI. Determine whether transparent pod-to-pod encryption is enabled and which technology is used (WireGuard or IPsec).

1. Write the encryption type (e.g. `Wireguard`, `IPsec`, or `Disabled`) to `/opt/course/11/encryption-type.txt`.
2. Write the full command you used to determine this to `/opt/course/11/command.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

cilium agent의 `cilium status` 출력에서 Encryption 줄을 읽는다. Cilium CLI가 있으면 `cilium status`, 없으면 DaemonSet pod에 exec.

**2) 단계별 풀이**

```bash
mkdir -p /opt/course/11

kubectl -n kube-system exec ds/cilium -- cilium status | grep -i encryption
# Encryption:    Wireguard   [NodeEncryption: Disabled, cilium_wg0 ...]

echo "Wireguard" > /opt/course/11/encryption-type.txt
echo 'kubectl -n kube-system exec ds/cilium -- cilium status | grep -i encryption' \
  > /opt/course/11/command.txt
```

**3) 검증**

```bash
# 교차 확인: cilium-config ConfigMap
kubectl -n kube-system get cm cilium-config -o yaml | grep -i -E "enable-wireguard|enable-ipsec"
# enable-wireguard: "true" 등이 보이면 일치
```

**⚠️ 함정 포인트**

- `docs.cilium.io/en/stable` 열람이 허용되므로 명령이 기억나지 않으면 문서에서 "encryption" 검색.
- cilium pod 이름을 직접 찾지 말고 `exec ds/cilium` 으로 DaemonSet을 바로 지정하면 빠르다.
- 답 파일에 grep 줄 전체를 넣지 말고 문제가 요구한 **타입 문자열만** 넣으라 — 채점 스크립트는 정확한 값을 기대한다.

</details>

### Q12. Istio — 네임스페이스 STRICT mTLS

```bash
kubectl config use-context cluster3
```

**Task**: Istio is installed on this cluster. Namespace `pay` contains Deployments `payments` and `ledger`, currently running without sidecars.

1. Enable automatic Istio sidecar injection for namespace `pay`.
2. Make sure all existing workloads in the namespace receive the sidecar.
3. Create a PeerAuthentication named `default` in namespace `pay` that enforces STRICT mTLS for all workloads in the namespace.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

라벨 → 전체 rollout restart → PeerAuthentication STRICT.

**2) 단계별 풀이**

```bash
kubectl label ns pay istio-injection=enabled
kubectl -n pay rollout restart deploy    # 네임스페이스의 모든 deploy 재시작

cat << 'EOF' | kubectl apply -f -
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: pay
spec:
  mtls:
    mode: STRICT
EOF
```

**3) 검증**

```bash
kubectl -n pay get pods
# 모든 pod의 READY가 2/2 (앱 + istio-proxy)
kubectl -n pay get peerauthentication
# NAME      MODE     AGE
# default   STRICT   ...
```

**⚠️ 함정 포인트**

- rollout restart 없이는 기존 pod에 sidecar가 붙지 않는다 — 이 문제의 핵심 채점 포인트.
- 라벨 키는 `istio-injection`, 값은 `enabled`. `istio-injection=true`가 아니다.
- PeerAuthentication의 mode 위치는 `spec.mtls.mode`. `spec.mode`로 쓰면 적용되지 않는다. `istio.io/latest/docs`에서 "PeerAuthentication"을 검색해 예제를 복사하는 것이 가장 안전하다.

</details>

---

## 🎯 시험 직전 체크리스트

- [ ] PSA 라벨 3모드(`enforce`/`audit`/`warn`)와 3레벨(`privileged`/`baseline`/`restricted`)을 자유롭게 조합해 붙일 수 있다.
- [ ] restricted 4종 세트(runAsNonRoot / allowPrivilegeEscalation false / drop ALL / seccomp RuntimeDefault)를 안 보고 쓸 수 있다.
- [ ] PSA 거부는 ReplicaSet events에서 확인한다는 것을 안다.
- [ ] AdmissionConfiguration(PodSecurityConfiguration)의 defaults/exemptions 구조와 apiserver `--admission-control-config-file` + hostPath mount를 설정할 수 있다.
- [ ] pod 레벨 전용(fsGroup 등)과 container 레벨 전용(privileged, capabilities, readOnlyRootFilesystem, allowPrivilegeEscalation) 필드를 구분한다.
- [ ] readOnlyRootFilesystem + emptyDir 조합으로 컨테이너 불변성을 만들 수 있다.
- [ ] secret 값 추출(`jsonpath` + `base64 -d`)과 env/volume 두 가지 주입 방식을 모두 쓸 수 있다.
- [ ] etcdctl로 `/registry/secrets/<ns>/<name>`을 인증서 3종과 함께 조회할 수 있다.
- [ ] EncryptionConfiguration에서 providers 순서의 의미(첫 번째=쓰기, 목록 전체=읽기)를 설명할 수 있다.
- [ ] apiserver에 `--encryption-provider-config` + volume mount 3군데 수정을 실수 없이 할 수 있다.
- [ ] `kubectl get secrets -A -o json | kubectl replace -f -` 재암호화와 `k8s:enc:aescbc:v1:` 접두어 확인을 할 수 있다.
- [ ] apiserver가 안 뜰 때 `crictl ps -a` / `journalctl -u kubelet` / `/var/log/pods/` 디버깅 순서를 안다.
- [ ] RuntimeClass(handler: runsc) 생성과 `runtimeClassName` 적용, dmesg 검증을 할 수 있다.
- [ ] Cilium 암호화 상태를 `cilium status`로 확인할 수 있다 (WireGuard/IPsec).
- [ ] Istio: `istio-injection=enabled` 라벨 → rollout restart → PeerAuthentication STRICT 3단계를 안다.
- [ ] 답안 파일은 `/opt/course/<번호>/` 에, 에러 메시지는 `&>` 로 저장한다.

## 핵심 명령어 치트시트

```bash
### PSA ###
kubectl label ns NS pod-security.kubernetes.io/enforce=restricted
kubectl label ns NS pod-security.kubernetes.io/warn=baseline pod-security.kubernetes.io/audit=baseline
kubectl label --dry-run=server --overwrite ns NS pod-security.kubernetes.io/enforce=restricted
kubectl -n NS describe rs RS명           # PSA 거부 사유 확인

### Secrets ###
kubectl -n NS create secret generic 이름 --from-literal=k=v
kubectl -n NS get secret 이름 -o jsonpath='{.data.키}' | base64 -d

### etcd 직접 조회 ###
ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/NS/이름 | hexdump -C | head

### Encryption at Rest ###
head -c 32 /dev/urandom | base64                          # aescbc 키 생성
# apiserver: --encryption-provider-config=/etc/kubernetes/enc/enc.yaml (+ hostPath mount)
kubectl get secrets -A -o json | kubectl replace -f -     # 일괄 재암호화

### apiserver 디버깅 ###
crictl ps -a | grep apiserver
journalctl -u kubelet | tail -30
ls /var/log/pods/kube-system_kube-apiserver-*/

### RuntimeClass / gVisor ###
kubectl get runtimeclass
kubectl exec POD -- dmesg | grep -i gvisor
kubectl exec POD -- uname -r

### Cilium ###
kubectl -n kube-system exec ds/cilium -- cilium status | grep -i encryption
kubectl -n kube-system get cm cilium-config -o yaml | grep -i -E "enable-wireguard|enable-ipsec"

### Istio ###
kubectl label ns NS istio-injection=enabled
kubectl -n NS rollout restart deploy
kubectl -n NS get peerauthentication

### 검증 단골 ###
kubectl -n NS exec POD -- id                 # UID/GID 확인
kubectl -n NS exec POD -- touch /test        # readOnlyRootFilesystem 확인
kubectl auth can-i get secrets --as=system:serviceaccount:NS:SA -n NS
```
