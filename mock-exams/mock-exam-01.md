# CKS 모의고사 1회 — 기본기 전수 커버 세트

실제 CKS 시험(2시간 / 16 tasks / 합격선 67%)과 동일한 형식으로 6개 도메인 전체를 커버하는 실전 모의고사 — 타이머를 켜고 풀고, 해설은 채점할 때만 열어라.

> **📌 이 모의고사의 설계**: 배점 합계 100%. 도메인 배분 — Cluster Setup 20%(T1~T3), Cluster Hardening 19%(T4~T6), System Hardening 11%(T7~T8), Minimize Microservice Vulnerabilities 21%(T9~T11), Supply Chain Security 19%(T12~T14), Monitoring/Logging/Runtime Security 10%(T15~T16). 실제 시험 가중치(15/15/10/20/20/20)와 정확히 같지는 않다 — 특히 Runtime Security 비중이 실제보다 낮으므로 T15~T16을 틀렸다면 해당 도메인을 더 무겁게 복습하라. 시험 환경 기준: **Kubernetes v1.35, containerd, Ubuntu 노드**.

## 목차

- [Exam Instructions](#exam-instructions)
- [Clusters & Contexts](#clusters--contexts)
- [Task 1 - Default Deny NetworkPolicy (7%)](#task-1---default-deny-networkpolicy-7)
- [Task 2 - kube-bench CIS Fixes (8%)](#task-2---kube-bench-cis-fixes-8)
- [Task 3 - Ingress TLS (5%)](#task-3---ingress-tls-5)
- [Task 4 - RBAC Least Privilege (7%)](#task-4---rbac-least-privilege-7)
- [Task 5 - ServiceAccount Token Automount (5%)](#task-5---serviceaccount-token-automount-5)
- [Task 6 - Cluster Upgrade (7%)](#task-6---cluster-upgrade-7)
- [Task 7 - AppArmor Profile (7%)](#task-7---apparmor-profile-7)
- [Task 8 - Suspicious Node Service (4%)](#task-8---suspicious-node-service-4)
- [Task 9 - Pod Security Admission (7%)](#task-9---pod-security-admission-7)
- [Task 10 - Secrets Encryption at Rest (8%)](#task-10---secrets-encryption-at-rest-8)
- [Task 11 - gVisor RuntimeClass (6%)](#task-11---gvisor-runtimeclass-6)
- [Task 12 - Image Vulnerability Scanning (6%)](#task-12---image-vulnerability-scanning-6)
- [Task 13 - Dockerfile and Manifest Hardening (7%)](#task-13---dockerfile-and-manifest-hardening-7)
- [Task 14 - ImagePolicyWebhook (6%)](#task-14---imagepolicywebhook-6)
- [Task 15 - Falco Rule (6%)](#task-15---falco-rule-6)
- [Task 16 - Audit Policy (4%)](#task-16---audit-policy-4)
- [채점표](#채점표)
- [실전 운영 가이드](#실전-운영-가이드)
- [취약 도메인 복습 매핑](#취약-도메인-복습-매핑)
- [🎯 시험 직전 체크리스트](#-시험-직전-체크리스트)
- [핵심 명령어 치트시트](#핵심-명령어-치트시트)

---

## Exam Instructions

Read the following instructions carefully before you begin.

- You have **2 hours** to complete **16 tasks**. The passing score is **67%**. Partial scoring is applied per sub-task.
- Every task starts with a `kubectl config use-context <name>` command. **You must run it first** — working on the wrong cluster scores zero for the task.
- Some tasks require you to connect to a node, e.g. `ssh master1`. You can only reach nodes from the main terminal. **Always type `exit` to return to the main terminal** before running the next `use-context`. Nested SSH is not supported.
- When a task asks you to save an answer, save it **exactly** at the given path under `/opt/course/<task-number>/` on the **main terminal**, unless the task states otherwise.
- You have root privileges via `sudo -i` on all nodes.
- Allowed documentation only: `kubernetes.io/docs`, `kubernetes.io/blog`, `falco.org/docs`, `kubernetes-sigs.github.io/bom/cli-reference/`, `etcd.io/docs`, `kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/`, `docs.cilium.io/en/stable`, `istio.io/latest/docs`.

## Clusters & Contexts

You have access to the following clusters/contexts:

| Context | Purpose | Control Plane | Worker | Version |
|---|---|---|---|---|
| `k8s-c1` | Main cluster (most tasks) | `master1` | `worker1` | v1.35 |
| `k8s-c2` | Cilium CNI cluster (reserved — not used in this exam set) | `cluster2-master1` | `cluster2-worker1` | v1.35 |
| `k8s-c3` | Upgrade cluster, single node, one minor version behind | `cluster3-master1` | — | v1.34 |

> **💡 시험 팁**: 실제 시험도 문제에 안 쓰이는 클러스터가 존재한다. 컨텍스트 전환 명령을 복사-실행하는 습관만 유지하면 헷갈릴 일이 없다.

---

## Task 1 - Default Deny NetworkPolicy (7%)

> `kubectl config use-context k8s-c1`

There are two namespaces on cluster `k8s-c1`: `payment` and `data`. Namespace `payment` runs Pods labelled `app=payment-api`, and namespace `data` runs PostgreSQL Pods labelled `app=postgres` listening on TCP port 5432.

1. Create a NetworkPolicy named `default-deny` in namespace `payment` that denies **all ingress and all egress** traffic for **all Pods** in that namespace.
2. Create a NetworkPolicy named `np-payment-api` in namespace `payment` that allows Pods labelled `app=payment-api` to:
   - open outgoing connections to Pods labelled `app=postgres` in namespace `data` on TCP port 5432
   - resolve DNS on port 53 (UDP and TCP)
3. Save both manifests in one file `/opt/course/1/policies.yaml` and apply them.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

default-deny는 빈 `podSelector: {}`에 `policyTypes`로 Ingress/Egress를 모두 명시. 허용 정책은 `payment-api`만 선택해서 egress 두 갈래(DB, DNS)를 연다. 여기서 DNS(Domain Name System)는 파드가 서비스명을 IP로 찾는 이름 해석이다. namespace를 지정할 때는 기본 라벨 `kubernetes.io/metadata.name`을 쓰는 것이 가장 안전하다.

**2) 단계별 풀이**

```bash
mkdir -p /opt/course/1
vim /opt/course/1/policies.yaml
```

> **🛠 만드는 법** — NetworkPolicy는 생성기가 없다: dry-run으로 못 뽑으니 kubernetes.io/docs의 최소 뼈대(`podSelector`, `policyTypes`)를 복사해 규칙을 채운다.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: payment
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np-payment-api
  namespace: payment
spec:
  podSelector:
    matchLabels:
      app: payment-api
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: data
          podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

```bash
kubectl apply -f /opt/course/1/policies.yaml
```

**3) 검증 방법**

```bash
kubectl -n payment describe netpol default-deny np-payment-api
# payment-api pod에서 DB 접속과 DNS가 되는지, 다른 목적지는 막히는지 확인
POD=$(kubectl -n payment get pod -l app=payment-api -o jsonpath='{.items[0].metadata.name}')
kubectl -n payment exec $POD -- nslookup kubernetes.default
kubectl -n payment exec $POD -- timeout 2 nc -zv postgres.data.svc.cluster.local 5432
```

**4) ⚠️ 함정 포인트**

- `namespaceSelector`와 `podSelector`를 **한 `to:` 항목 안에**(dash 1개) 써야 AND. dash를 2개로 나누면 "data 네임스페이스 전체 OR payment의 postgres pod"가 되어 오답 — CKS 최다 빈출 함정.
- DNS(53/UDP,TCP) egress를 빼먹으면 서비스명 해석이 안 되어 기능 검증에서 실패한다.
- `policyTypes`에 `Egress`를 명시하지 않으면 egress 규칙이 적용되지 않는다.
- default-deny에 `Ingress`만 쓰면 절반만 맞은 것 — 문제는 ingress+egress 모두 요구.

**예상 소요시간**: 7분 / **부분점수 포인트**: default-deny 생성(절반), 허용 정책의 DB 연결·DNS 각각 별도 채점.

</details>

---

## Task 2 - kube-bench CIS Fixes (8%)

> `kubectl config use-context k8s-c1`

The CIS benchmark tool `kube-bench` is installed on `master1` and `worker1`. Fix the following failed checks. Do not change anything else.

On `master1` (`ssh master1`), for the kube-apiserver:

1. Ensure that the `--profiling` argument is set to `false`.
2. Ensure that the `--anonymous-auth` argument is set to `false`.

On `worker1` (`ssh worker1`), for the kubelet:

3. Ensure that the read-only port is disabled (`readOnlyPort: 0`).
4. Ensure that the authorization mode is not `AlwaysAllow` — use `Webhook`, and make sure anonymous authentication stays disabled.

All components must be running and healthy afterwards.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

kube-bench 출력의 `Remediation` 섹션이 사실상 정답지다. apiserver는 static pod manifest 수정, kubelet은 `/var/lib/kubelet/config.yaml` 수정 후 `systemctl restart kubelet`.

**2) 단계별 풀이**

```bash
ssh master1
sudo -i
kube-bench run --targets=master | grep -A2 -E "1.2.(18|1) "   # 실패 항목/Remediation 확인
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

`spec.containers[0].command`에 추가/수정:

```yaml
    - --profiling=false
    - --anonymous-auth=false
```

```bash
# 저장하면 kubelet이 apiserver를 자동 재생성 (30초~1분 대기)
watch crictl ps            # kube-apiserver가 다시 Running 될 때까지
kubectl get nodes          # API 응답 확인
exit; exit                 # main terminal로 복귀

ssh worker1
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
```

**3) 검증 방법**

```bash
ssh master1 "sudo kube-bench run --targets=master" | grep -E "profiling|anonymous"
ssh worker1 "sudo kube-bench run --targets=node" | grep -E "read-only|authorization"
ssh worker1 "sudo ss -tlnp | grep 10255"   # 출력 없어야 함 (read-only port 닫힘)
```

**4) ⚠️ 함정 포인트**

- apiserver manifest를 고치고 **재생성을 기다리지 않고** 다음 문제로 넘어가면, 깨진 상태로 방치될 수 있다. 안 뜨면 `crictl ps -a`, `journalctl -u kubelet`, `/var/log/pods/`로 디버깅.
- kubelet의 `readOnlyPort: 0`은 "0번 포트"가 아니라 **비활성화**라는 뜻.
- `authorization.mode: Webhook`으로 바꿀 때 `authentication.webhook.enabled: true`가 함께 켜져 있어야 한다.
- kubelet config 수정 후 `systemctl restart kubelet`을 빼먹는 것이 가장 흔한 감점 요인.

**예상 소요시간**: 8분 / **부분점수 포인트**: apiserver 2개 플래그, kubelet 2개 설정이 각각 채점됨. 절반만 해도 4% 확보.

</details>

---

## Task 3 - Ingress TLS (5%)

> `kubectl config use-context k8s-c1`

Namespace `world` contains an existing Ingress named `world` that serves host `world.example.com` over plain HTTP. A TLS certificate and key are provided on the main terminal:

- `/opt/course/3/tls.crt`
- `/opt/course/3/tls.key`

1. Create a TLS Secret named `world-tls` in namespace `world` from these files.
2. Update the Ingress `world` so that connections for host `world.example.com` are served via HTTPS using that Secret.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`kubectl create secret tls`로 시크릿 생성 후, Ingress의 `spec.tls`에 host와 secretName을 추가하면 끝. 문서에서 "Ingress TLS"를 검색하면 예시가 그대로 나온다.

**2) 단계별 풀이**

```bash
kubectl -n world create secret tls world-tls \
  --cert=/opt/course/3/tls.crt --key=/opt/course/3/tls.key
kubectl -n world edit ingress world
```

`spec` 아래에 추가:

> **🛠 만드는 법** — Ingress는 생성기가 있다: `k create ingress <name> --rule="host/path=svc:port" $do > ing.yaml`로 뼈대를 뽑을 수 있다(여기선 기존 Ingress에 `spec.tls`만 추가). (`$do`=`--dry-run=client -o yaml`)

```yaml
  tls:
    - hosts:
        - world.example.com
      secretName: world-tls
```

**3) 검증 방법**

```bash
kubectl -n world describe ingress world     # TLS 섹션에 world-tls 표시 확인
# ingress-nginx의 NodePort로 직접 확인 (포트는 환경에 맞게)
curl -kv https://world.example.com --resolve world.example.com:443:<INGRESS_IP> 2>&1 | grep -E "subject|HTTP"
```

**4) ⚠️ 함정 포인트**

- Secret 타입은 반드시 `kubernetes.io/tls` — `create secret generic`으로 만들면 감점.
- Secret과 Ingress는 **같은 네임스페이스**에 있어야 한다.
- `spec.tls.hosts`의 호스트명이 `spec.rules`의 host와 정확히 일치해야 적용된다.

**예상 소요시간**: 4분 / **부분점수 포인트**: Secret 생성과 Ingress 수정이 별도 채점.

</details>

---

## Task 4 - RBAC Least Privilege (7%)

> `kubectl config use-context k8s-c1`

ServiceAccount `ci-runner` in namespace `ci` is currently bound to the ClusterRole `cluster-admin` via the ClusterRoleBinding `ci-runner-admin`. This violates least privilege.

1. Create a Role named `ci-runner-role` in namespace `ci` that only allows the verbs `get` and `list` on the resource `pods`.
2. Create a RoleBinding named `ci-runner-binding` in namespace `ci` that binds the Role to the ServiceAccount `ci-runner`.
3. Delete the ClusterRoleBinding `ci-runner-admin`.
4. Write the output of a check proving the ServiceAccount can no longer create Pods into `/opt/course/4/check.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

명령형(imperative) 커맨드로 처리하면 2분 컷. Role/RoleBinding은 네임스페이스 범위라는 것만 기억하면 된다. 검증은 `kubectl auth can-i`.

**2) 단계별 풀이**

```bash
kubectl -n ci create role ci-runner-role --verb=get,list --resource=pods
kubectl -n ci create rolebinding ci-runner-binding \
  --role=ci-runner-role --serviceaccount=ci:ci-runner
kubectl delete clusterrolebinding ci-runner-admin

mkdir -p /opt/course/4
kubectl auth can-i create pods -n ci \
  --as=system:serviceaccount:ci:ci-runner > /opt/course/4/check.txt
cat /opt/course/4/check.txt    # no
```

**3) 검증 방법**

```bash
kubectl auth can-i --list --as=system:serviceaccount:ci:ci-runner -n ci
kubectl auth can-i get pods -n ci --as=system:serviceaccount:ci:ci-runner   # yes
kubectl auth can-i get pods -n default --as=system:serviceaccount:ci:ci-runner  # no
```

**4) ⚠️ 함정 포인트**

- `--serviceaccount`는 `네임스페이스:SA명` 형식. `ci:ci-runner`를 `ci-runner`로만 쓰면 바인딩이 빈 주체를 가리킨다.
- 새 바인딩을 만들기 **전에** ClusterRoleBinding부터 지우면 그 사이 권한 공백이 생긴다. 순서는 만들고 → 지우기.
- `--as=system:serviceaccount:ci:ci-runner` 접두어(`system:serviceaccount:`)를 빼먹으면 일반 유저로 평가되어 검증이 틀어진다.
- 위험 verb(`escalate`, `bind`, `impersonate`, `*`)가 새 Role에 들어가지 않도록 요구된 verb만 넣는다.

**예상 소요시간**: 5분 / **부분점수 포인트**: Role 생성 / RoleBinding 생성 / 기존 바인딩 삭제 / check.txt 저장 각각 채점.

</details>

---

## Task 5 - ServiceAccount Token Automount (5%)

> `kubectl config use-context k8s-c1`

Namespace `batch` contains several ServiceAccounts and a Deployment `worker` which runs with ServiceAccount `batch-worker`. The Pods of `worker` do not talk to the Kubernetes API.

1. Configure the ServiceAccount `batch-worker` **and** the Pod template of Deployment `worker` so that the ServiceAccount token is **not** automounted.
2. Find all ServiceAccounts in namespace `batch` that are not used by any Pod and delete them. Do **not** delete the `default` ServiceAccount.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`automountServiceAccountToken: false`는 SA 레벨과 Pod 레벨 둘 다 설정 가능하고 **Pod 레벨이 우선**한다. 문제는 둘 다 요구하므로 둘 다 설정. 미사용 SA는 실행 중인 pod들의 `serviceAccountName`과 대조해서 찾는다.

**2) 단계별 풀이**

```bash
# 1) SA 레벨
kubectl -n batch patch sa batch-worker -p '{"automountServiceAccountToken": false}'

# 2) Pod 레벨 (deployment pod template)
kubectl -n batch edit deploy worker
```

`spec.template.spec`에 추가:

> **🛠 만드는 법** — Deployment는 생성기가 있다(여기선 기존 것을 `edit`): 새로 만들 땐 `k create deploy web --image=nginx --replicas=3 $do > deploy.yaml`로 뼈대를 뽑아 `spec.template.spec`에 필드를 채운다. (`$do`=`--dry-run=client -o yaml`)

```yaml
      automountServiceAccountToken: false
```

```bash
# 3) 미사용 SA 찾기
kubectl -n batch get sa
kubectl -n batch get pods -o jsonpath='{range .items[*]}{.spec.serviceAccountName}{"\n"}{end}' | sort -u
# 두 목록을 비교해 pod가 안 쓰는 SA 삭제 (default 제외)
kubectl -n batch delete sa unused-sa
```

**3) 검증 방법**

```bash
POD=$(kubectl -n batch get pod -l app=worker -o jsonpath='{.items[0].metadata.name}')
kubectl -n batch exec $POD -- ls /var/run/secrets/kubernetes.io/serviceaccount
# "No such file or directory" 여야 정답
kubectl -n batch get sa   # default + batch-worker 등 사용 중인 SA만 남았는지
```

**4) ⚠️ 함정 포인트**

- Deployment 수정 시 `automountServiceAccountToken`을 `spec.template.spec`(pod spec)이 아닌 최상위 `spec`에 넣으면 스키마 에러. 위치를 정확히.
- deployment를 수정해야 pod가 재생성된다. SA만 고치면 **기존 pod에는 소급 적용되지 않는다.**
- `default` SA를 지우면 안 된다 — 지워도 자동 재생성되지만 문제 조건 위반.
- ReplicaSet이 만드는 pod의 SA까지 확인하려면 pod 기준으로 조회하는 것이 정확하다.

**예상 소요시간**: 5분 / **부분점수 포인트**: SA 레벨 / Pod 레벨 / 미사용 SA 삭제 각각 채점.

</details>

---

## Task 6 - Cluster Upgrade (7%)

> `kubectl config use-context k8s-c3`

Cluster `k8s-c3` consists of a single control plane node `cluster3-master1` running Kubernetes **v1.34**. Upgrade the cluster (kubeadm, control plane, kubelet, kubectl) to the **latest available v1.35 patch version**.

- Use `kubeadm` for the upgrade (`ssh cluster3-master1`).
- Drain the node before upgrading kubelet and uncordon it afterwards.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

CKA에서 하던 kubeadm 업그레이드 그대로다. 순서: apt 저장소 마이너 버전 변경 → kubeadm 업그레이드 → `kubeadm upgrade plan/apply` → drain → kubelet/kubectl 업그레이드 → restart → uncordon. 정확한 패치 버전은 `apt-cache madison kubeadm`으로 확인한다(아래 1.35.1은 예시).

**2) 단계별 풀이**

```bash
ssh cluster3-master1
sudo -i

# pkgs.k8s.io 저장소를 v1.35로 변경
sed -i 's/v1\.34/v1.35/' /etc/apt/sources.list.d/kubernetes.list
apt-get update
apt-cache madison kubeadm | head -3     # 최신 1.35 패치 버전 확인

# kubeadm 업그레이드
apt-mark unhold kubeadm
apt-get install -y kubeadm=1.35.1-*
apt-mark hold kubeadm
kubeadm version

# control plane 업그레이드
kubeadm upgrade plan
kubeadm upgrade apply v1.35.1

# 노드 drain (main terminal 또는 이 노드에서 kubectl 사용 가능)
kubectl drain cluster3-master1 --ignore-daemonsets --delete-emptydir-data

# kubelet / kubectl 업그레이드
apt-mark unhold kubelet kubectl
apt-get install -y kubelet=1.35.1-* kubectl=1.35.1-*
apt-mark hold kubelet kubectl
systemctl daemon-reload
systemctl restart kubelet

kubectl uncordon cluster3-master1
exit; exit
```

**3) 검증 방법**

```bash
kubectl get nodes    # VERSION v1.35.x, STATUS Ready, SchedulingDisabled 아님
ssh cluster3-master1 "kubelet --version && kubeadm version -o short"
```

**4) ⚠️ 함정 포인트**

- apt 저장소가 마이너 버전별로 분리되어 있어(`/etc/apt/sources.list.d/kubernetes.list`) **저장소 URL을 v1.35로 바꾸지 않으면** 새 버전이 아예 보이지 않는다.
- `kubeadm upgrade apply` 전에 kubeadm 자체를 먼저 업그레이드해야 한다. 순서 바뀌면 실패.
- drain 없이 kubelet을 올리면 감점 — 문제에서 drain/uncordon을 명시적으로 요구.
- 마지막 `uncordon`을 잊으면 노드가 `SchedulingDisabled`로 남아 감점. 검증에서 반드시 확인.
- `apt-mark hold`를 되돌려 놓지 않아도 동작에는 문제 없지만, unhold → install → hold 루틴을 습관화하면 실수할 여지가 없다.

**예상 소요시간**: 10분 (apply 대기 포함) / **부분점수 포인트**: control plane 버전 / kubelet 버전 / drain·uncordon 상태가 각각 채점. `kubeadm upgrade apply`가 오래 걸리면 돌려놓고 다른 문제를 풀다 와도 된다.

</details>

---

## Task 7 - AppArmor Profile (7%)

> `kubectl config use-context k8s-c1`

An AppArmor profile file is provided at `/opt/course/7/profile` on node `worker1`:

```text
#include <tunables/global>
profile deny-write flags=(attach_disconnected) {
  #include <abstractions/base>
  file,
  deny /** w,
}
```

1. Load the profile on node `worker1` (`ssh worker1`) and make sure it survives a reboot.
2. Apply the profile to the container of Deployment `secure-app` in namespace `apparmor` using the `securityContext.appArmorProfile` field. Do **not** use annotations.
3. Verify enforcement: try to create a file inside a Pod of the Deployment and save the command output to `/opt/course/7/violation.txt` on the main terminal.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

v1.30+에서 AppArmor는 GA이며 `securityContext.appArmorProfile` 필드를 쓴다(과거 annotation `container.apparmor.security.beta.kubernetes.io/이름` 방식은 deprecated). 프로파일은 **pod가 스케줄될 노드에 로드되어 있어야** 하고, 재부팅 유지를 위해 `/etc/apparmor.d/`에 복사한다.

**2) 단계별 풀이**

```bash
ssh worker1
sudo -i
apparmor_parser -q /opt/course/7/profile        # 커널에 로드
cp /opt/course/7/profile /etc/apparmor.d/       # 재부팅 후에도 유지
aa-status | grep deny-write                     # 로드 확인
exit; exit

kubectl -n apparmor edit deploy secure-app
```

컨테이너 레벨 `securityContext`에 추가 (pod 레벨 `spec.template.spec.securityContext`도 가능):

```yaml
        securityContext:
          appArmorProfile:
            type: Localhost
            localhostProfile: deny-write
```

```bash
mkdir -p /opt/course/7
POD=$(kubectl -n apparmor get pod -l app=secure-app -o jsonpath='{.items[0].metadata.name}')
kubectl -n apparmor exec $POD -- touch /tmp/test 2>&1 | tee /opt/course/7/violation.txt
# "Permission denied" 가 저장되어야 함
```

**3) 검증 방법**

```bash
kubectl -n apparmor get pods                # Running 확인
kubectl -n apparmor exec $POD -- cat /proc/1/attr/current   # deny-write (enforce) 표시
cat /opt/course/7/violation.txt
```

**4) ⚠️ 함정 포인트**

- `localhostProfile`에는 **파일 안의 profile 이름**(`deny-write`)을 쓴다. 파일 경로나 파일명이 아니다.
- 프로파일이 로드되지 않은 노드에 pod가 스케줄되면 컨테이너 생성이 실패한다(`CreateContainerError`, 이벤트에 apparmor 관련 메시지). deployment에 nodeSelector가 있는지, 어느 노드에 스케줄되는지 확인.
- annotation 방식으로 적용하면 문제 조건("Do not use annotations") 위반으로 감점.
- `apparmor_parser`만 하고 `/etc/apparmor.d/`에 복사하지 않으면 재부팅 유지 조건 미달.

**예상 소요시간**: 8분 / **부분점수 포인트**: 프로파일 로드 / deployment 적용 / violation.txt 각각 채점.

</details>

---

## Task 8 - Suspicious Node Service (4%)

> `kubectl config use-context k8s-c1`

A previous administrator left a suspicious service running on node `worker1`. It is listening on TCP port **6666**.

1. Connect to `worker1` (`ssh worker1`) and identify the process and its systemd unit.
2. Stop the service and make sure it cannot start again after a reboot.
3. Write the systemd unit name (e.g. `something.service`) to `/opt/course/8/unit.txt` on the main terminal.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`ss -tlnp`로 포트→PID→프로세스를 찾고, `systemctl status PID`로 어떤 unit이 띄웠는지 역추적한다. `stop` + `disable`이 정답 조합.

**2) 단계별 풀이**

```bash
ssh worker1
sudo -i
ss -tlnp | grep 6666
# 예: users:(("nc",pid=12345,fd=3))
systemctl status 12345        # PID로 소속 unit 확인 → legacy-backup.service
systemctl stop legacy-backup.service
systemctl disable legacy-backup.service
ss -tlnp | grep 6666          # 출력 없어야 함
exit; exit

mkdir -p /opt/course/8
echo "legacy-backup.service" > /opt/course/8/unit.txt
```

**3) 검증 방법**

```bash
ssh worker1 "sudo systemctl is-enabled legacy-backup.service"   # disabled
ssh worker1 "sudo ss -tlnp | grep 6666 || echo CLOSED"          # CLOSED
```

**4) ⚠️ 함정 포인트**

- `stop`만 하고 `disable`을 안 하면 재부팅 후 되살아난다 — 문제의 핵심 채점 포인트.
- `systemctl status <PID>` 트릭을 모르면 `systemctl list-units --type=service | grep -i backup` 식으로 이름을 뒤져야 해서 느리다.
- `lsof -i :6666`도 대안. 컨테이너가 리슨 중이라면 `crictl ps`로 접근해야 한다(이 문제는 호스트 서비스).

**예상 소요시간**: 4분 / **부분점수 포인트**: stop / disable / unit.txt 각각 채점.

</details>

---

## Task 9 - Pod Security Admission (7%)

> `kubectl config use-context k8s-c1`

Namespace `team-orange` must enforce the **restricted** Pod Security Standard.

1. Label the namespace so that the `restricted` level is **enforced**, pinned to version `v1.35`. Also add a `warn` label for the same level.
2. Deployment `web-portal` in that namespace currently violates the restricted policy. Modify the Deployment so its Pods comply with `restricted` and reach `Running` state.
3. Write the reason why the original Pods were rejected into `/opt/course/9/reason.txt` (one or two lines are enough).

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

PSA(Pod Security Admission — 파드를 미리 정의된 보안 표준에 맞춰 검사·차단하는 내장 admission 컨트롤러)는 네임스페이스 라벨로 동작한다: `pod-security.kubernetes.io/<모드>=<레벨>` (모드: enforce/audit/warn, 레벨: privileged/baseline/restricted, 버전 고정: `enforce-version`). restricted 통과 조건은 사실상 고정 세트다: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`. (여기서 capabilities=리눅스 커널 권한을 잘게 나눈 단위, seccomp=컨테이너가 호출 가능한 시스템콜을 필터링하는 커널 기능.)

**2) 단계별 풀이**

```bash
kubectl label ns team-orange \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.35 \
  pod-security.kubernetes.io/warn=restricted

# 거부 사유 확인 (rollout restart 해보면 warn/enforce 메시지가 뜬다)
kubectl -n team-orange rollout restart deploy web-portal
kubectl -n team-orange get events --sort-by=.lastTimestamp | tail -5
kubectl -n team-orange describe rs -l app=web-portal | grep -i violate

mkdir -p /opt/course/9
echo 'Pods violate PodSecurity "restricted:v1.35": allowPrivilegeEscalation != false, unrestricted capabilities, runAsNonRoot != true, seccompProfile not set' > /opt/course/9/reason.txt

kubectl -n team-orange edit deploy web-portal
```

`spec.template.spec.containers[0]`에 (privileged/hostNetwork 등이 있으면 제거하고) 추가:

```yaml
        securityContext:
          runAsNonRoot: true
          runAsUser: 10001
          allowPrivilegeEscalation: false
          capabilities:
            drop:
              - ALL
          seccompProfile:
            type: RuntimeDefault
```

**3) 검증 방법**

```bash
kubectl get ns team-orange -o yaml | grep pod-security
kubectl -n team-orange get pods    # 새 pod가 Running
kubectl -n team-orange rollout status deploy web-portal
```

**4) ⚠️ 함정 포인트**

- PSA는 **pod 생성 시점**에만 검사한다. 라벨을 붙여도 기존 pod는 계속 돈다 — deployment를 수정(또는 rollout restart)해야 새 pod로 교체되며 채점 대상이 된다.
- 이미지가 root로만 도는 경우 `runAsNonRoot: true`만 넣으면 `CreateContainerConfigError`. `runAsUser: 10001`처럼 비루트 UID를 명시해야 안전하다.
- `seccompProfile`을 빼먹는 수험생이 가장 많다. restricted는 `RuntimeDefault` 또는 `Localhost`를 요구한다.
- `enforce-version` 라벨을 요구하는 문제인데 `enforce`만 붙이면 부분 감점.

**예상 소요시간**: 7분 / **부분점수 포인트**: 라벨링 / deployment 수정(Running 도달) / reason.txt 각각 채점.

</details>

---

## Task 10 - Secrets Encryption at Rest (8%)

> `kubectl config use-context k8s-c1`

Implement encryption at rest for Secrets on cluster `k8s-c1` (`ssh master1`).

1. Create an `EncryptionConfiguration` at `/etc/kubernetes/enc/enc.yaml` that encrypts **Secrets** using the `aescbc` provider with a key named `key1`. Previously stored unencrypted Secrets must remain readable.
2. Configure the kube-apiserver to use this configuration.
3. Re-encrypt **all existing Secrets in all namespaces**.
4. Verify that the Secret `s1` in namespace `one` is stored encrypted in etcd, and save the verification command output to `/opt/course/10/etcd-check.txt` on the main terminal.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

provider 순서가 핵심이다: **첫 번째 provider로 쓰기(암호화)**, 나머지는 읽기용. `aescbc`를 첫 번째, `identity: {}`를 두 번째에 두면 "새로 쓰는 건 암호화 + 기존 평문도 읽기 가능"이 된다. apiserver에는 플래그와 함께 hostPath 마운트를 추가해야 한다.

**2) 단계별 풀이**

```bash
ssh master1
sudo -i
mkdir -p /etc/kubernetes/enc
head -c 32 /dev/urandom | base64    # 32바이트 키 생성, 출력을 복사
vim /etc/kubernetes/enc/enc.yaml
```

> **🛠 만드는 법** — 이건 kubectl 리소스가 아니라 apiserver 설정 파일이다: kubernetes.io/docs의 EncryptionConfiguration 예제를 복사해 편집한다.

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <위에서 생성한 base64 키>
      - identity: {}
```

```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

command에 플래그, 그리고 volume/volumeMount 추가:

```yaml
    - --encryption-provider-config=/etc/kubernetes/enc/enc.yaml
```

```yaml
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

```bash
watch crictl ps       # apiserver 재기동 대기
kubectl get nodes     # API 정상 확인

# 기존 secret 전체 재암호화
kubectl get secrets -A -o json | kubectl replace -f -

# etcd에서 암호화 확인
ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/one/s1 | tee /tmp/etcd-check.txt
# 출력에 k8s:enc:aescbc:v1:key1 접두어가 보이면 성공
exit; exit
mkdir -p /opt/course/10
scp master1:/tmp/etcd-check.txt /opt/course/10/etcd-check.txt
```

**3) 검증 방법**

```bash
kubectl -n one get secret s1 -o yaml       # API로는 평문 디코딩 정상
grep "k8s:enc:aescbc:v1:key1" /opt/course/10/etcd-check.txt && echo ENCRYPTED
```

**4) ⚠️ 함정 포인트**

- **hostPath 마운트를 빼먹으면** apiserver가 enc.yaml을 못 읽고 CrashLoop — 이 문제의 최대 함정. `crictl ps -a`와 `/var/log/pods/`로 디버깅.
- provider 순서를 `identity` 먼저로 두면 새 secret이 **평문으로 저장**된다. 첫 번째 provider가 쓰기 담당.
- 재암호화(`kubectl get secrets -A -o json | kubectl replace -f -`)를 건너뛰면 기존 secret은 여전히 평문 — 4번 검증에서 걸린다.
- aescbc 키는 반드시 **32바이트를 base64 인코딩**한 값. 짧으면 apiserver가 기동 실패.

**예상 소요시간**: 10분 / **부분점수 포인트**: enc.yaml 작성 / apiserver 연동(정상 기동) / 재암호화 / etcd-check.txt 각각 채점. apiserver를 깨뜨렸다면 플래그·마운트를 제거해 원복부터.

</details>

---

## Task 11 - gVisor RuntimeClass (6%)

> `kubectl config use-context k8s-c1`

The gVisor runtime (`runsc`) is installed and configured in containerd on node `worker1`.

1. Create a RuntimeClass named `gvisor` with handler `runsc`.
2. Update Deployment `sandbox-api` in namespace `sandbox` to run its Pods with that RuntimeClass.
3. Exec `dmesg` inside one of the new Pods and save the full output to `/opt/course/11/dmesg` on the main terminal.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

RuntimeClass(`node.k8s.io/v1`)를 만들고 pod spec에 `runtimeClassName`을 넣으면 끝. gVisor 위에서 도는지 검증은 `dmesg`에 gVisor 문자열이 찍히는지(또는 `uname -r`이 호스트와 다른지)로 한다.

**2) 단계별 풀이**

> **🛠 만드는 법** — RuntimeClass는 생성기가 없다: dry-run으로 못 뽑으니 kubernetes.io/docs의 최소 뼈대(`handler` 포함)를 복사해 채운다.

```bash
cat << 'EOF' | kubectl apply -f -
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
EOF

kubectl -n sandbox edit deploy sandbox-api
```

`spec.template.spec`에 추가:

```yaml
      runtimeClassName: gvisor
```

```bash
kubectl -n sandbox rollout status deploy sandbox-api
mkdir -p /opt/course/11
POD=$(kubectl -n sandbox get pod -l app=sandbox-api -o jsonpath='{.items[0].metadata.name}')
kubectl -n sandbox exec $POD -- dmesg > /opt/course/11/dmesg
head -2 /opt/course/11/dmesg    # "Starting gVisor..." 확인
```

**3) 검증 방법**

```bash
kubectl -n sandbox get pods -o wide          # Running, worker1 스케줄 확인
grep -i gvisor /opt/course/11/dmesg && echo OK
kubectl -n sandbox exec $POD -- uname -r     # 호스트 커널과 다른 버전 표시
```

**4) ⚠️ 함정 포인트**

- `runtimeClassName`은 `spec.template.spec`(pod spec) 레벨. 컨테이너 레벨에 넣으면 스키마 에러.
- runsc가 설치된 노드는 worker1뿐이므로, pod가 다른 노드로 가면 기동 실패할 수 있다 — 환경에 따라 `nodeSelector`가 이미 걸려 있는지 확인.
- handler 이름은 containerd 설정의 runtime 이름(`runsc`)과 정확히 일치해야 한다. 임의로 `gvisor`라고 쓰면 pod가 `SandboxCreation` 실패.
- dmesg 출력 저장은 exec 결과를 **main terminal의 파일로 리다이렉트** — 노드 안에 저장하면 채점 안 됨.

**예상 소요시간**: 5분 / **부분점수 포인트**: RuntimeClass 생성 / deployment 적용 / dmesg 파일 각각 채점.

</details>

---

## Task 12 - Image Vulnerability Scanning (6%)

> `kubectl config use-context k8s-c1`

The tool `trivy` is installed on the main terminal. Namespace `applications` runs several Deployments.

1. Scan all container images used by Pods in namespace `applications` for vulnerabilities of severity **CRITICAL**.
2. Scale every Deployment that uses an image containing at least one CRITICAL vulnerability to **0 replicas**.
3. Write the vulnerable image names (one per line) to `/opt/course/12/vulnerable-images.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

이미지 목록을 뽑아 하나씩 `trivy image --severity CRITICAL`로 스캔한다. `--exit-code 1`을 쓰면 취약점 존재 여부를 종료 코드로 판별할 수 있어 빠르다. 취약 이미지를 쓰는 deployment만 scale 0.

**2) 단계별 풀이**

```bash
mkdir -p /opt/course/12

# 이미지 목록 추출
kubectl -n applications get pods -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u

# 이미지별 스캔 (취약하면 vulnerable 출력)
for img in $(kubectl -n applications get pods -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u); do
  if ! trivy image --severity CRITICAL --exit-code 1 --quiet "$img" > /dev/null 2>&1; then
    echo "$img" >> /opt/course/12/vulnerable-images.txt
  fi
done
cat /opt/course/12/vulnerable-images.txt

# 어떤 deployment가 그 이미지를 쓰는지 확인 후 scale 0
kubectl -n applications get deploy -o custom-columns=NAME:.metadata.name,IMAGE:.spec.template.spec.containers[*].image
kubectl -n applications scale deploy <vulnerable-deploy> --replicas=0
```

**3) 검증 방법**

```bash
kubectl -n applications get deploy    # 취약 deployment READY 0/0
trivy image --severity CRITICAL --exit-code 1 --quiet <남긴 이미지> > /dev/null && echo CLEAN   # exit 0 = CRITICAL 없음
```

**4) ⚠️ 함정 포인트**

- `--severity CRITICAL,HIGH`가 아니라 문제에서 요구한 심각도만 필터할 것 — HIGH까지 포함해 멀쩡한 deployment를 내리면 감점.
- pod가 아니라 **deployment를 scale** 해야 한다. pod를 지우면 ReplicaSet이 되살린다.
- 시간이 없으면 스크립트 대신 이미지 4~5개를 수동으로 스캔하는 것이 오히려 빠를 수 있다. `trivy image --severity CRITICAL --quiet IMG | tail -5`로 요약만 확인.
- 같은 이미지를 여러 deployment가 공유할 수 있다 — 이미지 기준이 아니라 deployment 기준으로 빠짐없이 내린다.

**예상 소요시간**: 7분 (스캔 대기 포함) / **부분점수 포인트**: scale 0 처리와 vulnerable-images.txt가 각각 채점.

</details>

---

## Task 13 - Dockerfile and Manifest Hardening (7%)

> `kubectl config use-context k8s-c1`

Two files on the main terminal have security issues:

`/opt/course/13/Dockerfile`:

```dockerfile
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
ENV API_TOKEN=super-secret-token-12345
COPY app /app
CMD ["/app"]
```

`/opt/course/13/deployment.yaml` (excerpt of the container spec):

```yaml
        securityContext:
          privileged: true
          allowPrivilegeEscalation: true
```

Fix **exactly** the following, keeping the functionality:

1. Dockerfile: pin the base image to `ubuntu:24.04`, remove the hardcoded secret, and make the image run as the non-root user `appuser` (UID 1001) — create the user in the image.
2. deployment.yaml: the container must not be privileged, must not allow privilege escalation, must drop **ALL** capabilities, and must use a read-only root filesystem.

Do not build or apply — fixing the files is enough.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

요구 항목이 열거되어 있으므로 그 항목만 정확히 고친다. 그 외를 건드리면(기능 변경) 감점 여지가 있다.

**2) 단계별 풀이**

`/opt/course/13/Dockerfile` 수정 후:

```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN useradd -u 1001 -m appuser
COPY app /app
USER appuser
CMD ["/app"]
```

`/opt/course/13/deployment.yaml`의 컨테이너 securityContext 수정 후:

```yaml
        securityContext:
          privileged: false
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
```

**3) 검증 방법**

```bash
grep -E "FROM|USER|API_TOKEN" /opt/course/13/Dockerfile   # 24.04 / USER appuser / 토큰 없음
grep -A6 securityContext /opt/course/13/deployment.yaml
```

**4) ⚠️ 함정 포인트**

- `ENV`/`ARG`/레이어에 secret을 남기면 이미지 히스토리로 유출된다 — 삭제가 정답이지 주석 처리가 아니다.
- `USER appuser`는 **COPY/RUN 등 루트가 필요한 작업 뒤, CMD 앞**에 둔다. 너무 앞에 두면 빌드가 깨진다.
- `readOnlyRootFilesystem`은 pod가 아니라 **컨테이너** securityContext 필드다.
- 실제 운영이라면 쓰기가 필요한 경로에 `emptyDir`를 마운트해야 하지만, 이 문제는 파일 수정까지만 요구 — 문제가 요구한 범위만 정확히.

**예상 소요시간**: 6분 / **부분점수 포인트**: Dockerfile 3개 항목, deployment 4개 항목이 개별 채점되는 전형적인 다득점 문제.

</details>

---

## Task 14 - ImagePolicyWebhook (6%)

> `kubectl config use-context k8s-c1`

An ImagePolicyWebhook setup has been partially prepared on `master1` (`ssh master1`) under `/etc/kubernetes/policywebhook/`:

- `admission_config.yaml` — incomplete AdmissionConfiguration
- `kubeconf` — kubeconfig pointing to the (currently unreachable) external policy service `https://localhost:1234`
- TLS certificates for the webhook connection

Complete the setup:

1. Finish `admission_config.yaml` so the `ImagePolicyWebhook` plugin uses `/etc/kubernetes/policywebhook/kubeconf` and **denies** Pod creation if the external service is unreachable (`defaultAllow: false`).
2. Enable the plugin on the kube-apiserver using `--enable-admission-plugins` and `--admission-control-config-file`.
3. Verify: creating any Pod must now fail. Save the error message of `kubectl run test --image=nginx` to `/opt/course/14/error.txt` on the main terminal.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

AdmissionConfiguration 안의 `imagePolicy.kubeConfigFile`과 `defaultAllow: false`를 채우고, apiserver에 플래그 2개를 연결한다. `/etc/kubernetes/policywebhook/`는 보통 이미 마운트되어 있지만 아니라면 hostPath 추가.

**2) 단계별 풀이**

```bash
ssh master1
sudo -i
vim /etc/kubernetes/policywebhook/admission_config.yaml
```

> **🛠 만드는 법** — 이건 kubectl 리소스가 아니라 apiserver admission 설정 파일이다: kubernetes.io/docs의 ImagePolicyWebhook 예제를 복사해 빈 필드를 채운다.

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: ImagePolicyWebhook
    configuration:
      imagePolicy:
        kubeConfigFile: /etc/kubernetes/policywebhook/kubeconf
        allowTTL: 100
        denyTTL: 50
        retryBackoff: 500
        defaultAllow: false
```

```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

command 수정/추가 (volume/volumeMount에 `/etc/kubernetes/policywebhook`이 없으면 hostPath로 추가):

```yaml
    - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
    - --admission-control-config-file=/etc/kubernetes/policywebhook/admission_config.yaml
```

```bash
watch crictl ps      # apiserver 재기동 대기
exit; exit
mkdir -p /opt/course/14
kubectl run test --image=nginx 2> /opt/course/14/error.txt
cat /opt/course/14/error.txt
# Error ... denied the request: Post "https://localhost:1234/...": connection refused
```

**3) 검증 방법**

```bash
kubectl run test2 --image=busybox   # 역시 거부되어야 함
kubectl get pods                    # 새 pod가 생성되지 않음
```

**4) ⚠️ 함정 포인트**

- `defaultAllow: true`로 두면 웹훅이 죽어 있을 때 모든 이미지가 통과 — 문제의 핵심 요구 위반.
- 기존 `--enable-admission-plugins=NodeRestriction`을 **덮어쓰지 말고 콤마로 추가**한다. NodeRestriction을 빼면 다른 채점 항목이 깨질 수 있다.
- AdmissionConfiguration의 apiVersion은 `apiserver.config.k8s.io/v1` — `audit.k8s.io`나 `admissionregistration.k8s.io`와 혼동 금지.
- apiserver가 안 뜨면 대부분 config 파일 경로/마운트 문제. `journalctl -u kubelet`과 `/var/log/pods/kube-system_kube-apiserver*/`에서 원인 확인.
- 이 상태에서는 **어떤 pod도 못 만든다**. 다음 문제로 넘어가기 전, 문제 지시가 "설정 유지"라면 그대로 두는 것이 맞다(실제 killer.sh도 동일).

**예상 소요시간**: 8분 / **부분점수 포인트**: admission_config 완성 / apiserver 플래그 / error.txt 각각 채점.

</details>

---

## Task 15 - Falco Rule (6%)

> `kubectl config use-context k8s-c1`

Falco is installed as a systemd service on node `worker1`. A Pod in namespace `team-x` periodically spawns shells inside its container.

1. On `worker1`, create a Falco rule named `shell in container` that triggers whenever a shell (`sh` or `bash`) is spawned in **any** container. Priority: `WARNING`. The output must contain exactly: event time, container id, container image repository, in this format:

   `%evt.time,%container.id,%container.image.repository`

2. Run Falco for **30 seconds** and collect the events matching your rule.
3. Save the collected output lines to `/opt/course/15/falco.log` on the main terminal.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

커스텀/오버라이드 룰은 `/etc/falco/falco_rules.local.yaml`에 쓴다(기본 룰 파일보다 나중에 로드되어 같은 이름이면 재정의). 기본 룰 파일에 정의된 macro `spawned_process`, `container`를 그대로 활용하면 condition이 짧아진다. 30초 수집은 `timeout 30s falco` 또는 `falco -M 30`.

**2) 단계별 풀이**

```bash
ssh worker1
sudo -i
vim /etc/falco/falco_rules.local.yaml
```

> **🛠 만드는 법** — Falco 룰은 kubectl 리소스가 아니라 노드의 룰 파일이다: falco.org/docs의 룰 예제를 복사해 `condition/output`을 편집한다.

```yaml
- rule: shell in container
  desc: detect shell spawned in any container
  condition: spawned_process and container and proc.name in (sh, bash)
  output: "%evt.time,%container.id,%container.image.repository"
  priority: WARNING
```

```bash
systemctl stop falco            # 중복 인스턴스 방지
falco -M 30 > /tmp/falco.out 2>/dev/null
# 또는: timeout 30s falco > /tmp/falco.out
# 표준 출력 라인(<time>: <priority> <output>)에는 rule 이름이 포함되지 않으므로 priority로 필터
grep ": Warning " /tmp/falco.out > /tmp/falco.log
systemctl start falco
exit; exit

mkdir -p /opt/course/15
scp worker1:/tmp/falco.log /opt/course/15/falco.log
head /opt/course/15/falco.log
# 예: 10:23:15.123456789: Warning 10:23:15.123456789,3a5b...,docker.io/library/nginx
```

**3) 검증 방법**

```bash
wc -l /opt/course/15/falco.log        # 30초 동안 여러 건 수집되었는지
ssh worker1 "sudo systemctl is-active falco"   # 서비스 원복 확인
```

**4) ⚠️ 함정 포인트**

- 출력 필드 순서/구분자를 문제 그대로 지켜야 한다. `%k8s.pod.name` 등 요구하지 않은 필드를 넣으면 감점.
- Falco의 표준 출력 라인에는 **rule 이름이 찍히지 않는다** — rule 이름으로 grep하면 아무것도 안 걸린다. priority(`Warning`)나 output 패턴으로 필터할 것.
- 기본 룰 `Terminal shell in container`를 **수정**하라는 변형 문제도 나온다. 그 경우에도 원본 파일이 아닌 `falco_rules.local.yaml`에 같은 rule 이름으로 재정의하는 것이 정석.
- macro를 쓰지 않고 직접 쓸 경우: `evt.type = execve and evt.dir = < and container.id != host and proc.name in (sh, bash)`.
- 룰 문법이 틀리면 falco가 기동 자체를 거부한다. `falco -M 5`로 짧게 먼저 돌려 문법 검증하면 안전.
- 로그 확인 대안: `journalctl -u falco` 또는 `/var/log/syslog`.

**예상 소요시간**: 8분 / **부분점수 포인트**: 룰 작성(트리거 여부) / 출력 포맷 / falco.log 각각 채점.

</details>

---

## Task 16 - Audit Policy (4%)

> `kubectl config use-context k8s-c1`

Configure audit logging on `master1` (`ssh master1`).

1. Create an audit policy at `/etc/kubernetes/audit/policy.yaml`:
   - changes to **Secrets** are logged at `Metadata` level
   - all requests in namespace `prod` are logged at `RequestResponse` level
   - everything else is **not logged** (`None`)
2. Configure the kube-apiserver to use this policy. Log to `/etc/kubernetes/audit/logs/audit.log`, keep logs for **30 days**, retain at most **5** backup files, rotate at **100 MB**.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

Audit Policy는 **첫 번째로 매칭되는 룰이 적용**되므로 순서가 곧 정답이다: secrets → prod 네임스페이스 → catch-all None. apiserver에는 플래그 4개 + policy 파일/로그 디렉토리 hostPath 마운트가 필요하다.

**2) 단계별 풀이**

```bash
ssh master1
sudo -i
mkdir -p /etc/kubernetes/audit/logs
vim /etc/kubernetes/audit/policy.yaml
```

> **🛠 만드는 법** — Audit Policy는 kubectl 리소스가 아니라 apiserver 설정 파일이다: kubernetes.io/docs의 Policy 예제를 복사해 룰을 채운다.

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - RequestReceived
rules:
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]
  - level: RequestResponse
    namespaces: ["prod"]
  - level: None
```

```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

command에 추가:

```yaml
    - --audit-policy-file=/etc/kubernetes/audit/policy.yaml
    - --audit-log-path=/etc/kubernetes/audit/logs/audit.log
    - --audit-log-maxage=30
    - --audit-log-maxbackup=5
    - --audit-log-maxsize=100
```

volumeMounts/volumes에 추가:

```yaml
    volumeMounts:
      - name: audit
        mountPath: /etc/kubernetes/audit
  volumes:
    - name: audit
      hostPath:
        path: /etc/kubernetes/audit
        type: DirectoryOrCreate
```

```bash
watch crictl ps       # apiserver 재기동 대기
```

**3) 검증 방법**

```bash
kubectl -n prod get pods; kubectl get secrets -A > /dev/null   # 이벤트 생성
tail -2 /etc/kubernetes/audit/logs/audit.log | head -c 400
# secrets 이벤트는 level Metadata, prod 이벤트는 RequestResponse인지 jq로 확인 가능
exit; exit
```

**4) ⚠️ 함정 포인트**

- 이 문제의 최대 함정은 policy가 아니라 **hostPath 마운트 누락** — policy 파일과 로그 디렉토리 둘 다 apiserver 컨테이너에서 접근 가능해야 한다(위처럼 상위 디렉토리 하나로 묶으면 간단).
- 룰 순서를 뒤집어 `- level: None`을 첫 번째에 두면 아무것도 기록되지 않는다. 첫 매칭 룰 적용 원칙.
- level 철자: `None`/`Metadata`/`Request`/`RequestResponse` — 대소문자 틀리면 apiserver 기동 실패.
- `--audit-log-maxage`(일)/`maxbackup`(개)/`maxsize`(MB)의 단위를 혼동하지 말 것.

**예상 소요시간**: 7분 / **부분점수 포인트**: policy 파일 / 플래그 4종 / 로그 실제 생성 각각 채점.

</details>

---

## 채점표

각 Task를 해설의 "부분점수 포인트" 기준으로 자가 채점하라. **67% 이상이면 합격권**이다.

| Task | 도메인 | 배점 | 부분점수 기준 (각 항목 균등 배분) | 내 점수 |
|---|---|---|---|---|
| 1 | Cluster Setup | 7% | default-deny / DB egress / DNS egress | |
| 2 | Cluster Setup | 8% | apiserver 플래그 2개 / kubelet 설정 2개 | |
| 3 | Cluster Setup | 5% | TLS Secret / Ingress 적용 | |
| 4 | Cluster Hardening | 7% | Role / RoleBinding / CRB 삭제 / check.txt | |
| 5 | Cluster Hardening | 5% | SA 레벨 / Pod 레벨 / 미사용 SA 삭제 | |
| 6 | Cluster Hardening | 7% | control plane 버전 / kubelet 버전 / drain·uncordon | |
| 7 | System Hardening | 7% | 프로파일 로드(영속) / 필드 적용 / violation.txt | |
| 8 | System Hardening | 4% | stop / disable / unit.txt | |
| 9 | MMV | 7% | PSA 라벨 / deployment 수정(Running) / reason.txt | |
| 10 | MMV | 8% | enc.yaml / apiserver 연동 / 재암호화 / etcd-check.txt | |
| 11 | MMV | 6% | RuntimeClass / 적용 / dmesg 파일 | |
| 12 | Supply Chain | 6% | scale 0 / vulnerable-images.txt | |
| 13 | Supply Chain | 7% | Dockerfile 3항목 / manifest 4항목 | |
| 14 | Supply Chain | 6% | admission_config / apiserver 플래그 / error.txt | |
| 15 | Runtime Security | 6% | 룰 트리거 / 출력 포맷 / falco.log | |
| 16 | Runtime Security | 4% | policy 파일 / 플래그·마운트 / 로그 생성 | |
| **합계** | | **100%** | **합격선 67%** | |

> **⚠️ 함정**: 실제 시험 채점은 결과 상태 기반 자동 채점이다. "명령은 맞게 쳤는데 pod가 Pending"이면 0점 — 반드시 **최종 상태(Running, 파일 존재, 포트 닫힘)**까지 확인하는 습관으로 채점하라.

## 실전 운영 가이드

2시간 타이머로 실전처럼 치는 법:

1. **환경 준비(연습용)**: killer.sh 세션 또는 kubeadm 멀티 노드 실습 환경(v1.35)을 준비하고, 위 문제의 사전 리소스(네임스페이스, deployment 등)는 문제 본문 그대로 미리 만들어 둔다.
2. **타이머 120분 고정**. 멈추지 말고, 해설은 절대 열지 않는다.
3. **1패스(90분)**: Task 1부터 순서대로. 한 문제 **8분** 넘으면 메모하고 다음으로. apiserver를 건드리는 문제(T2/T10/T14/T16)는 수정 전 manifest를 `cp`로 백업.
4. **2패스(25분)**: 건너뛴 문제 + 파일 답안(`/opt/course/N/`) 존재 여부 일괄 확인: `ls -R /opt/course/`.
5. **마지막 5분**: 모든 클러스터에서 `kubectl get nodes`, `kubectl get pods -A | grep -v Running` — 깨뜨린 것이 없는지 최종 점검.
6. 채점 후 **틀린 문제는 다음 날 빈 환경에서 다시** 푼다. 해설 보고 이해한 것과 손으로 재현하는 것은 다르다.

> **💡 시험 팁**: 이 세트에서 100분 안에 80% 이상이면 실전 합격권. 67~80%라면 아래 매핑 표에서 취약 도메인 개념서를 복습하고 1주 뒤 재응시하라.

## 취약 도메인 복습 매핑

| 틀린 Task | 취약 도메인 | 복습할 개념서 | 중점 복습 키워드 |
|---|---|---|---|
| T1, T2, T3 | Cluster Setup | `01-cluster-setup.md` | NetworkPolicy AND/OR, kube-bench Remediation, Ingress TLS |
| T4, T5, T6 | Cluster Hardening | `02-cluster-hardening.md` | RBAC(Role-Based Access Control — 역할 기반 접근 제어) 위험 verb, automountServiceAccountToken, kubeadm 업그레이드 |
| T7, T8 | System Hardening | `03-system-hardening.md` | appArmorProfile 필드, apparmor_parser, ss/systemctl |
| T9, T10, T11 | Minimize Microservice Vulnerabilities | `04-minimize-microservice-vulnerabilities.md` | PSA 라벨, EncryptionConfiguration provider 순서, RuntimeClass |
| T12, T13, T14 | Supply Chain Security | `05-supply-chain-security.md` | trivy, Dockerfile 하드닝, ImagePolicyWebhook defaultAllow |
| T15, T16 | Monitoring/Logging/Runtime Security | `06-monitoring-logging-runtime-security.md` | falco_rules.local.yaml, Audit Policy 룰 순서 |

## 🎯 시험 직전 체크리스트

- [ ] 모든 문제에서 첫 줄 `kubectl config use-context`를 **복사-실행**했다
- [ ] ssh 후 작업이 끝나면 **exit**로 main terminal에 돌아왔다
- [ ] 파일 답안을 `/opt/course/N/` 정확한 경로·파일명으로 저장했다 (`ls -R /opt/course/`로 확인)
- [ ] static pod manifest 수정 전 **백업**을 떴고, 수정 후 `watch crictl ps`로 재기동을 확인했다
- [ ] apiserver가 안 뜰 때 디버깅 3종 세트를 안다: `crictl ps -a` / `journalctl -u kubelet` / `/var/log/pods/`
- [ ] NetworkPolicy에서 namespaceSelector+podSelector의 **AND(dash 1개) vs OR(dash 2개)** 를 구분한다
- [ ] egress 정책에는 **DNS(53 UDP/TCP)** 허용을 잊지 않는다
- [ ] restricted PSA 통과 4종 세트를 외운다: runAsNonRoot / allowPrivilegeEscalation:false / drop ALL / seccompProfile RuntimeDefault
- [ ] EncryptionConfiguration은 **첫 provider가 쓰기(암호화)** 담당, hostPath 마운트 필수
- [ ] Audit Policy는 **첫 매칭 룰 적용** — None catch-all은 마지막에
- [ ] kubelet 수정 후 `systemctl restart kubelet`, 노드 업그레이드는 drain → upgrade → uncordon
- [ ] Falco 커스텀 룰은 `/etc/falco/falco_rules.local.yaml`, 수집은 `falco -M 30` 또는 `timeout 30s falco`

## 핵심 명령어 치트시트

```bash
# ---- 컨텍스트 / 노드 ----
kubectl config use-context k8s-c1
ssh master1; sudo -i        # 작업 후 exit; exit

# ---- static pod 수정 루틴 ----
cp /etc/kubernetes/manifests/kube-apiserver.yaml /root/kube-apiserver.yaml.bak
vim /etc/kubernetes/manifests/kube-apiserver.yaml
watch crictl ps                          # 재기동 대기 (30초~1분)
journalctl -u kubelet -f                 # 안 뜰 때
ls /var/log/pods/ | grep apiserver       # 컨테이너 로그 위치

# ---- kubelet 하드닝 ----
vim /var/lib/kubelet/config.yaml         # anonymous:false, webhook:true, mode:Webhook, readOnlyPort:0
systemctl restart kubelet

# ---- RBAC ----
kubectl -n NS create role R --verb=get,list --resource=pods
kubectl -n NS create rolebinding RB --role=R --serviceaccount=NS:SA
kubectl auth can-i --list --as=system:serviceaccount:NS:SA -n NS

# ---- 암호화 / etcd ----
head -c 32 /dev/urandom | base64
kubectl get secrets -A -o json | kubectl replace -f -
ETCDCTL_API=3 etcdctl --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/NS/NAME

# ---- AppArmor / seccomp / gVisor ----
apparmor_parser -q /path/profile && aa-status | grep NAME
# pod: securityContext.appArmorProfile: {type: Localhost, localhostProfile: NAME}
# pod: securityContext.seccompProfile: {type: RuntimeDefault}
kubectl exec POD -- dmesg | head -2      # gVisor 확인

# ---- Supply chain ----
trivy image --severity CRITICAL,HIGH IMAGE
trivy image --format spdx-json --output sbom.json IMAGE
bom generate --image IMAGE --output sbom.spdx
kubesec scan pod.yaml

# ---- Falco / Audit ----
vim /etc/falco/falco_rules.local.yaml && falco -M 30
tail -f /etc/kubernetes/audit/logs/audit.log | jq .level

# ---- 침해 조사 ----
crictl ps; crictl inspect CID; crictl logs CID
ss -tlnp | grep PORT; ls -l /proc/PID/exe
```
