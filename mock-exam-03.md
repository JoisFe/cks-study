# CKS 모의고사 3회 — 고난도 종합 리허설 세트

실제 CKS 시험(2시간 / 16 tasks / 합격선 67%)보다 **살짝 어렵게** 설계한 최종 리허설 — 1·2회에서 다루지 않은 시나리오(바이너리 무결성, key 로테이션, NodeRestriction 실증, Cilium WireGuard, cosign, 침해 포렌식)에 집중한다. 타이머 2시간을 켜고 풀고, 해설은 채점할 때만 열어라.

> **📌 이 모의고사의 설계**: 배점 합계 100%. 도메인 가중치를 실제 시험(15/15/10/20/20/20)에 최대한 가깝게 배분했다 — Cluster Setup 16%(T1~T3), Cluster Hardening 13%(T4~T5), System Hardening 12%(T6~T7), Minimize Microservice Vulnerabilities 20%(T8~T10), Supply Chain Security 19%(T11~T13), Monitoring/Logging/Runtime Security 20%(T14~T16). 시험 환경 기준: **Kubernetes v1.35, containerd, Ubuntu 노드, PSI Secure Browser**. 이 세트는 순서 의존성(T9 key 로테이션)과 서술형 제출(T10) 등 실전보다 까다로운 함정을 일부러 심어 두었다.

## 목차

- [Exam Instructions](#exam-instructions)
- [Clusters & Contexts](#clusters--contexts)
- [Task 1 - Kubelet Binary Integrity (4%)](#task-1---kubelet-binary-integrity-4)
- [Task 2 - Advanced NetworkPolicy AND/OR Egress (8%)](#task-2---advanced-networkpolicy-andor-egress-8)
- [Task 3 - NodePort Exposure Cleanup (4%)](#task-3---nodeport-exposure-cleanup-4)
- [Task 4 - NodeRestriction Admission (6%)](#task-4---noderestriction-admission-6)
- [Task 5 - API Server Anonymous Lockdown (7%)](#task-5---api-server-anonymous-lockdown-7)
- [Task 6 - Kernel Module Blacklist (5%)](#task-6---kernel-module-blacklist-5)
- [Task 7 - AppArmor + seccomp Combined (7%)](#task-7---apparmor--seccomp-combined-7)
- [Task 8 - PSA Labels + Exemptions (7%)](#task-8---psa-labels--exemptions-7)
- [Task 9 - Encryption Key Rotation (7%)](#task-9---encryption-key-rotation-7)
- [Task 10 - Cilium WireGuard Encryption (6%)](#task-10---cilium-wireguard-encryption-6)
- [Task 11 - cosign Image Signature Verify (7%)](#task-11---cosign-image-signature-verify-7)
- [Task 12 - KubeLinter + Dockerfile Hardening (7%)](#task-12---kubelinter--dockerfile-hardening-7)
- [Task 13 - Private Registry + trivy Compare (5%)](#task-13---private-registry--trivy-compare-5)
- [Task 14 - Falco Sensitive File Rule (7%)](#task-14---falco-sensitive-file-rule-7)
- [Task 15 - Compromise Investigation & Isolation (7%)](#task-15---compromise-investigation--isolation-7)
- [Task 16 - Container Immutability (6%)](#task-16---container-immutability-6)
- [채점표](#채점표)
- [취약 도메인 복습 매핑](#취약-도메인-복습-매핑)
- [🎯 시험 직전 체크리스트](#-시험-직전-체크리스트)
- [핵심 명령어 치트시트](#핵심-명령어-치트시트)

---

## Exam Instructions

Read the following instructions carefully before you begin.

- You have **2 hours** to complete **16 tasks**. The passing score is **67%**. Partial scoring is applied per sub-task.
- Every task starts with a `kubectl config use-context <name>` command. **Run it first** — working on the wrong cluster scores zero.
- Some tasks require a node connection, e.g. `ssh worker1`. Nodes are reachable only from the main terminal. **Type `exit` to return** before the next `use-context`. Nested SSH is not supported.
- When a task asks you to save an answer, save it **exactly** at the given path under `/opt/course/<task-number>/` on the **main terminal**, unless stated otherwise.
- You have root via `sudo -i` on all nodes.
- Allowed documentation only: `kubernetes.io/docs`, `kubernetes.io/blog`, `falco.org/docs`, `kubernetes-sigs.github.io/bom/cli-reference/`, `etcd.io/docs`, `kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/`, `docs.cilium.io/en/stable`, `istio.io/latest/docs`.

## Clusters & Contexts

You have access to the following clusters/contexts:

| Context | Purpose | Control Plane | Worker | Version |
|---|---|---|---|---|
| `k8s-p1` | Main cluster (most tasks) | `master1` | `worker1` | v1.35 |
| `k8s-p2` | Cilium CNI + WireGuard cluster (T10) | `cluster2-master1` | `cluster2-worker1` | v1.35 |
| `k8s-p3` | Reserved / spare cluster (not used in this set) | `cluster3-master1` | `cluster3-worker1` | v1.35 |

> **💡 시험 팁**: 안 쓰이는 클러스터(`k8s-p3`)를 일부러 넣어 두었다. 실제 시험도 그렇다. 컨텍스트 전환 명령을 **매 문제 복사-실행**하는 습관만 있으면 헷갈리지 않는다. 노드에서 작업을 마치면 반드시 `exit`으로 메인 터미널에 복귀하라.

---

## Task 1 - Kubelet Binary Integrity (4%)

> `kubectl config use-context k8s-p1`

A security audit suspects the `kubelet` binary on `worker1` may have been tampered with. The expected upstream `sha512` checksum for the installed kubelet version has been fetched from the official release and placed on the main terminal at `/opt/course/1/kubelet.sha512` (it contains only the hash).

1. On `worker1` (`ssh worker1`), locate the running `kubelet` binary and compute its `sha512` checksum.
2. Compare it against the expected checksum.
3. On the **main terminal**, write your verdict to `/opt/course/1/result.txt`: the single word `unmodified` if the checksums match, or `modified` if they differ.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

바이너리 무결성 검증은 "설치된 바이너리의 해시"와 "공식 릴리스 해시"를 비교하는 단순 작업이다. 핵심은 (1) 실제로 실행 중인 바이너리 경로를 정확히 찾는 것, (2) `sha512sum`으로 계산해 문자열을 정확히 대조하는 것이다. 경로는 배포판마다 `/usr/bin/kubelet` 또는 `/usr/local/bin/kubelet`일 수 있으니 추측하지 말고 확인한다.

**2) 단계별 풀이**

```bash
ssh worker1
sudo -i
# 실행 중인 kubelet의 실제 바이너리 경로 확인 (추측 금지)
systemctl status kubelet | grep -i cgroup -A1
which kubelet
readlink -f "$(which kubelet)"       # 심볼릭 링크면 실제 파일로 해석

# 체크섬 계산 (경로는 위에서 확인한 값 사용)
sha512sum /usr/bin/kubelet
exit
exit
```

메인 터미널로 돌아와 두 해시를 비교한다. `worker1`에서 계산한 값을 파일로 받아 두면 `diff`로 자동 비교할 수 있다.

```bash
# worker1에서 계산한 값을 파일로 받기
ssh worker1 "sudo sha512sum /usr/bin/kubelet | awk '{print \$1}'" > /opt/course/1/actual.sha512

# 공백/개행 차이를 무시하고 해시 문자열만 비교
EXPECTED=$(tr -d '[:space:]' < /opt/course/1/kubelet.sha512)
ACTUAL=$(tr -d '[:space:]' < /opt/course/1/actual.sha512)

if [ "$EXPECTED" = "$ACTUAL" ]; then
  echo unmodified > /opt/course/1/result.txt
else
  echo modified > /opt/course/1/result.txt
fi
cat /opt/course/1/result.txt
```

**3) 검증 방법**

```bash
# 두 해시를 눈으로 나란히 확인
echo "expected: $EXPECTED"
echo "actual  : $ACTUAL"
cat /opt/course/1/result.txt        # unmodified 또는 modified 한 단어만
```

**4) ⚠️ 함정 포인트**

- 바이너리 경로를 `/usr/bin/kubelet`으로 **가정**하지 마라. `which kubelet` / `readlink -f`로 실제 경로를 확인해야 한다. snap 설치나 `/usr/local/bin` 배치도 있다.
- `sha512sum` 출력은 `<hash>  <path>` 형태다. 파일 경로 부분까지 비교하면 항상 불일치가 되므로 `awk '{print $1}'`로 **해시만** 추출한다.
- 제공된 `kubelet.sha512`에 개행이나 공백이 섞여 있을 수 있어 `tr -d '[:space:]'`로 정규화 후 비교하는 것이 안전하다.
- 결과 파일에는 요구된 **한 단어만** 넣는다. 설명 문장을 덧붙이면 자동 채점에서 감점될 수 있다.
- `md5sum`/`sha256sum`이 아니라 문제에서 요구한 **`sha512`**를 써야 한다.

**예상 소요시간**: 4분 / **부분점수 포인트**: 올바른 바이너리 경로에서 sha512 계산(절반), result.txt에 정확한 단어 기록(절반).

</details>

---

## Task 2 - Advanced NetworkPolicy AND/OR Egress (8%)

> `kubectl config use-context k8s-p1`

Namespace `shop` runs a checkout service with Pods labelled `app=checkout`. You must lock down its **egress** precisely. Create a single NetworkPolicy named `checkout-egress` in namespace `shop` selecting Pods `app=checkout` and allowing **only** the following egress, denying everything else:

1. To Pods labelled `app=payments` that live in a namespace labelled `env=prod` — **both conditions must hold together** — on TCP port `8443`.
2. To **any** Pod in the namespace labelled `kubernetes.io/metadata.name=logging`, **or** to **any** Pod labelled `app=cache` in **any** namespace — these two are independent alternatives.
3. DNS resolution to any destination on UDP and TCP port `53`.

Namespace `finance` carries the label `env=prod` and runs the `app=payments` Pods. Assume all namespace labels already exist.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

이 문제의 전부는 **AND vs OR의 YAML 표현 차이**다.

- 하나의 `to:` 항목 **안에** `namespaceSelector`와 `podSelector`를 나란히 두면 **AND**(그 네임스페이스 안의, 그 라벨을 가진 pod).
- `to:` 아래에 `-`로 항목을 **분리**하면 각 항목은 **OR**로 합쳐진다.

요구사항 1은 AND(한 항목), 요구사항 2는 OR(두 항목), 요구사항 3은 DNS 별도 항목이다. `policyTypes: [Egress]`를 반드시 명시한다.

**2) 단계별 풀이**

```bash
mkdir -p /opt/course/2
vim /opt/course/2/checkout-egress.yaml
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: checkout-egress
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: checkout
  policyTypes:
    - Egress
  egress:
    # (1) AND: env=prod 네임스페이스 AND app=payments pod, 8443 — 한 항목 안에 둘 다
    - to:
        - namespaceSelector:
            matchLabels:
              env: prod
          podSelector:
            matchLabels:
              app: payments
      ports:
        - protocol: TCP
          port: 8443
    # (2) OR: logging 네임스페이스 전체
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: logging
    # (2) OR: 어느 네임스페이스든 app=cache pod (별개 항목이므로 위와 OR)
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              app: cache
    # (3) DNS
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

```bash
kubectl apply -f /opt/course/2/checkout-egress.yaml
```

**3) 검증 방법**

```bash
kubectl -n shop describe netpol checkout-egress
POD=$(kubectl -n shop get pod -l app=checkout -o jsonpath='{.items[0].metadata.name}')

# 허용되어야 하는 것
kubectl -n shop exec $POD -- nslookup kubernetes.default          # DNS OK
kubectl -n shop exec $POD -- timeout 3 nc -zv payments.finance 8443

# 차단되어야 하는 것 (예: 임의 외부 or 허용 안 된 pod → timeout)
kubectl -n shop exec $POD -- timeout 3 nc -zv <other-pod-ip> 80   # 실패해야 정상
```

**4) ⚠️ 함정 포인트**

- **최다 빈출 함정**: 요구사항 1에서 `namespaceSelector`와 `podSelector`를 `-`로 분리하면 "env=prod 네임스페이스의 모든 pod OR 임의 네임스페이스의 payments pod"가 되어 의미가 완전히 달라진다. **AND는 반드시 한 `-` 항목 안**에.
- 요구사항 2에서 "어느 네임스페이스든 app=cache"를 표현하려면 `namespaceSelector: {}`(모든 네임스페이스) + `podSelector`(app=cache)를 한 항목에 둔다. `namespaceSelector`를 생략하면 **정책이 있는 네임스페이스(shop)로 한정**되므로 "어느 네임스페이스든"이 안 된다.
- **DNS(53)를 빼먹으면** payments/cache의 Service DNS 이름 해석이 안 되어 기능 검증에서 통째로 실패한다. Egress를 잠글 때 DNS는 거의 항상 필요하다.
- `policyTypes: [Egress]` 누락 시 egress 규칙이 시행되지 않는다.
- 단일 NetworkPolicy로 만들라고 했으므로 여러 개로 쪼개지 말 것.

**예상 소요시간**: 9분 / **부분점수 포인트**: AND 항목(8443) / logging OR 항목 / cache OR 항목 / DNS 각각 별도 채점. AND/OR 하나만 틀려도 나머지는 부분점수 확보 가능.

</details>

---

## Task 3 - NodePort Exposure Cleanup (4%)

> `kubectl config use-context k8s-p1`

Namespace `web` exposes a Service named `web-frontend` of type `NodePort`, which unnecessarily opens a port on every node. Internal clients reach it via the ClusterIP DNS name only.

1. Change the Service `web-frontend` type to `ClusterIP` without changing its selector or ports.
2. Confirm on `worker1` that the previously allocated node port is no longer listening.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

NodePort는 모든 노드에 포트를 열어 공격 표면을 넓힌다. 내부 전용이면 ClusterIP로 충분하다. `type`만 바꾸면 되며, `edit` 시 `nodePort` 필드는 자동으로 제거되도록 함께 지운다. 바꾸기 전에 어떤 노드 포트가 열려 있었는지 기록해 두면 검증이 쉽다.

**2) 단계별 풀이**

```bash
# 바꾸기 전 할당된 nodePort 값 확인 (검증용으로 기억)
kubectl -n web get svc web-frontend -o wide
NODEPORT=$(kubectl -n web get svc web-frontend -o jsonpath='{.spec.ports[0].nodePort}')
echo "was NodePort: $NODEPORT"

# 방법 A: patch (가장 빠름) — type만 바꾸면 nodePort는 API가 정리
kubectl -n web patch svc web-frontend -p '{"spec":{"type":"ClusterIP"}}'

# 방법 B: edit로 직접 spec.type: ClusterIP 로 변경하고 각 port의 nodePort 라인 삭제
# kubectl -n web edit svc web-frontend
```

`type`이 `ClusterIP`로, `nodePort` 필드가 사라졌는지 확인한다.

```bash
kubectl -n web get svc web-frontend
# TYPE 열이 ClusterIP, PORT(S)에 :3xxxx/TCP 노드포트 표기가 사라져야 한다
```

**3) 검증 방법**

```bash
# worker1에서 예전 nodePort가 더 이상 리슨하지 않는지 확인
ssh worker1 "sudo ss -tlnp | grep :$NODEPORT || echo CLOSED"   # CLOSED 여야 함
exit
```

**4) ⚠️ 함정 포인트**

- `patch`로 `type`만 바꾸면 API 서버가 `nodePort` 필드를 자동 정리한다. 하지만 `edit`로 수정할 때는 각 포트의 `nodePort:` 라인을 **직접 지워야** 저장이 된다(안 지우면 검증 에러가 날 수 있다).
- `selector`나 `ports.port`/`targetPort`를 건드리면 안 된다 — `type`만 변경.
- 노드 포트 리스너 확인은 `kube-proxy`가 규칙을 갱신하는 데 몇 초 걸릴 수 있으니 즉시 안 닫혀 있으면 잠깐 후 재확인한다.
- `ss`에서 `grep :$NODEPORT`가 다른 포트에 우연히 매칭될 수 있으니 `:$NODEPORT `처럼 정확히 확인하거나 값이 특이한지 본다.
- kube-proxy가 iptables 모드면 NodePort가 애초에 리슨 소켓으로 안 보일 수 있다(iptables DNAT로 처리). 이 경우 변경 전후를 `curl <노드IP>:$NODEPORT`의 연결 성공/실패로 비교하는 것이 확실하다.

**예상 소요시간**: 4분 / **부분점수 포인트**: type을 ClusterIP로 변경(주요), 노드 포트 미리슨 검증.

</details>

---

## Task 4 - NodeRestriction Admission (6%)

> `kubectl config use-context k8s-p1`

Harden the API server on `master1` and prove the effect of the `NodeRestriction` admission plugin.

1. On `master1` (`ssh master1`), ensure the kube-apiserver enables the `NodeRestriction` admission plugin (in addition to any already enabled).
2. From `worker1`, using **the kubelet's own client credentials** (`/etc/kubernetes/kubelet.conf`), attempt to add a label to a **different** node (`master1`). This must be rejected.
3. Save the exact command output proving the rejection to `/opt/course/4/denied.txt` on the main terminal.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`NodeRestriction`은 Node authorizer와 함께 동작해, `system:node:<nodeName>` 신원으로 인증된 kubelet이 **자기 노드 객체만** 수정하도록 제한한다. 다른 노드의 라벨을 바꾸려 하면 admission 단계에서 거부된다. apiserver 플래그 `--enable-admission-plugins`에 `NodeRestriction`을 추가한 뒤, worker1의 kubelet kubeconfig로 master1 라벨 변경을 시도해 거부를 증명한다.

**2) 단계별 풀이**

```bash
ssh master1
sudo -i
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

`--enable-admission-plugins` 라인에 `NodeRestriction` 추가(기존 값 보존, 콤마로 이어붙임):

```yaml
    - --enable-admission-plugins=NodeRestriction
```

이미 다른 플러그인이 있으면 예: `--enable-admission-plugins=NodeRestriction,...`. 저장 후 apiserver 재생성 대기.

```bash
crictl ps | grep kube-apiserver     # 다시 Running 될 때까지 (30초~1분)
kubectl get nodes                   # API 응답 확인
exit
exit
```

이제 worker1에서 kubelet 자격증명으로 다른 노드 라벨 수정을 시도한다.

```bash
ssh worker1
sudo -i
# kubelet의 client cert kubeconfig를 사용 → 신원은 system:node:worker1
kubectl --kubeconfig /etc/kubernetes/kubelet.conf \
  label node master1 cks-test=denied 2>&1 | tee /tmp/denied.txt
# 예상: Error from server (Forbidden): nodes "master1" is forbidden:
#       node "worker1" is not allowed to modify node "master1"
exit
exit
```

메인 터미널에서 출력을 저장한다.

```bash
mkdir -p /opt/course/4
ssh worker1 "sudo kubectl --kubeconfig /etc/kubernetes/kubelet.conf label node master1 cks-test=denied" \
  > /opt/course/4/denied.txt 2>&1
cat /opt/course/4/denied.txt
```

**3) 검증 방법**

```bash
# apiserver에 플러그인이 켜졌는지
ssh master1 "sudo grep enable-admission-plugins /etc/kubernetes/manifests/kube-apiserver.yaml"
# 거부 메시지에 'forbidden' 과 'not allowed to modify node' 포함되어야 함
grep -i forbidden /opt/course/4/denied.txt
```

**4) ⚠️ 함정 포인트**

- `--enable-admission-plugins` 기존 값을 **덮어쓰지 마라**. 콤마로 이어붙여 `NodeRestriction`만 추가한다(기존 플러그인 제거 시 클러스터가 망가질 수 있다).
- 거부를 증명하려면 반드시 **kubelet의 자격증명**(`/etc/kubernetes/kubelet.conf`)으로 요청해야 한다. root의 admin.conf로 시도하면 당연히 허용되어 증명이 안 된다.
- 자기 노드(worker1) 라벨은 허용된다. **다른 노드(master1)** 라벨 수정을 시도해야 거부가 나온다.
- NodeRestriction은 Node authorizer(`--authorization-mode`에 `Node` 포함)와 함께여야 완전히 작동한다. 기본 kubeadm 클러스터는 `Node,RBAC`이므로 보통 이미 충족된다.

**예상 소요시간**: 8분 / **부분점수 포인트**: 플러그인 활성화(주요), 거부 출력 저장. 활성화만 해도 대부분 확보.

</details>

---

## Task 5 - API Server Anonymous Lockdown (7%)

> `kubectl config use-context k8s-p1`

On `master1`, tighten the API server's exposure.

1. Disable anonymous authentication on the kube-apiserver (`--anonymous-auth=false`).
2. Prove with `curl` from `master1` that an anonymous request to the API is now rejected. Save the HTTP response line to `/opt/course/5/anon.txt` on the main terminal.
3. A stale certificate user named `dev-legacy` exists in the admin kubeconfig `/root/.kube/config` on `master1`. Remove its user entry and any context referencing it.
4. Confirm the API server listens on port `6443` only (no additional plaintext/insecure listener).

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`--anonymous-auth=false`로 익명 요청을 막고, `curl -k`로 401이 나오는지 실증한다. 그다음 오래된 인증서 사용자를 kubeconfig에서 `kubectl config`로 정리하고, `ss`로 apiserver가 6443만 리슨하는지 확인한다.

**2) 단계별 풀이**

```bash
ssh master1
sudo -i
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

command에 추가/수정:

```yaml
    - --anonymous-auth=false
```

```bash
crictl ps | grep kube-apiserver      # 재생성 대기 (30초~1분)

# 익명 요청 검증: 인증정보 없이 접근 → 401
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:6443/api   # 401 기대
curl -sk https://localhost:6443/api | head             # Unauthorized 메시지

# 6443만 리슨하는지
ss -tlnp | grep kube-apiserver
exit
exit
```

메인 터미널에서 응답을 저장한다.

```bash
mkdir -p /opt/course/5
ssh master1 "curl -sk -i https://localhost:6443/api 2>/dev/null | head -1" > /opt/course/5/anon.txt
cat /opt/course/5/anon.txt      # HTTP/2 401 (curl이 HTTP/1.1로 협상하면 HTTP/1.1 401 Unauthorized)
```

오래된 인증서 사용자 정리(`master1`의 admin kubeconfig 대상):

```bash
ssh master1
sudo -i
export KUBECONFIG=/root/.kube/config
kubectl config view -o jsonpath='{.users[*].name}'; echo   # dev-legacy 존재 확인

# 사용자와 참조 컨텍스트 제거
kubectl config delete-user dev-legacy
kubectl config get-contexts                                # dev-legacy 쓰는 context 찾기
kubectl config delete-context <해당-context>               # 있으면 제거
kubectl config view | grep -i dev-legacy || echo GONE
exit
exit
```

**3) 검증 방법**

```bash
ssh master1 "sudo grep anonymous-auth /etc/kubernetes/manifests/kube-apiserver.yaml"   # false
cat /opt/course/5/anon.txt                                # 401 응답 라인
ssh master1 "sudo ss -tlnp | grep apiserver"              # :6443 만
```

**4) ⚠️ 함정 포인트**

- `--anonymous-auth=false` 후 kubelet/헬스체크가 다른 경로로 인증되는지 확인. 정상 kubeadm 클러스터는 서비스어카운트/인증서로 인증하므로 영향 없다. apiserver가 안 뜨면 `crictl ps -a`, `/var/log/pods/`로 디버깅.
- curl 검증은 `-k`(자체 서명 인증서 무시)와 `-i`(헤더 표시)를 함께. 상태코드만 필요하면 `-w "%{http_code}"`.
- kubeconfig 정리는 `kubectl config delete-user` / `delete-context`를 쓴다. YAML을 손으로 지우다 들여쓰기를 깨면 kubeconfig 전체가 무효가 된다.
- 사용자만 지우고 그 사용자를 참조하는 **context가 남으면** 감점될 수 있다. 사용자 + 관련 context 모두 제거.
- 최신 K8s에는 insecure port(8080) 자체가 제거되어 없다. `ss`로 6443 외 다른 리슨이 없음을 확인하는 것으로 충분하다.

**예상 소요시간**: 9분 / **부분점수 포인트**: anonymous-auth 플래그 / curl 401 저장 / stale user 제거 / 6443 확인 각각 채점.

</details>

---

## Task 6 - Kernel Module Blacklist (5%)

> `kubectl config use-context k8s-p1`

The security baseline forbids the rarely-used network protocols SCTP and DCCP. On `worker1`:

1. Blacklist the kernel modules `sctp` and `dccp` so they cannot be loaded, and make the block persistent across reboots.
2. If either module is currently loaded, unload it.
3. Verify that attempting to load them does not actually insert the module.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`/etc/modprobe.d/`에 blacklist 파일을 만들어 영구 차단한다. `blacklist <mod>`는 부팅 시 자동 로드를 막고, `install <mod> /bin/false`는 명시적 `modprobe`까지 무력화한다(더 강력). 이미 로드돼 있으면 `modprobe -r`로 내린다.

**2) 단계별 풀이**

```bash
ssh worker1
sudo -i

# 현재 로드 여부
lsmod | grep -E "sctp|dccp"

# 영구 blacklist 파일 작성
cat > /etc/modprobe.d/blacklist-cks.conf << 'EOF'
blacklist sctp
blacklist dccp
install sctp /bin/false
install dccp /bin/false
EOF

# 이미 로드되어 있으면 언로드
modprobe -r sctp 2>/dev/null || true
modprobe -r dccp 2>/dev/null || true
```

**3) 검증 방법**

```bash
# modprobe이 실제로 로드하지 않는지 (install /bin/false 효과)
modprobe -n -v sctp        # "install /bin/false" 표시 → 로드 안 함
modprobe sctp; echo $?     # 삽입 시도해도 lsmod에 안 떠야 함
lsmod | grep -E "sctp|dccp" || echo "NOT LOADED"

# 설정 파일 확인
cat /etc/modprobe.d/blacklist-cks.conf
exit
exit
```

**4) ⚠️ 함정 포인트**

- `blacklist`만 넣으면 **부팅 자동 로드**는 막지만 사용자가 `modprobe sctp`를 직접 하면 로드된다. 완전 차단하려면 `install <mod> /bin/false`를 함께 넣는다 — 고난도 세트에서 요구하는 포인트.
- 파일은 `/etc/modprobe.d/` 아래에 있어야 하고 확장자는 `.conf`여야 인식된다.
- 이미 로드된 모듈은 blacklist만으로 안 내려간다. `modprobe -r`(또는 `rmmod`)로 언로드해야 한다. 사용 중이면 내려가지 않을 수 있으니 `lsmod`로 refcount 확인.
- `modprobe -n -v`는 실제 로드 없이 무엇을 할지 보여주는 dry-run — 검증에 유용하다.

**예상 소요시간**: 5분 / **부분점수 포인트**: blacklist 설정 영구화 / 언로드 / 로드 방지 검증 각각 채점.

</details>

---

## Task 7 - AppArmor + seccomp Combined (7%)

> `kubectl config use-context k8s-p1`

Deployment `secure-web` in namespace `apps` runs a single container `web`. Apply **both** an AppArmor profile and a seccomp profile to it, using node-local (`Localhost`) profiles.

Profile sources are provided on the main terminal:

- AppArmor profile file: `/opt/course/7/k8s-web-profile` (profile name inside: `k8s-web-profile`).
- seccomp profile file: `/opt/course/7/audit.json`.

1. On `worker1`, load the AppArmor profile into enforce mode and place the seccomp profile in the kubelet seccomp directory as `profiles/audit.json`.
2. Update the Deployment so the `web` container uses AppArmor profile `k8s-web-profile` (type `Localhost`) **and** seccomp profile `profiles/audit.json` (type `Localhost`).
3. Ensure the Pod runs successfully with both profiles active.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

v1.30+ GA 문법을 쓴다. AppArmor/seccomp 모두 `securityContext.appArmorProfile` / `securityContext.seccompProfile`의 `type: Localhost`로 지정하며, Localhost일 때는 노드에 프로파일이 **먼저 존재**해야 한다. AppArmor는 `/etc/apparmor.d/`에 로드, seccomp는 `/var/lib/kubelet/seccomp/` 기준 상대경로다.

**2) 단계별 풀이 — 노드에 프로파일 배치**

```bash
# 프로파일 파일을 worker1로 복사 (환경에 따라 이미 노드에 있을 수 있음)
scp /opt/course/7/k8s-web-profile worker1:/tmp/k8s-web-profile
scp /opt/course/7/audit.json worker1:/tmp/audit.json

ssh worker1
sudo -i
# AppArmor 프로파일 배치 + enforce 로드
cp /tmp/k8s-web-profile /etc/apparmor.d/k8s-web-profile
apparmor_parser -q /etc/apparmor.d/k8s-web-profile
aa-status | grep k8s-web-profile        # enforce 목록에 보여야 함

# seccomp 프로파일 배치 (/var/lib/kubelet/seccomp/profiles/audit.json)
mkdir -p /var/lib/kubelet/seccomp/profiles
cp /tmp/audit.json /var/lib/kubelet/seccomp/profiles/audit.json
exit
exit
```

**Deployment 수정** (`securityContext` 두 필드를 컨테이너에 적용):

```bash
kubectl -n apps edit deploy secure-web
```

```yaml
    spec:
      containers:
        - name: web
          # ...
          securityContext:
            appArmorProfile:
              type: Localhost
              localhostProfile: k8s-web-profile
            seccompProfile:
              type: Localhost
              localhostProfile: profiles/audit.json
```

```bash
kubectl -n apps rollout status deploy secure-web
```

**3) 검증 방법**

```bash
POD=$(kubectl -n apps get pod -l app=secure-web -o jsonpath='{.items[0].metadata.name}')
kubectl -n apps get pod $POD -o jsonpath='{.spec.containers[0].securityContext}'; echo

# 노드에서 프로세스가 해당 apparmor 프로파일로 실행 중인지
ssh worker1 "sudo aa-status | grep k8s-web-profile"
```

**4) ⚠️ 함정 포인트**

- **구식 annotation 방식**(`container.apparmor.security.beta.kubernetes.io/web: localhost/...`)은 deprecated다. v1.35에서는 `securityContext.appArmorProfile` **필드**를 써라.
- seccomp `localhostProfile`은 `/var/lib/kubelet/seccomp/` **기준 상대경로**다. 문제의 `profiles/audit.json`은 실제 파일이 `/var/lib/kubelet/seccomp/profiles/audit.json`에 있어야 한다. 절대경로나 앞에 `/`를 붙이면 안 된다.
- AppArmor `localhostProfile`에는 **프로파일 이름**(파일명이 아니라 프로파일 내부 이름)을 쓴다. 노드에 로드되지 않은 이름을 쓰면 Pod가 `Blocked`/`CreateContainerError`로 뜬다.
- 프로파일을 **로드하지 않고** manifest만 고치면 Pod가 기동하지 못한다. 항상 노드 배치/로드 → manifest 순서.
- AppArmor는 pod의 다른 노드로 스케줄되면 그 노드에도 프로파일이 있어야 한다. 단일 워커면 문제없다.

**예상 소요시간**: 10분 / **부분점수 포인트**: AppArmor 노드 로드 / seccomp 파일 배치 / manifest appArmorProfile / manifest seccompProfile / Pod 정상 기동 각각 채점.

</details>

---

## Task 8 - PSA Labels + Exemptions (7%)

> `kubectl config use-context k8s-p1`

Use Pod Security Admission (PSA) to enforce standards on namespace `payments`, while exempting an internal namespace from cluster-wide defaults.

1. Label namespace `payments` so that the `baseline` standard is **enforced**, and the `restricted` standard is **audited and warned** (audit + warn). Pin the enforce level to a fixed version.
2. On `master1`, configure the API server's `PodSecurity` admission plugin via an `AdmissionConfiguration` file so that namespace `kube-system-tools` is added to the `exemptions.namespaces` list (so its Pods are never evaluated by PSA).

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

PSA는 두 갈래다. (a) **네임스페이스 라벨**로 per-namespace 정책, (b) **AdmissionConfiguration**으로 클러스터 기본값/예외(exemptions). 문제 1은 라벨, 문제 2는 apiserver에 `--admission-control-config-file`을 물려 exemptions를 추가한다.

**2) 단계별 풀이 — 네임스페이스 라벨**

```bash
kubectl label ns payments \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/enforce-version=v1.35 \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite

kubectl get ns payments --show-labels
```

**AdmissionConfiguration 구성**(`master1`):

```bash
ssh master1
sudo -i
mkdir -p /etc/kubernetes/pss
vim /etc/kubernetes/pss/admission-config.yaml
```

```yaml
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
        namespaces:
          - kube-system
          - kube-system-tools
```

apiserver에 파일을 물리고 hostPath로 마운트한다.

```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

```yaml
spec:
  containers:
    - command:
        - kube-apiserver
        - --admission-control-config-file=/etc/kubernetes/pss/admission-config.yaml
        # ... 기존 플래그 유지
      volumeMounts:
        - name: pss
          mountPath: /etc/kubernetes/pss
          readOnly: true
  volumes:
    - name: pss
      hostPath:
        path: /etc/kubernetes/pss
        type: DirectoryOrCreate
```

```bash
crictl ps | grep kube-apiserver      # 재생성 대기
kubectl get ns                       # API 정상 확인
exit
exit
```

**3) 검증 방법**

```bash
kubectl get ns payments -o jsonpath='{.metadata.labels}'; echo
# baseline 위반 pod는 payments에서 거부, restricted 위반은 warn 메시지
kubectl -n payments run test --image=nginx --privileged 2>&1 | head   # 거부/경고 확인
ssh master1 "sudo grep admission-control-config-file /etc/kubernetes/manifests/kube-apiserver.yaml"
```

**4) ⚠️ 함정 포인트**

- **최다 함정**: AdmissionConfiguration 파일 경로를 apiserver에 `hostPath volumeMount`로 마운트하지 않으면 컨테이너 안에서 파일을 못 찾아 apiserver가 안 뜬다. 플래그만 추가하고 볼륨 마운트를 빠뜨리는 실수를 조심.
- `enforce-version`을 라벨에 고정(`v1.35`)하면 향후 표준이 엄격해져도 정책이 안 바뀐다 — 문제에서 "fixed version" 요구.
- exemptions에 넣은 네임스페이스는 PSA 평가를 **전혀 받지 않는다**. `kube-system`은 기본 예외에 넣어두는 게 관례.
- AdmissionConfiguration의 `apiVersion`은 `apiserver.config.k8s.io/v1`, 내부 configuration은 `pod-security.admission.config.k8s.io/v1` — 두 그룹을 헷갈리지 말 것.
- 라벨 값 레벨은 `privileged`/`baseline`/`restricted` 세 가지뿐. 모드는 `enforce`/`audit`/`warn`.

**예상 소요시간**: 11분 / **부분점수 포인트**: 라벨 enforce/version/audit/warn / AdmissionConfiguration 작성 / apiserver 마운트 및 기동 각각 채점.

</details>

---

## Task 9 - Encryption Key Rotation (7%)

> `kubectl config use-context k8s-p1`

Secrets on `k8s-p1` are already encrypted at rest with an `aescbc` provider. The current key `key1` is considered old and must be **rotated out**. A new 32-byte key has been generated for you and is available at `/opt/course/9/newkey.b64` on `master1` (base64 of 32 random bytes).

The existing `EncryptionConfiguration` is at `/etc/kubernetes/enc/enc.yaml` on `master1`.

1. Add the new key as `key2` and make it the key used for **writing** new encryptions, while `key1` can still **decrypt** existing data.
2. Re-encrypt all existing Secrets so they are stored with `key2`.
3. Remove `key1` entirely, then re-encrypt again so no data depends on the old key.
4. The API server must stay healthy throughout.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

key 로테이션은 **순서가 전부**다. `aescbc` provider의 `keys` 리스트에서 **첫 번째 key가 암호화(write)에 사용**되고, 나머지 key들은 복호화(read)에만 쓰인다. 따라서:

1. 새 key를 리스트 **맨 앞**에 넣고(→ 새 write는 key2), 옛 key1은 뒤에 남긴다(→ 기존 데이터 read 가능).
2. 모든 Secret을 `replace`로 다시 써서 key2로 재암호화.
3. 그다음에야 key1을 제거하고 다시 재암호화 → 이제 어떤 데이터도 key1에 의존하지 않는다.

각 config 변경 후 apiserver 재시작(정적 파드 자동 재생성)이 필요하다.

**2) 단계별 풀이 — 1단계: 새 key를 첫 번째로**

```bash
ssh master1
sudo -i
NEWKEY=$(cat /opt/course/9/newkey.b64)
cp /etc/kubernetes/enc/enc.yaml /etc/kubernetes/enc/enc.yaml.bak   # 백업
vim /etc/kubernetes/enc/enc.yaml
```

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key2            # 새 key를 맨 앞 → write에 사용
              secret: <NEWKEY 값 붙여넣기>
            - name: key1            # 옛 key는 read용으로 유지
              secret: <기존 key1 값>
      - identity: {}
```

```bash
# enc.yaml은 hostPath로 마운트된 파일이라 수정만으로는 정적 파드가 재시작되지 않는다.
# manifest를 잠시 옮겼다가 되돌려 강제 재생성한다.
mv /etc/kubernetes/manifests/kube-apiserver.yaml /tmp/kube-apiserver.yaml
sleep 20
mv /tmp/kube-apiserver.yaml /etc/kubernetes/manifests/kube-apiserver.yaml

crictl ps | grep kube-apiserver     # 새 컨테이너로 교체 대기 (30초~1분)
kubectl get ns                      # API 정상

# 모든 Secret 재암호화 → 이제 key2로 저장됨
kubectl get secrets -A -o json | kubectl replace -f -
```

**3단계: key1 제거 후 재암호화**

```bash
vim /etc/kubernetes/enc/enc.yaml     # key1 블록 삭제, key2만 남김
```

```yaml
      - aescbc:
          keys:
            - name: key2
              secret: <NEWKEY 값>
      - identity: {}
```

```bash
# 다시 manifest 이동으로 apiserver 강제 재생성
mv /etc/kubernetes/manifests/kube-apiserver.yaml /tmp/kube-apiserver.yaml
sleep 20
mv /tmp/kube-apiserver.yaml /etc/kubernetes/manifests/kube-apiserver.yaml
crictl ps | grep kube-apiserver     # 재생성 대기

kubectl get secrets -A -o json | kubectl replace -f -   # key1 의존 제거 확정
exit
exit
```

**3) 검증 방법**

```bash
# etcd에 저장된 secret이 k8s:enc:aescbc:v1:key2 프리픽스로 시작하는지
ssh master1
sudo -i
ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/<any-secret> | hexdump -C | head
# k8s:enc:aescbc:v1:key2 문자열이 보이면 key2로 암호화됨
exit
exit
```

**4) ⚠️ 함정 포인트**

- **순서 오류가 치명적**이다. key2를 뒤에 넣으면 write는 여전히 key1로 되어 로테이션이 안 된다. **새 key는 반드시 맨 앞**.
- 1단계에서 key1을 **바로 지우면** 기존 데이터를 복호화할 수 없어 Secret 읽기가 깨진다. 반드시 재암호화(`replace`)를 마친 **뒤에** 제거한다.
- `identity: {}`는 provider 리스트에서 aescbc **뒤**에 두어야 한다. 앞에 두면 평문으로 저장된다(암호화 무력화).
- `kubectl get secrets -A -o json | kubectl replace -f -`는 모든 네임스페이스 Secret을 다시 쓰게 해 현재 write key로 재암호화한다. `apply`가 아니라 `replace`.
- key 값은 base64 인코딩된 32바이트여야 한다. 길이가 틀리면 apiserver가 기동에 실패한다.
- **enc.yaml 수정만으로는 apiserver가 재시작되지 않는다**(manifest 파일이 안 바뀌었으므로 kubelet이 감지하지 못함). manifest를 `/tmp`로 옮겼다가 되돌려 강제 재생성하고, 새 컨테이너가 뜬 것을 확인한 뒤 다음 단계로. 안 뜨면 `/var/log/pods/`, `crictl logs`로 디버깅.

**예상 소요시간**: 12분 / **부분점수 포인트**: key2를 첫 번째로 추가 / 1차 재암호화 / key1 제거 / 2차 재암호화 각각 채점. 순서만 지키면 부분점수 확보 쉬움.

</details>

---

## Task 10 - Cilium WireGuard Encryption (6%)

> `kubectl config use-context k8s-p2`

Cluster `k8s-p2` uses Cilium as its CNI. Node-to-node (pod-to-pod) traffic must be transparently encrypted with WireGuard.

1. Check whether WireGuard encryption is currently enabled using `cilium status`.
2. Write the current encryption status and, **if it is not enabled**, the exact Helm values (or config change) needed to enable WireGuard, into `/opt/course/10/wireguard.txt` on the main terminal.
3. In the same file, describe how you would verify that traffic between two nodes is actually encrypted.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

이 문제는 일부 서술형이다. `cilium status`로 현재 암호화 상태를 확인하고, 미적용이면 Cilium을 WireGuard 모드로 켜는 Helm 값을 기록한다. 그리고 노드 간 트래픽이 실제 암호화되는지 검증하는 방법을 서술한다. 허용 문서 `docs.cilium.io/en/stable`에서 "WireGuard" 검색으로 확인 가능하다.

**2) 단계별 풀이 — 상태 확인**

```bash
# Cilium 상태에서 Encryption 라인 확인
kubectl -n kube-system exec ds/cilium -- cilium status | grep -i encryption
# 미적용:  Encryption: Disabled
# 적용됨:  Encryption: Wireguard  [cilium_wg0 (Pubkey: ..., Port: 51871)]

# (cilium CLI가 있으면) 노드별 암호화 상태
kubectl -n kube-system exec ds/cilium -- cilium-dbg encrypt status
```

**답안 파일 작성** (미적용이라고 가정한 예시):

```bash
mkdir -p /opt/course/10
cat > /opt/course/10/wireguard.txt << 'EOF'
[Current status]
cilium status -> Encryption: Disabled

[How to enable WireGuard via Helm]
helm upgrade cilium cilium/cilium --namespace kube-system \
  --reuse-values \
  --set encryption.enabled=true \
  --set encryption.type=wireguard
# Then restart the agent so the change takes effect:
kubectl -n kube-system rollout restart ds/cilium

# (Equivalent ConfigMap keys if not using Helm)
#   enable-wireguard: "true"

[How to verify node-to-node traffic is encrypted]
1) cilium status | grep Encryption   -> should show "Wireguard"
2) On a node: sudo wg show            -> shows cilium_wg0 peers + handshakes + transfer bytes
3) kubectl -n kube-system exec ds/cilium -- cilium-dbg encrypt status
   -> per-node encryption state = enabled
4) tcpdump on the physical NIC between two pods on different nodes:
   payload should be UDP/51871 WireGuard, not plaintext pod traffic.
EOF
cat /opt/course/10/wireguard.txt
```

WireGuard를 실제로 켜야 하는 문제라면 위 `helm upgrade`를 실행한 뒤 `rollout restart ds/cilium`, 그리고 `cilium status`로 `Encryption: Wireguard` 확인.

**3) 검증 방법**

```bash
kubectl -n kube-system exec ds/cilium -- cilium status | grep -i encryption
# 노드에서 WireGuard 인터페이스와 핸드셰이크 확인
ssh cluster2-worker1 "sudo wg show"     # cilium_wg0, latest handshake, transfer
```

**4) ⚠️ 함정 포인트**

- Cilium 암호화 방식은 **WireGuard 또는 IPsec** 두 가지다. 문제에서 WireGuard를 요구하므로 `encryption.type=wireguard`를 명시한다(기본이 IPsec인 배포도 있음).
- Helm 변경 후 `rollout restart ds/cilium` 또는 파드 재시작을 해야 반영된다. 값만 바꾸고 재시작을 빠뜨리면 상태가 안 변한다.
- `--reuse-values`를 빼면 기존 Cilium 설정이 초기화되어 클러스터가 망가질 수 있다. 반드시 기존 값 보존.
- 검증은 단순히 config가 아니라 **런타임 상태**(`cilium status`의 Encryption, 노드의 `wg show` 핸드셰이크)로 확인해야 신뢰할 수 있다.
- 서술형 답안이므로 파일에 "현재 상태 + 활성화 방법 + 검증 방법" 세 가지가 모두 들어가야 만점.

**예상 소요시간**: 8분 / **부분점수 포인트**: 상태 확인 / 활성화 방법 기술 / 검증 방법 기술 각각 채점.

</details>

---

## Task 11 - cosign Image Signature Verify (7%)

> `kubectl config use-context k8s-p1`

Only signed container images may run in namespace `prod`. A cosign public key is provided at `/opt/course/11/cosign.pub` on the main terminal.

1. Two images are candidates: `registry.local:5000/app:signed` and `registry.local:5000/app:unsigned`. Use `cosign verify` with the provided public key to determine which one carries a valid signature.
2. Deployment `frontend` in namespace `prod` currently uses the **unsigned** image. Update it to use the **signed** image tag.
3. Save the successful `cosign verify` output for the signed image to `/opt/course/11/verify.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`cosign verify --key <pub> <image>`로 서명을 검증한다. 서명된 이미지는 검증 성공(payload 출력), 서명 안 된 이미지는 "no matching signatures" 에러가 난다. 서명된 태그를 찾아 Deployment 이미지를 교체하면 된다.

**2) 단계별 풀이**

```bash
mkdir -p /opt/course/11

# 두 이미지 검증
cosign verify --key /opt/course/11/cosign.pub \
  registry.local:5000/app:signed | tee /opt/course/11/verify.txt
# → 검증 성공: "Verification for registry.local:5000/app:signed --" 및 payload JSON 출력

cosign verify --key /opt/course/11/cosign.pub \
  registry.local:5000/app:unsigned
# → 실패: "Error: no matching signatures"
```

서명된 이미지로 Deployment 교체:

```bash
kubectl -n prod set image deploy/frontend \
  $(kubectl -n prod get deploy frontend -o jsonpath='{.spec.template.spec.containers[0].name}')=registry.local:5000/app:signed

# 또는 edit로 image 라인 직접 수정
kubectl -n prod rollout status deploy/frontend
```

**3) 검증 방법**

```bash
kubectl -n prod get deploy frontend -o jsonpath='{.spec.template.spec.containers[*].image}'; echo
# registry.local:5000/app:signed
cat /opt/course/11/verify.txt      # Verification for ... signed
```

**4) ⚠️ 함정 포인트**

- `cosign verify`는 서명이 없으면 **에러 코드로 종료**한다. 성공한 이미지의 출력만 `verify.txt`에 저장해야 한다(실패 출력을 저장하면 오답).
- 사설 레지스트리(`registry.local:5000`)라 TLS/인증 이슈가 있으면 `--allow-insecure-registry` 등의 옵션이 필요할 수 있다. 실제 시험 클러스터는 접근 가능하도록 세팅돼 있다.
- `set image`의 `<container>=<image>` 형식에서 컨테이너 이름을 정확히 써야 한다. 이름을 모르면 `jsonpath`로 먼저 뽑는다.
- 이미지 태그만 바꾸고 rollout이 새 ReplicaSet으로 완료됐는지 `rollout status`로 확인.
- (심화) 클러스터 차원 강제는 admission(예: policy controller)이 필요하지만, 이 문제는 검증+교체까지만 요구.

**예상 소요시간**: 8분 / **부분점수 포인트**: 서명 이미지 식별 / Deployment 교체 / verify.txt 저장 각각 채점.

</details>

---

## Task 12 - KubeLinter + Dockerfile Hardening (7%)

> `kubectl config use-context k8s-p1`

Static analysis must pass before deployment.

1. Run `kube-linter` against the manifests in `/opt/course/12/manifests/` on the main terminal. Fix the following reported issues in the manifest `web-deploy.yaml` in that directory:
   - image uses the `latest` tag → pin to a specific version (`nginx:1.27.3`),
   - no CPU/memory requests and limits set → add them,
   - container may run as root → set `runAsNonRoot: true` and a non-zero `runAsUser`.
2. A `Dockerfile` at `/opt/course/12/Dockerfile` builds in a single stage as root. Rewrite it as a **multi-stage** build producing a minimal, non-root final image. Save it back to the same path.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`kube-linter lint`로 지적사항을 뽑고, 각 항목을 manifest에 반영한다. Dockerfile은 빌드 스테이지와 런타임 스테이지를 분리(멀티스테이지)하고, 베이스 버전 고정 + 비루트 USER + 불필요 캐시 제거를 적용한다.

**2) 단계별 풀이 — kube-linter**

```bash
kube-linter lint /opt/course/12/manifests/
# 또는 특정 파일: kube-linter lint /opt/course/12/manifests/web-deploy.yaml
# 지적: latest-tag, unset-cpu-requirements, unset-memory-requirements, run-as-non-root ...

vim /opt/course/12/manifests/web-deploy.yaml
```

```yaml
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: web
          image: nginx:1.27.3            # latest → 고정 태그
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
```

```bash
# 재검사 → 해당 항목이 사라졌는지
kube-linter lint /opt/course/12/manifests/web-deploy.yaml
```

**멀티스테이지 Dockerfile** (`/opt/course/12/Dockerfile`):

```dockerfile
# --- build stage ---
FROM golang:1.23 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/app ./...

# --- runtime stage (minimal, non-root) ---
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
```

```bash
# (빌드 확인이 가능하면) docker build -t app:hardened /opt/course/12
```

**3) 검증 방법**

```bash
kube-linter lint /opt/course/12/manifests/     # 지적 항목 감소/제거 확인
grep -E "FROM|USER" /opt/course/12/Dockerfile  # 2개 FROM(멀티스테이지) + USER nonroot
```

**4) ⚠️ 함정 포인트**

- `runAsNonRoot: true`만 넣고 이미지의 기본 USER가 root이면 파드가 기동 시 거부된다. `runAsUser`를 0이 아닌 값으로 함께 지정한다.
- resources는 **requests와 limits 둘 다** 요구된다. 하나만 넣으면 kube-linter가 여전히 경고.
- Dockerfile 멀티스테이지의 핵심: 최종 이미지에는 컴파일러/빌드 도구가 없어야 한다. `distroless`/`alpine` 같은 최소 베이스에 산출물만 `COPY --from`.
- 베이스 이미지 태그를 `latest`로 두면 지적이 그대로 남는다. **버전 고정**.
- ENV/ARG에 secret을 넣지 않는다(레이어에 노출). 문제에 그런 라인이 있으면 제거.

**예상 소요시간**: 11분 / **부분점수 포인트**: latest 태그 수정 / resources / runAsNonRoot·runAsUser / 멀티스테이지 Dockerfile 각각 채점.

</details>

---

## Task 13 - Private Registry + trivy Compare (5%)

> `kubectl config use-context k8s-p1`

Namespace `internal` must pull from a private registry, and must run the less vulnerable of two image versions.

1. Create a `docker-registry` Secret named `regcred` in namespace `internal` for registry `registry.local:5000` (username `deployer`, password `S3cr3t!`, email `deployer@corp.local`).
2. Attach `regcred` as an `imagePullSecrets` entry to the ServiceAccount `default` in namespace `internal` (so all Pods using that SA can pull).
3. Scan both `registry.local:5000/api:1.4` and `registry.local:5000/api:1.5` with `trivy` for `CRITICAL,HIGH` vulnerabilities, and update Deployment `api` in namespace `internal` to use the tag with **fewer** such vulnerabilities.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`kubectl create secret docker-registry`로 pull secret을 만들고 SA에 붙인다(SA에 붙이면 그 SA를 쓰는 모든 Pod에 자동 적용). trivy로 두 태그의 CRITICAL/HIGH 개수를 비교해 적은 쪽으로 교체한다.

**2) 단계별 풀이**

```bash
# 1) docker-registry secret
kubectl -n internal create secret docker-registry regcred \
  --docker-server=registry.local:5000 \
  --docker-username=deployer \
  --docker-password='S3cr3t!' \
  --docker-email=deployer@corp.local

# 2) SA default에 imagePullSecrets 추가
kubectl -n internal patch serviceaccount default \
  -p '{"imagePullSecrets":[{"name":"regcred"}]}'
kubectl -n internal get sa default -o yaml | grep -A2 imagePullSecrets

# 3) 두 태그 취약점 비교
trivy image --severity CRITICAL,HIGH registry.local:5000/api:1.4 | tee /tmp/api14.txt
trivy image --severity CRITICAL,HIGH registry.local:5000/api:1.5 | tee /tmp/api15.txt
# Total 개수를 비교. 요약만 빠르게 보려면:
trivy image --severity CRITICAL,HIGH --quiet -f json registry.local:5000/api:1.4 \
  | jq '[.Results[].Vulnerabilities // []] | add | length'
```

취약점이 더 적은 태그(예: 1.5)로 교체:

```bash
kubectl -n internal set image deploy/api \
  $(kubectl -n internal get deploy api -o jsonpath='{.spec.template.spec.containers[0].name}')=registry.local:5000/api:1.5
kubectl -n internal rollout status deploy/api
```

**3) 검증 방법**

```bash
kubectl -n internal get sa default -o jsonpath='{.imagePullSecrets}'; echo
kubectl -n internal get deploy api -o jsonpath='{.spec.template.spec.containers[*].image}'; echo
kubectl -n internal get pods    # ImagePullBackOff 없이 Running
```

**4) ⚠️ 함정 포인트**

- `--docker-server`는 이미지의 레지스트리 호스트와 정확히 일치해야 한다(`registry.local:5000`). 불일치하면 인증이 안 걸려 `ImagePullBackOff`.
- SA에 붙인 `imagePullSecrets`는 **새로 생성되는 Pod**에만 적용된다. 기존 Pod는 재생성(rollout restart)해야 반영.
- Pod의 `spec.imagePullSecrets`와 SA의 `imagePullSecrets`는 둘 다 가능. 문제는 SA에 붙이라고 했으므로 SA 패치.
- trivy 비교 시 **같은 severity 필터**(`CRITICAL,HIGH`)로 두 태그를 재야 공정하다. 개수가 헷갈리면 `-f json | jq`로 정확히 센다.
- password에 특수문자(`!`)가 있어 작은따옴표로 감싼다.

**예상 소요시간**: 8분 / **부분점수 포인트**: secret 생성 / SA 연결 / trivy 비교 후 올바른 태그 교체 각각 채점.

</details>

---

## Task 14 - Falco Sensitive File Rule (7%)

> `kubectl config use-context k8s-p1`

Falco is installed and running on `worker1` (systemd service `falco`). Create a custom rule that detects reads of the sensitive file `/etc/shadow` inside containers.

On `worker1` (`ssh worker1`):

1. Add a custom rule named `Read sensitive shadow file` to `/etc/falco/falco_rules.local.yaml` that triggers when `/etc/shadow` is opened for reading inside a container, at priority `WARNING`. The output must include at least the container name.
2. Restart Falco and let it collect events for **30 seconds** while the existing workloads run.
3. From the events for this rule, extract only the **container names** that triggered it, sort them uniquely, and save the result to `/opt/course/14/containers.txt` on the main terminal.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`/etc/falco/falco_rules.local.yaml`에 커스텀 룰을 작성한다(로컬 룰 파일이 기본 룰을 오버라이드/추가). condition으로 `/etc/shadow` open+read를 잡고, output에 `%container.name`을 포함한다. `falco -M 30`으로 30초 수집 후 로그에서 container.name만 파싱해 `sort -u`.

**2) 단계별 풀이 — 룰 작성**

```bash
ssh worker1
sudo -i
vim /etc/falco/falco_rules.local.yaml
```

```yaml
- rule: Read sensitive shadow file
  desc: Detect any read of /etc/shadow inside a container
  condition: >
    open_read and container and fd.name = /etc/shadow
  output: >
    Sensitive file /etc/shadow opened for reading
    (container=%container.name image=%container.image.repository
     proc=%proc.cmdline user=%user.name pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: WARNING
```

**30초 수집** (JSON 출력이 파싱에 편하다):

```bash
# 기존 systemd 인스턴스를 잠시 멈추고 30초 수집 (포트/드라이버 충돌 방지)
systemctl stop falco 2>/dev/null || true

# JSON 라인 출력으로 30초 캡처
falco -M 30 -o json_output=true \
  -r /etc/falco/falco_rules.yaml \
  -r /etc/falco/falco_rules.local.yaml > /tmp/falco.out 2>/dev/null

# (또는 systemd로 재시작 후 로그에서 수집)
# systemctl restart falco ; sleep 30 ; journalctl -u falco --since "1 min ago" > /tmp/falco.out
```

**container.name만 추출 → 정렬 유니크**:

```bash
# JSON output일 때
grep "Read sensitive shadow file\|/etc/shadow" /tmp/falco.out \
  | jq -r '.output_fields["container.name"]' 2>/dev/null \
  | grep -v null | sort -u > /tmp/containers.txt

# JSON이 아니면 output 텍스트에서 container=<name> 파싱
# grep -oE 'container=[^ )]+' /tmp/falco.out | cut -d= -f2 | sort -u > /tmp/containers.txt
cat /tmp/containers.txt
exit
exit
```

메인 터미널로 저장:

```bash
mkdir -p /opt/course/14
scp worker1:/tmp/containers.txt /opt/course/14/containers.txt   # 또는 ssh ... cat
cat /opt/course/14/containers.txt
```

**3) 검증 방법**

```bash
# 룰 문법이 유효한지 (-V는 룰 파일을 인자로 받는다. 매크로 정의를 위해 기본 룰도 함께 검증)
ssh worker1 "sudo falco -V /etc/falco/falco_rules.yaml -V /etc/falco/falco_rules.local.yaml >/dev/null && echo RULE-OK"
cat /opt/course/14/containers.txt      # 컨테이너 이름들, 중복 없이 정렬
```

**4) ⚠️ 함정 포인트**

- 룰은 **`/etc/falco/falco_rules.local.yaml`**에 넣는다. `/etc/falco/falco_rules.yaml`(기본 룰)을 직접 고치면 업그레이드 시 덮여쓰기되고 관례에 어긋난다.
- `condition`에 **`container`** 매크로를 반드시 포함해야 "컨테이너 안에서"라는 조건이 성립한다(호스트 프로세스 제외).
- `open_read`(읽기 목적 open) 매크로를 쓰면 정확도가 높다. 단순 `evt.type=open`만 쓰면 write까지 잡힐 수 있다.
- output에 `%container.name`이 없으면 3번 추출이 불가능하다. 출력 필드를 반드시 포함.
- 제출 파일에는 **container name만** 들어가야 한다. 전체 로그 라인을 넣으면 오답. `sort -u`로 중복 제거.
- 수집은 정확히 30초. `falco -M 30`이 가장 간단. systemd와 동시에 두 인스턴스가 뜨면 충돌하니 하나만.

**예상 소요시간**: 12분 / **부분점수 포인트**: 룰 작성(condition/priority/output) / 30초 수집 / container.name 정렬 추출 각각 채점.

</details>

---

## Task 15 - Compromise Investigation & Isolation (7%)

> `kubectl config use-context k8s-p1`

A Pod in namespace `web` is suspected of running a malicious process that beacons out to the internet. **Do not delete the Pod** — it must be preserved for forensics.

1. Identify the suspicious Pod. A running process whose executable lives outside the normal image path (e.g. under `/tmp` or `/dev/shm`) is the indicator. Use `crictl` and `/proc` inspection on `worker1`.
2. Report the **absolute path of the malicious process's executable** into `/opt/course/15/exe.txt` on the main terminal.
3. Isolate the Pod without deleting it: remove its Pod labels so no Service selects it, and apply a `default-deny` NetworkPolicy (ingress + egress) in namespace `web` targeting the Pod so it can no longer communicate.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

침해 조사는 (a) 의심 Pod/컨테이너 식별 → (b) 컨테이너 PID로 `/proc/<pid>/exe` 확인해 실행 파일 실제 경로 파악 → (c) 삭제 없이 격리(라벨 제거로 Service에서 분리 + NetworkPolicy로 통신 차단). 포렌식 보존이 최우선이므로 **절대 delete/kill 하지 않는다**.

**2) 단계별 풀이 — 식별**

```bash
kubectl -n web get pods -o wide     # 후보 확인

ssh worker1
sudo -i
# 컨테이너 목록에서 web 네임스페이스 파드의 컨테이너 찾기
crictl ps

# 의심 컨테이너 상세 (이미지, 시작 프로세스)
crictl inspect <container-id> | jq '.status.metadata.name, .info.pid'

# 컨테이너의 init PID로 프로세스 트리와 실행 파일 경로 확인
PID=$(crictl inspect <container-id> | jq -r '.info.pid')
ls -l /proc/$PID/exe            # 정상 프로세스 경로
# 컨테이너 내부의 모든 프로세스 스캔: exe가 /tmp, /dev/shm 등을 가리키면 악성
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  exe=$(readlink -f /proc/$p/exe 2>/dev/null)
  case "$exe" in
    */tmp/*|*/dev/shm/*) echo "SUSPECT pid=$p exe=$exe cmd=$(tr '\0' ' ' </proc/$p/cmdline)";;
  esac
done
# 예: SUSPECT pid=23145 exe=/tmp/.x/miner
```

**실행 파일 경로 저장**:

```bash
readlink -f /proc/23145/exe        # /tmp/.x/miner
ls -l /proc/23145/cwd /proc/23145/environ   # 추가 포렌식 정보
exit
exit

mkdir -p /opt/course/15
echo "/tmp/.x/miner" > /opt/course/15/exe.txt
```

**격리 (삭제 금지)**:

```bash
# 어떤 파드인지 확인 후 라벨 제거 → Service selector에서 제외
POD=<의심-pod-이름>
kubectl -n web get pod $POD --show-labels
# 예: app=web,role=frontend → 모두 제거 (라벨 뒤에 '-')
kubectl -n web label pod $POD app- role-

# 격리용 default-deny NetworkPolicy: 이 파드에만 매칭되는 고유 라벨을 하나 붙여 타겟팅
kubectl -n web label pod $POD quarantine=true
cat > /opt/course/15/isolate.yaml << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine
  namespace: web
spec:
  podSelector:
    matchLabels:
      quarantine: "true"
  policyTypes:
    - Ingress
    - Egress
EOF
kubectl apply -f /opt/course/15/isolate.yaml
```

**3) 검증 방법**

```bash
kubectl -n web get pod $POD --show-labels        # app/role 라벨 사라짐, quarantine=true
kubectl -n web get pod $POD                        # 여전히 Running (삭제 안 됨)
kubectl -n web describe netpol quarantine
cat /opt/course/15/exe.txt                          # /tmp/.x/miner
# 격리 확인: 파드에서 외부로 못 나가는지
kubectl -n web exec $POD -- timeout 3 wget -qO- http://example.com || echo "BLOCKED"
```

**4) ⚠️ 함정 포인트**

- **절대 파드를 삭제/재시작하지 마라.** 포렌식 증거(메모리, /proc, 파일)가 사라진다. 문제의 핵심 채점 포인트.
- 라벨을 지워야 Service가 이 파드로 트래픽을 보내지 않는다. 하지만 라벨을 다 지우면 NetworkPolicy로 타겟팅할 수단이 없어지므로, **격리 전용 라벨(quarantine=true)**을 하나 붙여 그걸로 정책을 매칭한다.
- default-deny는 `podSelector`로 그 파드만 겨냥한다(네임스페이스 전체 `{}`로 하면 정상 파드까지 끊는다).
- 실행 파일 경로는 `readlink -f /proc/<pid>/exe`로 확인한다. `crictl exec`로 컨테이너 안에서 `ls`만 보면 삭제된 바이너리(deleted)나 위장 이름에 속을 수 있다.
- 컨테이너 init PID만 보면 자식 악성 프로세스를 놓친다. `/proc` 전체를 스캔해 exe가 비정상 경로인 것을 찾는다.

**예상 소요시간**: 12분 / **부분점수 포인트**: 의심 파드 식별 / exe 경로 저장 / 라벨 제거 / NetworkPolicy 격리 / 파드 보존(삭제 안 함) 각각 채점.

</details>

---

## Task 16 - Container Immutability (6%)

> `kubectl config use-context k8s-p1`

Deployment `report-gen` in namespace `apps` runs with a writable root filesystem and a `hostPath` mount, and its container can escalate privileges. Make it **immutable**.

1. Set the container's root filesystem to read-only (`readOnlyRootFilesystem: true`).
2. The application writes temporary files to `/var/cache/app`. Provide that path via an `emptyDir` volume so the app still works with a read-only root.
3. Remove the `hostPath` volume/mount entirely, and ensure `privileged: false`, `allowPrivilegeEscalation: false`.
4. After rollout, exec into the Pod and prove that writing to the root filesystem fails while writing to `/var/cache/app` succeeds.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

불변 컨테이너의 4요소: `readOnlyRootFilesystem: true`, 쓰기 필요한 경로만 `emptyDir`, `privileged: false`, `allowPrivilegeEscalation: false`. hostPath는 노드 파일시스템 접근 위험이라 제거한다. 마지막에 exec로 write 실패/성공을 실증.

**2) 단계별 풀이**

```bash
kubectl -n apps edit deploy report-gen
```

```yaml
    spec:
      # hostPath 볼륨 제거하고 emptyDir로 대체
      volumes:
        - name: cache
          emptyDir: {}
      containers:
        - name: report-gen
          # ...
          securityContext:
            readOnlyRootFilesystem: true
            privileged: false
            allowPrivilegeEscalation: false
          volumeMounts:
            - name: cache
              mountPath: /var/cache/app
```

hostPath 관련 `volumes` 항목과 그 `volumeMounts`를 반드시 삭제한다.

```bash
kubectl -n apps rollout status deploy/report-gen
```

**3) 검증 방법**

```bash
POD=$(kubectl -n apps get pod -l app=report-gen -o jsonpath='{.items[0].metadata.name}')

# 루트 FS 쓰기 → 실패해야 함
kubectl -n apps exec $POD -- sh -c 'echo x > /root-test 2>&1 || echo "ROOT-FS READONLY OK"'
# emptyDir 경로 쓰기 → 성공해야 함
kubectl -n apps exec $POD -- sh -c 'echo x > /var/cache/app/t && echo "CACHE WRITE OK"'

# securityContext 확인
kubectl -n apps get pod $POD -o jsonpath='{.spec.containers[0].securityContext}'; echo
# hostPath 볼륨이 사라졌는지
kubectl -n apps get deploy report-gen -o yaml | grep -A2 hostPath || echo "NO HOSTPATH"
```

**4) ⚠️ 함정 포인트**

- `readOnlyRootFilesystem: true`만 켜고 앱이 쓰는 경로에 `emptyDir`를 안 붙이면 앱이 크래시한다. 쓰기 경로를 정확히 식별해 마운트.
- hostPath는 **볼륨 정의와 volumeMount 양쪽 모두** 지워야 한다. 한쪽만 지우면 스키마 에러 또는 잔존.
- `emptyDir`는 노드 메모리/디스크에 임시 생성되며 Pod 삭제 시 사라진다 — 임시 캐시 용도에 적합.
- `allowPrivilegeEscalation: false`는 setuid 바이너리를 통한 권한 상승까지 막는다. `privileged: false`와 별개 항목이니 둘 다 명시.
- 검증 시 write 실패는 "성공적으로 막혔다"는 뜻이므로 `|| echo OK` 패턴으로 확인한다.
- (심화) `capabilities.drop: ["ALL"]`, `runAsNonRoot: true`까지 더하면 더 견고하지만, 문제 요구사항에 맞춰 과하게 바꿔 앱을 깨뜨리지 않도록 주의.

**예상 소요시간**: 8분 / **부분점수 포인트**: readOnlyRootFilesystem / emptyDir 마운트 / hostPath 제거 / privileged·allowPrivilegeEscalation / write 실패 실증 각각 채점.

</details>

---

## 채점표

각 Task를 all-or-nothing이 아니라 sub-task 단위로 자가 채점하라. 실제 시험도 부분점수를 준다. 67%(= 67점) 이상이면 합격선이다.

| Task | 주제 | 도메인 | 배점 | 획득 | 자가 채점 핵심 |
|---|---|---|---:|---:|---|
| T1 | Kubelet Binary Integrity | Cluster Setup | 4 | | 올바른 경로 sha512 / result.txt 정확한 단어 |
| T2 | Advanced NetworkPolicy (AND/OR) | Cluster Setup | 8 | | AND 항목 / logging OR / cache OR / DNS |
| T3 | NodePort → ClusterIP | Cluster Setup | 4 | | type 변경 / 노드포트 미리슨 |
| T4 | NodeRestriction Admission | Cluster Hardening | 6 | | 플러그인 활성화 / 거부 출력 저장 |
| T5 | Anonymous Lockdown | Cluster Hardening | 7 | | anonymous-auth / curl 401 / stale user / 6443 |
| T6 | Kernel Module Blacklist | System Hardening | 5 | | blacklist 영구화 / 언로드 / 로드 방지 |
| T7 | AppArmor + seccomp | System Hardening | 7 | | AppArmor 로드 / seccomp 배치 / 두 필드 / 기동 |
| T8 | PSA Labels + Exemptions | MMV | 7 | | 라벨 4종 / AdmissionConfiguration / 마운트 기동 |
| T9 | Encryption Key Rotation | MMV | 7 | | key2 첫번째 / 재암호화 / key1 제거 / 재암호화 |
| T10 | Cilium WireGuard | MMV | 6 | | 상태 확인 / 활성화 방법 / 검증 방법 |
| T11 | cosign Verify | Supply Chain | 7 | | 서명 이미지 식별 / 교체 / verify.txt |
| T12 | KubeLinter + Dockerfile | Supply Chain | 7 | | latest / resources / nonroot / 멀티스테이지 |
| T13 | Private Registry + trivy | Supply Chain | 5 | | secret / SA 연결 / trivy 비교 교체 |
| T14 | Falco Sensitive File | Runtime | 7 | | 룰 / 30초 수집 / container.name 정렬 |
| T15 | Compromise & Isolation | Runtime | 7 | | 식별 / exe 경로 / 라벨 제거 / netpol / 보존 |
| T16 | Container Immutability | Runtime | 6 | | readOnlyRootFS / emptyDir / hostPath 제거 / write 실패 |
| **합계** | | | **100** | | **67 이상 합격** |

## 취약 도메인 복습 매핑

채점 후 틀린 Task의 도메인을 아래 학습 노트로 되돌아가 복습하라.

| 틀린 Task | 복습할 파일/주제 |
|---|---|
| T1, T4, T5 | `00-exam-guide.md`, `01-cluster-setup.md` (바이너리 검증), `02-cluster-hardening.md` (apiserver/NodeRestriction) |
| T2, T3 | `01-cluster-setup.md` (NetworkPolicy AND/OR, Service 노출) |
| T6, T7 | `03-system-hardening.md` (kernel module, AppArmor/seccomp) |
| T8, T9, T10 | `04-minimize-microservice-vulnerabilities.md` (PSA, EncryptionConfiguration, Cilium 암호화) |
| T11, T12, T13 | `05-supply-chain-security.md` (cosign, KubeLinter, trivy, Dockerfile) |
| T14, T15, T16 | Runtime Security 노트 (Falco, crictl 포렌식, immutability) |

> **💡 리허설 활용법**: 이 3회는 실전보다 어렵게 설계됐다. 60점만 넘겨도 실제 시험에서는 합격권이니 점수에 낙담하지 말고, **틀린 이유가 "몰라서"인지 "실수(함정)"인지** 구분해 오답노트를 만들어라. 함정 실수는 체크리스트로, 지식 공백은 위 파일로 메운다.

---

## 🎯 시험 직전 체크리스트

- [ ] 매 Task 첫 줄 `kubectl config use-context <ctx>`를 **복사-실행**했다. (T10만 `k8s-p2`, 나머지 `k8s-p1`)
- [ ] 노드 작업 후 `exit`으로 메인 터미널에 복귀했다. (중첩 ssh 금지)
- [ ] 답안 파일은 정확히 `/opt/course/<번호>/<파일명>`에, 요구된 내용만 저장했다.
- [ ] NetworkPolicy: `policyTypes` 명시 + `namespaceSelector`/`podSelector`의 AND(한 항목) vs OR(별개 항목) 구분 + egress DNS(53 UDP/TCP) 허용.
- [ ] apiserver manifest 수정 후 **재생성 대기**(`crictl ps`), 안 뜨면 `/var/log/pods/`·`crictl logs`·`journalctl -u kubelet`.
- [ ] apiserver에 파일을 물릴 때 **hostPath volumeMount** 추가(PSA AdmissionConfiguration, audit policy 공통 함정).
- [ ] EncryptionConfiguration key 로테이션: 새 key **맨 앞**, 재암호화(`replace`) **후에** 옛 key 제거, `identity`는 항상 뒤.
- [ ] AppArmor/seccomp: 노드에 프로파일 **먼저 배치/로드** → manifest는 `securityContext.appArmorProfile`/`seccompProfile` **필드**(annotation 아님).
- [ ] seccomp `localhostProfile`은 `/var/lib/kubelet/seccomp/` 기준 **상대경로**.
- [ ] Falco 커스텀 룰은 `/etc/falco/falco_rules.local.yaml`, `condition`에 `container` 포함, output에 `%container.name`.
- [ ] 침해 조사: **삭제 금지**, 라벨 제거 + 격리용 라벨 + default-deny NetworkPolicy로 보존 격리.
- [ ] 불변 컨테이너: `readOnlyRootFilesystem` + 쓰기 경로 `emptyDir` + `allowPrivilegeEscalation:false` + hostPath 제거.
- [ ] 서술형/파일 제출(T1, T10, T14 등)은 요구된 **형식과 단어**를 정확히 지켰다.
- [ ] 남는 5~10분에 저장 안 된 edit, 미완 Task, 재생성 실패 컴포넌트를 다시 훑었다.

## 핵심 명령어 치트시트

```bash
# ── 컨텍스트 / 노드 ──────────────────────────────
kubectl config use-context k8s-p1
kubectl config get-contexts
ssh worker1 ; sudo -i ; exit          # 노드 작업 후 반드시 exit

# ── 바이너리 무결성 (T1) ─────────────────────────
readlink -f "$(which kubelet)"
sha512sum /usr/bin/kubelet | awk '{print $1}'

# ── NetworkPolicy (T2) : AND=한 항목 / OR=별개 항목 ─
# egress DNS 필수:
#   - ports: [{protocol: UDP, port: 53},{protocol: TCP, port: 53}]

# ── Service 노출 정리 (T3) ───────────────────────
kubectl -n web patch svc web-frontend -p '{"spec":{"type":"ClusterIP"}}'
ssh worker1 "sudo ss -tlnp | grep :<nodeport> || echo CLOSED"

# ── apiserver 하드닝 (T4/T5/T8) ──────────────────
#   /etc/kubernetes/manifests/kube-apiserver.yaml
#   --enable-admission-plugins=NodeRestriction,...
#   --anonymous-auth=false
#   --admission-control-config-file=/etc/kubernetes/pss/admission-config.yaml (+ hostPath mount)
crictl ps | grep kube-apiserver
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:6443/api   # 401
kubectl --kubeconfig /etc/kubernetes/kubelet.conf label node master1 x=y  # NodeRestriction 거부

# ── kubeconfig 정리 (T5) ─────────────────────────
kubectl config delete-user dev-legacy
kubectl config delete-context <ctx>

# ── kernel module blacklist (T6) ─────────────────
printf 'blacklist sctp\ninstall sctp /bin/false\n' | sudo tee /etc/modprobe.d/blacklist-cks.conf
modprobe -r sctp ; modprobe -n -v sctp ; lsmod | grep sctp

# ── AppArmor / seccomp (T7) ──────────────────────
apparmor_parser -q /etc/apparmor.d/k8s-web-profile ; aa-status | grep k8s-web
cp audit.json /var/lib/kubelet/seccomp/profiles/audit.json
#   securityContext.appArmorProfile: {type: Localhost, localhostProfile: k8s-web-profile}
#   securityContext.seccompProfile: {type: Localhost, localhostProfile: profiles/audit.json}

# ── PSA 라벨 (T8) ────────────────────────────────
kubectl label ns payments \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/enforce-version=v1.35 \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted --overwrite

# ── Encryption 재암호화 (T9) ─────────────────────
kubectl get secrets -A -o json | kubectl replace -f -
ETCDCTL_API=3 etcdctl --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/<name> | hexdump -C | head

# ── Cilium 암호화 (T10) ──────────────────────────
kubectl -n kube-system exec ds/cilium -- cilium status | grep -i encryption
helm upgrade cilium cilium/cilium -n kube-system --reuse-values \
  --set encryption.enabled=true --set encryption.type=wireguard
ssh cluster2-worker1 "sudo wg show"

# ── Supply chain (T11/T12/T13) ───────────────────
cosign verify --key /opt/course/11/cosign.pub registry.local:5000/app:signed
kube-linter lint /opt/course/12/manifests/
trivy image --severity CRITICAL,HIGH registry.local:5000/api:1.5
kubectl -n internal create secret docker-registry regcred \
  --docker-server=registry.local:5000 --docker-username=deployer \
  --docker-password='S3cr3t!' --docker-email=deployer@corp.local
kubectl -n internal patch sa default -p '{"imagePullSecrets":[{"name":"regcred"}]}'

# ── Falco (T14) ──────────────────────────────────
#   /etc/falco/falco_rules.local.yaml : condition에 container, output에 %container.name
falco -M 30 -o json_output=true -r /etc/falco/falco_rules.yaml -r /etc/falco/falco_rules.local.yaml > /tmp/falco.out
jq -r '.output_fields["container.name"]' /tmp/falco.out | grep -v null | sort -u

# ── 침해 조사 (T15) : 삭제 금지 ──────────────────
crictl ps ; crictl inspect <id> | jq '.info.pid'
readlink -f /proc/<pid>/exe
kubectl -n web label pod <pod> app- role- ; kubectl -n web label pod <pod> quarantine=true
#   default-deny NetworkPolicy (podSelector: quarantine=true, Ingress+Egress)

# ── 불변 컨테이너 (T16) ──────────────────────────
#   securityContext: {readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, privileged: false}
#   volumes: emptyDir 로 쓰기 경로 제공, hostPath 제거
kubectl -n apps exec <pod> -- sh -c 'echo x > /ro 2>&1 || echo READONLY-OK'
```

> **📌 마지막 당부**: 이 세트를 2시간 안에 60% 이상 풀 수 있으면 실전 준비는 충분하다. 틀린 함정은 위 체크리스트에 자기 언어로 한 줄씩 추가해 시험장 직전 5분에 훑어라. 행운을 빈다.
