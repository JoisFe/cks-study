# CKS 모의고사 2회 — 2024 개편 신규 토픽 강조 세트

CKS 실전 감각을 완성하는 두 번째 풀세트 모의고사로, 2024-10-15 커리큘럼 대개편에서 새로 추가된 Cilium/Istio 암호화·mTLS, SBOM(bom), Kubesec, ValidatingAdmissionPolicy를 집중적으로 훈련한다.

> **📌 시험 개요** — 실제 CKS는 **2시간, 15~20개(보통 16개) hands-on 과제, 합격선 67%**, Kubernetes **v1.35** / containerd / Ubuntu 노드 환경(PSI Secure Browser 원격 데스크톱, XFCE)에서 치러진다. 응시 전제조건은 유효한 CKA, 자격 유효기간은 2년, 무료 재시험 1회가 포함된다. 이 세트는 개편에서 비중이 커진 **Minimize Microservice Vulnerabilities 20% / Supply Chain Security 20% / Monitoring, Logging & Runtime Security 20%** 도메인을 집중 공략한다.

## 목차

1. [Exam Instructions](#exam-instructions)
2. [클러스터 구성](#클러스터-구성)
3. [Task 01 CiliumNetworkPolicy (7%)](#task-01-ciliumnetworkpolicy-7)
4. [Task 02 Metadata Endpoint 차단 (5%)](#task-02-metadata-endpoint-차단-5)
5. [Task 03 etcd CIS 하드닝 (6%)](#task-03-etcd-cis-하드닝-6)
6. [Task 04 CSR 사용자 생성과 RBAC (7%)](#task-04-csr-사용자-생성과-rbac-7)
7. [Task 05 kubelet 하드닝 (7%)](#task-05-kubelet-하드닝-7)
8. [Task 06 cluster-admin 과잉 바인딩 정리 (5%)](#task-06-cluster-admin-과잉-바인딩-정리-5)
9. [Task 07 Seccomp Localhost 프로파일 (6%)](#task-07-seccomp-localhost-프로파일-6)
10. [Task 08 SSH 하드닝과 sudo 제거 (4%)](#task-08-ssh-하드닝과-sudo-제거-4)
11. [Task 09 Istio mTLS STRICT (6%)](#task-09-istio-mtls-strict-6)
12. [Task 10 Secret 추출과 etcd 평문 확인 (6%)](#task-10-secret-추출과-etcd-평문-확인-6)
13. [Task 11 Deployment SecurityContext (7%)](#task-11-deployment-securitycontext-7)
14. [Task 12 bom으로 SBOM 생성 (7%)](#task-12-bom으로-sbom-생성-7)
15. [Task 13 Kubesec 스캔과 개선 (6%)](#task-13-kubesec-스캔과-개선-6)
16. [Task 14 ValidatingAdmissionPolicy 레지스트리 제한 (7%)](#task-14-validatingadmissionpolicy-레지스트리-제한-7)
17. [Task 15 Falco 룰 오버라이드 (7%)](#task-15-falco-룰-오버라이드-7)
18. [Task 16 Audit Log 분석과 RBAC 축소 (7%)](#task-16-audit-log-분석과-rbac-축소-7)
19. [채점표](#채점표)
20. [🎯 시험 직전 체크리스트](#-시험-직전-체크리스트)
21. [핵심 명령어 치트시트](#핵심-명령어-치트시트)

---

## Exam Instructions

Read these instructions carefully before starting. They mirror the tone of the real exam.

- This mock exam consists of **16 tasks**. You have **120 minutes**. The passing score is **67%**.
- Each task states the cluster context to use on its first line. **Always run the `kubectl config use-context` command first.**
- Some tasks require you to SSH into a node (e.g. `ssh cks-master2`). When you are done, **type `exit` to return to the main terminal** before starting the next task. Nested SSH sessions are a common source of mistakes.
- Answer files must be created at the exact paths given (e.g. `/opt/course/4/sara.key`). Unless stated otherwise, answer files live on the **main terminal**.
- You may only use the official documentation during the exam:
  - `kubernetes.io/docs`, `kubernetes.io/blog`
  - `falco.org/docs`
  - `kubernetes-sigs.github.io/bom/cli-reference/`
  - `etcd.io/docs`
  - `kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/`
  - `docs.cilium.io/en/stable`, `istio.io/latest/docs`

> **💡 시험 팁:** 배점이 높은 문제(7%)부터 훑어보고, 노드 재기동이 필요한 문제(kubelet, etcd, Falco)는 기다리는 시간 동안 다른 문제를 병행하라. static pod 수정 후 kubelet이 재생성하는 데 30초~1분 걸린다.

> **⚠️ 함정:** 컨텍스트 전환을 빠뜨리고 다른 클러스터에 리소스를 만드는 것이 모의고사 채점에서 가장 흔한 0점 원인이다. 문제마다 첫 줄의 `kubectl config use-context`를 기계적으로 실행하는 습관을 들여라.

## 클러스터 구성

| Context | Control Plane | Worker | 특이사항 / 주요 용도 |
|---------|---------------|--------|----------------------|
| `k8s-s1` | `cks-master1` | `cks-worker1` | CNI: Cilium. NetworkPolicy, RBAC, Secrets, ValidatingAdmissionPolicy, Audit 분석 |
| `k8s-s2` | `cks-master2` | `cks-worker2` | 노드 하드닝 전용: etcd, kubelet, seccomp, SSH, Falco(worker2에 설치) |
| `k8s-s3` | `cks-master3` | `cks-worker3` | Istio 설치됨. mTLS, Supply Chain(bom, kubesec) |

---

## Task 01 CiliumNetworkPolicy (7%)

> **배점 7% | 도메인: Cluster Setup | 클러스터: k8s-s1**

```bash
kubectl config use-context k8s-s1
```

In namespace `payments` a Deployment named `backend` is running. Its Pods carry the label `app: backend` and are exposed by a Service `backend` on port `8080`.

Create a `CiliumNetworkPolicy` named `backend-allow-frontend` in namespace `payments` that:

1. Applies to all Pods with label `app: backend`.
2. Allows ingress traffic on TCP port `8080` **only** from Pods with label `role: frontend`.
3. Denies all other ingress traffic to the `backend` Pods.

Save the manifest you applied to `/opt/course/1/cilium-policy.yaml`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

CiliumNetworkPolicy는 표준 NetworkPolicy의 `podSelector` 대신 `endpointSelector`를 쓰고, 허용 대상은 `fromEndpoints`, 포트는 `toPorts`로 지정한다. Cilium은 화이트리스트 모델이므로 ingress 룰을 하나라도 걸면 명시하지 않은 트래픽은 자동 거부된다. 문서는 `docs.cilium.io/en/stable`에서 "Layer 4 Examples"를 검색하면 된다.

**2) 단계별 명령어/YAML**

```bash
mkdir -p /opt/course/1
vim /opt/course/1/cilium-policy.yaml
```

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: backend-allow-frontend
  namespace: payments
spec:
  endpointSelector:
    matchLabels:
      app: backend
  ingress:
  - fromEndpoints:
    - matchLabels:
        role: frontend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
```

```bash
kubectl apply -f /opt/course/1/cilium-policy.yaml
```

**3) 검증 방법**

```bash
# 허용: role=frontend 라벨 pod에서 접근 → 응답이 와야 함
kubectl -n payments run t1-ok --labels=role=frontend --image=busybox:1.36 \
  --rm -it --restart=Never -- wget -qO- --timeout=3 backend:8080

# 거부: 라벨 없는 pod에서 접근 → timeout이어야 함
kubectl -n payments run t1-deny --image=busybox:1.36 \
  --rm -it --restart=Never -- wget -qO- --timeout=3 backend:8080
```

**4) ⚠️ 함정 포인트**

- `toPorts`의 `port`는 반드시 **문자열**(`"8080"`)이어야 한다. 숫자로 쓰면 apply가 거부된다.
- `fromEndpoints`는 기본적으로 **같은 네임스페이스**의 pod만 매칭한다. 다른 네임스페이스에서의 접근을 허용하려면 `k8s:io.kubernetes.pod.namespace` 라벨을 함께 지정해야 한다.
- 파일 저장(`/opt/course/1/…`)과 클러스터 apply를 **둘 다** 해야 만점이다.

**예상 소요시간:** 7분 | **부분점수 포인트:** 정책 리소스 생성(라벨/네임스페이스 정확) → 포트/프로토콜 제한 → 파일 제출 순으로 부분 채점된다.

</details>

---

## Task 02 Metadata Endpoint 차단 (5%)

> **배점 5% | 도메인: Cluster Setup | 클러스터: k8s-s1**

```bash
kubectl config use-context k8s-s1
```

The nodes of cluster `k8s-s1` run on a cloud provider. Pods must not be able to reach the cloud metadata endpoint.

Create a NetworkPolicy named `deny-metadata` in namespace `apps` that:

1. Applies to **all** Pods in namespace `apps`.
2. Denies egress traffic to `169.254.169.254/32`.
3. Allows all other egress traffic (including DNS).

Save the manifest to `/opt/course/2/netpol.yaml` and apply it.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

"특정 IP만 막고 나머지는 전부 허용"은 `ipBlock`의 `cidr: 0.0.0.0/0` + `except`로 구현한다. egress 정책이 pod에 걸리는 순간 화이트리스트에 없는 트래픽은 모두 차단되므로, 전체 허용 CIDR을 명시하는 것이 핵심이다.

**2) 단계별 명령어/YAML**

```bash
mkdir -p /opt/course/2
vim /opt/course/2/netpol.yaml
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata
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
```

```bash
kubectl apply -f /opt/course/2/netpol.yaml
```

**3) 검증 방법**

```bash
kubectl -n apps run t2 --image=busybox:1.36 --rm -it --restart=Never -- sh -c \
  'wget -qO- --timeout=3 http://169.254.169.254 || echo BLOCKED; nslookup kubernetes.default'
# 기대: BLOCKED 출력 + DNS 조회는 성공
```

**4) ⚠️ 함정 포인트**

- `podSelector: {}`(빈 셀렉터)가 "네임스페이스 내 전체 pod"라는 의미다. 생략해도 빈 셀렉터로 처리되어 전체 pod에 적용되지만, 의도가 드러나도록 반드시 명시하는 습관을 들여라.
- `policyTypes: [Egress]`를 명시하지 않으면 egress 룰이 있어도 Ingress 정책으로 해석될 수 있다. **policyTypes 명시는 필수 습관.**
- `0.0.0.0/0` 허용 룰이 있으므로 DNS(53)를 따로 열 필요는 없지만, 만약 특정 CIDR만 허용하는 변형 문제라면 **UDP/TCP 53 허용을 절대 잊지 말 것** — egress 최다 빈출 함정이다.

**예상 소요시간:** 4분 | **부분점수 포인트:** 정책 생성(전체 pod 적용) → except로 메타데이터 IP 차단 → 나머지 egress 정상 동작 확인.

</details>

---

## Task 03 etcd CIS 하드닝 (6%)

> **배점 6% | 도메인: Cluster Setup | 클러스터: k8s-s2**

```bash
kubectl config use-context k8s-s2
ssh cks-master2
```

The etcd instance of cluster `k8s-s2` must comply with the following CIS Benchmark checks:

1. `--client-cert-auth` is set to `true`.
2. `--peer-client-cert-auth` is set to `true`.
3. `--auto-tls` is not set to `true`.
4. `--peer-auto-tls` is not set to `true`.

Inspect the static Pod manifest `/etc/kubernetes/manifests/etcd.yaml`, fix any non-compliant setting, and wait until etcd is running again.

Write the final state of the four checks to `/opt/course/3/etcd-flags.txt` on `cks-master2`, one per line, in the format `flag=value` (use `not-set` if a flag is absent).

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

kube-bench의 etcd 섹션(CIS 2.x)에 해당하는 문제다. static pod manifest에서 플래그를 확인하고, 누락/오설정을 고친 뒤 kubelet이 etcd pod를 재생성할 때까지 기다린다.

**2) 단계별 명령어/YAML**

```bash
# 현재 상태 확인
grep -E 'client-cert-auth|auto-tls' /etc/kubernetes/manifests/etcd.yaml

sudo vim /etc/kubernetes/manifests/etcd.yaml
```

command 섹션이 아래를 만족하도록 수정한다.

```yaml
  - command:
    - etcd
    - --client-cert-auth=true
    - --peer-client-cert-auth=true
    # --auto-tls / --peer-auto-tls 라인이 true로 있으면 삭제하거나 false로 변경
    - --cert-file=/etc/kubernetes/pki/etcd/server.crt
    - --key-file=/etc/kubernetes/pki/etcd/server.key
    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
    - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
    - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
```

```bash
mkdir -p /opt/course/3
cat > /opt/course/3/etcd-flags.txt <<'TXT'
--client-cert-auth=true
--peer-client-cert-auth=true
--auto-tls=not-set
--peer-auto-tls=not-set
TXT
```

**3) 검증 방법**

```bash
# etcd static pod 재기동 확인 (30초~1분 대기)
sudo crictl ps | grep etcd

# 인증서를 제시하면 성공
sudo ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key endpoint health

# 인증서 없이 접근하면 실패해야 정상 (client-cert-auth 동작 증거)
sudo ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 endpoint health || echo DENIED
```

**4) ⚠️ 함정 포인트**

- etcd manifest를 잘못 고치면 **kube-apiserver까지 연쇄로 죽는다.** 수정 전 `cp etcd.yaml /tmp/`로 백업하고, 안 뜨면 `sudo crictl ps -a`와 `journalctl -u kubelet`으로 디버깅하라.
- `--auto-tls=true`가 있으면 자체 서명 인증서를 쓰게 되어 CIS 위반이다. **삭제**가 가장 안전한 처리.
- 답안 파일을 main terminal이 아니라 **cks-master2에** 만들어야 한다. 문제의 파일 위치 지시를 항상 재확인하라.

**예상 소요시간:** 8분 | **부분점수 포인트:** 플래그 2개(client/peer) 설정 → auto-tls 제거 → etcd 정상 기동 → 답안 파일 형식 준수.

</details>

---

## Task 04 CSR 사용자 생성과 RBAC (7%)

> **배점 7% | 도메인: Cluster Hardening | 클러스터: k8s-s1**

```bash
kubectl config use-context k8s-s1
```

Create a new user `sara` who must be able to `get`, `list` and `watch` Pods in namespace `dev-team` only.

1. Generate a private key `/opt/course/4/sara.key` and a CSR file `/opt/course/4/sara.csr` with subject `/CN=sara` using openssl.
2. Create a CertificateSigningRequest object named `sara`, approve it, and save the issued certificate to `/opt/course/4/sara.crt`.
3. Create a Role `pod-reader` and a RoleBinding `sara-pod-reader` in namespace `dev-team` granting the required permissions.
4. Add the user as credentials `sara` and a context `sara@k8s-s1` to the default kubeconfig. Verify that listing Pods in `dev-team` works and that reading Secrets is forbidden.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

인증서 기반 사용자 생성의 정석 4단계: openssl로 key/CSR → CSR 오브젝트(`signerName: kubernetes.io/kube-apiserver-client`) 제출·승인 → RBAC 부여 → kubeconfig 등록. 인증서의 CN이 곧 사용자 이름이 된다.

**2) 단계별 명령어/YAML**

```bash
mkdir -p /opt/course/4 && cd /opt/course/4
openssl genrsa -out sara.key 2048
openssl req -new -key sara.key -out sara.csr -subj "/CN=sara"

cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: sara
spec:
  request: $(base64 -w0 < sara.csr)
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
EOF

kubectl certificate approve sara
kubectl get csr sara -o jsonpath='{.status.certificate}' | base64 -d > sara.crt
```

```bash
kubectl -n dev-team create role pod-reader \
  --verb=get --verb=list --verb=watch --resource=pods
kubectl -n dev-team create rolebinding sara-pod-reader \
  --role=pod-reader --user=sara

kubectl config set-credentials sara \
  --client-key=/opt/course/4/sara.key \
  --client-certificate=/opt/course/4/sara.crt --embed-certs
kubectl config set-context sara@k8s-s1 --cluster=k8s-s1 --user=sara
```

**3) 검증 방법**

```bash
kubectl --context sara@k8s-s1 -n dev-team get pods          # 성공해야 함
kubectl --context sara@k8s-s1 -n dev-team get secrets       # Forbidden이어야 함
kubectl auth can-i list pods -n dev-team --as sara          # yes
kubectl auth can-i get secrets -n dev-team --as sara        # no
```

**4) ⚠️ 함정 포인트**

- CSR 오브젝트의 `request` 필드는 **CSR 파일의 base64 한 줄**(`base64 -w0`)이다. 줄바꿈이 섞이면 apply가 실패한다.
- `signerName`을 `kubernetes.io/kube-apiserver-client`로 정확히 써야 한다. kubelet-serving 등 다른 signer를 쓰면 client 인증서가 발급되지 않는다.
- 승인 전 상태는 `Pending`이다. `kubectl certificate approve`를 잊으면 `.status.certificate`가 비어 있다.
- Role/RoleBinding은 **네임스페이스 리소스**다. ClusterRoleBinding으로 만들면 권한 범위 초과로 감점될 수 있다.

**예상 소요시간:** 9분 | **부분점수 포인트:** key/CSR 파일 → CSR 승인·인증서 저장 → Role/RoleBinding → kubeconfig 등록·검증. 각 단계가 독립 채점된다.

</details>

---

## Task 05 kubelet 하드닝 (7%)

> **배점 7% | 도메인: Cluster Hardening | 클러스터: k8s-s2**

```bash
kubectl config use-context k8s-s2
ssh cks-worker2
```

The kubelet on node `cks-worker2` currently accepts anonymous requests and exposes the read-only port. Harden it so that:

1. Anonymous authentication is disabled.
2. Webhook authentication is enabled.
3. Authorization mode is `Webhook`.
4. The read-only port is disabled.

Restart the kubelet afterwards. Then verify on the node that `curl -sk https://localhost:10250/pods` is rejected as unauthorized and that port `10255` refuses connections. Write the HTTP status line returned by the first curl to `/opt/course/5/status.txt` on `cks-worker2`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

kubelet 하드닝 4종 세트는 전부 `/var/lib/kubelet/config.yaml` 한 파일에서 끝난다. 수정 후 `systemctl restart kubelet`을 잊지 않는 것이 핵심.

**2) 단계별 명령어/YAML**

```bash
sudo vim /var/lib/kubelet/config.yaml
```

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
readOnlyPort: 0
```

```bash
sudo systemctl restart kubelet
sudo systemctl status kubelet --no-pager   # active (running) 확인
```

**3) 검증 방법**

```bash
mkdir -p /opt/course/5
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:10250/pods
# 기대: 401
curl -sk -i https://localhost:10250/pods | head -1 | sudo tee /opt/course/5/status.txt
curl -s --max-time 3 http://localhost:10255/pods || echo "10255 REFUSED"
```

**4) ⚠️ 함정 포인트**

- `readOnlyPort: 0`은 "0번 포트 사용"이 아니라 **비활성화**를 의미한다. 라인 자체가 없으면 kubeadm 기본값이 0이지만, 명시적으로 적는 편이 안전하다.
- `authorization.mode`를 `AlwaysAllow`로 두면 익명 인증을 꺼도 인증된 요청이 전부 허용된다. 반드시 `Webhook`.
- kubelet이 안 올라오면 YAML 들여쓰기 오류일 확률이 높다. `journalctl -u kubelet -f`로 원인을 확인하라.
- 이 문제의 답안 파일도 **노드 위**에 만든다. 작업 후 `exit`로 main terminal 복귀.

**예상 소요시간:** 7분 | **부분점수 포인트:** 설정 4개 항목 각각 + 재시작 후 kubelet 정상 동작 + 검증 파일.

</details>

---

## Task 06 cluster-admin 과잉 바인딩 정리 (5%)

> **배점 5% | 도메인: Cluster Hardening | 클러스터: k8s-s1**

```bash
kubectl config use-context k8s-s1
```

In namespace `ops` of cluster `k8s-s1`, several RoleBindings reference the ClusterRole `cluster-admin`. Only the ServiceAccount `ops-admin-sa` legitimately requires these permissions.

1. Find all RoleBindings in namespace `ops` that reference ClusterRole `cluster-admin`.
2. Delete every such RoleBinding whose subject is **not** ServiceAccount `ops-admin-sa`.
3. Write the names of the deleted RoleBindings to `/opt/course/6/removed.txt`, one per line.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

RoleBinding이 ClusterRole을 참조하면 해당 네임스페이스 범위로 ClusterRole 권한이 부여된다. `roleRef.name`이 `cluster-admin`인 바인딩을 찾아 subject를 대조한 뒤 불필요한 것만 삭제한다.

**2) 단계별 명령어/YAML**

```bash
# cluster-admin을 참조하는 RoleBinding 나열
kubectl -n ops get rolebindings \
  -o custom-columns='NAME:.metadata.name,ROLE:.roleRef.name,SUBJECTS:.subjects[*].name' \
  | grep cluster-admin

# 각 바인딩의 subject 상세 확인
kubectl -n ops describe rolebindings

# 예: ci-runner-admin, log-reader-admin 이 과잉 바인딩이라면
kubectl -n ops delete rolebinding ci-runner-admin log-reader-admin

mkdir -p /opt/course/6
cat > /opt/course/6/removed.txt <<'TXT'
ci-runner-admin
log-reader-admin
TXT
```

**3) 검증 방법**

```bash
# 남은 바인딩은 ops-admin-sa용 하나뿐이어야 함
kubectl -n ops get rolebindings -o custom-columns='NAME:.metadata.name,ROLE:.roleRef.name' | grep cluster-admin

# 제거된 SA가 더 이상 아무거나 할 수 없는지 확인
kubectl auth can-i '*' '*' -n ops --as=system:serviceaccount:ops:ci-runner   # no
kubectl auth can-i --list --as=system:serviceaccount:ops:ci-runner -n ops
```

**4) ⚠️ 함정 포인트**

- ClusterRoleBinding이 아니라 **RoleBinding**을 보라는 문제다. 범위를 착각해 ClusterRoleBinding을 지우면 다른 문제 환경까지 망가질 수 있다.
- `ops-admin-sa`가 subject로 들어 있는 바인딩은 남겨야 한다. 삭제 전 `-o yaml`로 subjects를 반드시 확인.
- 위험 권한 점검 습관: verb `escalate`, `bind`, `impersonate`, 와일드카드(`*`)가 있는 Role은 항상 의심하라.

**예상 소요시간:** 5분 | **부분점수 포인트:** 과잉 바인딩 식별 → 정확한 것만 삭제(정상 바인딩 보존) → 파일 제출.

</details>

---

## Task 07 Seccomp Localhost 프로파일 (6%)

> **배점 6% | 도메인: System Hardening | 클러스터: k8s-s2**

```bash
kubectl config use-context k8s-s2
```

A seccomp profile is provided at `/opt/course/7/audit.json` on node `cks-worker2`.

1. Install the profile on node `cks-worker2` so the kubelet can use it as a `Localhost` profile (kubelet seccomp root is `/var/lib/kubelet/seccomp/`, use subdirectory `profiles/`).
2. Create a Pod `seccomp-pod` in namespace `system-hard` (image `busybox:1.36`, command `sleep 1d`, scheduled on `cks-worker2`) that uses this profile via `securityContext.seccompProfile`.
3. Exec into the Pod, run `touch /tmp/f && chmod 700 /tmp/f`, and confirm which operation is denied. Write the denied syscall name(s) listed in the profile to `/opt/course/7/denied.txt` on the main terminal.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

Localhost 타입 seccomp은 **pod가 뜨는 노드의** `/var/lib/kubelet/seccomp/` 아래에 프로파일이 있어야 하고, `localhostProfile`은 그 디렉토리 기준 **상대경로**로 적는다.

**2) 단계별 명령어/YAML**

```bash
ssh cks-worker2
sudo mkdir -p /var/lib/kubelet/seccomp/profiles
sudo cp /opt/course/7/audit.json /var/lib/kubelet/seccomp/profiles/audit.json
cat /var/lib/kubelet/seccomp/profiles/audit.json   # 어떤 syscall을 막는지 확인
exit
```

프로파일 예시(제공 파일): `chmod` 계열을 거부한다.

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["chmod", "fchmod", "fchmodat"],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
```

main terminal로 돌아와 `vim pod7.yaml`로 아래 manifest를 작성한다.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-pod
  namespace: system-hard
spec:
  nodeName: cks-worker2
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json
  containers:
  - name: app
    image: busybox:1.36
    command: ["sh", "-c", "sleep 1d"]
```

```bash
kubectl apply -f pod7.yaml
mkdir -p /opt/course/7
printf 'chmod\nfchmod\nfchmodat\n' > /opt/course/7/denied.txt
```

**3) 검증 방법**

```bash
kubectl -n system-hard exec seccomp-pod -- sh -c 'touch /tmp/f && chmod 700 /tmp/f'
# 기대: touch는 성공, chmod: /tmp/f: Operation not permitted
```

**4) ⚠️ 함정 포인트**

- `localhostProfile: /var/lib/kubelet/seccomp/profiles/audit.json`처럼 **절대경로를 쓰면 안 된다.** seccomp 루트 기준 상대경로 `profiles/audit.json`이 정답.
- 프로파일이 없는 노드에 pod가 스케줄되면 `CreateContainerError`가 난다. 멀티 워커 환경이라면 `nodeName` 또는 nodeSelector로 고정하라.
- 프로파일 JSON을 수정한 경우 이미 떠 있는 pod에는 반영되지 않는다. pod를 재생성해야 한다.

**예상 소요시간:** 7분 | **부분점수 포인트:** 노드에 프로파일 배치 → pod securityContext 정확성 → 거부 동작 확인·파일 제출.

</details>

---

## Task 08 SSH 하드닝과 sudo 제거 (4%)

> **배점 4% | 도메인: System Hardening | 클러스터: k8s-s2**

```bash
kubectl config use-context k8s-s2
ssh cks-worker2
```

Harden the SSH daemon on node `cks-worker2`:

1. Root login via SSH must be disabled.
2. Password authentication must be disabled.

Additionally, the user `jane` must no longer be able to use `sudo`. Do **not** delete the user.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`/etc/ssh/sshd_config`에서 두 지시어를 고치고 데몬을 재시작한다. sudo 제거는 Ubuntu에서 `sudo` 그룹 탈퇴 + sudoers 개별 항목 확인의 2단계.

**2) 단계별 명령어/YAML**

```bash
sudo vim /etc/ssh/sshd_config
```

```text
PermitRootLogin no
PasswordAuthentication no
```

```bash
# Ubuntu는 include 파일이 우선 적용될 수 있으므로 함께 확인
sudo grep -rE 'PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config.d/ || true

sudo sshd -t                    # 문법 검증 (필수 습관)
sudo systemctl restart ssh      # Ubuntu의 서비스 이름은 ssh

# jane의 sudo 제거
id jane                         # 그룹 확인
sudo deluser jane sudo          # 또는 gpasswd -d jane sudo
sudo grep -r jane /etc/sudoers /etc/sudoers.d/ || echo "no direct sudoers entry"
```

**3) 검증 방법**

```bash
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication'
# permitrootlogin no / passwordauthentication no

sudo -l -U jane   # "not allowed to run sudo" 류의 출력이어야 함
id jane           # sudo 그룹이 빠졌는지 확인
```

**4) ⚠️ 함정 포인트**

- 설정 라인이 `#PermitRootLogin prohibit-password`처럼 **주석 처리**되어 있으면 주석만 지우고 값도 `no`로 바꿔야 한다.
- `/etc/ssh/sshd_config.d/*.conf`의 include 파일이 본문을 덮어쓸 수 있다. `sshd -T`(유효 설정 덤프)로 최종값을 검증하는 것이 가장 확실하다.
- sudo 그룹 탈퇴 후에도 `/etc/sudoers.d/`에 jane 개별 항목이 있으면 여전히 sudo가 된다. 반드시 grep으로 확인.
- 현재 SSH 세션은 재시작해도 끊기지 않지만, 실수로 자신을 잠그지 않도록 세션을 유지한 채 검증하라.

**예상 소요시간:** 4분 | **부분점수 포인트:** sshd 지시어 2개 + 재시작 → sudo 제거(그룹/sudoers 모두).

</details>

---

## Task 09 Istio mTLS STRICT (6%)

> **배점 6% | 도메인: Minimize Microservice Vulnerabilities | 클러스터: k8s-s3**

```bash
kubectl config use-context k8s-s3
```

Istio is installed in cluster `k8s-s3`. Namespace `pay` runs workloads with Envoy sidecars. Namespace `legacy` contains a Pod `curl-legacy` **without** a sidecar. A Service `payment` in namespace `pay` listens on port `8080`.

1. Verify that namespace `pay` carries the label `istio-injection=enabled`; add it if missing.
2. Enforce mutual TLS for all workloads in namespace `pay`: create a PeerAuthentication named `default` in namespace `pay` with mTLS mode `STRICT`. Save the manifest to `/opt/course/9/peer-auth.yaml`.
3. Verify that a plaintext request from `curl-legacy` to `http://payment.pay.svc.cluster.local:8080` is rejected, while requests between sidecar-injected Pods inside `pay` still succeed.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

네임스페이스 단위 mTLS 강제는 PeerAuthentication 리소스 하나로 끝난다. `STRICT`는 sidecar 간 mTLS 트래픽만 허용하므로, sidecar 없는 pod의 평문 요청은 연결 단계에서 거부된다.

**2) 단계별 명령어/YAML**

```bash
kubectl get ns pay --show-labels
kubectl label ns pay istio-injection=enabled --overwrite

mkdir -p /opt/course/9
vim /opt/course/9/peer-auth.yaml
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

```bash
kubectl apply -f /opt/course/9/peer-auth.yaml
```

**3) 검증 방법**

```bash
# sidecar 없는 pod에서 평문 접근 → 실패해야 함 (connection reset 등)
kubectl -n legacy exec curl-legacy -- curl -s --max-time 5 \
  http://payment.pay.svc.cluster.local:8080 || echo "PLAINTEXT REJECTED"

# pay 내부 sidecar pod 간 통신은 성공해야 함
kubectl -n pay get pods -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.containers[*].name}{"\n"}{end}'
# istio-proxy 컨테이너가 보이는 pod에서:
kubectl -n pay exec deploy/frontend -c app -- curl -s --max-time 5 http://payment:8080
```

**4) ⚠️ 함정 포인트**

- 라벨을 지금 붙여도 **이미 떠 있는 pod에는 sidecar가 자동 주입되지 않는다.** 문제에서 워크로드 재기동을 요구하면 `kubectl -n pay rollout restart deploy`를 수행.
- PeerAuthentication 이름을 `default`로, **네임스페이스에 정확히** 만들어야 네임스페이스 전체에 적용된다. 클러스터 전체 적용은 istio 루트 네임스페이스(istio-system)에 만드는 변형 문제로 나온다.
- `PERMISSIVE`는 평문도 허용하는 마이그레이션용 모드다. 문제 요구가 "강제"라면 반드시 `STRICT`.

**예상 소요시간:** 6분 | **부분점수 포인트:** 라벨 확인/부여 → PeerAuthentication 생성(이름·ns·모드) → 평문 거부 검증.

</details>

---

## Task 10 Secret 추출과 etcd 평문 확인 (6%)

> **배점 6% | 도메인: Minimize Microservice Vulnerabilities | 클러스터: k8s-s1**

```bash
kubectl config use-context k8s-s1
```

1. A Secret `db-creds` exists in namespace `db`. Extract the decoded values of keys `username` and `password` and write them to `/opt/course/10/username.txt` and `/opt/course/10/password.txt`.
2. Create a new generic Secret `db-token` in namespace `db` with key `token` and value `Sup3rT0ken!`.
3. Create a Pod `db-client` in namespace `db` (image `busybox:1.36`, command `sleep 1d`) that mounts Secret `db-token` read-only at `/etc/db-token`.
4. SSH into `cks-master1` and use `etcdctl` to check whether Secret `db-token` is stored encrypted or in plaintext. Write either `encrypted` or `plaintext` to `/opt/course/10/etcd-state.txt` on the main terminal.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

Secret은 base64 인코딩일 뿐 암호화가 아니다. etcd에 암호화 저장되는지는 EncryptionConfiguration 적용 여부에 달렸고, etcdctl로 직접 키를 읽어 `k8s:enc:` 접두어 유무로 판별한다.

**2) 단계별 명령어/YAML**

```bash
mkdir -p /opt/course/10
kubectl -n db get secret db-creds -o jsonpath='{.data.username}' | base64 -d > /opt/course/10/username.txt
kubectl -n db get secret db-creds -o jsonpath='{.data.password}' | base64 -d > /opt/course/10/password.txt

kubectl -n db create secret generic db-token --from-literal=token='Sup3rT0ken!'
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: db-client
  namespace: db
spec:
  containers:
  - name: app
    image: busybox:1.36
    command: ["sh", "-c", "sleep 1d"]
    volumeMounts:
    - name: token
      mountPath: /etc/db-token
      readOnly: true
  volumes:
  - name: token
    secret:
      secretName: db-token
```

```bash
kubectl apply -f pod10.yaml

ssh cks-master1
sudo ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/db/db-token | hexdump -C | head -20
exit
```

**3) 검증 방법**

```bash
kubectl -n db exec db-client -- cat /etc/db-token/token   # Sup3rT0ken!
# etcd 출력에 Sup3rT0ken! 문자열이 그대로 보이면 평문
echo plaintext > /opt/course/10/etcd-state.txt
```

etcd 값이 `k8s:enc:aescbc:v1:...`로 시작하면 `encrypted`라고 적는다. (참고: 암호화를 적용하려면 `apiserver.config.k8s.io/v1`의 EncryptionConfiguration을 만들고 kube-apiserver에 `--encryption-provider-config`를 지정하며, providers **첫 번째** 항목으로 암호화된다. 기존 secret 일괄 재암호화는 `kubectl get secrets -A -o json | kubectl replace -f -`.)

**4) ⚠️ 함정 포인트**

- `base64 -d`를 빼먹고 인코딩된 값을 제출하는 실수가 잦다. 파일 내용을 cat으로 재확인하라.
- etcd 키 경로는 `/registry/secrets/<namespace>/<name>` 형식이다. 네임스페이스를 빼면 빈 결과가 나온다.
- etcdctl 인증서 3종(`--cacert/--cert/--key`)을 빠뜨리면 연결 자체가 실패한다.
- 답안 파일 위치(main terminal)와 조회 위치(master 노드)가 다르다. 노드에서 확인한 결과를 main terminal 파일에 적어야 한다.

**예상 소요시간:** 8분 | **부분점수 포인트:** 값 추출 2개 → secret 생성 → pod 마운트(readOnly) → etcd 판별 결과.

</details>

---

## Task 11 Deployment SecurityContext (7%)

> **배점 7% | 도메인: Minimize Microservice Vulnerabilities | 클러스터: k8s-s1**

```bash
kubectl config use-context k8s-s1
```

Namespace `secure-apps` contains a Deployment `web-secure` (image `nginxinc/nginx-unprivileged:1.27`, container name `web`, listening on port `8080`). Adjust the Deployment so that **all** of the following requirements hold:

1. The container runs as user ID `3000` and as non-root.
2. Privilege escalation is not allowed.
3. All capabilities are dropped; only `NET_BIND_SERVICE` is added.
4. The root filesystem is read-only.
5. The `RuntimeDefault` seccomp profile is used.

The Deployment must reach `Ready` state again. Mount writable `emptyDir` volumes where the application needs to write.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

pod 레벨(seccomp, runAsUser/runAsNonRoot)과 container 레벨(capabilities, readOnlyRootFilesystem, allowPrivilegeEscalation)을 나눠 적용한다. readOnlyRootFilesystem을 켜면 앱이 쓰는 경로가 전부 막히므로, 쓰기가 필요한 경로만 emptyDir로 뚫어주는 것이 컨테이너 불변성(immutability)의 정석이다.

**2) 단계별 명령어/YAML**

```bash
kubectl -n secure-apps edit deploy web-secure
```

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 3000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: web
        image: nginxinc/nginx-unprivileged:1.27
        ports:
        - containerPort: 8080
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir: {}
```

**3) 검증 방법**

```bash
kubectl -n secure-apps rollout status deploy web-secure
kubectl -n secure-apps exec deploy/web-secure -- id          # uid=3000
kubectl -n secure-apps exec deploy/web-secure -- touch /etc/x || echo "READ-ONLY OK"
kubectl -n secure-apps exec deploy/web-secure -- touch /tmp/x && echo "TMP WRITABLE"
```

**4) ⚠️ 함정 포인트**

- `readOnlyRootFilesystem`과 `capabilities`는 **container 레벨에만** 존재하는 필드다. pod 레벨에 쓰면 스키마 오류가 난다.
- nginx-unprivileged는 pid 파일과 캐시를 `/tmp`에 쓴다. emptyDir 마운트를 빼먹으면 `CrashLoopBackOff` — Ready 조건을 만족하지 못해 대부분의 점수를 잃는다. 원인 확인은 `kubectl logs`.
- `drop: [ALL]`을 빼고 add만 하면 "모든 capability 제거" 요구를 충족하지 못한다. drop과 add는 함께 명시.
- 참고: 불변성 세트에는 `privileged: false`, `hostPID/hostIPC/hostNetwork: false`도 함께 나온다. 요구사항 목록을 하나씩 체크하며 작업하라.

**예상 소요시간:** 8분 | **부분점수 포인트:** 요구사항 5개가 개별 채점 + Deployment Ready 여부가 별도 배점.

</details>

---

## Task 12 bom으로 SBOM 생성 (7%)

> **배점 7% | 도메인: Supply Chain Security | 클러스터: k8s-s3**

```bash
kubectl config use-context k8s-s3
```

Work on the main terminal, where the `bom` tool is installed.

1. Generate an SPDX SBOM for the image `nginx:1.27` and save it to `/opt/course/12/sbom.spdx`.
2. Inspect the document with `bom document outline`.
3. Find the version of the package `openssl` contained in the image and write **only the version string** to `/opt/course/12/openssl-version.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

SBOM 생성은 `bom generate`, 내용 확인은 `bom document outline`이다. SPDX tag-value 문서에서 특정 패키지 버전은 outline 출력이나 파일 grep으로 찾는다. 시험 중 문서는 `kubernetes-sigs.github.io/bom/cli-reference/`가 허용된다.

**2) 단계별 명령어/YAML**

```bash
mkdir -p /opt/course/12
bom generate --image nginx:1.27 --output /opt/course/12/sbom.spdx

# 문서 구조(패키지 트리) 확인
bom document outline /opt/course/12/sbom.spdx | less

# openssl 패키지 항목 찾기
bom document outline /opt/course/12/sbom.spdx | grep -i openssl
grep -iA3 'openssl' /opt/course/12/sbom.spdx | grep -iE 'name|version'
```

출력에서 openssl의 버전 문자열(예: `3.0.x-...` 형태)을 확인해 그 값만 저장한다.

```bash
echo '<확인한 버전 문자열>' > /opt/course/12/openssl-version.txt
```

**3) 검증 방법**

```bash
head -20 /opt/course/12/sbom.spdx        # SPDXVersion 헤더가 보이면 정상 SPDX 문서
cat /opt/course/12/openssl-version.txt   # 버전 문자열만 한 줄
```

**4) ⚠️ 함정 포인트**

- 이미지 SBOM 생성은 `--image` 플래그다. 로컬 디렉토리(`--dirs`)나 파일과 혼동하지 말 것.
- 이미지 pull이 필요하므로 첫 실행은 시간이 걸린다. 기다리는 동안 다른 문제를 진행하라.
- "버전 문자열만" 제출하라는 지시를 지켜라. `openssl 3.x.y` 전체 라인을 넣으면 감점될 수 있다.
- 변형 문제로 **trivy 기반 SBOM**(`trivy image --format spdx-json --output 파일 이미지`)과 취약점 스캔(`trivy image --severity CRITICAL,HIGH 이미지`)도 같이 연습해 두라.

**예상 소요시간:** 7분 | **부분점수 포인트:** SBOM 파일 생성(형식 SPDX) → outline 사용 → 버전 파일 정확성.

</details>

---

## Task 13 Kubesec 스캔과 개선 (6%)

> **배점 6% | 도메인: Supply Chain Security | 클러스터: k8s-s3**

```bash
kubectl config use-context k8s-s3
```

A Pod manifest is provided at `/opt/course/13/pod.yaml` on the main terminal.

1. Scan the manifest with `kubesec` and save the full JSON result to `/opt/course/13/report-before.json`.
2. Fix the issues reported in the `critical` and `advise` sections by editing `/opt/course/13/pod.yaml` (the Pod's purpose must not change).
3. Scan again and save the result to `/opt/course/13/report-after.json`. The score must have improved. The Pod does not need to be deployed.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

kubesec은 manifest를 정적 분석해 `score`와 함께 `critical`(감점 요인)·`advise`(권장 개선) 목록을 JSON으로 반환한다. critical부터 제거하고 advise 항목(securityContext 강화, 리소스 제한 등)을 반영하면 점수가 오른다.

**2) 단계별 명령어/YAML**

```bash
kubesec scan /opt/course/13/pod.yaml > /opt/course/13/report-before.json
jq '.[0].score, .[0].scoring.critical' /opt/course/13/report-before.json
```

제공 manifest 예시(문제 상황): `privileged: true`가 critical로 잡힌다.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: report-api
spec:
  containers:
  - name: api
    image: report-api:2.1
    securityContext:
      privileged: true
```

advise를 반영해 수정한 manifest:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: report-api
spec:
  serviceAccountName: report-api-sa
  containers:
  - name: api
    image: report-api:2.1
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 500m
        memory: 256Mi
    securityContext:
      runAsNonRoot: true
      runAsUser: 10001
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
```

```bash
kubesec scan /opt/course/13/pod.yaml > /opt/course/13/report-after.json
```

**3) 검증 방법**

```bash
jq '.[0].score' /opt/course/13/report-before.json /opt/course/13/report-after.json
# after 점수 > before 점수, critical 배열은 비어 있어야 함
jq '.[0].scoring.critical' /opt/course/13/report-after.json
```

**4) ⚠️ 함정 포인트**

- `privileged: true` 같은 critical 항목은 점수를 크게 깎는다. **critical을 먼저 전부 제거**하는 것이 최우선.
- kubesec 바이너리가 없으면 API 방식도 가능: `curl -sSX POST --data-binary @pod.yaml https://v2.kubesec.io/scan` (시험 환경에서는 로컬 바이너리가 기본).
- before 리포트를 저장하기 **전에** 파일을 고치면 전후 비교 증빙이 사라진다. 순서를 지켜라.
- 같은 계열 도구로 **KubeLinter**(`kube-linter lint 파일`)도 출제 범위다. 명령 형태만 기억해 두면 된다.

**예상 소요시간:** 7분 | **부분점수 포인트:** before 리포트 → manifest 수정(critical 제거/advise 반영) → after 리포트·점수 향상.

</details>

---

## Task 14 ValidatingAdmissionPolicy 레지스트리 제한 (7%)

> **배점 7% | 도메인: Supply Chain Security | 클러스터: k8s-s1**

```bash
kubectl config use-context k8s-s1
```

Company policy requires that in namespaces labeled `registry=restricted` only images from the internal registry `registry.internal.example.com` may run. Images from `docker.io` or any other registry must be rejected.

1. Create a `ValidatingAdmissionPolicy` named `allowed-registry` that validates `CREATE` and `UPDATE` of Pods: every container and initContainer image must start with `registry.internal.example.com/`. Use the denial message `only registry.internal.example.com images are allowed`.
2. Create a `ValidatingAdmissionPolicyBinding` named `allowed-registry-binding` with validation action `Deny`, matching namespaces labeled `registry=restricted`.
3. Label namespace `vap-test` with `registry=restricted` and verify that a Pod with image `docker.io/nginx:1.27` is rejected, while a Pod with image `registry.internal.example.com/base/nginx:1.27` passes admission.

Save both manifests to `/opt/course/14/`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

ValidatingAdmissionPolicy(v1.30 GA)는 CEL 표현식으로 어드미션 검증을 선언하는 in-tree 기능이다. Policy(검증 로직)와 Binding(적용 대상)을 분리해 만든다. 외부 컨트롤러가 필요한 OPA Gatekeeper와 달리 추가 설치가 없다.

**2) 단계별 명령어/YAML**

```bash
mkdir -p /opt/course/14
vim /opt/course/14/policy.yaml
```

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: allowed-registry
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      operations: ["CREATE", "UPDATE"]
      resources: ["pods"]
  validations:
  - expression: "object.spec.containers.all(c, c.image.startsWith('registry.internal.example.com/'))"
    message: "only registry.internal.example.com images are allowed"
  - expression: "!has(object.spec.initContainers) || object.spec.initContainers.all(c, c.image.startsWith('registry.internal.example.com/'))"
    message: "only registry.internal.example.com images are allowed"
```

```bash
vim /opt/course/14/binding.yaml
```

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: allowed-registry-binding
spec:
  policyName: allowed-registry
  validationActions:
  - Deny
  matchResources:
    namespaceSelector:
      matchLabels:
        registry: restricted
```

```bash
kubectl apply -f /opt/course/14/policy.yaml -f /opt/course/14/binding.yaml
kubectl label ns vap-test registry=restricted
```

**3) 검증 방법**

```bash
# 거부되어야 함 (메시지에 policy 이름이 표시됨)
kubectl -n vap-test run bad --image=docker.io/nginx:1.27
# 기대: ... denied the request: ... only registry.internal.example.com images are allowed

# 어드미션은 통과해야 함 (이미지 pull 실패는 무관 — 오브젝트 생성 자체가 성공하면 됨)
kubectl -n vap-test run good --image=registry.internal.example.com/base/nginx:1.27
kubectl -n vap-test get pod good
```

**4) ⚠️ 함정 포인트**

- CEL에서 없는 필드를 참조하면 평가 오류가 난다. `initContainers`처럼 선택적 필드는 반드시 `!has(...) ||` 가드로 감싸라.
- Binding의 `validationActions`를 `[Warn]`이나 `[Audit]`로 두면 위반이 거부되지 않는다. "reject" 요구면 **Deny**.
- Policy만 만들고 **Binding을 빠뜨리면 아무 효과가 없다.** 둘은 항상 세트.
- 네임스페이스 라벨을 붙이는 것을 잊으면 검증 pod가 그냥 생성돼 버린다. `kubectl get ns vap-test --show-labels`로 확인.
- `startsWith`의 접미 `/`가 없으면 `registry.internal.example.com.evil.io` 같은 우회가 가능하다. 경로 구분자까지 포함해 비교하라.

**예상 소요시간:** 9분 | **부분점수 포인트:** Policy(CEL 정확성) → Binding(Deny·라벨 셀렉터) → 라벨링·거부/허용 검증 → 파일 제출.

</details>

---

## Task 15 Falco 룰 오버라이드 (7%)

> **배점 7% | 도메인: Monitoring, Logging & Runtime Security | 클러스터: k8s-s2**

```bash
kubectl config use-context k8s-s2
ssh cks-worker2
```

Falco is installed as a systemd service on node `cks-worker2`.

1. Find the existing default rule that triggers when a shell is spawned inside a container (rule name `Terminal shell in container` in `/etc/falco/falco_rules.yaml`).
2. Override this rule in `/etc/falco/falco_rules.local.yaml` so that its output contains **exactly** the following fields in this format: `%evt.time,%user.name,%container.id,%proc.cmdline`
3. Restart Falco, trigger the rule by executing a shell in any running container, and save one resulting log line to `/opt/course/15/falco-output.txt` on the node.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

Falco는 `/etc/falco/falco_rules.local.yaml`에 **같은 rule 이름**으로 다시 정의하면 기본 룰을 오버라이드한다(local 파일이 나중에 로드됨). 기본 룰의 condition을 그대로 복사하고 output만 바꾸는 것이 안전하다.

**2) 단계별 명령어/YAML**

```bash
# 기본 룰 확인 — condition 블록을 그대로 복사해 온다
grep -B2 -A12 'Terminal shell in container' /etc/falco/falco_rules.yaml

sudo vim /etc/falco/falco_rules.local.yaml
```

```yaml
- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
  output: "%evt.time,%user.name,%container.id,%proc.cmdline"
  priority: NOTICE
  tags: [container, shell, mitre_execution]
```

(condition은 설치된 Falco 버전의 기본 룰에서 **그대로 복사**하라. `spawned_process`, `shell_procs`, `container_entrypoint`는 기본 룰 파일에 정의된 macro라서 local 파일에서 재정의 없이 사용할 수 있다.)

```bash
sudo systemctl restart falco
sudo systemctl status falco --no-pager   # active (running) 확인
```

**3) 검증 방법**

```bash
# main terminal(또는 다른 셸)에서 룰 트리거
kubectl config use-context k8s-s2
kubectl -n default exec -it <아무 실행중인 pod> -- sh -c 'echo shell-triggered'

# 노드에서 이벤트 확인 (rule 이름은 output에 없으므로 NOTICE와 필드 형태로 식별)
sudo journalctl -u falco --since "5 minutes ago" --no-pager | grep -E 'Notice|NOTICE' | tail -5

mkdir -p /opt/course/15
sudo journalctl -u falco --since "5 minutes ago" --no-pager \
  | grep -E 'Notice|NOTICE' | tail -1 > /opt/course/15/falco-output.txt
cat /opt/course/15/falco-output.txt   # 예: 10:41:22.123456789,root,3ad9f2a1c4d2,sh -c echo shell-triggered
```

**4) ⚠️ 함정 포인트**

- output을 바꾸면 로그에 "Terminal shell in container" 문자열이 **더 이상 나오지 않는다.** 룰 이름으로 grep하면 못 찾으니 priority(NOTICE)나 필드 패턴으로 찾아라.
- 기본 룰 파일(`falco_rules.yaml`)을 직접 수정하지 말 것 — 업그레이드 시 덮어써지고, 시험 채점도 local 파일 오버라이드를 기대한다.
- 필드 구분자·순서를 문제 지시와 **정확히 동일하게** 맞춰라(`%evt.time,%user.name,%container.id,%proc.cmdline`). 임의로 공백을 넣으면 감점.
- 재시작 없이 룰이 반영되길 기대하지 마라. `systemctl restart falco` 후 status 확인까지가 한 세트. 문법이 틀리면 falco가 기동 실패하므로 `journalctl -u falco`로 즉시 확인.
- 일정 시간만 수집하고 싶으면 서비스 대신 `timeout 30s falco` 또는 `falco -M 30`도 가능하다(서비스가 돌고 있으면 먼저 stop).

**예상 소요시간:** 9분 | **부분점수 포인트:** 룰 위치 파악 → local 파일 오버라이드(이름 일치·output 형식) → 재시작 후 정상 동작 → 트리거 로그 파일 제출.

</details>

---

## Task 16 Audit Log 분석과 RBAC 축소 (7%)

> **배점 7% | 도메인: Monitoring, Logging & Runtime Security | 클러스터: k8s-s1**

```bash
kubectl config use-context k8s-s1
```

An API server audit log is provided at `/opt/course/16/audit.log` on the main terminal.

1. Using `jq`, find all events in which the Secret `prod-db-pass` in namespace `prod` was accessed.
2. Write a report to `/opt/course/16/report.txt` containing for each access: the username, the verb and the `requestReceivedTimestamp`.
3. The offending ServiceAccount obtained its access through Role `report-role` in namespace `prod`. Modify this Role so it no longer grants **any** access to Secrets, while keeping all its other permissions. Verify the change with `kubectl auth can-i`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

audit 로그는 한 줄에 JSON 이벤트 하나다. `objectRef`(resource/namespace/name)로 대상 secret 접근 이벤트를 걸러내고, `user.username`·`verb`·`requestReceivedTimestamp`를 추출한다. 이후 해당 계정의 Role에서 secrets 권한만 제거한다.

**2) 단계별 명령어/YAML**

```bash
mkdir -p /opt/course/16

jq -r 'select(.objectRef.resource=="secrets"
        and .objectRef.namespace=="prod"
        and .objectRef.name=="prod-db-pass")
       | "\(.user.username) \(.verb) \(.requestReceivedTimestamp)"' \
  /opt/course/16/audit.log | tee /opt/course/16/report.txt
# 예: system:serviceaccount:prod:report-sa get 2026-07-21T09:14:22.123456Z
```

```bash
kubectl -n prod get role report-role -o yaml
kubectl -n prod edit role report-role
```

rules에서 `secrets`만 제거한다(다른 리소스 권한은 유지).

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: report-role
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["configmaps", "pods"]   # secrets 를 목록에서 삭제
  verbs: ["get", "list"]
```

**3) 검증 방법**

```bash
kubectl auth can-i get secrets -n prod \
  --as=system:serviceaccount:prod:report-sa        # no
kubectl auth can-i list configmaps -n prod \
  --as=system:serviceaccount:prod:report-sa        # yes (기존 권한 유지)
kubectl auth can-i --list -n prod \
  --as=system:serviceaccount:prod:report-sa
```

**4) ⚠️ 함정 포인트**

- 로그 줄 일부가 JSON이 아닐 수 있으면 `jq -R 'fromjson? | ...'` 패턴으로 파싱 오류를 건너뛸 수 있다.
- `objectRef.name` 없이 resource만 거르면 다른 secret 접근까지 섞인다. **세 조건(resource/namespace/name)을 모두** 걸어라.
- Role에서 secrets를 지울 때 rule 하나에 여러 리소스가 묶여 있으면 **secrets만 빼고 나머지는 남겨야** 한다. rule 전체 삭제는 과잉 조치로 감점.
- RoleBinding이 아니라 **Role을 고치라는 지시**다. 바인딩을 지우면 다른 권한까지 사라진다.
- audit 로그 레벨은 Policy(`audit.k8s.io/v1`)의 None/Metadata/Request/RequestResponse로 결정되며 **첫 매칭 룰이 적용**된다 — 로그에 requestObject가 없는 것은 Metadata 레벨로 기록됐기 때문일 수 있다.

**예상 소요시간:** 9분 | **부분점수 포인트:** jq 필터 정확성·리포트 파일 → Role 수정(secrets 제거·기존 권한 보존) → can-i 검증.

</details>

---

## 채점표

목표: **67점 이상**. 각 Task의 해설 속 "부분점수 포인트"를 기준으로 스스로 부분 점수를 매겨라.

| Task | 주제 | 도메인 | 배점 | 자가 채점 |
|------|------|--------|------|-----------|
| 01 | CiliumNetworkPolicy L3/L4 | Cluster Setup | 7% | |
| 02 | Metadata endpoint egress 차단 | Cluster Setup | 5% | |
| 03 | etcd CIS 하드닝 | Cluster Setup | 6% | |
| 04 | CSR 사용자 + RBAC | Cluster Hardening | 7% | |
| 05 | kubelet 하드닝 | Cluster Hardening | 7% | |
| 06 | cluster-admin 바인딩 정리 | Cluster Hardening | 5% | |
| 07 | seccomp Localhost 프로파일 | System Hardening | 6% | |
| 08 | SSH 하드닝 + sudo 제거 | System Hardening | 4% | |
| 09 | Istio mTLS STRICT | Minimize Microservice Vulnerabilities | 6% | |
| 10 | Secret 추출 + etcd 평문 확인 | Minimize Microservice Vulnerabilities | 6% | |
| 11 | Deployment securityContext | Minimize Microservice Vulnerabilities | 7% | |
| 12 | bom SBOM 생성/분석 | Supply Chain Security | 7% | |
| 13 | Kubesec 스캔/개선 | Supply Chain Security | 6% | |
| 14 | ValidatingAdmissionPolicy 레지스트리 제한 | Supply Chain Security | 7% | |
| 15 | Falco 룰 오버라이드 | Monitoring, Logging & Runtime Security | 7% | |
| 16 | Audit log 분석 + RBAC 축소 | Monitoring, Logging & Runtime Security | 7% | |
| **합계** | | | **100%** | |

> **📌 암기 포인트:** 도메인 가중치 — Cluster Setup 15%, Cluster Hardening 15%, System Hardening 10%, Minimize Microservice Vulnerabilities 20%, Supply Chain Security 20%, Monitoring/Logging/Runtime Security 20%. 이 세트의 배점 분포도 이 가중치를 기준으로 근사하게 구성했다.

---

## 🎯 시험 직전 체크리스트

- [ ] 문제마다 첫 줄 `kubectl config use-context` 실행 — 컨텍스트 미전환은 통째로 0점
- [ ] SSH로 노드에 들어갔으면 작업 후 반드시 `exit` — 다음 문제를 노드 위에서 풀지 않기
- [ ] 답안 파일 경로(`/opt/course/N/...`)와 **파일이 위치할 호스트**(main terminal vs 노드)를 문제에서 재확인
- [ ] static pod(manifest) 수정 전 `/tmp`로 백업, 수정 후 30초~1분 대기, 안 뜨면 `crictl ps -a` + `journalctl -u kubelet`
- [ ] NetworkPolicy: `policyTypes` 명시, egress에는 DNS(UDP/TCP 53) 허용 여부 검토, namespaceSelector+podSelector의 AND/OR 구분
- [ ] PSA 라벨 형식 암기: `pod-security.kubernetes.io/enforce=restricted` (모드 enforce/audit/warn, 레벨 privileged/baseline/restricted, `enforce-version`으로 버전 고정)
- [ ] AppArmor는 v1.30+ GA 필드 `securityContext.appArmorProfile` (RuntimeDefault/Localhost/Unconfined) — 과거 annotation 방식은 deprecated
- [ ] seccomp `localhostProfile`은 `/var/lib/kubelet/seccomp/` 기준 **상대경로**
- [ ] kubelet 하드닝 4종: anonymous false / webhook true / authorization Webhook / readOnlyPort 0 → `systemctl restart kubelet`
- [ ] RBAC 위험 verb: `escalate`, `bind`, `impersonate`, `*` — 점검은 `kubectl auth can-i --list --as=system:serviceaccount:NS:SA`
- [ ] ServiceAccount 토큰: `automountServiceAccountToken: false` (Pod 레벨이 SA 레벨보다 우선)
- [ ] EncryptionConfiguration: providers **첫 항목으로 암호화**, `identity: {}` 위치가 읽기 호환성 결정, 일괄 재암호화는 `kubectl get secrets -A -o json | kubectl replace -f -`
- [ ] RuntimeClass(gVisor): `handler: runsc`, pod에 `runtimeClassName`, 검증은 pod 안 `dmesg`의 gVisor 문자열
- [ ] 바이너리 검증: `sha512sum` 출력과 공식 체크섬 `diff`
- [ ] Audit Policy: 첫 매칭 룰 적용, apiserver에 policy 파일·로그 경로 **hostPath 마운트 추가** 잊지 않기
- [ ] Falco 커스텀 룰은 `/etc/falco/falco_rules.local.yaml`에 같은 이름으로 오버라이드
- [ ] cosign 서명/검증: `cosign sign --key cosign.key 이미지` / `cosign verify --key cosign.pub 이미지`
- [ ] Dockerfile 보안: 태그 고정(latest 금지), USER 비루트, 멀티스테이지, secret을 ENV/ARG에 넣지 않기
- [ ] 허용 문서 북마크: kubernetes.io/docs, falco.org/docs, docs.cilium.io/en/stable, istio.io/latest/docs, etcd.io/docs, kubernetes-sigs.github.io/bom/cli-reference/

## 핵심 명령어 치트시트

```bash
# ---- 컨텍스트/노드 ----
kubectl config use-context k8s-s1
ssh cks-master1                                   # 작업 후 exit

# ---- static pod / 노드 디버깅 ----
sudo crictl ps -a | grep -E 'apiserver|etcd'
sudo journalctl -u kubelet -f
ls /var/log/pods/

# ---- kubelet 하드닝 ----
sudo vim /var/lib/kubelet/config.yaml             # anonymous/webhook/Webhook/readOnlyPort
sudo systemctl restart kubelet
curl -sk https://localhost:10250/pods             # 401이어야 정상

# ---- etcd 직접 조회 ----
sudo ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/<ns>/<name> | hexdump -C | head

# ---- RBAC 점검 ----
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa> -n <ns>
kubectl auth can-i get secrets -n <ns> --as=<user>
kubectl create token <sa>

# ---- CSR 사용자 ----
openssl genrsa -out user.key 2048
openssl req -new -key user.key -out user.csr -subj "/CN=user"
kubectl certificate approve <csr>
kubectl get csr <csr> -o jsonpath='{.status.certificate}' | base64 -d > user.crt
kubectl config set-credentials user --client-key=user.key --client-certificate=user.crt --embed-certs

# ---- PSA / seccomp / AppArmor ----
kubectl label ns <ns> pod-security.kubernetes.io/enforce=restricted
# seccomp: type Localhost + localhostProfile: profiles/xxx.json
sudo aa-status && sudo apparmor_parser -q /etc/apparmor.d/<profile>

# ---- Supply Chain ----
trivy image --severity CRITICAL,HIGH <image>
trivy image --format spdx-json --output sbom.json <image>
bom generate --image <image> --output sbom.spdx
bom document outline sbom.spdx
kubesec scan pod.yaml | jq '.[0].score, .[0].scoring'
kube-linter lint <dir|file>
cosign verify --key cosign.pub <image>

# ---- Runtime ----
sudo vim /etc/falco/falco_rules.local.yaml        # 같은 rule 이름으로 오버라이드
sudo systemctl restart falco && sudo journalctl -u falco --since "5 minutes ago"
sudo crictl ps && sudo crictl inspect <id> && sudo crictl logs <id>
ls -l /proc/<PID>/exe /proc/<PID>/cwd

# ---- Audit ----
jq 'select(.objectRef.resource=="secrets")
    | {user: .user.username, verb: .verb, time: .requestReceivedTimestamp}' audit.log
```

> **💡 시험 팁:** 이 모의고사를 90분 안에 85점 이상으로 풀 수 있다면 실전(120분, 합격선 67%)은 시간 여유가 있는 편이다. 모의고사 1회(기본기 세트)와 번갈아 풀며 약한 도메인을 좁혀라.
