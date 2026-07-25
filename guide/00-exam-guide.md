# CKS 시험 종합 가이드 (2026년판)

CKS(Certified Kubernetes Security Specialist) 시험의 규정·환경·전략을 한 문서로 정리한 수험 가이드 — 이 문서를 먼저 읽고 도메인별 학습(01~06)으로 넘어가라.

> **📌 이 문서가 다루는 것**: 시험 자체에 대한 모든 것. 2시간 동안 15~20개의 100% hands-on 과제를 풀어야 하고, 합격선은 **67%**다. 문제 하나하나가 실제 클러스터를 고치는 작업이므로, "아는 것"과 "제한 시간 안에 손으로 해내는 것"은 완전히 다르다. 전략 없이 들어가면 아는 문제도 놓친다.

## 목차

- [1. CKS 시험 개요](#1-cks-시험-개요)
- [2. 최신 변경사항 정리](#2-최신-변경사항-정리)
- [3. 도메인별 가중치와 출제 경향](#3-도메인별-가중치와-출제-경향)
- [4. 시험 환경 완전 정복](#4-시험-환경-완전-정복)
- [5. 시간 관리 전략](#5-시간-관리-전략)
- [6. 생산성 세팅](#6-생산성-세팅-시험-시작-직후-90초)
- [7. 6주 학습 로드맵](#7-6주-학습-로드맵)
- [8. 자주 하는 실수 TOP 10](#8-자주-하는-실수-top-10)
- [9. 허용 문서 활용법](#9-허용-문서-활용법)
- [🎯 시험 직전 체크리스트](#-시험-직전-체크리스트)
- [핵심 명령어 치트시트](#핵심-명령어-치트시트)

---

## 1. CKS 시험 개요

| 항목 | 내용 |
|---|---|
| 시험 시간 | **2시간 (120분)** |
| 문항 수 | 15~20개 hands-on 과제 (보통 **16개**) |
| 합격선 | **67%** |
| 응시 전제조건 | **유효한 CKA 자격**(Certified Kubernetes Administrator — CKS 응시에 필요한 선행 자격) 보유 (만료된 CKA로는 응시 불가) |
| 자격 유효기간 | **2년** |
| 재시험 | 무료 재시험(retake) **1회** 포함 |
| 시험 형식 | 100% 실습형. 원격 감독(proctored) 온라인 시험 |
| 시험 환경 | PSI Secure Browser 원격 데스크톱(XFCE — 경량 리눅스 데스크톱 환경) + 터미널 + Firefox(허용 문서만) |
| Kubernetes 버전 | **v1.35** (containerd 런타임, Ubuntu 노드) |
| 부분 점수 | 있음. 한 문제 안의 하위 작업별로 채점됨 |

### 등록 방법

1. Linux Foundation Training 포털(training.linuxfoundation.org)에서 CKS를 구매한다. 세일 기간(연말, Kubecon 시즌)에 할인 폭이 크다.
2. 구매 후 응시 자격은 일정 기간 유지되므로, 결제 후 학습 진도에 맞춰 시험 일정을 예약하면 된다.
3. 예약은 시험 포털에서 시간대를 선택한다. 재시험 1회가 포함되어 있으니 "떨어지면 끝"이라는 부담은 갖지 않아도 된다.

### killer.sh 시뮬레이터 (무료 2회 세션)

- CKS 구매 시 **killer.sh CKS 시뮬레이터 세션 2회**가 무료로 포함된다.
- 각 세션은 활성화 후 **36시간** 동안 열려 있고, 그 안에서 환경을 여러 번 리셋해 다시 풀 수 있다.
- **두 세션의 문제는 동일**하다. 따라서 1회차는 실전 모의(시간 재고 풀기), 2회차는 복습·재검증 용도로 쓰는 것이 정석이다.
- killer.sh는 실제 시험보다 어렵게 설계되어 있다. 여기서 시간 내에 60~70%를 풀면 실전은 합격권이다.

> **💡 시험 팁**: killer.sh 세션은 아껴두지 마라. 시험 2주 전과 3일 전에 각각 활성화하는 것이 가장 효율적이다. (7장 로드맵 참고)

---

## 2. 최신 변경사항 정리

### 2024-10-15 커리큘럼 대개편 (Before / After)

| 구분 | 개편 전 (2024-10-15 이전) | 개편 후 (현행) |
|---|---|---|
| Pod 보안 | PodSecurityPolicy(PSP) 중심 | **PSP 완전 삭제** (v1.25에서 제거됨) → Pod Security Admission(PSA) 라벨 |
| pod 간 암호화 | 커리큘럼에 없음 | **Cilium(WireGuard/IPsec) / Istio(mTLS — 양쪽이 서로 인증서로 인증하는 TLS) pod-to-pod 암호화** 추가 |
| SBOM | 커리큘럼에 없음 | **SBOM(Software Bill of Materials — 이미지에 포함된 소프트웨어·의존성 명세) 생성/분석**(bom — SBOM 생성 도구, trivy — 이미지 취약점 스캐너) 추가 |
| 정적 분석 | 명시적 도구 없음 | **Kubesec, KubeLinter**(YAML·매니페스트의 보안 설정을 검사하는 정적 분석 도구) 추가 |
| 폐기 기능 전반 | 구버전 기능 잔존 | v1.25+에서 제거된 기능 관련 내용 일괄 삭제 |

### 2026-07 현재 상태

- **2024-10-15 개편 이후 지금까지 도메인 구성과 가중치 변동 없음.** 아래 3장의 표가 현행 커리큘럼이다.
- 다만 **시험 환경의 Kubernetes 버전은 계속 최신을 따라간다**: 새 마이너 버전이 릴리스되면 **4~8주 내**에 시험 환경에 반영된다. 현재는 v1.35 기반.

> **💡 시험 팁 — 버전 추종 대응법**: kubernetes.io 문서를 항상 최신 버전 기준으로 학습하라. 특히 GA(General Availability — 정식 기능으로 안정화됨) 전환된 기능(AppArmor(리눅스 커널 강제접근제어 — 프로세스의 파일·자원 접근을 프로파일로 제한) `securityContext.appArmorProfile`은 v1.30+ GA, ValidatingAdmissionPolicy(웹훅 없이 API 서버가 규칙식으로 요청을 검증·거부하는 내장 정책)는 v1.30 GA)은 구식 방법(annotation 방식 AppArmor 등)이 아닌 **현행 방식**으로 답해야 한다. 시험 예약 전에 시험 환경 버전을 공식 페이지에서 한 번 확인하는 습관을 들여라.

---

## 3. 도메인별 가중치와 출제 경향

| 도메인 | 가중치 | 실제로 나오는 과제 유형 |
|---|---|---|
| Cluster Setup | 15% | NetworkPolicy 작성(default-deny, 선택적 허용), kube-bench(CIS 벤치마크로 클러스터 설정을 점검하는 도구) 실패 항목 Remediation 적용, Ingress(외부에서 들어오는 HTTP 트래픽을 서비스로 라우팅하는 리소스) TLS(Transport Layer Security — 전송 구간 암호화) 설정, 바이너리 sha512sum 검증, 메타데이터 엔드포인트(169.254.169.254) 차단 |
| Cluster Hardening | 15% | RBAC(Role-Based Access Control — 역할 기반 접근 제어) 최소권한 재구성, ServiceAccount 토큰 automount(파드에 SA 토큰을 자동 마운트하는 것) 차단, kube-apiserver 플래그 하드닝, kubeadm 클러스터 업그레이드, CSR(CertificateSigningRequest — 클러스터 CA에 인증서 서명을 요청하는 리소스)로 사용자 인증서 발급 |
| System Hardening | 10% | AppArmor/seccomp(허용된 시스템콜만 통과시키는 커널 필터) 프로파일 적용, kubelet 설정 하드닝, 노드의 불필요 서비스·패키지·포트 제거 |
| Minimize Microservice Vulnerabilities | 20% | PSA 네임스페이스 라벨, Secrets encryption at rest(EncryptionConfiguration — secret을 저장 시 암호화) + etcd(클러스터 상태·secret을 저장하는 키·값 저장소) 직접 확인, RuntimeClass(gVisor 등 샌드박스 런타임을 파드에 지정하는 리소스), Cilium/Istio pod 간 암호화, ValidatingAdmissionPolicy |
| Supply Chain Security | 20% | Dockerfile 보안 결함 수정, trivy 이미지 스캔, SBOM 생성/분석(bom/trivy), cosign(컨테이너 이미지에 서명하고 서명을 검증하는 도구) 서명·검증, Kubesec/KubeLinter 정적분석, 허용 레지스트리 제한 |
| Monitoring, Logging & Runtime Security | 20% | Falco(런타임에 비정상 행위를 탐지하는 도구) 룰 작성/오버라이드 + 출력 포맷 수정, Audit Policy(API 서버 감사 로그의 기록 범위를 정하는 정책) 구성, 침해 흔적 조사(crictl, /proc, audit 로그), 컨테이너 불변성(readOnlyRootFilesystem) 적용 |

> **📌 암기 포인트**: 뒤의 세 도메인(20% × 3 = 60%)이 승부처다. 특히 Falco와 Audit Policy, Supply Chain 도구 체인(trivy/bom/cosign)은 사실상 매 시험 출제된다고 보면 된다.

### 📝 문제로 이해하기 — 실제 CKS Task는 이렇게 생겼다

모든 문제는 첫 줄에 컨텍스트 전환 지시가 오고, 본문은 영어 명령형으로 리소스명·네임스페이스·저장 경로를 못박는다. 아래는 전형적인 예시다.

```
kubectl config use-context workload-prod
```

> Namespace `team-red` must enforce the `restricted` Pod Security Standard.
>
> 1. Add the required label to namespace `team-red` so that Pods violating the `restricted` standard are rejected.
> 2. Verify the enforcement by trying to create a Pod named `web` using image `nginx` in namespace `team-red`, and save the error message returned by the API server to `/opt/course/1/rejected.txt`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

PodSecurityPolicy는 v1.25에서 제거되었고, 현행 방식은 Pod Security Admission(PSA)의 네임스페이스 라벨이다. `enforce` 모드로 `restricted` 레벨을 걸면 위반 Pod 생성이 거부된다.

**2) 단계별 명령어**

```bash
kubectl config use-context workload-prod

# enforce 모드로 restricted 레벨 적용
kubectl label ns team-red pod-security.kubernetes.io/enforce=restricted

# nginx 기본 Pod는 restricted 요건(runAsNonRoot, seccompProfile,
# capabilities drop 등)을 충족하지 못해 거부된다. 에러는 stderr로 나온다.
mkdir -p /opt/course/1
kubectl run web --image=nginx -n team-red 2> /opt/course/1/rejected.txt
```

**3) 검증 방법**

```bash
kubectl get ns team-red --show-labels     # enforce 라벨 확인
cat /opt/course/1/rejected.txt            # "violates PodSecurity" 메시지 확인
```

**4) ⚠️ 함정 포인트**

- 모드 3종을 혼동하지 말 것: `enforce`(거부), `audit`(감사 로그만), `warn`(경고만). 문제가 "rejected"를 요구하면 반드시 `enforce`.
- PSA는 **이미 실행 중인 Pod에는 소급 적용되지 않는다**. 기존 Pod까지 정리하라는 지시가 있으면 삭제/재생성해야 한다.
- 버전 고정이 필요하면 `pod-security.kubernetes.io/enforce-version=v1.35` 라벨을 함께 쓴다.
- 에러 메시지는 stdout이 아니라 **stderr**다. `>`가 아니라 `2>`로 리다이렉트해야 파일에 담긴다.

</details>

---

## 4. 시험 환경 완전 정복

### PSI 원격 데스크톱의 실체

- 시험은 **PSI Secure Browser**를 설치해 치른다. 브라우저 안에 **XFCE 원격 데스크톱** 전체가 스트리밍되고, 그 안에서 터미널과 Firefox를 쓴다.
- 로컬 머신의 다른 앱, 메모, 클립보드는 쓸 수 없다. **모든 작업은 원격 데스크톱 안에서만** 이뤄진다.
- 원격 데스크톱 특성상 약간의 입력 지연이 있다. 긴 YAML을 손으로 치기보다 문서에서 복사하거나 `--dry-run=client -o yaml`로 생성하는 습관이 중요하다.

### 복사/붙여넣기 (가장 많이 당황하는 부분)

| 위치 | 복사 | 붙여넣기 |
|---|---|---|
| 터미널(XFCE) | `Ctrl+Shift+C` | `Ctrl+Shift+V` |
| Firefox / 문제 지문 | `Ctrl+C` | `Ctrl+V` |
| 공통 | 텍스트 드래그 선택 후 마우스 우클릭 → Copy/Paste도 동작 | 동일 |

> **⚠️ 함정**: 터미널에서 `Ctrl+C`는 복사가 아니라 **프로세스 중단**이다. 문제 지문의 리소스명은 반드시 복사해서 쓰고(오타 = 0점), 터미널에서는 `Ctrl+Shift+C/V`를 몸에 익혀라.

### Firefox — 허용 문서만 열람 가능

시험 중 Firefox로 접근할 수 있는 사이트는 아래 **8개가 전부**다(하위 경로 포함). 그 외 도메인은 차단된다.

1. `kubernetes.io/docs`
2. `kubernetes.io/blog`
3. `falco.org/docs`
4. `kubernetes-sigs.github.io/bom/cli-reference/`
5. `etcd.io/docs`
6. `kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/`
7. `docs.cilium.io/en/stable`
8. `istio.io/latest/docs`

### 터미널과 시험 UI 다루기

- 화면 구성은 좌측 문제 패널 + 우측 원격 데스크톱이다. 문제 패널에서 **flag(나중에 다시 볼 표시)** 를 켜고 끌 수 있고, 메모용 노트 기능이 제공된다.
- 각 문제 상단에 해당 문제의 컨텍스트(`kubectl config use-context ...`)와, 노드 작업이 필요한 경우 접속할 호스트(`ssh 노드명`)가 명시된다. **문제에 적힌 호스트 외에는 ssh로 들어가지 마라** — 규정 위반으로 간주될 수 있다.
- 기본 셸 사용자에서 루트 권한이 필요하면 `sudo -i`를 쓴다. 노드 작업(파일 수정, systemctl)은 대부분 루트가 필요하다.
- 터미널은 탭을 여러 개 열 수 있다. "kubectl용 탭 1개 + 노드 ssh용 탭 1개" 정도의 단순한 구성을 권한다.
- 원격 데스크톱이 멈추면 당황하지 말고 PSI 화면의 새로고침/재접속 기능을 쓰고, 안 되면 채팅으로 감독관에게 알려라. 기술 문제로 잃은 시간은 보정받을 수 있다.

### 시험 전 시스템 체크와 응시 규정

- **사전 시스템 체크**: PSI가 제공하는 호환성 테스트를 시험 며칠 전에 반드시 돌려라(웹캠, 마이크, 네트워크, Secure Browser 설치 가능 여부).
- **신분증**: 로마자 이름이 표기된 정부 발급 신분증(여권 권장). 등록한 이름과 일치해야 한다.
- **환경 점검**: 시험 시작 전 감독관이 웹캠으로 방 전체·책상 위·책상 아래를 스캔시킨다. 책상 위는 완전히 비워야 하며(음료는 투명 용기에 라벨 제거), 시험 중 자리 이탈·입 가림·혼잣말은 제지당할 수 있다.
- **모니터**: 단일 화면만 허용되는 것이 원칙이다(외장 모니터 1개로 대체 가능). 예약 전 최신 규정을 확인하라.
- 체크인 절차에 15~30분이 걸리므로 **예약 시간 30분 전에 접속**하라.

---

## 5. 시간 관리 전략

**120분 ÷ 16문제 = 문제당 평균 7분.** 이 숫자를 기준으로 모든 전략을 세운다.

### 3-패스 전략

| 패스 | 시간 | 하는 일 |
|---|---|---|
| 1차 (0~80분) | 문제당 최대 7분 | 순서대로 풀되, 7분 안에 안 풀리면 **flag(표시) 후 즉시 스킵** |
| 2차 (80~110분) | 남은 시간 배분 | flag한 문제 중 배점 높은 것부터 재도전 |
| 3차 (110~120분) | 마지막 10분 | 새 문제 손대지 말고 **검증만**: 만든 리소스 Running 확인, 답안 파일 경로 확인 |

### 부분 점수 전략

- 채점은 하위 작업 단위다. 한 문제를 완벽히 못 풀어도 **할 수 있는 하위 작업까지는 반드시 해놓고** 넘어가라. (예: Falco 룰은 못 고쳐도 로그 수집·파일 저장까지는 해둔다)
- 배점은 문제마다 다르며 화면에 표시된다. 배점 높은 문제(보통 apiserver 하드닝, Falco, Audit 등 복합 과제)에 2차 패스 시간을 몰아줘라.

> **💡 시험 팁**: apiserver static pod를 건드리는 문제는 실패 시 복구에 시간이 급격히 녹는다. 1차 패스에서는 자신 있을 때만 건드리고, 애매하면 flag 후 2차 패스 초반(멘탈과 시간이 남아 있을 때)에 처리하라.

> **⚠️ 함정**: 한 문제에 15분 이상 매몰되는 순간 합격선이 흔들린다. 67%는 "16문제 중 5개는 버려도 된다"는 뜻이기도 하다. 버릴 문제를 빨리 정하는 것도 실력이다.

### 문제 유형별 표준 소요 시간 감각

| 유형 | 목표 시간 | 비고 |
|---|---|---|
| 라벨/플래그 한두 개 수정 (PSA, SA automount) | 2~4분 | 1차 패스에서 즉시 처리 |
| NetworkPolicy / RBAC 작성 | 5~7분 | 문서에서 스켈레톤 복사 후 수정 |
| trivy/bom/cosign/kube-bench 도구 실행형 | 4~6분 | 명령만 알면 빠름. 출력 저장 경로 주의 |
| apiserver/kubelet 하드닝, Audit Policy | 8~10분 | 재기동 대기 시간 포함. 백업 필수 |
| Falco 룰, 침해 조사 | 8~12분 | 부분 점수 챙기고 과감히 손절 판단 |

### 30초 검증 루틴 (문제 끝날 때마다)

```bash
kubectl get pod -n NS POD          # Running/Ready 확인
kubectl describe pod -n NS POD | tail -20   # 이벤트에 에러 없는지
ls -l /opt/course/N/               # 답안 파일이 지시된 경로·이름인지
```

---

## 6. 생산성 세팅 (시험 시작 직후 90초)

시험 환경에는 `alias k=kubectl`과 kubectl 자동완성이 **기본 제공**된다. 추가로 아래만 세팅하면 충분하다.

```bash
# 1) YAML 생성 단축 변수 (매 문제에서 쓴다)
export do="--dry-run=client -o yaml"    # 사용: k run web --image=nginx $do > pod.yaml
export now="--force --grace-period 0"   # 사용: k delete pod web $now

# 2) vim 설정 — YAML 들여쓰기 2칸, 탭을 스페이스로
cat <<'EOF' >> ~/.vimrc
set tabstop=2
set shiftwidth=2
set expandtab
EOF

# 3) (자동완성이 k에 안 붙어 있을 때만)
source <(kubectl completion bash)
complete -o default -F __start_kubectl k
```

- **tmux는 불필요하다.** 터미널 탭/창을 새로 열 수 있고, 멀티플렉서 조작에 쓰는 뇌 용량이 아깝다. 평소 안 쓰던 도구를 시험장에서 쓰지 마라.
- ssh로 노드에 들어가면 위 설정이 없다는 점을 기억하라. 노드에서는 짧게 작업하고 바로 `exit`하는 것이 원칙이다.

> **📌 암기 포인트**: 세팅은 90초 안에 끝내라. `do`/`now` 변수와 vimrc 세 줄, 이 두 가지가 투자 대비 효과의 전부다.

---

## 7. 6주 학습 로드맵

이 저장소의 도메인 파일(01~06)을 아래 순서로 학습한다. 모의고사는 총 3회(killer.sh 2세션 + 재풀이 1회).

| 주차 | 학습 범위 | 목표 |
|---|---|---|
| 1주 | `00-exam-guide.md`(본 문서) → `01-cluster-setup.md` | NetworkPolicy를 문서 안 보고 작성, kube-bench 워크플로 체득 |
| 2주 | `02-cluster-hardening.md` → `03-system-hardening.md` | RBAC/SA/CSR, apiserver·kubelet 하드닝, AppArmor/seccomp 1회독 |
| 3주 | `04-minimize-microservice-vulnerabilities.md` | PSA, EncryptionConfiguration+etcd 검증, gVisor, Cilium/Istio 암호화 |
| 4주 | `05-supply-chain-security.md` → **모의 1회차: killer.sh 세션 1** (주말, 2시간 엄수) | trivy/bom/cosign/Kubesec/KubeLinter 손에 익히기 + 첫 실전 감각 |
| 5주 | `06-monitoring-logging-runtime-security.md` → 모의 1회차 오답 전 문제 재풀이 | Falco 룰과 Audit Policy를 빈 파일에서 작성 가능한 수준으로 |
| 6주 | 전 파일 2회독(문제만 다시 풀기) → **모의 2회차: killer.sh 세션 2**(시험 3일 전) → **모의 3회차: 같은 세션 내 리셋 후 재풀이**(시험 전날, 만점 목표) | 약점 도메인 마감, 치트시트 암기 |

### 회독 전략

- **1회독**: 개념 설명을 읽고 명령어를 실제 클러스터에서 직접 친다. 눈으로만 읽은 것은 시험장에서 재현되지 않는다.
- **2회독**: 각 파일의 "📝 문제로 이해하기" Task만 골라서, 해설을 접은 채로 시간 재며 푼다. 7분을 넘긴 문제만 해설을 정독한다.
- **3회독(시험 전 2일)**: 각 파일의 함정 콜아웃(⚠️)과 치트시트만 훑는다.
- 연습 환경은 killercoda.com의 무료 CKS 시나리오나 kubeadm 2노드 VM(마스터+워커, Ubuntu)을 권장한다.

---

## 8. 자주 하는 실수 TOP 10

1. **`kubectl config use-context`를 안 하고 푼다** — 다른 클러스터에 리소스를 만들면 0점. 매 문제 첫 줄의 컨텍스트 명령을 복사·실행하는 것을 기계적 습관으로.
2. **ssh로 노드에 들어간 뒤 `exit`를 안 한다** — 다음 문제의 kubectl을 워커 노드에서 실행하며 "왜 안 되지"로 5분을 태운다. 프롬프트의 호스트명을 항상 확인.
3. **static pod 수정 후 기다리지 않는다** — `/etc/kubernetes/manifests/kube-apiserver.yaml` 저장 후 kubelet이 재생성하는 데 30초~1분 걸린다. 즉시 `kubectl`이 안 붙는다고 설정을 더 건드리면 수렁에 빠진다.
4. **apiserver manifest 백업을 안 한다 (또는 잘못된 곳에 한다)** — 수정 전 반드시 백업하되, 백업 파일을 `/etc/kubernetes/manifests/` 안에 두면 kubelet이 그것도 static pod로 띄운다. 반드시 **디렉토리 밖**(예: `/root/`)에 복사.
5. **NetworkPolicy의 AND/OR 혼동** — 한 `from` 항목 안에 `namespaceSelector`와 `podSelector`를 같이 쓰면 AND, `-`로 분리된 별개 항목이면 OR. 그리고 egress 문제에서 **DNS(UDP/TCP 53) 허용을 빠뜨려** 검증이 실패한다.
6. **답안 파일 경로·파일명을 지시와 다르게 저장** — `/opt/course/N/...` 경로와 파일명은 채점 스크립트가 그대로 읽는다. 오타 하나로 그 하위 작업은 0점.
7. **검증을 생략한다** — Pod가 Running인지, `kubectl auth can-i`가 기대대로인지, `kubectl get ns --show-labels`가 맞는지 30초 검증이 몇 점을 지킨다.
8. **vim에서 탭 문자로 YAML을 망가뜨린다** — vimrc 설정(6장)을 안 하고 문서에서 복사·수정하다 `found a tab character` 파싱 에러. 에러가 나면 `:set list`로 탭을 찾아라.
9. **kubelet/서비스 재시작을 잊는다** — `/var/lib/kubelet/config.yaml` 수정 후 `systemctl restart kubelet`, Falco 설정 수정 후 재시작. 파일만 고치고 넘어가면 반영되지 않는다.
10. **시간 배분 실패** — 5장의 3-패스 전략을 지키지 않고 초반 어려운 문제에 매몰. flag 기능을 쓰는 데 주저함이 없어야 한다.

---

## 9. 허용 문서 활용법

시험 환경 Firefox에는 개인 북마크를 가져갈 수 없다. 따라서 **"어느 사이트에서 무슨 검색어로 찾는지"를 외워 가는 것**이 북마크의 대체물이다. 연습 때 아래 페이지들을 북마크해두고 경로 구조에 익숙해져라.

| 허용 사이트 | 시험 중 찾을 것 | 외워둘 검색어/페이지 |
|---|---|---|
| kubernetes.io/docs | 거의 모든 것: PSA, NetworkPolicy, Audit, seccomp/AppArmor, encryption, RuntimeClass, ValidatingAdmissionPolicy, kubeadm upgrade | "Pod Security Standards", "Network Policies", "Encrypting Confidential Data at Rest", "Auditing", "Restrict a Container's Syscalls with seccomp", "Restrict a Container's Access to Resources with AppArmor", "Runtime Class", "Validating Admission Policy" |
| kubernetes.io/blog | PSA 전환, 보안 기능 GA 발표 등 배경 자료 | 보조용. docs에서 못 찾을 때만 |
| falco.org/docs | 룰 문법(rule/macro/list), condition 연산자, **출력 필드 전체 목록** | "Rules", "Supported Fields for Conditions and Outputs" |
| kubernetes-sigs.github.io/bom/cli-reference/ | `bom generate` / `bom document outline` 플래그 | CLI reference 첫 페이지가 전부다 |
| etcd.io/docs | etcdctl 인증 플래그, get 문법 | "Interacting with etcd" (단, 자주 쓰는 명령은 암기가 빠름) |
| kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/ | Ingress annotation, TLS 관련 설정 | "annotations" 페이지 |
| docs.cilium.io/en/stable | CiliumNetworkPolicy 문법(endpointSelector, toFQDNs, toPorts), WireGuard/IPsec 암호화 활성화·확인 | "Network Policy", "Encryption" |
| istio.io/latest/docs | PeerAuthentication STRICT mTLS, sidecar injection 라벨 | "Mutual TLS Migration", "PeerAuthentication" 레퍼런스 |

> **💡 시험 팁**: kubernetes.io/docs의 검색창은 느리다. 검색보다 **URL 직접 타이핑**이 빠른 페이지(예: `/docs/concepts/security/pod-security-standards/`)는 경로째 외워라. 그리고 문서에서 YAML을 복사할 때는 코드블록 우상단의 복사 버튼을 쓰면 들여쓰기가 보존된다.

> **⚠️ 함정**: 허용 목록 밖 사이트(GitHub, Stack Overflow, 개인 블로그)는 열리지 않는다. 평소 연습 때부터 허용 문서만으로 문제를 푸는 훈련을 해야 시험장에서 "구글 없이 못 푸는" 병목이 안 생긴다.

---

## 🎯 시험 직전 체크리스트

**시험 1주 전**

- [ ] PSI 시스템 호환성 체크 완료 (웹캠/마이크/네트워크/Secure Browser)
- [ ] 로마자 신분증(여권) 준비, 등록 이름과 일치 확인
- [ ] killer.sh 세션 2 완료, 오답 문제 전부 재풀이
- [ ] 도메인 파일 01~06의 ⚠️ 함정 콜아웃만 1회 통독

**시험 전날**

- [ ] 모의 3회차(killer.sh 리셋 재풀이) — 2시간 내 완주
- [ ] 아래 치트시트 암기 상태 점검 (특히 etcdctl 인증 플래그, PSA 라벨, kubelet config 4종)
- [ ] 시험 공간 정리: 책상 비우기, 벽 포스터 제거, 조용한 환경 확보

**시험 당일**

- [ ] 예약 30분 전 접속, 체크인 시작
- [ ] 시작 직후 90초 세팅: `export do=...`, `export now=...`, vimrc 3줄
- [ ] 매 문제: ① 컨텍스트 명령 복사·실행 ② 리소스명은 지문에서 복사 ③ 작업 후 검증 ④ ssh 했으면 exit
- [ ] 7분 초과 시 flag 후 스킵 / 마지막 10분은 검증 전용

---

## 핵심 명령어 치트시트

```bash
# ---------- 세팅 ----------
export do="--dry-run=client -o yaml"
export now="--force --grace-period 0"

# ---------- PSA ----------
kubectl label ns NS pod-security.kubernetes.io/enforce=restricted
kubectl label ns NS pod-security.kubernetes.io/warn=baseline

# ---------- RBAC 점검 ----------
kubectl auth can-i --list --as=system:serviceaccount:NS:SA
kubectl create token SA명

# ---------- etcd에서 secret 직접 조회 ----------
ETCDCTL_API=3 etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/NS/이름

# ---------- 기존 secret 일괄 재암호화 ----------
kubectl get secrets -A -o json | kubectl replace -f -

# ---------- kubelet 하드닝 (/var/lib/kubelet/config.yaml) ----------
# authentication.anonymous.enabled: false
# authentication.webhook.enabled: true
# authorization.mode: Webhook
# readOnlyPort: 0
systemctl restart kubelet

# ---------- static pod 트러블슈팅 ----------
crictl ps -a
journalctl -u kubelet | tail -50
ls /var/log/pods/

# ---------- 바이너리 검증 ----------
sha512sum /usr/bin/kubelet   # 공식 릴리스 체크섬과 diff 비교

# ---------- Supply Chain ----------
trivy image --severity CRITICAL,HIGH 이미지명
trivy image --format spdx-json --output sbom.json 이미지명
bom generate --image 이미지 --output sbom.spdx
bom document outline sbom.spdx
cosign sign --key cosign.key 이미지
cosign verify --key cosign.pub 이미지
kubesec scan pod.yaml
kube-linter lint 디렉토리

# ---------- Falco ----------
systemctl status falco
timeout 30s falco            # 또는 falco -M 30
journalctl -u falco          # 로그 (또는 /var/log/syslog)
# 커스텀/오버라이드 룰: /etc/falco/falco_rules.local.yaml

# ---------- 침해 조사 ----------
crictl ps
crictl inspect CID
crictl logs CID
ls -l /proc/PID/exe /proc/PID/cwd
kubectl get events -A --sort-by=.lastTimestamp

# ---------- AppArmor (호스트) ----------
aa-status
apparmor_parser -q /etc/apparmor.d/프로파일파일

# ---------- gVisor 검증 ----------
kubectl exec POD -- dmesg | grep -i gvisor

# ---------- 인증서 사용자 생성 흐름 ----------
openssl genrsa -out user.key 2048
openssl req -new -key user.key -out user.csr -subj "/CN=user"
# CSR 리소스(certificates.k8s.io/v1, signerName: kubernetes.io/kube-apiserver-client,
# request: cat user.csr | base64 -w0) 생성 후:
kubectl certificate approve user
kubectl config set-credentials user --client-key=user.key --client-certificate=user.crt
```

### 자주 쓰는 YAML 스켈레톤

```yaml
# default-deny NetworkPolicy (해당 NS 전체 pod, ingress+egress 차단)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: NS
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
# EncryptionConfiguration (첫 provider로 암호화, identity는 읽기 폴백)
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <32바이트를 base64 인코딩한 값>
      - identity: {}
---
# RuntimeClass (gVisor)
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```

> **📌 암기 포인트**: EncryptionConfiguration은 `--encryption-provider-config` 플래그로 apiserver에 연결하고, **policy 파일·audit 로그와 마찬가지로 static pod에 hostPath volume/volumeMount를 추가해야** apiserver가 파일을 읽을 수 있다. 이 마운트 누락이 최다 실수다.

**합격의 공식**: 도메인 60%(뒤 3개)를 확실히 + 컨텍스트/검증 습관 + 7분 룰. 건투를 빈다.
