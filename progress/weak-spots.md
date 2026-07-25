# 약점 트래커 (Weak Spots Tracker)

CKS 학습 중 나온 오답·약점·모의고사 점수를 한곳에 누적 기록하는 개인 트래커다.
"어디가 약한지"를 데이터로 남겨 복습 우선순위와 다음 액션을 정하는 것이 목적이다.

시험 환경 기준: **Kubernetes v1.35, containerd 런타임, Ubuntu 노드 / 120분 / 약 16 Task / 합격선 67%(부분점수 있음).**

---

## 1. 사용법 — 기록 규약(표준)

이 파일은 손으로도 채울 수 있지만, 도우미들이 **동일한 규약**으로 자동 기록·집계한다. 규약이 흔들리면 `/weak-spots`의 빈도 집계가 무의미해지므로 **아래 표준을 모든 writer가 그대로 따른다.**

### 1-1. 단일 소스 — `§2 약점 로그`

모든 오답·약점은 **오직 `§2 약점 로그` 표에 한 줄(row)로 append** 한다. 다른 섹션에 오답을 흩뿌리지 않는다. 표준 열과 값:

| 열 | 값 규칙 |
|---|---|
| 날짜 | `YYYY-MM-DD` (오늘 날짜) |
| 도메인 | `D<n> <축약명>` — `D1 Cluster Setup` / `D2 Cluster Hardening` / `D3 System Hardening` / `D4 Microservice Vuln` / `D5 Supply Chain` / `D6 Monitoring·Runtime` |
| 토픽 | 짧은 토픽명 (예: `NetworkPolicy AND vs OR`) |
| 유형 | `오답` / `부분감점` / `시간초과` / `개념혼동` 중 하나 |
| 출처 | `mock-01 T9` / `quiz D4 Q3` / `grade` / `killer.sh S1` 처럼 어디서 나온 약점인지 |
| 근거 개념서 | `domains/0N-*.md` (복습할 파일) |

표준 한 줄 예시(이 문자열 형태를 그대로 씀):

```
| 2026-07-25 | D4 Microservice Vuln | PSA restricted 필수 필드 누락 | 오답 | mock-01 T9 | domains/04-minimize-microservice-vulnerabilities.md |
```

**중복 규칙**: 같은 `도메인+토픽`이 이미 있으면 새 행을 또 추가하지 말고, 기존 행 `토픽` 칸 끝에 `(재발 xN)`으로 재발 횟수만 올린다. 기존 기록은 절대 삭제·수정하지 않는다(append 우선).

### 1-2. 누가 무엇을 기록/갱신하나 (소유권)

| 주체 | §2 약점 로그 | §3 도메인별 현황 | §4 모의고사 점수 로그 | §5 killer.sh 로그 |
|---|---|---|---|---|
| **exam-proctor / `/mock-exam`** | 틀린 Task마다 1행 append | (건드리지 않음) | 세트 결과 1행 append | (건드리지 않음) |
| **`/grade`** | 감점 항목마다 1행 append | (건드리지 않음) | (건드리지 않음) | (건드리지 않음) |
| **`/quiz`** | 오답 문항마다 1행 append | (건드리지 않음) | (건드리지 않음) | (건드리지 않음) |
| **`/weak-spots`** | 읽기(집계) + 수동 입력 시 append | §2를 집계해 스냅샷 갱신 | 읽기 | 읽기 | 
| **사람(수동)** | append 가능 | 갱신 가능 | append 가능 | append 가능 |

즉 **오답의 유일한 기록처는 §2**이고, **§3은 §2를 요약한 뷰**(주로 `/weak-spots`가 갱신)이며, **§4·§5는 전용 로그**다. 날짜 형식은 항상 `YYYY-MM-DD`.

연계 흐름: 약점 확인(`/weak-spots`) → 개념 복습(`domains/*.md`, 필요 시 **cks-tutor**) → 랩드파이어 연습(`/quiz`) → 실습 막힘 시 **k8s-troubleshooter** → 재측정(`/mock-exam` 또는 `/grade`).

---

## 2. 약점 로그 (append-only) — 오답·약점의 단일 기록처

아래 표에 §1-1 규약대로 한 줄씩 append 한다. 첫 행은 형식 예시이므로, 실제 기록이 쌓이면 지워도 된다.

| 날짜 | 도메인 | 토픽 | 유형 | 출처 | 근거 개념서 |
|---|---|---|---|---|---|
| _예시_ | D1 Cluster Setup | NetworkPolicy AND vs OR 혼동 | 개념혼동 | quiz D1 Q3 | domains/01-cluster-setup.md |

---

## 3. 도메인별 현황 (요약 스냅샷)

`§2 약점 로그`를 도메인·토픽으로 집계한 **요약 뷰**다. 주로 `/weak-spots`가 갱신하고, writer(exam-proctor·grade·quiz)는 여기를 직접 건드리지 않는다. 아래는 6개 도메인 대표 토픽의 seed 행(초기 상태 `미착수`)이다. 학습하며 `시도횟수 / 상태 / 마지막 복습일 / 다음 액션`을 갱신한다.

> 상태 4단계: `미착수`(아직 안 봄) → `약함`(틀리거나 막힘) → `보통`(도움 있으면 풀림) → `강함`(제한시간 내 무보조로 정확). 같은 토픽을 연속 2회 정확히 풀면 한 단계↑, 틀리면 한 단계↓.

### Domain 1 — Cluster Setup (15%)

| 도메인 | 토픽 | 시도횟수 | 상태 | 마지막 복습일 | 다음 액션 |
|---|---|---|---|---|---|
| D1 Cluster Setup | NetworkPolicy (default-deny 3종) | 0 | 미착수 | - | `domains/01-cluster-setup.md` §1 정독 후 `/quiz 1` |
| D1 Cluster Setup | NetworkPolicy selector AND vs OR 함정 | 0 | 미착수 | - | 임시 Pod로 연결 테스트 실습 |
| D1 Cluster Setup | egress + DNS(53) 허용 동반 규칙 | 0 | 미착수 | - | egress 정책 작성 반복 |
| D1 Cluster Setup | CIS Benchmark / kube-bench 수정 | 0 | 미착수 | - | `domains/01-cluster-setup.md` §2 |
| D1 Cluster Setup | kube-apiserver 하드닝 (anonymous-auth 등, kube-bench 연계) | 0 | 미착수 | - | manifest 수정 → static pod 재기동 확인 |
| D1 Cluster Setup | Ingress TLS Secret 구성 | 0 | 미착수 | - | ingress-nginx 문서 확인 |

### Domain 2 — Cluster Hardening (15%)

| 도메인 | 토픽 | 시도횟수 | 상태 | 마지막 복습일 | 다음 액션 |
|---|---|---|---|---|---|
| D2 Cluster Hardening | RBAC 최소권한 설계 (Role/Binding 4조합) | 0 | 미착수 | - | `domains/02-cluster-hardening.md` §1 + 명령형 생성 연습 |
| D2 Cluster Hardening | RBAC 감사 (can-i / 역추적) | 0 | 미착수 | - | `kubectl auth can-i` 반복 |
| D2 Cluster Hardening | ServiceAccount 토큰 automount 비활성화 | 0 | 미착수 | - | SA/Pod 레벨 우선순위 확인 |
| D2 Cluster Hardening | 최소권한 SA 생성 → Pod 연결 → 토큰 발급 | 0 | 미착수 | - | 전체 워크플로우 1회 완주 |
| D2 Cluster Hardening | kubelet 인증/인가 하드닝 | 0 | 미착수 | - | anonymous/authz-mode 설정 확인 |
| D2 Cluster Hardening | kubeadm 클러스터 업그레이드 | 0 | 미착수 | - | 업그레이드 절차 암기 |

### Domain 3 — System Hardening (10%)

| 도메인 | 토픽 | 시도횟수 | 상태 | 마지막 복습일 | 다음 액션 |
|---|---|---|---|---|---|
| D3 System Hardening | 호스트 공격면 축소 (서비스/패키지/포트) | 0 | 미착수 | - | `domains/03-system-hardening.md` §2 |
| D3 System Hardening | 열린 포트 → 프로세스 → 유닛 추적 | 0 | 미착수 | - | `ss -tlnp` / systemd 유닛 추적 연습 |
| D3 System Hardening | AppArmor 프로파일 적용 | 0 | 미착수 | - | 프로파일 로드 후 Pod annotation/필드 확인 |
| D3 System Hardening | seccomp 프로파일 적용 (RuntimeDefault/커스텀) | 0 | 미착수 | - | seccompProfile 필드 실습 |
| D3 System Hardening | 커널 모듈 / sysctl 제한 | 0 | 미착수 | - | modprobe blacklist 확인 |
| D3 System Hardening | 최소권한 IAM / SSH 하드닝 | 0 | 미착수 | - | 사용자·그룹 정리 실습 |

### Domain 4 — Minimize Microservice Vulnerabilities (20%)

| 도메인 | 토픽 | 시도횟수 | 상태 | 마지막 복습일 | 다음 액션 |
|---|---|---|---|---|---|
| D4 Microservice Vuln | Pod Security Standards / PSA (3레벨·3모드) | 0 | 미착수 | - | `domains/04-minimize-microservice-vulnerabilities.md` §1 + dry-run 검사 |
| D4 Microservice Vuln | restricted 통과 Pod 템플릿 작성 | 0 | 미착수 | - | 표준 템플릿 암기 후 재현 |
| D4 Microservice Vuln | securityContext (비루트/readOnlyRootFS/cap) | 0 | 미착수 | - | 빈출 3조합 반복 |
| D4 Microservice Vuln | Secret 관리 (마운트/환경변수) | 0 | 미착수 | - | Secret 생성·주입 실습 |
| D4 Microservice Vuln | etcd Encryption at Rest (EncryptionConfiguration) | 0 | 미착수 | - | provider 순서·마운트 실습, etcd 평문 확인 |
| D4 Microservice Vuln | mTLS (Istio PeerAuthentication STRICT) | 0 | 미착수 | - | istio.io 문서 확인 |
| D4 Microservice Vuln | 런타임 샌드박스 (gVisor / RuntimeClass) | 0 | 미착수 | - | RuntimeClass 생성 → Pod 지정 |

### Domain 5 — Supply Chain Security (20%)

| 도메인 | 토픽 | 시도횟수 | 상태 | 마지막 복습일 | 다음 액션 |
|---|---|---|---|---|---|
| D5 Supply Chain | 베이스 이미지 최소화 / 멀티스테이지 빌드 | 0 | 미착수 | - | `domains/05-supply-chain-security.md` §1 Dockerfile 리팩터 |
| D5 Supply Chain | SBOM 생성/조회 (bom, trivy) | 0 | 미착수 | - | SPDX/CycloneDX 생성 실습 |
| D5 Supply Chain | SBOM에서 패키지/버전 찾기 (grep/jq) | 0 | 미착수 | - | 출력 파싱 연습 |
| D5 Supply Chain | 이미지 취약점 스캔 (trivy) | 0 | 미착수 | - | 심각도 필터링 옵션 숙지 |
| D5 Supply Chain | 아티팩트 서명/검증 (cosign) | 0 | 미착수 | - | `domains/05-supply-chain-security.md` §3 |
| D5 Supply Chain | 이미지 허용 정책 (ImagePolicyWebhook / ValidatingAdmissionPolicy) | 0 | 미착수 | - | admission plugin 설정 실습 |

### Domain 6 — Monitoring, Logging & Runtime Security (20%)

| 도메인 | 토픽 | 시도횟수 | 상태 | 마지막 복습일 | 다음 액션 |
|---|---|---|---|---|---|
| D6 Monitoring·Runtime | Falco 룰 문법 (rule/macro/list) | 0 | 미착수 | - | `domains/06-monitoring-logging-runtime-security.md` §1.3 룰 작성 |
| D6 Monitoring·Runtime | Falco 기존 룰 output 오버라이드 (최다 빈출) | 0 | 미착수 | - | 룰 grep → local 파일 복사 → output 수정 |
| D6 Monitoring·Runtime | Falco 실행·수집·시간범위 추출 | 0 | 미착수 | - | journalctl / `-M` 옵션 실습 |
| D6 Monitoring·Runtime | API server audit logging 구성 | 0 | 미착수 | - | audit policy + apiserver 플래그 |
| D6 Monitoring·Runtime | 컨테이너 immutability (readOnlyRootFS) | 0 | 미착수 | - | Domain 4와 연계 복습 |
| D6 Monitoring·Runtime | 런타임 이상행위 탐지/대응 | 0 | 미착수 | - | falco.org/docs 참조 |

---

## 4. 모의고사 점수 로그 (append-only)

모의고사를 한 번 볼 때마다 아래에 한 줄 append 한다. `/mock-exam` 종료 후 **exam-proctor**가 채점 결과로 채운다(오답 자체는 §2에 별도 기록).

| 날짜 | 세트 | 점수(%) | 합격여부(≥67%) | 주요 오답 (도메인·Task) |
|---|---|---|---|---|
| _예시_ | mock-exam-01 | _--_ | _-_ | _D1 NetworkPolicy egress DNS 누락, D6 Falco output 오버라이드_ |

> 합격여부는 67% 기준으로 O/X. 주요 오답에는 도메인 번호와 Task 번호, 한 줄 원인을 남긴다(상세는 §2 참조).

---

## 5. killer.sh 세션 로그

killer.sh 시뮬레이터는 실제 시험보다 어렵게 설계돼 있다. 무료 세션 **2회(각 세션 활성 후 36시간 접근)** 가 시험 등록에 포함된다. 세션당 반복 응시하며 아래에 점수 추이와 배운 점을 기록한다. `/weak-spots`는 추천 시 이 로그도 함께 읽는다.

| 회차 | 시작일 | 점수 | 시간초과 여부 | 가장 크게 막힌 부분 | 배운 점 / 다음 액션 |
|---|---|---|---|---|---|
| 세션 1 (1차 시도) | _YYYY-MM-DD_ | _--_ | _-_ | _예: kubelet 인증 설정에서 시간 소모_ | _해당 개념서 재복습_ |
| 세션 1 (2차 시도) | _YYYY-MM-DD_ | _--_ | _-_ | | |
| 세션 2 (1차 시도) | _YYYY-MM-DD_ | _--_ | _-_ | | |
| 세션 2 (2차 시도) | _YYYY-MM-DD_ | _--_ | _-_ | | |

체크리스트(세션 후 회고):
- [ ] 각 Task 시작 시 `kubectl config use-context <name>`를 먼저 실행했는가
- [ ] 답안을 문제가 지정한 `/opt/course/<task>/` 경로에 정확히 저장했는가
- [ ] 허용 문서 8개 범위만으로 풀 수 있었는가 (검색에 시간 낭비 없었는가)
- [ ] 부분점수를 노리고 막힌 Task를 넘기는 판단을 제때 했는가
- [ ] 이번 세션의 오답 토픽을 **§2 약점 로그**에 반영했는가
