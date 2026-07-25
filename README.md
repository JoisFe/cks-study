# CKS 학습 저장소 — Certified Kubernetes Security Specialist

CKS(Certified Kubernetes Security Specialist) 시험 합격을 위한 한국어 학습 저장소다. 시험 종합 가이드 1권, 공식 커리큘럼 6개 도메인을 각각 다루는 개념서 6권, 실전 형식 풀세트 모의고사 3회분으로 구성되어 있으며, 여기에 Claude Code로 함께 공부할 수 있도록 학습 도우미 에이전트 4개와 슬래시 명령 스킬 5개를 얹었다. 모든 문서는 **문제 본문은 실전과 동일한 영어, 해설은 한국어(접기식)** 로 작성되어 있고, 명령어와 YAML은 v1.35 환경에서 복사 후 바로 실행 가능하도록 검증되었다. `guide/00-exam-guide.md`로 시험의 규칙과 전략을 먼저 잡고, `domains/01`~`06` 개념서로 도메인별 기술을 익힌 뒤, `mock-exams/`의 모의고사 1~3회로 2시간 실전 리허설을 하는 흐름으로 사용하면 된다.

## 목차

- [CKS 시험 개요](#cks-시험-개요)
- [최신 변경사항](#최신-변경사항)
- [시험 중 허용 문서](#시험-중-허용-문서)
- [폴더 구조](#폴더-구조)
- [파일 인덱스](#파일-인덱스)
- [Claude Code 학습 방](#claude-code-학습-방)
- [권장 학습 순서](#권장-학습-순서)
- [6주 학습 로드맵](#6주-학습-로드맵)
- [공식 링크](#공식-링크)

---

## CKS 시험 개요

| 항목 | 내용 |
|---|---|
| 시험 시간 | **2시간 (120분)** |
| 문항 수 | 15~20개 hands-on 과제 (보통 **16문제 내외**) |
| 합격선 | **67%** (부분 점수 있음) |
| 응시 전제조건 | **유효한 CKA 자격** 보유 (만료된 CKA로는 응시 불가) |
| 자격 유효기간 | **2년** |
| 재시험 | 무료 재시험 1회 포함 |
| 시뮬레이터 | killer.sh **2회 세션**(각 36시간) 무료 포함 |
| Kubernetes 버전 | **v1.35** (containerd 런타임, Ubuntu 노드) |
| 시험 환경 | **PSI Secure Browser 원격 데스크톱**(XFCE) + 터미널 + Firefox(허용 문서만) |

## 최신 변경사항

### 2024-10-15 커리큘럼 대개편 요약

- **삭제**: PodSecurityPolicy(PSP) 등 폐기된 메커니즘이 커리큘럼에서 제거됐다.
- **추가**: Cilium/Istio 기반 **pod-to-pod 암호화**(WireGuard/IPsec, mTLS STRICT), **SBOM**(bom, trivy), **정적 분석**(Kubesec, KubeLinter), **ValidatingAdmissionPolicy(CEL)** 등 신규 토픽이 대거 들어왔다.
- **비중 재편**: Minimize Microservice Vulnerabilities / Supply Chain Security / Monitoring, Logging & Runtime Security 세 도메인이 각 20%로 최고 가중치가 됐다.
- 상세 before/after 표는 [guide/00-exam-guide.md](guide/00-exam-guide.md)의 "2. 최신 변경사항 정리" 참고. 신규 토픽 집중 훈련은 [mock-exams/mock-exam-02.md](mock-exams/mock-exam-02.md)가 담당한다.

### 2026-07 현재 상태

- 2024-10-15 대개편 이후 **추가 커리큘럼 개편 발표는 없다** (2026-07 기준).
- ⚠️ 다만 **시험 환경의 Kubernetes 버전은 K8s 릴리스를 따라 주기적으로 올라간다**(현재 v1.35). 응시 직전에 반드시 [공식 페이지](https://training.linuxfoundation.org/certification/certified-kubernetes-security-specialist/)에서 현재 시험 버전과 커리큘럼을 재확인하라.

## 시험 중 허용 문서

시험 중에는 Firefox로 아래 8개 사이트만 열 수 있다.

1. <https://kubernetes.io/docs> — Kubernetes 공식 문서 (검색·복붙의 중심)
2. <https://kubernetes.io/blog> — Kubernetes 공식 블로그
3. <https://falco.org/docs> — Falco 룰 문법·설정
4. <https://kubernetes-sigs.github.io/bom/cli-reference/> — bom CLI 레퍼런스 (SBOM)
5. <https://etcd.io/docs> — etcd (etcdctl 인증 플래그)
6. <https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/> — ingress-nginx 설정
7. <https://docs.cilium.io/en/stable> — Cilium (CiliumNetworkPolicy, WireGuard)
8. <https://istio.io/latest/docs> — Istio (PeerAuthentication mTLS)

## 폴더 구조

```text
cks/
├── README.md                  ← 지금 이 문서 (저장소 전체 안내)
├── CLAUDE.md                  ← Claude Code용 저장소 규칙·컨텍스트
├── guide/
│   ├── 00-exam-guide.md       ← 시험 종합 가이드 (규칙·전략·환경)
│   └── exam-tactics.md        ← 실전 조작 플레이북 (Mac 접속·dry-run·복구 팁)
├── domains/                   ← 도메인별 개념서 6권 (커리큘럼 6개 도메인)
│   ├── 01-cluster-setup.md
│   ├── 02-cluster-hardening.md
│   ├── 03-system-hardening.md
│   ├── 04-minimize-microservice-vulnerabilities.md
│   ├── 05-supply-chain-security.md
│   └── 06-monitoring-logging-runtime-security.md
├── mock-exams/                ← 실전 형식 모의고사 3세트
│   ├── mock-exam-01.md
│   ├── mock-exam-02.md
│   └── mock-exam-03.md
├── progress/
│   └── weak-spots.md          ← 누적 약점 기록 (스킬이 자동 append)
└── .claude/
    ├── agents/                ← 학습 도우미 에이전트 4개
    │   ├── cks-tutor.md
    │   ├── exam-proctor.md
    │   ├── k8s-troubleshooter.md
    │   └── study-doc-writer.md
    └── skills/                ← 슬래시 명령 스킬 5개
        ├── mock-exam/SKILL.md
        ├── quiz/SKILL.md
        ├── grade/SKILL.md
        ├── weak-spots/SKILL.md
        └── cheatsheet/SKILL.md
```

## 파일 인덱스

| 파일 | 도메인 | 시험 비중 | 핵심 내용 | 문제 수 |
|---|---|---|---|---|
| [guide/00-exam-guide.md](guide/00-exam-guide.md) | 시험 종합 가이드 | — | 시험 규정·2024-10 개편 정리, PSI 환경 공략, 3-패스 시간 관리, 시작 직후 90초 생산성 세팅, 6주 로드맵, 실수 TOP 10, 허용 문서 활용법, 치트시트 | 1 |
| [guide/exam-tactics.md](guide/exam-tactics.md) | 실전 조작 플레이북 | — | dry-run→apply 동선, context/namespace 위생(0점 방지), 되돌리기·복구(apiserver/kubelet static pod), **Mac 접속 복사·붙여넣기·키보드**, 자동완성, vim 생존술, 사고 체크리스트 | — |
| [domains/01-cluster-setup.md](domains/01-cluster-setup.md) | 1. Cluster Setup | 15% | NetworkPolicy(AND/OR·ipBlock·DNS), kube-bench CIS 하드닝, Ingress TLS, 메타데이터(169.254.169.254) 차단, sha512 바이너리 검증 | 15 |
| [domains/02-cluster-hardening.md](domains/02-cluster-hardening.md) | 2. Cluster Hardening | 15% | RBAC 최소권한, ServiceAccount 보안(automount 차단), API/kubelet 접근 제한, CSR 사용자 생성 6단계, kubeadm 업그레이드 | 15 |
| [domains/03-system-hardening.md](domains/03-system-hardening.md) | 3. System Hardening | 10% | 호스트 서비스/포트/패키지 정리, SSH·sudo 최소화, 방화벽, AppArmor·seccomp 프로파일 적용, 커널 모듈 블랙리스트·sysctl | 14 |
| [domains/04-minimize-microservice-vulnerabilities.md](domains/04-minimize-microservice-vulnerabilities.md) | 4. Minimize Microservice Vulnerabilities | 20% | Pod Security Admission, securityContext 총정리, Secrets·etcd 평문 조회, Encryption at Rest, gVisor RuntimeClass, Cilium/Istio pod-to-pod 암호화 | 18 |
| [domains/05-supply-chain-security.md](domains/05-supply-chain-security.md) | 5. Supply Chain Security | 20% | 베이스 이미지 최소화(distroless), SBOM(bom·trivy), cosign 서명, ImagePolicyWebhook·ValidatingAdmissionPolicy(CEL), kubesec/kube-linter, trivy 스캔 | 17 |
| [domains/06-monitoring-logging-runtime-security.md](domains/06-monitoring-logging-runtime-security.md) | 6. Monitoring, Logging & Runtime Security | 20% | Falco 룰 작성·오버라이드, 침해 조사(crictl·/proc), 컨테이너 불변성, Audit Policy·jq 로그 분석 | 18 |
| [mock-exams/mock-exam-01.md](mock-exams/mock-exam-01.md) | 모의고사 1회 | 전 도메인 | 기본기 전수 커버 세트 — NetworkPolicy·kube-bench·RBAC·업그레이드·AppArmor·PSA·암호화·gVisor·trivy·ImagePolicyWebhook·Falco·Audit, 배점 합계 100% | 16 |
| [mock-exams/mock-exam-02.md](mock-exams/mock-exam-02.md) | 모의고사 2회 | 전 도메인 | 2024 개편 신규 토픽 강조 — CiliumNetworkPolicy, Istio mTLS, SBOM(bom), Kubesec, ValidatingAdmissionPolicy + 노드 레벨 하드닝 | 16 |
| [mock-exams/mock-exam-03.md](mock-exams/mock-exam-03.md) | 모의고사 3회 | 전 도메인 | 고난도 최종 리허설 — 바이너리 무결성, key 로테이션, NodeRestriction, Cilium WireGuard, cosign, 침해 포렌식 등 1·2회 미중복 시나리오 | 16 |

> 개념서(01~06)의 문제 수는 개념별 미니 Task + 실전 형식 연습문제의 합계다. 모든 문제에 접기식 해설(접근·명령어·검증·함정)이 붙어 있다.

## Claude Code 학습 방

이 저장소는 단순한 문서 모음이 아니라 **Claude Code로 대화하며 공부하는 학습 방**이다. 저장소를 Claude Code로 열면 `.claude/`에 정의된 **에이전트 4개**와 **슬래시 명령 스킬 5개**가 활성화된다. 저장소 규칙(문제는 영어·해설은 한국어, v1.35 즉시 실행, 폐기 메커니즘 금지 등)은 루트의 [CLAUDE.md](CLAUDE.md)에 정의되어 있어, 모든 도우미가 이 규칙을 따라 답한다.

### 에이전트 (Agent 툴로 호출)

| 에이전트 | 역할 | 언제 부르나 |
|---|---|---|
| **cks-tutor** | 개념 튜터 | 도메인 개념이 헷갈릴 때. 개념서를 근거로 풀어 설명하고 예제·함정을 짚어준다. |
| **exam-proctor** | 모의고사 감독 | 실전 모의고사를 볼 때. 2시간 타이머·규칙 고지·진행 관리·채점 유도를 맡는다. |
| **k8s-troubleshooter** | 실습 디버깅 | 실습 중 Pod가 안 뜨거나 정책이 안 먹을 때. 원인을 좁혀가며 디버깅한다. |
| **study-doc-writer** | 문서 유지/확장 | 새 모의고사·개념 정리가 필요할 때. 저장소 스타일 그대로 문서를 만들거나 보강한다. |

### 슬래시 명령 스킬

| 슬래시 명령 | 역할 | 사용 예 |
|---|---|---|
| **/mock-exam** | 타이머 실전 모의고사 | `/mock-exam` → 세트 선택 후 exam-proctor 감독 하에 2시간 리허설 |
| **/quiz** | 랩드파이어 퀴즈 | `/quiz 4` → 도메인 4를 짧은 문답으로 빠르게 회상 훈련 |
| **/grade** | 답안 채점 | `/grade` → 내 답안을 67% 기준·부분점수로 채점 |
| **/weak-spots** | 약점 조회/추천 | `/weak-spots` → 누적 약점을 조회하고 복습 우선순위 추천 |
| **/cheatsheet** | 치트시트 | `/cheatsheet` → 자주 쓰는 명령·YAML 스니펫 빠른 조회 |

### 이렇게 공부한다 (사용 예시)

- **실전 리허설 한 바퀴**: `/mock-exam` 으로 모의고사를 시작하면 exam-proctor가 2시간 타이머를 켜고 감독한다. 종료 후 `/grade`로 67% 기준 채점하고, 틀린 Task는 자동으로 [progress/weak-spots.md](progress/weak-spots.md)에 도메인·토픽 단위로 기록된다.
- **도메인 집중 회상**: `/quiz 4` 처럼 도메인 번호를 붙이면 해당 개념서(`domains/04-...md`)를 근거로 랩드파이어 퀴즈가 나온다. 개념이 막히면 곧바로 **cks-tutor** 를 불러 그 토픽만 깊게 복습한다.
- **약점 기반 복습 루프**: `/weak-spots` 로 그동안 쌓인 약점을 조회해 우선순위를 정하고, 손이 안 익은 명령은 `/cheatsheet` 로 빠르게 확인한 뒤, 실습이 꼬이면 **k8s-troubleshooter** 로 디버깅한다.

## 권장 학습 순서

1. **[guide/00-exam-guide.md](guide/00-exam-guide.md)를 먼저 읽는다.** 시험 규칙·환경·시간 관리 전략을 모르고 개념부터 파면 비효율적이다. 실전에서 **손으로 어떻게 조작하는지**(특히 **Mac에서 접속할 때 복사/붙여넣기·키보드**, dry-run→apply, 되돌리기)는 [guide/exam-tactics.md](guide/exam-tactics.md)에 따로 정리돼 있으니 시험 1~2주 전 반드시 한 번 훑어라.
2. **개념서 01 → 06 순서로 학습한다.** 단, 비중이 높은 **04·05·06(각 20%)에 시간을 더 배분**하라. 세 도메인 합이 전체의 60%다. 01·02(각 15%)는 CKA 지식의 연장이라 상대적으로 빠르게 넘어갈 수 있고, 03(10%)은 AppArmor/seccomp 절차 암기가 핵심이다. 개념이 막히면 **cks-tutor** 에이전트로 풀어 설명받고, 챕터 끝에 `/quiz`로 회상을 점검한다.
3. **모의고사 1 → 2 → 3회를 타이머 2시간을 켜고 실전처럼 푼다.** `/mock-exam`(→ exam-proctor 감독)으로 진행하고, 해설은 채점할 때만 열며 `/grade`로 점수를 낸다. 틀린 문제는 각 모의고사 말미의 복습 매핑 표를 따라 해당 개념서로 돌아가 복습한다.
4. **killer.sh 시뮬레이터를 병행하라.** CKS 구매 시 2회 세션(각 36시간, 문제 동일)이 무료 포함된다. 시험 2주 전과 3일 전에 활성화하는 것이 정석이다 — 상세 활용법은 [guide/00-exam-guide.md](guide/00-exam-guide.md) 참고.

## 6주 학습 로드맵

| 주차 | 학습 자료 | 목표 |
|---|---|---|
| 1주차 | [guide/00-exam-guide.md](guide/00-exam-guide.md) + [domains/01-cluster-setup.md](domains/01-cluster-setup.md) | 시험 규칙·전략 숙지, NetworkPolicy를 안 보고 쓰는 수준까지 |
| 2주차 | [domains/02-cluster-hardening.md](domains/02-cluster-hardening.md) + [domains/03-system-hardening.md](domains/03-system-hardening.md) | RBAC/SA 최소권한, AppArmor·seccomp 절차 체화 |
| 3주차 | [domains/04-minimize-microservice-vulnerabilities.md](domains/04-minimize-microservice-vulnerabilities.md) | PSA·Encryption at Rest·gVisor·Cilium/Istio 암호화 (최고 비중 도메인) |
| 4주차 | [domains/05-supply-chain-security.md](domains/05-supply-chain-security.md) + **[mock-exams/mock-exam-01.md](mock-exams/mock-exam-01.md) 응시** | SBOM·cosign·admission 제어 학습 후 기본기 점검 (1회차 모의고사) |
| 5주차 | [domains/06-monitoring-logging-runtime-security.md](domains/06-monitoring-logging-runtime-security.md) + **[mock-exams/mock-exam-02.md](mock-exams/mock-exam-02.md) 응시** | Falco·Audit Policy 완성, 신규 토픽 점검 (2회차 모의고사) + killer.sh 1차 세션 |
| 6주차 | 오답 복습(`/weak-spots`) + **[mock-exams/mock-exam-03.md](mock-exams/mock-exam-03.md) 응시(시험 직전)** | 고난도 최종 리허설, killer.sh 2차 세션, 체크리스트·치트시트 최종 암기 |

## 공식 링크

- **CNCF CKS 페이지**: <https://www.cncf.io/training/certification/cks/>
- **Linux Foundation 등록 페이지**: <https://training.linuxfoundation.org/certification/certified-kubernetes-security-specialist/>
- **공식 커리큘럼 (cncf/curriculum)**: <https://github.com/cncf/curriculum>
