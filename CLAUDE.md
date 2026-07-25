# CLAUDE.md — CKS 학습 저장소 작업 지침

이 파일은 Claude Code가 이 저장소에서 작업할 때 항상 따르는 프로젝트 지침이다. 사용자는 이 저장소 안에서 Claude Code와 대화하며 CKS(Certified Kubernetes Security Specialist) 시험을 준비한다. 저장소 전체 소개와 6주 로드맵은 [README.md](README.md), 시험 규정·전략 상세는 [guide/00-exam-guide.md](guide/00-exam-guide.md)에 있으니 여기서는 반복하지 않는다.

## 1. 저장소 목적과 핵심 시험 사실

목적: CKS 시험 합격을 위한 한국어 개인 학습 저장소. 시험 종합 가이드 1권, 공식 6개 도메인 개념서 6권, 실전 형식 모의고사 3회분, 약점 기록으로 구성된다.

| 항목 | 값 |
|---|---|
| Kubernetes 버전 | **v1.35** (containerd 런타임, Ubuntu 노드) |
| 시험 시간 | **2시간(120분)** |
| 문항 수 | **약 16개** (15~20개) 100% hands-on Task |
| 합격선 | **67%** (부분 점수 있음) |
| 응시 전제 | 유효한 **CKA** 자격 필요 |
| 부가 혜택 | 무료 재시험 1회, killer.sh 시뮬레이터 2회 세션(각 36시간) 무료 포함 |

## 2. 파일 지도

| 경로 | 내용 | 시험 비중 |
|---|---|---|
| `guide/00-exam-guide.md` | 시험 규정·2024-10 개편 정리, PSI 환경 공략, 시간 관리, 6주 로드맵, 치트시트 | — |
| `guide/exam-tactics.md` | 실전 조작 플레이북 — dry-run→apply, context/namespace 위생, 되돌리기·복구, **Mac 접속 복사/붙여넣기·키보드**, 자동완성, vim | — |
| `domains/01-cluster-setup.md` | Cluster Setup — NetworkPolicy, kube-bench/CIS, Ingress TLS, 메타데이터 차단, 바이너리 검증 | **15%** |
| `domains/02-cluster-hardening.md` | Cluster Hardening — RBAC 최소권한, ServiceAccount, API/kubelet 접근 제한, CSR, 업그레이드 | **15%** |
| `domains/03-system-hardening.md` | System Hardening — 호스트 정리, SSH/sudo, 방화벽, AppArmor·seccomp, 커널 모듈·sysctl | **10%** |
| `domains/04-minimize-microservice-vulnerabilities.md` | Pod Security Admission, securityContext, Secrets·Encryption at Rest, gVisor, Cilium/Istio 암호화 | **20%** |
| `domains/05-supply-chain-security.md` | 이미지 최소화(distroless), SBOM(bom·trivy), cosign, ImagePolicyWebhook·ValidatingAdmissionPolicy(CEL), kubesec/kube-linter | **20%** |
| `domains/06-monitoring-logging-runtime-security.md` | Falco 룰, 침해 조사(crictl·/proc), 컨테이너 불변성, Audit Policy | **20%** |
| `mock-exams/mock-exam-01.md` | 모의고사 1회 — 전 도메인 기본기 커버 세트 (배점 합계 100%) | 전 도메인 |
| `mock-exams/mock-exam-02.md` | 모의고사 2회 — 2024 개편 신규 토픽 강조 세트 | 전 도메인 |
| `mock-exams/mock-exam-03.md` | 모의고사 3회 — 고난도 최종 리허설, 1·2회 미중복 시나리오 | 전 도메인 |
| `progress/weak-spots.md` | 채점 결과·오답·약점 누적 기록 (아래 7번 참고) | — |

## 3. 문서 규칙

- **문제 본문은 실전과 동일한 영어, 해설은 한국어**로 쓴다. 해설은 HTML `<details>`/`<summary>` 접기식으로 감싸 채점 전에 답이 노출되지 않게 한다.
- 설정/지침 문서(.claude/ 등)의 본문은 한국어로 쓰되 기술 용어(NetworkPolicy, RBAC, seccomp, securityContext 등)는 영어를 그대로 쓴다.
- 모든 명령어와 YAML은 **v1.35 환경에서 복사 후 즉시 실행 가능**해야 한다. 손보지 않고 복붙되는 것을 전제로 작성한다.
- 문서를 새로 만들거나 확장할 때 기존 문서의 포맷(제목 체계, 접기식 해설의 접근·명령어·검증·함정 구조)을 따른다.

## 4. Claude 도우미 사용법

에이전트(`.claude/agents/`) — 특정 역할이 필요할 때 해당 subagent를 부른다.

- **cks-tutor**: 개념 튜터. 도메인 개념을 설명·심화하거나 "왜 이렇게 하는지" 원리를 물을 때.
- **exam-proctor**: 모의고사 감독. 타이머를 켜고 실전처럼 모의고사를 진행·감독할 때.
- **k8s-troubleshooter**: 실습 디버깅. 랩에서 매니페스트·클러스터가 의도대로 동작하지 않을 때 원인을 추적.
- **study-doc-writer**: 문서 유지/확장. 개념서·모의고사 문서를 추가하거나 스타일 규칙에 맞춰 수정할 때.

스킬(슬래시 명령, `.claude/skills/`) — 반복 학습 동작을 한 번에 실행한다.

- **/mock-exam**: 타이머 2시간 실전 모의고사를 시작.
- **/quiz**: 랩드파이어(rapid-fire) 단답 퀴즈로 개념을 빠르게 점검.
- **/grade**: 제출한 답안을 채점하고 결과를 `progress/weak-spots.md`에 기록.
- **/weak-spots**: 누적된 약점을 조회하고 다음 학습을 추천.
- **/cheatsheet**: 자주 쓰는 명령·YAML 치트시트를 조회.

## 5. 권장 학습 워크플로우

1. **`guide/00-exam-guide.md`를 먼저** 읽어 시험 규칙·환경·시간 관리를 잡는다.
2. **`domains/01` → `06` 순서로 개념서**를 학습하되, 비중이 높은 **04·05·06(각 20%, 합 60%)에 시간을 더 배분**한다. 01·02(각 15%)는 CKA 지식의 연장, 03(10%)은 AppArmor/seccomp 절차 암기가 핵심.
3. **모의고사 1 → 2 → 3회를 타이머 2시간을 켜고** 실전처럼 푼다. 해설은 채점할 때만 열고, 틀린 문제는 해당 도메인 개념서로 돌아가 복습한다.
4. **killer.sh 시뮬레이터를 병행**한다. 2회 세션(각 36시간)이 무료 포함되며 시험 2주 전·3일 전 활성화가 정석 — 상세는 00 가이드.

> **실습 환경**: 개념서·모의고사의 명령/YAML은 v1.35 클러스터에서 **직접 쳐 봐야** 손에 익는다. `/grade`·`exam-proctor`의 "결과 상태 기반 채점"도 사용자에게 실제 클러스터가 있다는 전제다. 실습 클러스터는 **killer.sh 무료 세션(2회)** 이나 로컬 **kind / minikube / kubeadm**(v1.35)으로 마련한다. 이 저장소 자체는 문서·학습 도구만 담고 클러스터는 포함하지 않는다.

## 6. 작업 가드레일

- **근거는 허용 문서 8개만**: kubernetes.io/docs, kubernetes.io/blog, falco.org/docs, kubernetes-sigs.github.io/bom/cli-reference, etcd.io/docs, kubernetes.github.io/ingress-nginx, docs.cilium.io/en/stable, istio.io/latest/docs. 사실 확인이 필요하면 이 소스를 열어 확인한 내용만 쓴다.
- **v1.35 기준**으로만 작성한다. 명령·플래그·API 버전이 릴리스마다 바뀔 수 있으니 v1.35에서 동작하는 것만 쓴다.
- **폐기 토픽 언급 금지**: PodSecurityPolicy(PSP) 등 2024-10 개편에서 삭제된 메커니즘은 문제·해설·예시 어디에도 넣지 않는다.
- **검증된 명령만**: 추측으로 명령·YAML을 쓰지 않는다. 불확실하면 허용 문서로 확인하거나 불확실함을 명시한다.
- **과장·환각 금지**, 해설은 한국어. 확실하지 않은 시험 사실을 단정하지 않는다.

## 7. 채점·오답 기록 (단일 규약)

채점(`/grade`)·모의고사(`exam-proctor`)·퀴즈(`/quiz`) 결과와 반복해서 틀리는 개념은 모두 **`progress/weak-spots.md`의 `§2 약점 로그` 표에 표준 한 줄**로 누적 기록한다. 기록 열·값·중복(`(재발 xN)`) 규칙은 그 파일의 **§1-1 기록 규약**이 단일 기준이며, 모든 writer(exam-proctor·`/grade`·`/quiz`·`/weak-spots`)가 이를 그대로 따른다 — 포맷이 흩어지면 `/weak-spots` 집계가 무의미해진다. `§3 도메인별 현황`은 `/weak-spots`가 §2를 집계해 갱신하는 요약 뷰다. `/weak-spots`로 이 기록을 조회해 다음 학습 우선순위를 정한다.
