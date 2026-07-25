---
name: weak-spots
description: 약점 트래커(progress/weak-spots.md)를 조회해 약한 도메인·토픽과 모의고사 점수 추이를 요약하고, 시험 가중치와 약점을 함께 고려해 다음에 뭘 공부할지 우선순위로 추천한다. 사용자가 "약점", "취약", "뭐 공부", "뭐부터", "복습", "약한 부분", "weak spots", "다음에 뭐 볼까"라고 하거나 새 모의고사·퀴즈 결과를 트래커에 반영하려 할 때 사용한다.
---

# /weak-spots — 약점 트래커 조회 및 다음 학습 추천

`/Users/jo/cks/progress/weak-spots.md`에 누적된 오답·시간초과·모의고사 점수를 읽어, **지금 무엇을 공부하는 것이 합격에 가장 효율적인지**를 도메인 가중치와 함께 계산해 알려주는 스킬이다. `/quiz`·`/mock-exam`이 끝날 때마다 쌓인 약점을 여기서 되짚고, 다음 학습 계획으로 연결한다.

> ℹ️ 이 스킬은 "무엇을 얼마나 공부할지"를 정하는 **네비게이터**다. 실제 훈련은 개념 복습(`domains/*.md`, cks-tutor), 랩드파이어(`/quiz`), 타이머 실전(`/mock-exam`)으로 이어진다.

---

## 역할

약점 트래커(`§2 약점 로그`)를 집계해 다음 학습 우선순위를 도메인 가중치와 함께 추천하는 **네비게이터**다.

## 하지 않는 것

- 실제 개념/실습 훈련 대행 (→ 개념서·cks-tutor·`/quiz`·`/mock-exam`)
- 기록에 없는 약점 지어내기 (환각 금지)
- `§1-1` 표준 규약을 벗어난 포맷으로 기록

## 참고 상수 — 도메인 가중치와 근거 개념서

추천 우선순위 계산의 기준이 되는 시험 가중치와, 각 도메인의 근거 개념서 경로다. 항상 이 표를 기준으로 판단한다.

| # | 도메인 | 가중치 | 근거 개념서 | 대표 소재 |
|---|---|---|---|---|
| 1 | Cluster Setup | 15% | `/Users/jo/cks/domains/01-cluster-setup.md` | NetworkPolicy(AND/OR·ipBlock·DNS egress), kube-bench, Ingress TLS, 메타데이터(169.254.169.254) 차단, sha512 바이너리 검증 |
| 2 | Cluster Hardening | 15% | `/Users/jo/cks/domains/02-cluster-hardening.md` | RBAC 최소권한, ServiceAccount(automount 차단), API/kubelet 접근 제한, CSR 사용자 생성, kubeadm 업그레이드 |
| 3 | System Hardening | 10% | `/Users/jo/cks/domains/03-system-hardening.md` | 서비스/포트/패키지 정리, SSH·sudo 최소화, AppArmor, seccomp, 커널 모듈 블랙리스트·sysctl |
| 4 | Minimize Microservice Vulnerabilities | 20% | `/Users/jo/cks/domains/04-minimize-microservice-vulnerabilities.md` | Pod Security Admission, securityContext, Secrets·etcd 평문, Encryption at Rest, gVisor RuntimeClass, Cilium/Istio 암호화 |
| 5 | Supply Chain Security | 20% | `/Users/jo/cks/domains/05-supply-chain-security.md` | distroless·멀티스테이지, SBOM(bom·trivy), cosign 서명, ImagePolicyWebhook·ValidatingAdmissionPolicy(CEL), kubesec/kube-linter |
| 6 | Monitoring, Logging & Runtime Security | 20% | `/Users/jo/cks/domains/06-monitoring-logging-runtime-security.md` | Falco 룰 작성·오버라이드, 침해 조사(crictl·/proc), 컨테이너 불변성, Audit Policy·jq 분석 |

가중치 합계: 15+15+10+20+20+20 = 100%. 4·5·6번(각 20%)이 합계 60%로, 여기서의 실수는 합격선 67%에 가장 큰 영향을 준다.

---

## 1단계 — 트래커 읽고 요약

1. `/Users/jo/cks/progress/weak-spots.md`를 **Read**한다. 이 파일은 스캐폴딩에 이미 존재하며 구조는 `§2 약점 로그`(오답의 단일 소스), `§3 도메인별 현황`(요약 스냅샷), `§4 모의고사 점수 로그`, `§5 killer.sh 세션 로그`다.
2. **아직 실기록(예시 행 외 실제 데이터)이 없으면**: 기록된 약점이 없다고 알린다. `/quiz`나 `/mock-exam`을 먼저 한 세션 진행하면 약점이 §2에 자동으로 쌓인다고 안내하고, 그래도 지금 시작점을 원하면 **가중치가 높은 도메인(4·5·6, 각 20%)부터** 훑기를 권한 뒤 종료한다. (사용자가 새 결과 입력을 원하면 4단계로 간다.)
3. 실기록이 있으면 다음을 뽑아 요약한다(예시 행은 제외).
   - **약한 도메인/토픽**: `§2 약점 로그`를 도메인별로 묶고, **빈도(같은 토픽의 반복/재발 — `(재발 xN)` 포함)** 를 센다. 반복될수록 우선순위가 높다.
   - **모의고사 점수 추이**: `§4`의 세트별 점수를 시간순으로 나열하고, **67% 합격선 대비 상승·정체·하락** 경향을 한 줄로 판정한다.
   - **killer.sh 추이**: `§5`에 기록이 있으면 점수·시간초과·크게 막힌 부분을 함께 반영한다(실제 시험보다 어렵게 설계됨을 감안).
   - **최근성**: 최근 며칠 안의 오답을 오래된 것보다 더 비중 있게 본다.
4. 요약은 표나 짧은 불릿으로 보여 준다(도메인 | 약한 토픽 | 등장 횟수 | 최근 날짜).

## 2단계 — 다음 학습 우선순위 추천

약점 요약과 **도메인 가중치(%)** 를 함께 고려해 우선순위를 매긴다. 사고 순서:

1. **가중치 × 약점 빈도**로 대략의 영향도를 가늠한다. 예: 20% 도메인에서 반복 오답이 나는 토픽 > 10% 도메인의 단발 오답.
2. **모의고사에서 반복 실점하거나 시간초과가 잦은 토픽**은 실전 리스크가 크므로 상단에 올린다.
3 개 안팎의 **우선순위 목록**을 근거와 함께 제시한다. 각 항목에 "왜 지금 이걸 하는가"(가중치·빈도·최근성)를 한 줄로 붙인다.
4. 균형도 언급한다: 특정 도메인만 파고들어 다른 20% 도메인이 방치되지 않도록, 약점이 없어도 4·5·6은 주기적으로 점검하라고 상기시킨다.

## 3단계 — 학습 링크와 이어가기 제안

우선순위 각 항목에 대해 **바로 실행 가능한 다음 행동**을 붙인다.

1. **개념서 링크**: 위 상수 표의 근거 개념서 경로를 제시하고, 가능하면 섹션까지 지목한다(예: `근거: domains/01-cluster-setup.md — NetworkPolicy AND vs OR`). 깊은 개념 복습이 필요하면 **cks-tutor** 에이전트를 권한다.
2. **랩드파이어**: 해당 도메인 번호로 `/quiz <도메인번호>`를 이어가라고 제안한다(예: "NetworkPolicy가 약하면 `/quiz 1`").
3. **실전 감각**: 손에 익히는 훈련이 필요하면 `/mock-exam`으로 타이머 실전 세트를 권한다. 아직 안 푼 세트(01~03)가 있으면 그걸 먼저 권하고, 3세트를 다 풀었으면 신규 세트 생성을 안내한다.
4. **디버깅 막힘**: 실습 중 kubectl/노드 문제로 막히면 **k8s-troubleshooter** 에이전트로 넘기라고 안내한다.

## 4단계 — 새 결과로 트래커 갱신

사용자가 새 퀴즈/모의고사 결과나 새로 발견한 약점을 주면 `/Users/jo/cks/progress/weak-spots.md`를 그 파일의 **표준 규약(§1-1)** 대로 갱신한다. 파일은 이미 존재하므로 새로 만들지 않는다(만약 없으면 §1~§5 구조를 그대로 갖춰 생성).

1. **오답/약점 항목**은 `§2 약점 로그` 표에 표준 한 줄로 **append** 한다(기존 내용 절대 삭제·수정 금지). 열: `날짜 | 도메인 | 토픽 | 유형 | 출처 | 근거 개념서`. 예:
   - `| 2026-07-25 | D4 Microservice Vuln | PSA restricted 필수 필드 누락 | 오답 | mock-02 T9 | domains/04-minimize-microservice-vulnerabilities.md |`
   - 날짜는 오늘 날짜. **같은 `도메인+토픽`이 이미 있으면 새 행 대신** 기존 행 토픽 끝에 `(재발 xN)`을 올린다.
2. **모의고사 점수**는 `§4 모의고사 점수 로그` 표에 행을 추가한다(`날짜 | 세트 | 점수% | 합격(≥67%) | 주요 오답`).
3. **`§3 도메인별 현황` 스냅샷 갱신**(이 스킬의 고유 역할): §2를 집계해 해당 토픽 행의 `시도횟수 / 상태 / 마지막 복습일 / 다음 액션`을 최신화한다. 상태는 §3 상단의 4단계 규칙(연속 2회 정확→↑, 틀림→↓)을 따른다.
4. 갱신 후, 바뀐 우선순위를 반영해 1~3단계 요약·추천을 다시 한 줄로 정리해 준다.

---

## 준수 사항

- 트래커에 **실제로 기록된 내용에만** 근거해 요약·추천한다. 없는 오답을 지어내지 않는다(과장·환각 금지).
- 추천의 근거(가중치·빈도·최근성)를 항상 밝힌다.
- 개념서·명령어 안내는 v1.35(containerd, Ubuntu 노드) 기준이며, 폐기된 PodSecurityPolicy(PSP) 등 삭제된 메커니즘은 언급하지 않는다.
- 트래커 갱신은 **append 우선**, 기존 기록을 보존한다. 파일 경로는 항상 `/Users/jo/cks/progress/weak-spots.md`.
