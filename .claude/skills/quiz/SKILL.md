---
name: quiz
description: 특정 도메인의 랩드파이어 퀴즈로 개념·명령·함정을 빠르게 회상 훈련한다. 사용자가 "퀴즈", "quiz", "빠른 문제", "개념 점검", "도메인 N 문제 내줘", "랩드파이어" 등을 말할 때 사용. 실전 hands-on 대신 짧은 문답으로 암기를 점검하고 싶을 때 발동한다.
---

# /quiz — 도메인별 랩드파이어 퀴즈

CKS 개념서(`domains/01`~`06`)를 근거로 **짧은 문제를 한 번에 하나씩** 내고, 사용자가 답하면 즉시 정오답을 판정하는 빠른 회상(recall) 훈련 스킬이다.

> ⚠️ **이 스킬은 빠른 회상 훈련용이다.** 실제 CKS 시험은 100% hands-on Task(터미널에서 kubectl/YAML/노드 작업)이므로, 실전 감각은 `/mock-exam`(타이머 실전 모의고사)로 길러야 한다. `/quiz`는 그 전 단계에서 개념·명령어·함정을 머릿속에 빠르게 인출하는 워밍업/점검 도구임을 세션 시작 시 사용자에게 한 줄로 알려라.

---

## 역할

CKS 개념서 근거의 짧은 문답으로 개념·명령·함정을 빠르게 회상(recall) 훈련한다.

## 하지 않는 것

- hands-on 실전 감각 훈련 (→ `/mock-exam`)
- 개념서에 없는 내용 출제 (환각 금지, 근거 파일 필수)
- 폐기 토픽(PodSecurityPolicy 등) 출제

## 1단계 — 세션 설정

사용자에게 두 가지를 물어 확정한다(이미 요청에 들어 있으면 되묻지 말고 바로 진행).

1. **도메인 선택**: `1`~`6` 중 하나, 또는 `전체`(all).
2. **문항 수**: 기본 **5문항**. 사용자가 숫자를 주면 그 값을 쓴다.

도메인 번호 → 근거 개념서 매핑(문제와 해설은 반드시 아래 파일에서 확인한 내용에만 근거한다):

| 도메인 | 근거 파일 | 핵심 소재 |
|---|---|---|
| 1. Cluster Setup (15%) | `/Users/jo/cks/domains/01-cluster-setup.md` | NetworkPolicy(AND/OR·ipBlock·DNS egress), kube-bench, Ingress TLS, 메타데이터(169.254.169.254) 차단, sha512 바이너리 검증 |
| 2. Cluster Hardening (15%) | `/Users/jo/cks/domains/02-cluster-hardening.md` | RBAC 최소권한, ServiceAccount(automount 차단), API/kubelet 접근 제한, CSR 사용자 생성, kubeadm 업그레이드 |
| 3. System Hardening (10%) | `/Users/jo/cks/domains/03-system-hardening.md` | 서비스/포트/패키지 정리, SSH·sudo 최소화, AppArmor, seccomp, 커널 모듈 블랙리스트·sysctl |
| 4. Minimize Microservice Vulnerabilities (20%) | `/Users/jo/cks/domains/04-minimize-microservice-vulnerabilities.md` | Pod Security Admission, securityContext, Secrets·etcd 평문, Encryption at Rest, gVisor RuntimeClass, Cilium/Istio 암호화 |
| 5. Supply Chain Security (20%) | `/Users/jo/cks/domains/05-supply-chain-security.md` | distroless·멀티스테이지, SBOM(bom·trivy), cosign 서명, ImagePolicyWebhook·ValidatingAdmissionPolicy(CEL), kubesec/kube-linter, trivy |
| 6. Monitoring, Logging & Runtime Security (20%) | `/Users/jo/cks/domains/06-monitoring-logging-runtime-security.md` | Falco 룰 작성·오버라이드, 침해 조사(crictl·/proc), 컨테이너 불변성, Audit Policy·jq 분석 |

- `전체`를 고르면 6개 도메인 전부에서 출제하되, **시험 가중치(20%인 4·5·6에 더 많이)** 를 반영해 문항을 배분한다.
- 출제 전에 해당 개념서를 **Read**로 열어 실제 내용을 확인한다. 기억에만 의존해 문제를 만들지 않는다.

## 2단계 — 출제 방식

- **한 번에 한 문제만** 낸다. 다음 문제는 사용자가 현재 문제에 답한 뒤에만 낸다.
- 문제는 **짧게(1~3줄)** 낸다. 유형을 섞는다:
  - **개념형**: "restricted PSS가 금지하는 대표 3가지는?", "Role과 ClusterRole의 차이는?"
  - **명령형**: "SA `batch-sa`가 특정 verb를 가졌는지 yes/no로 확인하는 kubectl 명령은?"
  - **함정형(빈출 오답)**: NetworkPolicy의 namespaceSelector+podSelector가 같은 `-` 아래면 AND, 서로 다른 `-`면 OR 같은 헷갈리는 지점.
- 저장소 원칙(문제 본문은 실전과 동일한 영어)을 반영해, **시나리오/명령형 문제의 stem은 영어**를 우선한다. 순수 개념 회상 질문은 한국어로 물어도 된다. **정오답 판정과 해설은 항상 한국어**로 한다.
- 명령어·YAML을 묻는 문제의 정답은 **v1.35 환경에서 즉시 실행 가능**해야 한다. 폐기된 PodSecurityPolicy(PSP) 등 2024-10 개편에서 삭제된 메커니즘은 절대 출제·정답에 쓰지 않는다.
- 문항 번호를 표시한다(예: `Q3/5`).

## 3단계 — 즉시 채점 (문항마다)

사용자가 답하면 곧바로:

1. **정오답 판정**: ✅ 정답 / ⚠️ 부분정답 / ❌ 오답 중 하나로 명확히 표시한다.
2. **한국어 해설 1~2줄**: 왜 그런지 핵심만. 오답이면 올바른 답을 함께 제시한다.
3. **근거 파일 표기**: 해당 개념서 경로와 가능하면 섹션명(예: `근거: domains/01-cluster-setup.md §1.4 namespaceSelector와 podSelector의 AND vs OR`).
4. 판정 후 곧바로 다음 문제로 넘어간다. 오답 문항은 도메인·개념을 내부적으로 기록해 둔다(4단계 요약과 기록 제안에 사용).

## 4단계 — 세션 마무리

마지막 문항 채점 후:

1. **점수**: `점수: N/총문항 (정답률 %)` 형식으로 출력한다. 부분정답은 0.5점 등으로 환산했다면 기준을 밝힌다.
2. **약한 개념 요약**: 틀리거나 헷갈린 문항을 도메인·소재별로 2~4줄로 묶어 알려준다(예: "NetworkPolicy AND/OR, PSA restricted 필수 필드가 약함").
3. **오답 기록 제안**: 오답이 있으면 `/Users/jo/cks/progress/weak-spots.md`의 **`§2 약점 로그`** 표에 기록할지 물어본다. 동의하면 그 표에 표준 한 줄을 append 한다(그 파일 §1-1 규약, 기존 내용 보존). 열: `날짜 | 도메인 | 토픽 | 유형 | 출처 | 근거 개념서`. 예:
   - `| 2026-07-25 | D1 Cluster Setup | NetworkPolicy AND vs OR 혼동 | 개념혼동 | quiz D1 Q3 | domains/01-cluster-setup.md |`
   - 날짜는 오늘 날짜. 같은 `도메인+토픽`이 이미 있으면 새 행 대신 기존 행 토픽 끝에 `(재발 xN)`을 올린다.
4. **다음 단계 안내**: 약점이 드러나면 해당 개념서 섹션 재복습을 권하고, 손에 익히는 훈련은 `/mock-exam`(타이머 실전 모의고사)로, 누적 약점 확인은 `/weak-spots`로 이어가도록 한 줄로 제안한다.

---

## 준수 사항

- 문제·해설·정답은 반드시 지정된 개념서에서 확인한 내용에만 근거한다. 과장·환각 금지, 근거 파일을 항상 밝힌다.
- 명령어/YAML은 v1.35(containerd, Ubuntu 노드) 기준으로 즉시 실행 가능해야 한다.
- PSP 등 삭제된 메커니즘은 출제하지 않는다.
- 랩드파이어답게 **빠른 템포**를 유지한다. 문제는 짧게, 해설은 핵심만.
