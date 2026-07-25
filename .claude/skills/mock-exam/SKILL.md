---
name: mock-exam
description: 타이머를 켠 실전 CKS 모의고사를 시작하는 진입점. "모의고사", "실전 연습", "mock exam", "시험 리허설", "2시간 풀 세트로 풀어보고 싶다"고 할 때 사용. 세트(1~3회 또는 신규)를 고르고, 2시간 실전 규칙을 고지한 뒤, exam-proctor 역할 지침을 이 대화에서 채택해 문제를 하나씩 진행하고 종료 후 67% 기준으로 채점한다.
---

# /mock-exam — 실전 모의고사 진입점

이 스킬은 실전 모의고사의 "시작 버튼"이다. 진행 방식(규칙·출제·채점)은 **exam-proctor** 역할 지침을 따르되, **감독은 이 메인 대화에서 직접** 수행한다. 아래 절차를 순서대로 따른다.

## 역할

실전 2시간 모의고사의 진입점. exam-proctor 역할을 이 대화에서 채택해 세트 선택·규칙 고지·turn-by-turn 진행·채점을 오케스트레이션한다.

## 하지 않는 것

- 진행 중 힌트·정답·부분정답 노출 (감독 규칙 위반)
- 실제 벽시계 타이머 대행 — 카운트다운은 사용자 타이머가 기준
- 개념 설명 (→ cks-tutor), 실습 디버깅 대행 (→ k8s-troubleshooter)

## 절차

1. **exam-proctor 역할을 이 대화에서 채택한다.** (서브에이전트로 스폰하지 않는다.)
   - 실전 감독은 문제를 여러 턴에 걸쳐 하나씩 주고받는 **대화형**이다. Claude Code 서브에이전트는 1회 자율 실행 후 결과를 한 번만 반환하는 구조라 turn-by-turn 감독을 할 수 없다. 따라서 `/Users/jo/cks/.claude/agents/exam-proctor.md`를 **Read해 그 지침을 메인 어시스턴트가 그대로 따르며** 본 대화에서 진행한다.
   - 예외: 진행이 다 끝나 답안이 모두 모인 뒤 **순수 채점만** 격리해 돌리고 싶으면 그때 exam-proctor를 서브에이전트로 1회 호출해도 된다. 진행(출제·수집)은 반드시 이 대화에서 한다.

2. **세트를 선택하게 한다.** 사용자에게 아래 중 하나를 고르게 한다.
   - `mock-exams/mock-exam-01.md` — 1회, 기본기 전수 커버 세트
   - `mock-exams/mock-exam-02.md` — 2회, 2024 개편 신규 토픽 강조 세트
   - `mock-exams/mock-exam-03.md` — 3회, 고난도 종합 리허설 세트
   - 신규 세트 — 기존 3세트를 이미 풀었거나 새 문제를 원하면, study-doc-writer 에이전트에게 신규 모의고사 작성을 위임한다. 실제 가중치(Cluster Setup 15% / Cluster Hardening 15% / System Hardening 10% / Minimize Microservice Vulnerabilities 20% / Supply Chain Security 20% / Monitoring, Logging & Runtime Security 20%)를 반영하도록 요청한다.
   - 선택한 세트 파일을 Read로 열되, **문제 본문만 노출하고 해설(details 접기)은 채점 전까지 열지 않는다.**

3. **2시간 실전 규칙을 고지한다.** 문제 풀이를 시작하기 전 반드시 다음을 안내한다.
   - 제한 시간 **120분(2시간)**, 약 **16개 Task**, 합격선 **67%**(부분점수 있음). ⚠️ 어시스턴트는 벽시계 시간을 셀 수 없으니 **사용자가 직접 카운트다운 타이머(휴대폰·터미널 `date`·타이머 앱)를 켜게** 하고, 어시스턴트는 사용자가 알려준 경과 시간 기준 best-effort 체크포인트만 준다.
   - 각 Task는 `kubectl config use-context <name>`를 **먼저** 실행한다. 잘못된 클러스터에서 작업하면 0점.
   - 노드 접속은 main terminal에서만 가능하며, 다음 context 전환 전 반드시 `exit`로 복귀한다(중첩 SSH 불가). 노드 root는 `sudo -i`.
   - 답안 저장 경로는 문제가 지정한 `/opt/course/<task-number>/` 경로에 **정확히** 저장한다.
   - 허용 문서는 8개뿐(`kubernetes.io/docs`, `kubernetes.io/blog`, `falco.org/docs`, `kubernetes-sigs.github.io/bom/cli-reference`, `etcd.io/docs`, `kubernetes.github.io/ingress-nginx`, `docs.cilium.io/en/stable`, `istio.io/latest/docs`). 실전 감각을 위해 이 범위만 참고하도록 권한다.
   - 시험 환경 기준: **Kubernetes v1.35, containerd 런타임, Ubuntu 노드.**
   - 시간이 모자라면 부분점수를 노리고 다음 Task로 넘어가는 전략을 상기시킨다.

4. **종료 후 채점하고 약점을 기록한다.**
   - 시간이 끝나거나 사용자가 종료를 선언하면, 세트 파일의 **채점표**와 각 Task 해설의 "부분점수 포인트"를 기준으로 채점한다. 채점은 **최종 상태(Pod가 Running인지, 파일이 존재하는지, 포트가 닫혔는지 등)**로 판정한다 — 명령만 맞고 결과가 틀리면 해당 항목 0점.
   - 합계를 내고 **67% 기준으로 합격/불합격**을 판정한다. 세밀한 채점 유도는 `/grade` 스킬을 함께 활용한다.
   - 결과를 `/Users/jo/cks/progress/weak-spots.md`의 **표준 규약(그 파일 §1-1)** 대로 기록한다: 틀리거나 시간초과한 Task마다 `§2 약점 로그`에 한 줄(`날짜 | 도메인 | 토픽 | 유형 | 출처(mock-0N T번호) | 근거 개념서`), 세트 총점은 `§4 모의고사 점수 로그`에 한 줄 append 한다. 파일은 이미 존재하므로 새로 만들지 않는다. (`§3 도메인별 현황`은 `/weak-spots`가 집계 갱신한다.)
   - 마지막에 취약 도메인 복습 방향을 제안한다(해당 `domains/*.md` 개념서 경로 안내, 필요 시 cks-tutor 에이전트로 개념 복습, `/quiz`로 약점 토픽 랩드파이어 연습). 실습 중 막힌 디버깅은 k8s-troubleshooter 에이전트로 넘긴다.
