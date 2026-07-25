---
name: cheatsheet
description: 토픽 하나를 입력하면 그 주제의 핵심 명령어와 YAML을 복붙 가능한 형태로 즉석 압축 요약한다. "치트시트", "cheatsheet", "명령어 정리", "빠른 참조", "핵심만 정리", "NetworkPolicy 명령 모아줘" 같이 말할 때 사용. 개념 설명·문제풀이가 아니라, 이미 아는 주제의 명령/문법을 시험 직전에 빠르게 되짚고 싶을 때 발동한다.
---

# /cheatsheet — 토픽별 핵심 명령/YAML 즉석 요약

특정 토픽(예: NetworkPolicy, PSA, etcd 암호화, Falco, AppArmor, cosign)을 입력받아, 저장소 개념서에서 **복사해서 바로 실행 가능한** 핵심 명령어와 YAML 스켈레톤만 뽑아 압축 출력하는 스킬이다. 개념 설명이나 hands-on 문제 풀이가 아니라, **시험 직전 빠른 참조(quick reference)** 용도다.

> ⚠️ **이 스킬은 요약·인출용이다.** 개념을 처음 배우는 단계라면 해당 `domains/*.md` 개념서를 직접 읽거나 cks-tutor 에이전트를 쓰고, 손에 익히는 연습은 `/quiz`·`/mock-exam`으로 해야 한다. `/cheatsheet`는 "이미 아는 것을 시험 직전에 빠르게 되짚는" 도구임을 세션 시작 시 한 줄로 알려라.

---

## 역할

토픽 하나의 핵심 명령어·YAML 스켈레톤을 개념서·가이드 근거로 복붙 가능하게 압축 출력한다.

## 하지 않는 것

- 근거 없는 명령/문법 생성 (환각 금지, 개념서에서 확인)
- 폐기 토픽(PodSecurityPolicy 등) 포함
- 개념 심화 설명·문제 풀이 (→ cks-tutor, `/quiz`)

## 1단계 — 토픽 입력 받기

사용자에게 요약할 **토픽 하나**를 확정한다(이미 요청에 들어 있으면 되묻지 말고 바로 진행).

- 예시 토픽: `NetworkPolicy`, `PSA`, `etcd 암호화`(EncryptionConfiguration), `Falco`, `AppArmor`, `seccomp`, `RBAC`, `ServiceAccount`, `CSR 인증서`, `kubelet 하드닝`, `apiserver 하드닝`, `kube-bench`, `Ingress TLS`, `gVisor RuntimeClass`, `Cilium/Istio 암호화`, `ValidatingAdmissionPolicy`, `SBOM`(bom/trivy), `cosign`, `kubesec/kube-linter`, `securityContext`(컨테이너 불변성), `Audit Policy`, `Secrets`, `침해 조사`(crictl/proc), `System Hardening`.
- 토픽이 모호하거나 여러 개면 하나로 좁히도록 되묻는다. "전부"를 원하면 `guide/00-exam-guide.md`의 「핵심 명령어 치트시트」 섹션 전체를 안내하고, 그 안에서 관심 토픽을 고르게 한다.

### 토픽 → 근거 파일/섹션 매핑

출력 전에 **반드시 아래 근거 파일을 Read로 열어** 실제 명령/YAML을 확인한다. 기억에만 의존해 만들지 않는다. 1차 근거는 항상 `guide/00-exam-guide.md`의 「핵심 명령어 치트시트」·「자주 쓰는 YAML 스켈레톤」 섹션이고, 도메인 개념서에서 세부를 보강한다.

| 토픽 | 근거 파일 (핵심 섹션) |
|---|---|
| NetworkPolicy | `domains/01-cluster-setup.md` §1 (1.2 default-deny, 1.4 AND/OR, 1.5 ipBlock, 1.6 DNS egress) + guide 치트시트 default-deny YAML |
| kube-bench | `domains/01-cluster-setup.md` §2 (2.2 실행, 2.4 빈출 수정, 2.5 static pod 절차) |
| Ingress TLS | `domains/01-cluster-setup.md` §3 (3.2 TLS Secret, 3.3 Ingress 연결) |
| 바이너리 검증(sha512) | `domains/01-cluster-setup.md` + guide 치트시트 `sha512sum` |
| RBAC | `domains/02-cluster-hardening.md` §1 (1.1 명령형 생성, 1.3 감사, 1.4 축소) + guide `auth can-i --list` |
| ServiceAccount / automount | `domains/02-cluster-hardening.md` §2 (2.2 SA vs Pod 레벨, 2.3 토큰 발급) |
| apiserver 하드닝 | `domains/02-cluster-hardening.md` §3 (3.2 하드닝 플래그) |
| kubelet 하드닝 | `domains/02-cluster-hardening.md` §3.3 + guide 치트시트 kubelet config 4종 |
| CSR 인증서 발급 | `domains/02-cluster-hardening.md` + guide 치트시트 「인증서 사용자 생성 흐름」 |
| System Hardening(서비스/포트/패키지) | `domains/03-system-hardening.md` §2 (2.1 서비스, 2.2 패키지, 2.3 포트) |
| SSH/sudo 최소화 | `domains/03-system-hardening.md` §3 (3.2 sudo, 3.3 SSH) |
| AppArmor | `domains/03-system-hardening.md` + guide 치트시트 `aa-status`/`apparmor_parser` |
| seccomp | `domains/03-system-hardening.md` |
| PSA (Pod Security Admission) | `domains/04-minimize-microservice-vulnerabilities.md` §1 (1.3 3모드, 1.4 restricted 템플릿, 1.6 AdmissionConfiguration) + guide PSA 라벨 |
| securityContext / 컨테이너 불변성 | `domains/04-...md` §2 (2.3 빈출 조합) + `domains/06-...md` §3 |
| Secrets | `domains/04-...md` §3 (3.2 생성/사용, 3.3 etcd 평문, 3.4 RBAC 제한) |
| etcd 암호화(EncryptionConfiguration) | `domains/04-...md` §3.3 + guide EncryptionConfiguration YAML·etcdctl·재암호화 |
| gVisor RuntimeClass | `domains/04-...md` + guide RuntimeClass YAML·`dmesg | grep gvisor` |
| Cilium/Istio 암호화 | `domains/04-...md` (Cilium WireGuard/IPsec, Istio PeerAuthentication STRICT) |
| 베이스 이미지 / Dockerfile | `domains/05-supply-chain-security.md` §1 (멀티스테이지, 체크리스트) |
| SBOM (bom / trivy) | `domains/05-...md` §2 + guide 치트시트 `bom generate`/`trivy image` |
| cosign | `domains/05-...md` §3 (cosign 기본 명령) + guide `cosign sign/verify` |
| ValidatingAdmissionPolicy (CEL) | `domains/05-...md` §3 (허용 레지스트리 강제) |
| kubesec / kube-linter | `domains/05-...md` §4 |
| Falco | `domains/06-monitoring-logging-runtime-security.md` §1 (1.3 문법, 1.4 output 오버라이드, 1.5 실행/수집) + guide Falco 블록 |
| 침해 조사 (crictl / /proc) | `domains/06-...md` §2 + guide 치트시트 「침해 조사」 |
| Audit Policy | `domains/06-...md` §4 |

## 2단계 — 압축 요약 출력

Read로 확인한 실제 내용을 근거로, **바로 복붙해 실행할 수 있는 형태**로 압축한다.

- 출력 순서: ① 한 줄 핵심 요약 → ② 핵심 명령어 블록(```bash```) → ③ 필요한 경우 YAML 스켈레톤(```yaml```) → ④ 빈출 함정 1~3줄(⚠️) → ⑤ 3단계의 허용 문서 안내.
- **길게 설명하지 마라.** 치트시트답게 명령/문법 위주로, 각 줄에 한국어 주석으로 용도만 짧게 단다(예: `# 라벨 확인`). 개념 배경은 넣지 않는다.
- `NS`, `POD`, `SA`, `이미지명` 같은 자리표시자는 그대로 두어 사용자가 값만 바꿔 쓰게 한다.
- 명령/YAML은 **v1.35(containerd, Ubuntu 노드) 환경에서 즉시 실행 가능**해야 한다. 폐기된 PodSecurityPolicy(PSP)나 annotation 방식 AppArmor 등 2024-10 개편에서 삭제·대체된 메커니즘은 절대 출력하지 않는다(현행: `securityContext.appArmorProfile`, PSA 라벨, `securityContext.seccompProfile`).
- 근거에 없는 플래그·필드를 추측해 채우지 않는다. 확인한 내용만 쓰고, 근거 파일 경로를 마지막에 한 줄로 표기한다(예: `근거: domains/06-...md §1.4, guide/00-exam-guide.md 치트시트`).

## 3단계 — 허용 문서 안내

시험 중 Firefox로 열 수 있는 문서는 **8개뿐**이다. 출력한 토픽을 시험장에서 확인하려면 어느 문서의 어떤 페이지를 보면 되는지 함께 알려준다. 토픽 → 허용 문서 매핑:

| 토픽 | 허용 문서 | 찾을 페이지/검색어 |
|---|---|---|
| NetworkPolicy | kubernetes.io/docs | "Network Policies" (default-deny·selector YAML 복사용) |
| CiliumNetworkPolicy / Cilium 암호화 | docs.cilium.io/en/stable | "Network Policy", "Encryption" (WireGuard/IPsec) |
| Istio mTLS | istio.io/latest/docs | "PeerAuthentication", "Mutual TLS Migration" |
| PSA | kubernetes.io/docs | "Pod Security Standards" (`/docs/concepts/security/pod-security-standards/`), "Pod Security Admission" |
| securityContext | kubernetes.io/docs | "Configure a Security Context for a Pod or Container" |
| etcd 암호화 | kubernetes.io/docs | "Encrypting Confidential Data at Rest" (EncryptionConfiguration YAML) |
| etcdctl 사용 | etcd.io/docs | "Interacting with etcd" (인증 플래그) — 단, 자주 쓰면 암기가 빠름 |
| seccomp | kubernetes.io/docs | "Restrict a Container's Syscalls with seccomp" |
| AppArmor | kubernetes.io/docs | "Restrict a Container's Access to Resources with AppArmor" (현행 `appArmorProfile`) |
| RuntimeClass (gVisor) | kubernetes.io/docs | "Runtime Class" |
| ValidatingAdmissionPolicy | kubernetes.io/docs | "Validating Admission Policy" (CEL 표현식) |
| RBAC / ServiceAccount / CSR | kubernetes.io/docs | "Using RBAC Authorization", "Certificate Signing Requests" |
| kubelet / apiserver 하드닝 | kubernetes.io/docs | "kubelet 설정 파일 참조", kube-apiserver 플래그 레퍼런스 |
| Audit Policy | kubernetes.io/docs | "Auditing" (Policy·backend 설정) |
| Ingress TLS | kubernetes.github.io/ingress-nginx | "annotations", nginx-configuration |
| Falco | falco.org/docs | "Rules", "Supported Fields for Conditions and Outputs" (output 필드 전체) |
| SBOM (bom) | kubernetes-sigs.github.io/bom/cli-reference | CLI reference 첫 페이지 (`bom generate`/`document outline`) |

> ⚠️ **허용 문서에 없는 도구는 명령어를 암기해야 한다.** `trivy`, `cosign`, `kubesec`, `kube-linter`, `kube-bench` 등은 8개 허용 문서에 공식 페이지가 없다. 이 토픽을 요약할 때는 "이 도구는 시험 중 참조할 문서가 없으니 아래 명령을 외워 가야 한다"고 명시하라. (SBOM은 `bom`만 문서 참조 가능, `trivy`로 만드는 SBOM 명령은 암기.)

---

## 준수 사항

- 모든 명령/YAML은 반드시 `guide/00-exam-guide.md`와 지정된 개념서에서 **Read로 확인한 내용**에만 근거한다. 과장·환각 금지, 근거 파일 경로를 항상 밝힌다.
- 명령/YAML은 v1.35 기준 즉시 실행 가능해야 한다. PSP 등 삭제된 메커니즘은 출력하지 않는다.
- 치트시트답게 **짧고 복붙 가능하게**. 설명은 주석 한 줄, 본문은 명령/문법 위주.
- 허용 문서 8개 밖을 시험 중 참조처로 안내하지 않는다. 문서가 없는 도구는 그 사실을 알린다.
