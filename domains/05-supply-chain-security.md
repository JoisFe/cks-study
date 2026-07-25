# Domain 5 — Supply Chain Security (공급망 보안)

컨테이너 이미지가 만들어지고, 서명되고, 클러스터에 배포되기까지의 전체 공급망을 방어하는 도메인이다. 최소 베이스 이미지, SBOM, 아티팩트 서명, 정적 분석, 이미지 취약점 스캔을 다룬다.

> **📊 시험 비중: 20% (공동 최고 비중)** — Minimize Microservice Vulnerabilities, Monitoring/Logging/Runtime Security와 함께 가장 높은 가중치를 가진 도메인이다. 2024-10-15 커리큘럼 대개편으로 **SBOM(bom/trivy)** 과 **정적 분석(Kubesec/KubeLinter)** 이 새로 추가되어 신규 유형이 활발히 출제된다. 16문제 기준 3문제 이상이 이 도메인에서 나온다고 가정하고 준비하라. 시험 중 참조 가능한 공식 문서에 `kubernetes-sigs.github.io/bom/cli-reference/`가 포함되어 있다는 점을 기억할 것.

## 목차

- [1. 베이스 이미지 최소화](#1-베이스-이미지-최소화)
- [2. 공급망 이해와 SBOM](#2-공급망-이해와-sbom)
- [3. 아티팩트 서명과 검증](#3-아티팩트-서명과-검증)
- [4. 정적 분석 (Kubesec / KubeLinter)](#4-정적-분석-kubesec--kubelinter)
- [5. 이미지 취약점 스캔 (Trivy)](#5-이미지-취약점-스캔-trivy)
- [연습문제 (실전 12문제)](#연습문제-실전-12문제)
- [🎯 시험 직전 체크리스트](#-시험-직전-체크리스트)
- [핵심 명령어 치트시트](#핵심-명령어-치트시트)

---

## 1. 베이스 이미지 최소화

### 이미지 레이어와 공격면

컨테이너 이미지는 Dockerfile의 각 명령(`FROM`, `RUN`, `COPY` 등)이 만든 레이어의 적층이다. 레이어에 들어간 것은 **다음 레이어에서 지워도 이미지 히스토리에 남는다**. 즉:

- 빌드 도구(gcc, go, git), 패키지 매니저 캐시, 디버깅 유틸리티(curl, vim)가 최종 이미지에 남아 있으면 그만큼 CVE(Common Vulnerabilities and Exposures — 공개된 보안 취약점에 부여되는 고유 식별자) 노출 면적이 커진다.
- `ENV`/`ARG`/`COPY`로 들어간 secret은 `docker history`, `docker inspect`로 그대로 노출된다. 뒤 레이어에서 `rm` 해도 소용없다.
- 베이스 이미지가 클수록(ubuntu 전체 > alpine > distroless > scratch) 취약점 수도 비례해서 많다.

레이어 확인은 다음 명령으로 한다.

```bash
docker history nginx:1.25.3            # 레이어별 명령과 크기
docker inspect nginx:1.25.3            # ENV, USER, ENTRYPOINT 등 메타데이터
```

### 멀티스테이지 빌드 — Before / After

빌드 환경과 실행 환경을 분리하는 것이 핵심이다. 빌드 스테이지의 레이어는 최종 이미지에 **전혀 포함되지 않는다**.

**Before — 나쁜 예 (시험에 이런 Dockerfile이 주어진다):**

```dockerfile
FROM ubuntu:latest
RUN apt-get update && apt-get install -y golang git curl vim
ENV DB_PASSWORD=SuperSecret123
COPY . /app
WORKDIR /app
RUN go build -o /app/server .
CMD ["/app/server"]
```

문제점: `latest` 태그, 루트 실행, 빌드 도구/에디터가 최종 이미지에 잔존, secret이 ENV로 박제, apt 캐시 미정리.

**After — 멀티스테이지 + distroless + 비루트:**

```dockerfile
FROM golang:1.22.5-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/server /server
USER nonroot
ENTRYPOINT ["/server"]
```

최종 이미지에는 정적 바이너리 하나만 남는다. 쉘도 패키지 매니저도 없으므로 공격자가 침투해도 할 수 있는 일이 거의 없다.

### 베이스 이미지 비교표

| 베이스 | 크기 | 쉘/패키지 매니저 | 디버깅 | 적합한 경우 |
|---|---|---|---|---|
| `scratch` | 0 B | 없음 | 매우 어려움 | 완전 정적 바이너리 (Go, Rust) |
| `gcr.io/distroless/*` | 수 MB~수십 MB | 없음 (쉘 없음, `:debug` 태그에만 busybox) | 어려움 | 런타임 라이브러리가 필요한 앱, 보안 최우선 |
| `alpine` | 약 5 MB | ash + apk | 쉬움 | 쉘/패키지 설치가 필요한 경우 |
| `ubuntu`/`debian` (slim 아님) | 수십~수백 MB | bash + apt | 매우 쉬움 | 피해야 함 (공격면 최대) |

### Dockerfile 보안 체크리스트

시험에서 "이 Dockerfile의 보안 문제를 고쳐라" 유형이 나오면 아래 순서로 점검한다.

1. **버전 고정**: `FROM nginx:latest` 금지 → `FROM nginx:1.25.3-alpine` 처럼 특정 태그(가능하면 `@sha256:...` digest)로 고정.
2. **비루트 USER**: `USER 10001` 또는 `USER nginx` 지정. distroless는 `:nonroot` 태그 사용.
3. **secret 금지**: `ENV API_KEY=...`, `ARG PASSWORD`, `COPY id_rsa /root/.ssh/` 전부 제거. secret은 런타임에 Kubernetes Secret으로 주입.
4. **캐시/불필요 패키지 제거**: `apk add --no-cache ...`, `apt-get install -y ... && rm -rf /var/lib/apt/lists/*`. curl/vim/git 같은 불필요 도구 설치 삭제.
5. **멀티스테이지**: 빌드 도구는 build 스테이지에만, 최종 스테이지는 distroless/alpine/scratch.
6. **COPY 최소화**: `COPY . .` 대신 필요한 파일만. (`.dockerignore` 개념도 알아둘 것.)

> **💡 시험 팁**: Dockerfile 수정 문제는 보통 "고칠 항목"을 명시해 준다(예: "run as user myuser", "pin the base image version"). 요구하지 않은 부분까지 과도하게 리팩터링하다가 빌드를 깨뜨리지 마라. 수정 후 `docker build`(또는 `podman build`)로 빌드가 되는지 확인하라는 지시가 있으면 반드시 실행할 것.

> **⚠️ 함정**: `RUN rm -rf /var/lib/apt/lists/*`를 **별도의 RUN**으로 쓰면 캐시가 이전 레이어에 이미 박제되어 크기가 줄지 않는다. 반드시 `apt-get install`과 **같은 RUN에서 &&로 연결**해야 한다. secret도 마찬가지로 뒤에서 지워도 레이어에 남는다.

### 📝 문제로 이해하기

**Task (mini):** A Dockerfile is located at `/opt/course/m1/Dockerfile`. It currently uses the `latest` tag and the container runs as root. Change the base image to `nginx:1.25.3-alpine` and make the container process run as user `nginx`. Build the image as `web:fixed` to confirm it still builds.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

FROM 라인의 태그를 고정하고, 마지막 단계(CMD/ENTRYPOINT 직전)에 `USER nginx`를 추가한 뒤 빌드로 검증한다.

**2) 단계별 명령어**

```bash
vim /opt/course/m1/Dockerfile
```

```dockerfile
FROM nginx:1.25.3-alpine
COPY index.html /usr/share/nginx/html/
USER nginx
CMD ["nginx", "-g", "daemon off;"]
```

```bash
docker build -t web:fixed /opt/course/m1
```

**3) 검증 방법**

```bash
docker run --rm web:fixed id     # uid가 nginx(비루트)인지 확인 (쉘이 있는 이미지일 때)
docker inspect web:fixed | grep -A2 '"User"'
```

**4) ⚠️ 함정 포인트**

- `USER`는 그 **이후의** RUN/CMD/ENTRYPOINT에만 적용된다. 루트 권한이 필요한 `RUN`(패키지 설치 등)보다 뒤, 실행 명령보다 앞에 둘 것.
- nginx 공식 이미지를 비루트로 돌리면 80 포트 바인딩이 실패할 수 있다. 문제에서 빌드 성공만 요구하면 빌드 확인까지, 실행 확인을 요구하면 포트 설정까지 챙긴다.

</details>

---

## 2. 공급망 이해와 SBOM

### SBOM이란

SBOM(Software Bill of Materials)은 소프트웨어(여기서는 컨테이너 이미지)에 **어떤 패키지가 어떤 버전으로 포함되어 있는지**를 기계가 읽을 수 있는 형식으로 기록한 "부품 명세서"다. Log4Shell 같은 사태가 터졌을 때 "우리 이미지에 log4j 2.x가 들어 있는가?"를 즉시 답할 수 있게 해 준다. 2024 커리큘럼 개편에서 새로 추가된 주제이며 `bom`과 `trivy` 두 도구가 출제 대상이다.

### SPDX vs CycloneDX

| 항목 | SPDX | CycloneDX |
|---|---|---|
| 주관 | Linux Foundation (ISO/IEC 5962 국제표준) | OWASP |
| 포맷 | tag-value(.spdx), JSON, YAML 등 | JSON, XML |
| 성격 | 라이선스/컴플라이언스 기원, 범용 | 보안(취약점 연계) 중심 |
| 도구 | `bom`(SPDX 전용), `trivy --format spdx-json` | `trivy --format cyclonedx` |

### bom으로 SBOM 생성/조회

`bom`은 Kubernetes SIG Release가 만든 SPDX(Software Package Data Exchange) 전용 도구다. 문서는 시험 중 열람 허용 목록에 있다: `kubernetes-sigs.github.io/bom/cli-reference/`.

```bash
# 이미지에서 SPDX SBOM 생성
bom generate --image registry.k8s.io/kube-apiserver:v1.35.0 --output /opt/course/5/sbom.spdx

# 생성된 SBOM 구조를 트리 형태로 조회
bom document outline /opt/course/5/sbom.spdx

# 특정 패키지 찾기 (outline 출력을 grep)
bom document outline /opt/course/5/sbom.spdx | grep -i libssl
```

`bom generate`는 `--image`(이미지), `--dirs`(디렉토리), `--file`(파일)을 입력으로 받을 수 있고, `--output`이 없으면 stdout으로 출력한다.

### trivy로 SBOM 생성/스캔

```bash
# SPDX JSON 형식 SBOM 생성
trivy image --format spdx-json --output /opt/course/5/sbom.json nginx:1.25.3

# CycloneDX 형식 SBOM 생성
trivy image --format cyclonedx --output /opt/course/5/sbom.cdx.json nginx:1.25.3

# 이미 만들어진 SBOM 파일을 입력으로 취약점 스캔
trivy sbom /opt/course/5/sbom.json
trivy sbom --severity CRITICAL /opt/course/5/sbom.json
```

### 빈출 유형: SBOM에서 특정 패키지/버전 찾기

"이미지 X의 SBOM을 만들고, 그 안의 패키지 Y의 버전을 파일에 기록하라" 유형이 나온다.

```bash
# SPDX tag-value(.spdx)라면
grep -A3 -i 'PackageName: openssl' /opt/course/5/sbom.spdx    # PackageVersion 라인 확인

# SPDX JSON이라면 jq 사용
jq -r '.packages[] | select(.name | test("openssl")) | "\(.name) \(.versionInfo)"' /opt/course/5/sbom.json
```

> **📌 암기 포인트**: `bom generate --image ... --output ...` → 생성, `bom document outline ...` → 조회. 이 두 서브커맨드 조합만 기억하면 bom 문제는 풀린다. trivy는 `--format spdx-json|cyclonedx` + `--output`, 그리고 SBOM을 다시 스캔할 때는 `trivy sbom 파일`.

> **⚠️ 함정**: `bom document outline`은 사람이 읽는 트리 출력이다. 문제가 "버전을 파일에 저장하라"고 하면 grep으로 찾아서 **요구한 정확한 경로/형식**으로 저장해야 한다. 또한 이미지 태그를 문제 지문과 정확히 일치시켜라. 태그가 다르면 패키지 버전도 달라져 오답 처리된다.

### 📝 문제로 이해하기

**Task (mini):** Using `bom`, generate an SPDX SBOM for the image `alpine:3.19` and save it to `/opt/course/m2/sbom.spdx`. Then find the version of the package `musl` contained in the image and write it to `/opt/course/m2/musl-version`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`bom generate`로 SBOM을 만들고 `bom document outline` 또는 grep으로 musl 패키지 버전을 찾아 기록한다.

**2) 단계별 명령어**

```bash
mkdir -p /opt/course/m2
bom generate --image alpine:3.19 --output /opt/course/m2/sbom.spdx
bom document outline /opt/course/m2/sbom.spdx | grep -i musl
grep -A3 -i 'PackageName: musl' /opt/course/m2/sbom.spdx
echo "1.2.4-r2" > /opt/course/m2/musl-version   # 실제 확인된 버전으로 기록
```

**3) 검증 방법**

```bash
cat /opt/course/m2/musl-version
ls -l /opt/course/m2/sbom.spdx
```

**4) ⚠️ 함정 포인트**

- 버전 문자열을 눈으로 확인한 그대로 기록할 것. 추측 금지.
- 출력 파일 경로가 문제 지문과 한 글자라도 다르면 채점되지 않는다. 디렉토리가 없으면 `mkdir -p` 먼저.

</details>

---

## 3. 아티팩트 서명과 검증

### 서명이 공급망에서 중요한 이유

레지스트리의 이미지 태그는 언제든 다른 내용으로 덮어써질 수 있다(태그는 가변 포인터다). 서명은 "이 이미지는 우리가 빌드한 그 바이트 그대로"임을 암호학적으로 보장한다. CI에서 빌드 → 서명 → 배포 시 검증(admission — apiserver가 리소스를 저장하기 전 요청을 검사해 허용·거부·변경하는 단계)으로 이어지는 체인이 공급망 보안의 골격이다.

### cosign 기본 명령

```bash
# 키 쌍 생성: cosign.key(개인키) + cosign.pub(공개키). 암호는 COSIGN_PASSWORD 환경변수로도 전달 가능
cosign generate-key-pair

# 이미지 서명 (서명이 OCI 아티팩트로 레지스트리에 push됨)
cosign sign --key cosign.key registry.example.com/apps/web:v1.2.3

# 서명 검증 (성공 시 서명 claim JSON 출력, 실패 시 비정상 종료코드)
cosign verify --key cosign.pub registry.example.com/apps/web:v1.2.3
```

> **💡 시험 팁**: `sign`은 **개인키(cosign.key)**, `verify`는 **공개키(cosign.pub)**. 서명은 레지스트리에 저장되므로 push 권한이 필요하다. 검증 실패(변조/미서명)는 명령이 0이 아닌 종료코드로 끝나는 것으로 판별한다.

### ImagePolicyWebhook Admission Controller

kube-apiserver의 admission 단계에서 **외부 웹훅 서버에게 "이 이미지 배포를 허용할까?"를 물어보는** 컨트롤러다. 시험에서는 보통 웹훅 서버와 파일들이 미리 준비되어 있고, 설정 파일을 완성하고 apiserver에 연결하는 것까지가 과제다.

**구성 요소 3가지:**

1. **AdmissionConfiguration 파일** — admission 플러그인별 설정 진입점:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: ImagePolicyWebhook
    configuration:
      imagePolicy:
        kubeConfigFile: /etc/kubernetes/admission/kubeconf
        allowTTL: 50
        denyTTL: 50
        retryBackoff: 500
        defaultAllow: false
```

- `defaultAllow: false` = **fail-closed**. 웹훅 서버에 연결할 수 없으면 모든 Pod 생성을 **거부**한다. `true`면 웹훅 장애 시 전부 허용(보안상 구멍). 시험에서는 거의 항상 `false`를 요구한다.

2. **kubeConfigFile** — apiserver가 웹훅 서버에 접속할 때 쓰는 kubeconfig 형식 파일:

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: image-checker
    cluster:
      certificate-authority: /etc/kubernetes/admission/external-ca.crt
      server: https://image-checker.example.com/review
contexts:
  - name: image-checker
    context:
      cluster: image-checker
      user: api-server
current-context: image-checker
users:
  - name: api-server
    user:
      client-certificate: /etc/kubernetes/admission/apiserver-client.crt
      client-key: /etc/kubernetes/admission/apiserver-client.key
```

3. **kube-apiserver 플래그** — `/etc/kubernetes/manifests/kube-apiserver.yaml` 수정:

```yaml
- --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
- --admission-control-config-file=/etc/kubernetes/admission/admission_config.yaml
```

설정 파일 디렉토리를 apiserver Pod가 읽을 수 있도록 hostPath 볼륨을 추가해야 한다(자주 빠뜨리는 함정):

```yaml
# volumeMounts에 추가
- name: admission-config
  mountPath: /etc/kubernetes/admission
  readOnly: true
# volumes에 추가
- name: admission-config
  hostPath:
    path: /etc/kubernetes/admission
    type: DirectoryOrCreate
```

저장하면 kubelet이 apiserver를 자동 재생성한다(30초~1분 대기). 안 뜨면 `crictl ps -a`, `journalctl -u kubelet`, `/var/log/pods/`로 디버깅한다.

> **⚠️ 함정**: `--enable-admission-plugins`에 ImagePolicyWebhook을 추가할 때 **기존 값(NodeRestriction 등)을 지우지 말고 콤마로 이어붙여야** 한다. 또 `--admission-control-config-file` 플래그 자체를 잊거나, hostPath 마운트를 빠뜨려 apiserver가 CrashLoop에 빠지는 것이 최다 실수다.

### ValidatingAdmissionPolicy (CEL) — 허용 레지스트리 강제의 현대적 방법

v1.30에서 GA된 ValidatingAdmissionPolicy는 **웹훅 서버 없이** apiserver 내장 CEL(Common Expression Language — 정책 조건을 기술하는 표현식 언어) 엔진으로 리소스를 검증한다. 외부 의존성이 없어 ImagePolicyWebhook보다 간단하고, "특정 레지스트리 이미지만 허용" 같은 정책에 적합하다. (OPA Gatekeeper도 같은 목적의 도구지만 CKS에서는 참고 수준으로만 알아두면 된다.)

**Policy — 검증 규칙 정의:**

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
    - expression: >-
        object.spec.containers.all(c, c.image.startsWith('registry.company.io/'))
        && (!has(object.spec.initContainers)
            || object.spec.initContainers.all(c, c.image.startsWith('registry.company.io/')))
      message: "Only images from registry.company.io are allowed."
```

**Binding — 어디에 적용할지 연결:**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: allowed-registry-binding
spec:
  policyName: allowed-registry
  validationActions: ["Deny"]
  matchResources:
    namespaceSelector:
      matchLabels:
        registry-policy: enforced
```

- `validationActions`: `Deny`(거부), `Warn`(경고만), `Audit`(audit 로그 기록). 시험은 보통 Deny.
- Policy만 만들고 **Binding을 안 만들면 아무 효과가 없다** — 빈출 함정.
- CEL에서 옵셔널 필드는 `has()`로 존재 확인 후 접근해야 한다(`initContainers`가 대표적).

검증:

```bash
kubectl label ns team-a registry-policy=enforced
kubectl -n team-a run bad --image=docker.io/nginx:1.25.3        # 거부되어야 함
kubectl -n team-a run good --image=registry.company.io/nginx:1.25.3   # 허용(레지스트리 존재 시)
```

### 📝 문제로 이해하기

**Task (mini):** Generate a cosign key pair in `/opt/course/m3/`. Sign the image `registry.local:5000/demo/app:v1` with the private key, then verify it with the public key and save the verification output to `/opt/course/m3/verify.json`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`generate-key-pair` → `sign --key cosign.key` → `verify --key cosign.pub` 순서. verify의 stdout을 파일로 리다이렉트한다.

**2) 단계별 명령어**

```bash
mkdir -p /opt/course/m3 && cd /opt/course/m3
cosign generate-key-pair                      # 암호 입력 프롬프트 (빈 암호 허용)
cosign sign --key cosign.key registry.local:5000/demo/app:v1
cosign verify --key cosign.pub registry.local:5000/demo/app:v1 > /opt/course/m3/verify.json
```

**3) 검증 방법**

```bash
echo $?                        # 0이면 검증 성공
cat /opt/course/m3/verify.json # 서명 claim JSON 확인
```

**4) ⚠️ 함정 포인트**

- sign 단계에서 레지스트리 push가 일어나므로 로컬/사설 레지스트리 접근이 되는지 확인. `-y` 없이 실행하면 확인 프롬프트가 나올 수 있다(`cosign sign -y ...`로 스킵 가능).
- verify는 **공개키**다. `--key cosign.key`로 verify하면 실패한다.

</details>

---

## 4. 정적 분석 (Kubesec / KubeLinter)

### kubesec — manifest 점수화

kubesec은 단일 Kubernetes manifest의 보안 위험을 **점수(score)** 로 평가하고 개선 항목을 알려 준다. 2024 개편에서 추가된 도구다.

```bash
# 로컬 바이너리로 스캔
kubesec scan /opt/course/8/pod.yaml

# 바이너리가 없으면 공개 API 사용
curl -sSX POST --data-binary @/opt/course/8/pod.yaml https://v2.kubesec.io/scan
```

출력(JSON)의 핵심 필드:

```json
[
  {
    "object": "Pod/web.default",
    "valid": true,
    "score": -30,
    "scoring": {
      "critical": [
        {
          "id": "Privileged",
          "selector": "containers[] .securityContext .privileged == true",
          "reason": "Privileged containers can allow almost completely unrestricted host access"
        }
      ],
      "advise": [
        {
          "id": "ApparmorAny",
          "reason": "Well defined AppArmor policies may provide greater protection"
        },
        {
          "id": "ReadOnlyRootFilesystem",
          "reason": "An immutable root filesystem can prevent malicious binaries being added"
        }
      ]
    }
  }
]
```

- **critical**: 점수를 크게 깎는 즉시 수정 대상 (privileged, hostPID, hostNetwork, CAP_SYS_ADMIN 등).
- **advise**: 점수를 올려 주는 권장 사항 (runAsNonRoot, readOnlyRootFilesystem, capabilities drop ALL, requests/limits, serviceAccountName 등).

시험 유형: "kubesec으로 스캔해서 critical 이슈를 제거하라" → manifest에서 `privileged: true` 삭제, `securityContext` 보강 후 재스캔으로 점수 상승 확인.

```yaml
# 점수를 올리는 대표 securityContext 패턴
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

### KubeLinter — manifest/차트 린트

KubeLinter는 여러 파일/디렉토리/Helm 차트에 대해 수십 개의 체크를 일괄 실행한다.

```bash
kube-linter lint /opt/course/9/manifests/       # 디렉토리 전체
kube-linter lint /opt/course/9/deploy.yaml      # 단일 파일
kube-linter checks list                         # 사용 가능한 체크 목록
kube-linter lint --format json /opt/course/9/   # JSON 출력
```

자주 보고되는 체크: `run-as-non-root`, `no-read-only-root-fs`, `unset-cpu-requirements`, `unset-memory-requirements`, `latest-tag`, `privileged-container`. 출력 메시지에 **수정 방법(Remediation)이 함께 표시**되므로 그대로 따라 고치면 된다.

CI 관점: 두 도구 모두 종료코드로 성공/실패를 반환하므로 파이프라인 게이트(빌드 → lint/scan 실패 시 중단)로 쓰는 것이 표준 패턴이다. 시험에서는 개념만 알면 충분하다.

### 도구 비교표 — 무엇을 스캔하는가

| 도구 | 스캔 대상 | 출력 | 대표 용도 |
|---|---|---|---|
| **kubesec** | Kubernetes manifest 1개 | score + critical/advise JSON | manifest 보안 점수화·개선 |
| **kube-linter** | manifest 다수 / 디렉토리 / Helm 차트 | 체크 위반 목록 + Remediation | 배포 전 일괄 린트 |
| **trivy** | 컨테이너 이미지, 파일시스템, SBOM, IaC | CVE 목록, SBOM | 취약점 스캔·SBOM 생성 |
| **bom** | 컨테이너 이미지/디렉토리/파일 | SPDX SBOM | SBOM 생성·조회 |
| **cosign** | 이미지(OCI 아티팩트 — Open Container Initiative 표준) | 서명/검증 결과 | 아티팩트 서명·검증 |

> **📌 암기 포인트**: "manifest 점수 = kubesec, manifest 린트 = kube-linter, 이미지 CVE = trivy, SBOM = bom/trivy, 서명 = cosign". 문제 지문에 등장하는 도구 이름을 보고 즉시 스캔 대상을 떠올릴 수 있어야 한다.

### 📝 문제로 이해하기

**Task (mini):** Run `kubesec scan` against `/opt/course/m4/pod.yaml`. The manifest currently contains a critical issue. Remove the critical issue, improve the manifest so the score is positive, and save the fixed manifest to `/opt/course/m4/pod-fixed.yaml`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

스캔 → critical 항목(대개 `privileged: true`) 제거 → advise 항목 반영(runAsNonRoot, readOnlyRootFilesystem 등) → 재스캔으로 점수 확인.

**2) 단계별 명령어**

```bash
kubesec scan /opt/course/m4/pod.yaml          # score와 critical 확인
cp /opt/course/m4/pod.yaml /opt/course/m4/pod-fixed.yaml
vim /opt/course/m4/pod-fixed.yaml
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  containers:
    - name: web
      image: nginx:1.25.3-alpine
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
```

```bash
kubesec scan /opt/course/m4/pod-fixed.yaml    # score가 양수인지 확인
```

**3) 검증 방법**

재스캔 출력에서 `"critical": []` (또는 critical 부재)과 `score` 양수를 확인한다.

**4) ⚠️ 함정 포인트**

- `privileged: true`를 지우지 않고 advise만 반영하면 점수가 계속 음수다. critical 먼저.
- 수정본을 별도 파일로 저장하라는 지시가 있으면 원본을 덮어쓰지 말 것.

</details>

---

## 5. 이미지 취약점 스캔 (Trivy)

### trivy image 기본기

```bash
# 기본 스캔
trivy image nginx:1.25.3

# 심각도 필터 (시험 빈출: CRITICAL만, 또는 CRITICAL,HIGH)
trivy image --severity CRITICAL,HIGH nginx:1.25.3

# 수정 가능한(fixed version 존재) 취약점만
trivy image --severity CRITICAL --ignore-unfixed nginx:1.25.3

# JSON 출력을 파일로
trivy image -f json -o /opt/course/11/report.json nginx:1.25.3
```

테이블 출력 마지막의 `Total: N (CRITICAL: x, HIGH: y)` 라인으로 개수를 빠르게 파악할 수 있다.

JSON에서 CRITICAL만 추출하는 jq 패턴(외워 두면 시간 절약):

```bash
# CRITICAL CVE ID 목록
jq -r '.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL") | .VulnerabilityID' report.json | sort -u

# CRITICAL 개수
jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' report.json
```

### 빈출 유형: 클러스터에서 취약 이미지 찾아 조치

"네임스페이스 X의 Pod들이 쓰는 이미지를 스캔해 CRITICAL 취약점이 있는 Pod를 삭제(또는 Deployment scale 0)하라" 유형이 단골이다.

```bash
# 1) 네임스페이스의 Pod별 이미지 나열
kubectl -n team-blue get pods -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.containers[*].image}{"\n"}{end}'

# 2) 각 이미지 스캔 (CRITICAL 존재 여부만 빠르게)
trivy image --severity CRITICAL nginx:1.19.6 | grep -E 'Total|CRITICAL'

# 3) 취약 이미지를 쓰는 워크로드 조치
kubectl -n team-blue delete pod web-1                      # 단독 Pod이면 삭제
kubectl -n team-blue scale deploy web --replicas=0         # Deployment이면 scale 0 (문제 지시에 따름)
```

> **💡 시험 팁**: 스캔 대상 이미지가 4~5개면 각각 `trivy image --severity CRITICAL 이미지 | tail -5` 식으로 요약만 확인하라. 전체 출력을 읽을 시간이 없다. 조치 방법(삭제 vs scale 0 vs 이미지 교체)은 **반드시 문제 지시를 따를 것** — 임의로 다른 조치를 하면 감점이다.

> **⚠️ 함정**: Pod가 Deployment/ReplicaSet 소유라면 Pod만 삭제해도 즉시 재생성된다. 소유자를 `kubectl -n ns get pod 이름 -o jsonpath='{.metadata.ownerReferences[0].kind}'`로 확인하고 상위 리소스를 조치해야 한다. 또한 같은 Deployment의 replica들은 같은 이미지를 쓰므로 이미지 단위로 스캔하면 중복 스캔을 피할 수 있다.

### 📝 문제로 이해하기

**Task (mini):** Use trivy to scan the images `nginx:1.19.6` and `nginx:1.25.3`. Write the name of the image that contains CRITICAL vulnerabilities to `/opt/course/m5/vulnerable-image`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

두 이미지를 각각 `--severity CRITICAL`로 스캔하고 Total 라인을 비교한다.

**2) 단계별 명령어**

```bash
mkdir -p /opt/course/m5
trivy image --severity CRITICAL nginx:1.19.6 | grep -E 'Total|CRITICAL'
trivy image --severity CRITICAL nginx:1.25.3 | grep -E 'Total|CRITICAL'
echo "nginx:1.19.6" > /opt/course/m5/vulnerable-image
```

**3) 검증 방법**

```bash
cat /opt/course/m5/vulnerable-image
```

**4) ⚠️ 함정 포인트**

- 오래된 태그(1.19.x)가 CRITICAL을 갖는 것이 일반적이지만, **실제 스캔 결과를 보고** 기록해야 한다. 스캔 없이 추측으로 쓰면 틀릴 수 있다.
- CRITICAL이 0인 이미지도 HIGH는 있을 수 있다. 문제의 심각도 기준을 정확히 읽을 것.

</details>

---

## 연습문제 (실전 12문제)

실제 시험과 동일하게 문제 본문은 영어다. 각 문제의 첫 코드블록(컨텍스트 전환/ssh)을 반드시 먼저 실행하는 습관을 들여라.

### 문제 1 — Dockerfile 보안 수정 (버전 고정 · 비루트 · secret 제거)

```bash
kubectl config use-context workload-prod
```

**Task:**

There is a Dockerfile at `/opt/course/1/Dockerfile` that builds an image for a Go application. Fix the following security issues without breaking the build:

1. Pin the base images: use `golang:1.22.5` for the build stage and `alpine:3.19` for the final stage instead of `latest`.
2. Make the final container run as user ID `10001`.
3. Remove the hardcoded secret that is baked into the image.

Build the image as `app:secure` to confirm the Dockerfile still builds successfully.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

FROM 두 줄의 태그 고정 → `ENV`로 박힌 secret 라인 삭제 → 최종 스테이지에 `USER 10001` 추가 → 빌드 검증. 요구된 3가지 외에는 손대지 않는다.

**2) 단계별 명령어/YAML**

수정 전(예시):

```dockerfile
FROM golang:latest AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app .

FROM alpine:latest
ENV ADMIN_PASSWORD=Sup3rS3cret!
COPY --from=build /out/app /app
CMD ["/app"]
```

수정 후:

```dockerfile
FROM golang:1.22.5 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app .

FROM alpine:3.19
COPY --from=build /out/app /app
USER 10001
CMD ["/app"]
```

```bash
docker build -t app:secure /opt/course/1
```

**3) 검증 방법**

```bash
docker inspect app:secure | grep -A2 '"User"'      # "10001" 확인
docker history app:secure | grep -i password       # 아무것도 안 나와야 함
```

**4) ⚠️ 함정 포인트**

- secret 라인을 지우는 대신 값만 비우면(`ENV ADMIN_PASSWORD=`) 여전히 감점 대상이다. **라인 자체를 삭제**한다.
- `USER`를 build 스테이지에 넣으면 최종 이미지에는 효과가 없다. **최종 스테이지**에 넣을 것.
- 빌드 확인을 요구하는 문제에서 빌드를 안 돌리면 오타(태그 철자 등)를 못 잡는다. 반드시 실행.

</details>

### 문제 2 — Dockerfile 멀티스테이지 전환 (distroless)

```bash
kubectl config use-context workload-prod
```

**Task:**

The Dockerfile at `/opt/course/2/Dockerfile` produces an image that ships the whole Go toolchain, git and a shell to production. Convert it to a multi-stage build:

1. Compile the binary in a build stage based on `golang:1.22.5-alpine`.
2. The final stage must be based on `gcr.io/distroless/static-debian12:nonroot` and contain only the compiled binary at `/server`.
3. The final image must run as a non-root user.

Build the image as `api:v2`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

기존 단일 스테이지를 `AS build`로 명명하고, distroless 최종 스테이지를 추가해 `COPY --from=build`로 바이너리만 가져온다. distroless `:nonroot` 태그는 기본이 비루트지만 명시적으로 `USER nonroot`를 넣어 두면 안전하다.

**2) 단계별 명령어/YAML**

```dockerfile
FROM golang:1.22.5-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/server /server
USER nonroot
ENTRYPOINT ["/server"]
```

```bash
docker build -t api:v2 /opt/course/2
```

**3) 검증 방법**

```bash
docker history api:v2                      # 최종 레이어에 toolchain 없음
docker inspect api:v2 | grep -A2 '"User"'  # nonroot 확인
docker run --rm --entrypoint sh api:v2     # 쉘이 없어서 실패해야 정상 (distroless)
```

**4) ⚠️ 함정 포인트**

- distroless static 이미지에는 libc가 없다. Go 빌드 시 `CGO_ENABLED=0`을 빼면 동적 링크되어 실행이 실패할 수 있다.
- `ENTRYPOINT`/`CMD`의 바이너리 경로를 COPY 목적지(`/server`)와 일치시킬 것.
- distroless에는 쉘이 없으므로 `CMD ["sh", "-c", ...]` 형태는 동작하지 않는다. exec form으로 바이너리를 직접 지정.

</details>

### 문제 3 — bom으로 SBOM 생성 및 패키지 버전 조회

```bash
kubectl config use-context infra-prod
```

**Task:**

1. Using the tool `bom`, generate an SPDX SBOM of the image `nginx:1.25.3` and save it to `/opt/course/3/sbom.spdx`.
2. Inspect the SBOM with `bom document outline` and find the version of the package `openssl` contained in the image.
3. Write the version string to `/opt/course/3/openssl-version`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`bom generate --image` → `bom document outline` + grep → 확인된 버전을 파일로 저장.

**2) 단계별 명령어**

```bash
mkdir -p /opt/course/3
bom generate --image nginx:1.25.3 --output /opt/course/3/sbom.spdx

bom document outline /opt/course/3/sbom.spdx | grep -i openssl
# tag-value 원문에서 직접 확인할 수도 있다:
grep -B1 -A3 -i 'PackageName: openssl' /opt/course/3/sbom.spdx
```

출력에서 확인한 `PackageVersion` 값을 그대로 기록한다(예: `3.0.11-1~deb12u2` — 반드시 실제 출력 값 사용):

```bash
echo "3.0.11-1~deb12u2" > /opt/course/3/openssl-version
```

**3) 검증 방법**

```bash
ls -l /opt/course/3/sbom.spdx
cat /opt/course/3/openssl-version
```

**4) ⚠️ 함정 포인트**

- `bom generate`는 이미지를 pull하므로 몇 분 걸릴 수 있다. 기다리는 동안 다른 문제로 넘어가지 말고 명령이 끝났는지 확인부터.
- outline 출력이 길면 반드시 grep으로 좁혀라. 육안으로 훑다가 버전을 잘못 옮겨 적는 실수가 잦다.
- 저장 경로/파일명은 지문 그대로. `openssl-version.txt`처럼 확장자를 임의로 붙이면 안 된다.

</details>

### 문제 4 — trivy로 SBOM 생성 후 SBOM 스캔

```bash
kubectl config use-context infra-prod
```

**Task:**

1. Using trivy, generate a CycloneDX SBOM of the image `httpd:2.4.57` and save it to `/opt/course/4/sbom.cdx.json`.
2. Scan that SBOM file (not the image) with trivy for vulnerabilities.
3. Write all unique CRITICAL vulnerability IDs found in the SBOM to `/opt/course/4/critical-cves.txt`, one per line.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`trivy image --format cyclonedx`로 SBOM 생성 → `trivy sbom` 서브커맨드로 그 파일을 입력 삼아 스캔 → JSON 출력 + jq로 CRITICAL ID 추출.

**2) 단계별 명령어**

```bash
mkdir -p /opt/course/4
trivy image --format cyclonedx --output /opt/course/4/sbom.cdx.json httpd:2.4.57

# SBOM 파일을 입력으로 취약점 스캔 (JSON으로 받아 파싱)
trivy sbom -f json /opt/course/4/sbom.cdx.json \
  | jq -r '.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL") | .VulnerabilityID' \
  | sort -u > /opt/course/4/critical-cves.txt
```

**3) 검증 방법**

```bash
cat /opt/course/4/critical-cves.txt        # CVE-... 형식 라인들
trivy sbom --severity CRITICAL /opt/course/4/sbom.cdx.json | tail -20   # 개수 대조
```

**4) ⚠️ 함정 포인트**

- 지문이 "SBOM 파일을 스캔하라"고 하면 `trivy image`를 다시 돌리면 요구사항 위반이다. **`trivy sbom 파일`** 을 써야 한다.
- jq에서 `.Vulnerabilities[]?`의 `?`가 없으면 취약점이 없는 Result에서 에러가 난다.
- `sort -u`로 중복 CVE 제거 — "unique"라는 단어를 놓치지 말 것.

</details>

### 문제 5 — cosign 서명과 검증

```bash
kubectl config use-context infra-prod
```

**Task:**

A cosign key pair already exists at `/opt/course/5/cosign.key` and `/opt/course/5/cosign.pub` (the key password is empty).

1. Sign the image `registry.killer.sh:5000/infra/backend:v1.4` with the private key.
2. Verify the signature with the public key and save the verification output to `/opt/course/5/verified.json`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

키가 이미 있으므로 `generate-key-pair`는 불필요. sign(개인키) → verify(공개키) → stdout 리다이렉트.

**2) 단계별 명령어**

```bash
cosign sign --key /opt/course/5/cosign.key -y registry.killer.sh:5000/infra/backend:v1.4
# 암호 프롬프트가 나오면 그냥 Enter (빈 암호)

cosign verify --key /opt/course/5/cosign.pub \
  registry.killer.sh:5000/infra/backend:v1.4 > /opt/course/5/verified.json
```

**3) 검증 방법**

```bash
echo $?                          # 0 = 검증 성공
jq . /opt/course/5/verified.json # 서명 claim JSON이 유효한지 확인
```

**4) ⚠️ 함정 포인트**

- sign에 공개키, verify에 개인키를 넣는 뒤바뀜이 최다 실수. **sign=key(개인키), verify=pub(공개키)**.
- `-y`를 주면 "이 서명을 push할까요" 확인 프롬프트를 건너뛴다. 프롬프트에서 멈춘 채 시간을 버리지 말 것.
- verify 출력에는 경고성 stderr 텍스트가 섞일 수 있다. 파일에는 stdout(JSON)만 리다이렉트되므로 그대로 두면 된다.

</details>

### 문제 6 — ImagePolicyWebhook 구성

```bash
kubectl config use-context infra-prod
ssh cks-master
```

**Task:**

The control plane node has a partially prepared ImagePolicyWebhook setup in `/etc/kubernetes/admission/`:

- `admission_config.yaml` — incomplete AdmissionConfiguration
- `kubeconf` — kubeconfig pointing to the external image policy backend
- TLS certificates used by `kubeconf`

Complete the setup:

1. Configure the ImagePolicyWebhook so that pods are **denied** if the external backend is unreachable.
2. Enable the `ImagePolicyWebhook` admission plugin on the kube-apiserver and make it use `/etc/kubernetes/admission/admission_config.yaml`.
3. The external backend is currently down. Verify that creating a pod is rejected.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`defaultAllow: false` 설정 → apiserver static pod에 플래그 2개 추가 + `/etc/kubernetes/admission` hostPath 마운트 확인 → apiserver 재기동 대기 → Pod 생성 시도로 거부 확인.

**2) 단계별 명령어/YAML**

`/etc/kubernetes/admission/admission_config.yaml` 완성:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: ImagePolicyWebhook
    configuration:
      imagePolicy:
        kubeConfigFile: /etc/kubernetes/admission/kubeconf
        allowTTL: 50
        denyTTL: 50
        retryBackoff: 500
        defaultAllow: false
```

`/etc/kubernetes/manifests/kube-apiserver.yaml` 수정:

```yaml
    - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
    - --admission-control-config-file=/etc/kubernetes/admission/admission_config.yaml
```

volumeMounts / volumes 추가(이미 있으면 생략):

```yaml
    volumeMounts:
      - name: admission-config
        mountPath: /etc/kubernetes/admission
        readOnly: true
  volumes:
    - name: admission-config
      hostPath:
        path: /etc/kubernetes/admission
        type: DirectoryOrCreate
```

저장 후 apiserver 재생성 대기(30초~1분):

```bash
watch crictl ps          # kube-apiserver 컨테이너가 다시 Running이 될 때까지
```

**3) 검증 방법**

```bash
kubectl run ipw-test --image=nginx
# 에러 메시지에 image policy webhook 거부 사유가 표시되어야 함 (backend down + defaultAllow=false)
kubectl get pods ipw-test   # NotFound여야 정상
```

**4) ⚠️ 함정 포인트**

- apiserver가 안 뜨면: `crictl ps -a`로 Exited 컨테이너 확인, `crictl logs 컨테이너ID` 또는 `/var/log/pods/kube-system_kube-apiserver-*/` 로그 확인, `journalctl -u kubelet | tail`. 대부분 플래그 오타나 마운트 누락이다.
- `--enable-admission-plugins`에서 **기존 NodeRestriction을 지우면 안 된다.** 콤마로 병기.
- `defaultAllow: true`로 두면 backend가 죽어 있어도 Pod가 생성되어 검증 단계에서 문제를 알아챌 수 있다 — 지문 요구는 fail-closed(`false`)다.
- 수정 전에 `cp /etc/kubernetes/manifests/kube-apiserver.yaml /root/kube-apiserver.yaml.bak` 백업을 떠 두면 복구가 빠르다 (단, 백업본을 manifests 디렉토리 **안에** 두면 kubelet이 그것도 실행하려 든다 — 반드시 밖에 저장).

</details>

### 문제 7 — ValidatingAdmissionPolicy로 허용 레지스트리 강제

```bash
kubectl config use-context workload-prod
```

**Task:**

1. Create a `ValidatingAdmissionPolicy` named `restrict-registry` that only allows pods whose containers (including initContainers) use images from the registry `registry.company.io/`.
2. Create a `ValidatingAdmissionPolicyBinding` named `restrict-registry-binding` that enforces (denies) the policy in all namespaces labeled `env=prod`.
3. Namespace `prod-apps` is already labeled `env=prod`. Verify that a pod using image `nginx:1.25.3` is rejected there, and that the same pod is still allowed in namespace `default`.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

Policy(CEL 표현식)와 Binding(namespaceSelector + Deny)을 각각 생성한다. initContainers는 옵셔널 필드이므로 `has()`로 가드한다.

**2) 단계별 명령어/YAML**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: restrict-registry
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: >-
        object.spec.containers.all(c, c.image.startsWith('registry.company.io/'))
        && (!has(object.spec.initContainers)
            || object.spec.initContainers.all(c, c.image.startsWith('registry.company.io/')))
      message: "Only images from registry.company.io are allowed."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: restrict-registry-binding
spec:
  policyName: restrict-registry
  validationActions: ["Deny"]
  matchResources:
    namespaceSelector:
      matchLabels:
        env: prod
```

```bash
kubectl apply -f vap.yaml
```

**3) 검증 방법**

```bash
kubectl -n prod-apps run bad --image=nginx:1.25.3
# → admission denied, message "Only images from registry.company.io are allowed."
kubectl -n default run ok --image=nginx:1.25.3   # → 생성됨 (라벨 없는 네임스페이스)
kubectl -n default delete pod ok                 # 정리
```

**4) ⚠️ 함정 포인트**

- **Binding 없이는 Policy가 아무 효과가 없다.** 둘 다 만들었는지 확인.
- CEL에서 `object.spec.initContainers`를 `has()` 없이 접근하면 initContainers가 없는 Pod에서 평가 에러가 난다. `failurePolicy: Fail`이면 그 에러가 곧 거부로 이어져 의도치 않게 모든 Pod를 막을 수 있다.
- 레지스트리 문자열 끝의 `/`를 빼먹으면 `registry.company.io.evil.com/...` 같은 우회가 가능해진다.
- Deployment가 아니라 **pods** 리소스를 매칭해야 kubectl run 테스트가 의미가 있다.

</details>

### 문제 8 — kubesec 스캔과 manifest 개선

```bash
kubectl config use-context workload-prod
```

**Task:**

1. Run `kubesec scan` against `/opt/course/8/deployment.yaml` and save the full JSON output to `/opt/course/8/report.json`.
2. The manifest contains critical issues. Fix all critical issues and improve the securityContext so that the score becomes positive. Do not change the image.
3. Save the fixed manifest to `/opt/course/8/deployment-fixed.yaml` and apply it to the cluster.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

스캔 → critical(대개 `privileged: true`, hostNetwork 등) 제거 → advise 반영 → 재스캔 → apply.

**2) 단계별 명령어/YAML**

```bash
kubesec scan /opt/course/8/deployment.yaml > /opt/course/8/report.json
jq '.[0].score, .[0].scoring.critical' /opt/course/8/report.json
cp /opt/course/8/deployment.yaml /opt/course/8/deployment-fixed.yaml
vim /opt/course/8/deployment-fixed.yaml
```

컨테이너 spec에서 critical 항목 삭제 후 다음으로 교체:

```yaml
        securityContext:
          runAsNonRoot: true
          runAsUser: 10001
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
```

```bash
kubesec scan /opt/course/8/deployment-fixed.yaml | jq '.[0].score'   # 양수 확인
kubectl apply -f /opt/course/8/deployment-fixed.yaml
```

**3) 검증 방법**

재스캔에서 `scoring.critical`이 비어 있고 score가 양수인지, `kubectl get deploy`로 롤아웃이 정상인지 확인.

**4) ⚠️ 함정 포인트**

- `privileged: true`, `hostNetwork: true`, `hostPID: true` 같은 critical 필드는 **값 변경이 아니라 삭제**(또는 false)해야 한다.
- readOnlyRootFilesystem 적용 후 앱이 `/tmp` 등에 써야 해서 CrashLoop이 나면 해당 경로에 emptyDir을 마운트한다. apply까지 요구되는 문제라면 Pod가 Running인지 반드시 확인.
- 출력 파일 2개(report.json, deployment-fixed.yaml)의 경로를 모두 채워야 만점이다.

</details>

### 문제 9 — KubeLinter로 manifest 린트 및 수정

```bash
kubectl config use-context workload-prod
```

**Task:**

1. Run `kube-linter` against the directory `/opt/course/9/manifests/`.
2. Fix every finding of the checks `run-as-non-root` and `no-read-only-root-fs` in the manifests.
3. Re-run kube-linter and confirm those two checks no longer report any findings. Other findings may remain.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

린트 실행 → 두 체크가 지적한 리소스/컨테이너 위치를 확인 → securityContext 필드 추가 → 재린트로 소거 확인.

**2) 단계별 명령어/YAML**

```bash
kube-linter lint /opt/course/9/manifests/
kube-linter lint /opt/course/9/manifests/ | grep -E 'run-as-non-root|no-read-only-root-fs'
```

지적된 각 컨테이너에 추가:

```yaml
        securityContext:
          runAsNonRoot: true
          runAsUser: 10001
          readOnlyRootFilesystem: true
```

```bash
kube-linter lint /opt/course/9/manifests/ | grep -E 'run-as-non-root|no-read-only-root-fs'
# 아무 출력도 없어야 함
```

**3) 검증 방법**

grep 결과가 비어 있으면 완료. 다른 체크(unset-cpu-requirements 등)는 문제 지시상 남아 있어도 된다.

**4) ⚠️ 함정 포인트**

- `runAsNonRoot: true`만 넣으면 이미지가 루트 유저로 빌드된 경우 kube-linter가 여전히 경고하거나 런타임에 실패할 수 있다. `runAsUser`를 함께 명시하는 것이 안전하다.
- 디렉토리에 manifest가 여러 개면 **모든 파일**의 모든 해당 컨테이너를 고쳐야 한다. 하나 빠뜨리면 재린트에서 다시 나온다.
- kube-linter 출력의 Remediation 문구가 정답 힌트다. 그대로 따르면 된다.

</details>

### 문제 10 — 네임스페이스 이미지 일괄 스캔

```bash
kubectl config use-context workload-prod
```

**Task:**

Namespace `team-red` contains several pods. Using trivy, scan all container images used by these pods. Write the image names (including tag) of every image that contains CRITICAL vulnerabilities to `/opt/course/10/insecure-images`, one image per line.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

Pod들의 이미지 목록을 뽑아 중복 제거 → 각 이미지를 `--severity CRITICAL`로 스캔 → CRITICAL 개수가 0이 아닌 이미지만 기록.

**2) 단계별 명령어**

```bash
mkdir -p /opt/course/10
kubectl -n team-red get pods -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u
```

이미지마다 반복(수동으로 하나씩 돌려도 된다):

```bash
for img in $(kubectl -n team-red get pods -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u); do
  echo "== $img =="
  trivy image --severity CRITICAL "$img" 2>/dev/null | grep -E '^Total|CRITICAL: [1-9]'
done
```

CRITICAL이 1개 이상인 이미지를 기록:

```bash
vim /opt/course/10/insecure-images   # 예: nginx:1.19.6 한 줄, registry.../legacy:v1 한 줄...
```

**3) 검증 방법**

```bash
cat /opt/course/10/insecure-images
# 각 라인에 대해 trivy 요약의 CRITICAL 수가 1 이상인지 재확인
```

**4) ⚠️ 함정 포인트**

- initContainers도 이미지가 있을 수 있다. 지문이 "all container images"라면 `{.spec.initContainers[*].image}`도 함께 뽑는 것이 안전하다.
- 이미지 이름은 **태그까지** Pod spec에 적힌 그대로 기록한다. 태그를 생략하면 오답.
- 시간 절약: 같은 이미지를 쓰는 Pod가 여러 개여도 스캔은 이미지당 1회면 된다(`sort -u`).

</details>

### 문제 11 — trivy JSON 리포트 분석

```bash
kubectl config use-context workload-prod
```

**Task:**

1. Scan the image `golang:1.19` with trivy and save a JSON report to `/opt/course/11/report.json`.
2. Write the number of CRITICAL vulnerabilities to `/opt/course/11/critical-count`.
3. Write the unique CRITICAL vulnerability IDs to `/opt/course/11/critical-cves`, one per line.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

`-f json -o` 로 리포트 생성 후 jq 두 방으로 개수와 ID 목록을 추출한다.

**2) 단계별 명령어**

```bash
mkdir -p /opt/course/11
trivy image -f json -o /opt/course/11/report.json golang:1.19

jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' \
  /opt/course/11/report.json > /opt/course/11/critical-count

jq -r '.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL") | .VulnerabilityID' \
  /opt/course/11/report.json | sort -u > /opt/course/11/critical-cves
```

**3) 검증 방법**

```bash
cat /opt/course/11/critical-count
wc -l /opt/course/11/critical-cves
trivy image --severity CRITICAL golang:1.19 | grep '^Total'   # 테이블 요약과 대조
```

**4) ⚠️ 함정 포인트**

- "number of CRITICAL vulnerabilities"(전체 발생 건수)와 "unique IDs"(중복 제거)는 다른 숫자일 수 있다. 두 파일의 요구를 각각 정확히 따를 것.
- `.Results[]`는 OS 패키지/언어별 패키지 등 여러 개일 수 있다. 하나의 Result만 보면 누락된다 — 위 jq는 전체를 순회한다.
- jq가 없으면 `trivy image --severity CRITICAL golang:1.19` 테이블 출력에서 수작업으로 세어도 되지만 시간이 오래 걸린다. jq 패턴을 외워 가라.

</details>

### 문제 12 — 복합: 스캔 후 취약 워크로드 조치

```bash
kubectl config use-context workload-prod
```

**Task:**

Namespace `team-purple` contains several Deployments. Using trivy:

1. Scan the images used by all Deployments in the namespace with severity filter CRITICAL.
2. Scale every Deployment that uses an image with CRITICAL vulnerabilities to 0 replicas.
3. Write the names of the scaled-down Deployments to `/opt/course/12/scaled-down`, one per line.

<details>
<summary>✅ 정답 및 해설</summary>

**1) 접근 방법**

Deployment별 이미지 목록 확보 → 이미지 스캔 → CRITICAL 보유 이미지를 쓰는 Deployment를 scale 0 → 이름 기록.

**2) 단계별 명령어**

```bash
mkdir -p /opt/course/12
kubectl -n team-purple get deploy \
  -o jsonpath='{range .items[*]}{.metadata.name}{" -> "}{.spec.template.spec.containers[*].image}{"\n"}{end}'
```

예시 출력:

```text
api -> nginx:1.19.6
web -> nginx:1.25.3
cache -> redis:7.2.4
```

각 이미지 스캔:

```bash
trivy image --severity CRITICAL nginx:1.19.6 | grep '^Total'
trivy image --severity CRITICAL nginx:1.25.3 | grep '^Total'
trivy image --severity CRITICAL redis:7.2.4  | grep '^Total'
```

CRITICAL이 있는 Deployment 조치(예: api 하나만 걸린 경우):

```bash
kubectl -n team-purple scale deploy api --replicas=0
echo "api" > /opt/course/12/scaled-down
```

**3) 검증 방법**

```bash
kubectl -n team-purple get deploy       # 해당 Deployment READY 0/0
kubectl -n team-purple get pods         # 해당 Pod들이 사라짐
cat /opt/course/12/scaled-down
```

**4) ⚠️ 함정 포인트**

- **Pod가 아니라 Deployment 단위로 조치**하라는 지문이다. Pod만 지우면 ReplicaSet이 재생성한다.
- 지시가 "scale to 0"이면 delete 하지 마라. 반대로 delete를 요구하면 scale로 대신하지 마라 — 채점 스크립트는 지시된 상태를 그대로 확인한다.
- 여러 컨테이너를 가진 Deployment는 컨테이너 이미지 중 **하나라도** CRITICAL이면 조치 대상이다.

</details>

---

## 🎯 시험 직전 체크리스트

- [ ] Dockerfile: `latest` 금지·태그 고정, `USER` 비루트, secret 라인 삭제, 캐시 정리를 같은 RUN에서, 멀티스테이지로 빌드 도구 격리 — 5가지를 반사적으로 점검할 수 있다.
- [ ] `bom generate --image ... --output ...` 과 `bom document outline ...` 을 문서 없이 칠 수 있다 (허용 문서: kubernetes-sigs.github.io/bom/cli-reference/).
- [ ] `trivy image --severity CRITICAL,HIGH`, `--ignore-unfixed`, `-f json -o 파일` 플래그를 외웠다.
- [ ] trivy SBOM 3종 세트: `--format spdx-json`, `--format cyclonedx`, `trivy sbom 파일` 을 구분한다.
- [ ] jq 패턴 — CRITICAL ID 추출과 개수 세기 — 를 외웠다.
- [ ] cosign: sign=개인키(cosign.key), verify=공개키(cosign.pub). `generate-key-pair`로 생성.
- [ ] ImagePolicyWebhook: AdmissionConfiguration(apiserver.config.k8s.io/v1) + kubeConfigFile + `defaultAllow: false`(fail-closed) + apiserver 플래그 2개(`--enable-admission-plugins`에 추가, `--admission-control-config-file`) + hostPath 마운트.
- [ ] apiserver가 안 뜰 때 디버깅 루틴: `crictl ps -a` → `crictl logs` → `/var/log/pods/` → `journalctl -u kubelet`.
- [ ] ValidatingAdmissionPolicy(v1.30 GA, CEL): Policy + Binding 세트, `validationActions: ["Deny"]`, initContainers는 `has()` 가드, 레지스트리 접두사 끝에 `/`.
- [ ] kubesec: `kubesec scan 파일` → critical 먼저 제거, advise로 점수 올리기. API 대안 `https://v2.kubesec.io/scan`.
- [ ] kube-linter: `kube-linter lint 경로`, 출력의 Remediation을 그대로 적용.
- [ ] 클러스터 이미지 나열 jsonpath(`{.spec.containers[*].image}`)를 칠 수 있다.
- [ ] 조치 방식(삭제/scale 0/이미지 교체)은 반드시 문제 지시를 그대로 따른다.
- [ ] 답안 파일은 항상 지문의 `/opt/course/문제번호/...` 경로에 정확한 파일명으로 저장한다.

## 핵심 명령어 치트시트

```bash
### Dockerfile / 이미지 검사
docker build -t app:secure /opt/course/1
docker history 이미지            # 레이어·secret 잔존 확인
docker inspect 이미지 | grep -A2 '"User"'

### SBOM — bom (SPDX)
bom generate --image nginx:1.25.3 --output sbom.spdx
bom document outline sbom.spdx | grep -i 패키지명
grep -A3 -i 'PackageName: 패키지명' sbom.spdx     # PackageVersion 확인

### SBOM — trivy
trivy image --format spdx-json --output sbom.json 이미지
trivy image --format cyclonedx --output sbom.cdx.json 이미지
trivy sbom [-f json] [--severity CRITICAL] sbom파일

### 취약점 스캔 — trivy
trivy image --severity CRITICAL,HIGH 이미지
trivy image --severity CRITICAL --ignore-unfixed 이미지
trivy image -f json -o report.json 이미지
jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' report.json
jq -r '.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL") | .VulnerabilityID' report.json | sort -u

### 서명 — cosign
cosign generate-key-pair                      # cosign.key / cosign.pub
cosign sign --key cosign.key -y 이미지
cosign verify --key cosign.pub 이미지

### 정적 분석
kubesec scan pod.yaml
curl -sSX POST --data-binary @pod.yaml https://v2.kubesec.io/scan
kube-linter lint 디렉토리또는파일
kube-linter checks list

### ImagePolicyWebhook (apiserver 플래그)
# --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
# --admission-control-config-file=/etc/kubernetes/admission/admission_config.yaml
# + /etc/kubernetes/admission hostPath 볼륨/마운트, defaultAllow: false

### 클러스터 이미지 나열
kubectl -n NS get pods -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.containers[*].image}{"\n"}{end}'
kubectl -n NS get deploy -o jsonpath='{range .items[*]}{.metadata.name}{" -> "}{.spec.template.spec.containers[*].image}{"\n"}{end}'

### 디버깅 (apiserver 재기동 실패 시)
crictl ps -a
crictl logs 컨테이너ID
journalctl -u kubelet | tail -50
ls /var/log/pods/
```
