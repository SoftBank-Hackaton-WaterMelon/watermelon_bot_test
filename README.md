# Lambda ChatOps 봇

Slack Slash Command로 GitHub Actions를 트리거하는 서버리스 ChatOps 봇.

## 🎯 전체 플로우

```
Slack Slash Command (/platform-*)
    ↓
API Gateway → Lambda(slack_event.py)
    ↓
GitHub API repository_dispatch(dev_deploy)
    ↓
GitHub Actions: Build → Test → Docker → 승인(선택) → 배포/롤백
```

## 📋 아키텍처

```
Slack Events API → API Gateway → AWS Lambda → GitHub API → GitHub Actions
```

**핵심 기술**:

- AWS Lambda + API Gateway (서버리스)
- GitHub Actions (CI/CD)
- Python 3.11

---

## ⚙️ 설정 가이드

### Lambda 함수 설정

**환경 변수** (Lambda Console → Configuration → Environment variables):

| 변수명                         | 설명                                                        | 필수 |
| ------------------------------ | ----------------------------------------------------------- | ---- |
| `GITHUB_PERSONAL_ACCESS_TOKEN` | GitHub Personal Access Token (classic: repo, workflow 필수) | ✅   |
| `SLACK_SIGNING_SECRET`         | Slack 앱 Signing Secret                                     | ⚠️   |
| `SLACK_BOT_TOKEN`              | Slack Bot OAuth Token                                       | ⚠️   |
| `GITHUB_ID`                    | `SoftBank-Hackaton-WaterMelon`                              | 선택 |
| `GITHUB_REPO`                  | `watermelon_bot_test`                                       | 선택 |
| `ECS_CLUSTER_NAME`             | ECS 클러스터명 (상태 조회용)                                | 선택 |
| `ECS_SERVICE_NAME`             | ECS 서비스명 (상태 조회용)                                  | 선택 |
| `GIF_BASE_URL`                 | GIF 이미지 기본 URL (예: `https://example.com/gifs`)       | 선택 |
| `GIF_DEPLOYING`                | 배포 시작 GIF URL (기본값: `{GIF_BASE_URL}/deploying.gif`) | 선택 |
| `GIF_DEPLOY_SUCCESS`           | 배포 성공 GIF URL (기본값: `{GIF_BASE_URL}/deploy_complete.gif`) | 선택 |
| `GIF_DEPLOY_FAIL`              | 배포 실패 GIF URL (기본값: `{GIF_BASE_URL}/failed.gif`)    | 선택 |

### GitHub Secrets 설정

**Lambda 자동 배포용**:

- `AWS_ACCESS_KEY_ID` (AWS IAM → Users → Security credentials → Create access key)
- `AWS_SECRET_ACCESS_KEY`

**CI/CD 파이프라인용** (Slack 봇 담당자 설정):

- `SLACK_CHANNEL_ID`
- `SLACK_BOT_TOKEN`
- `SLACK_APP_TOKEN`
- `SLACK_SIGNING_SECRET`
- `SLACK_APPROVERS` (승인자 Slack 사용자 ID, 쉼표 구분)

## 🚀 사용 방법

### Slash Commands (채널에서 입력)

```
/platform-deploy v1.2.3   # 특정 버전 배포 (버전 생략 시 latest)
/platform-status           # ECS 서비스 상태 조회 (선택 기능)
/platform-rollback        # 최근 성공 배포로 롤백 (선택 기능)
```

입력하면 Lambda가 GitHub Actions의 `repository_dispatch(dev_deploy)`를 호출하고,
Actions 워크플로우 `ChatOps Deploy`가 실행됩니다.

### Lambda 코드 수정 및 배포

1. `lambda/slack_event.py` 수정 (핸들러: `slack_event.lambda_handler`)
2. GitHub에 커밋 및 푸시
3. GitHub Actions가 자동으로 Lambda 함수 업데이트

---

## 🧪 테스트

### Lambda 함수 테스트

**AWS Lambda Console → Test 탭**

**URL 검증 테스트**:

```json
{
  "body": "{\"type\":\"url_verification\",\"challenge\":\"test123\"}"
}
```

예상 결과: `{"statusCode": 200, "body": "test123"}`

---

## 📁 프로젝트 구조

```
watermelon_bot_test/
├── .github/workflows/
│   ├── dev_deploy.yml       # Lambda가 트리거하는 CI/CD 파이프라인
│   └── deploy-lambda.yml    # Lambda 자동 배포
└── lambda/
    ├── slack_event.py       # Lambda 핵심 코드 (Slash Command 라우팅)
    ├── requirements.txt      # Python 의존성
    ├── deploy.sh           # ZIP 파일 생성
    └── .gitignore
```

---

## 👥 역할 분담

- **Lambda 담당** (현재 소유자)

  - Lambda 핸들러 `slack_event.lambda_handler` 유지/배포
  - 환경변수 관리(`GITHUB_PERSONAL_ACCESS_TOKEN` 교체 시 즉시 반영)
  - CloudWatch 로그 모니터링 및 3초 응답 보장(response_url 사용)

- **Slack 봇 담당**

  - Slack App에 Slash Commands 등록: `/platform-deploy`, `/platform-status`, `/platform-rollback`
  - Request URL: API Gateway `.../prod/slack/events`
  - Signing Secret/Bot Token 발급 및 공유(Secrets/Lambda env에 반영)

- **GitHub Actions 담당**

  - `dev_deploy.yml` 모니터링, Dockerfile 유무에 따른 빌드 경로 확인
  - Organization/Repository Actions 권한 설정 확인
    - Org(Owner): Actions ON, Allow all, 해당 리포 허용
    - Repo: Allow all actions, Workflow permissions = Read and write

- **인프라 담당**
  - ECS/CodeDeploy 실제 리소스 연결 시 환경변수(ECS_CLUSTER_NAME 등) 제공
  - EC2 배포 필요 시 Secrets(EC2_HOST, EC2_USER, SSH_PRIVATE_KEY) 제공

## ✅ 구현된 기능

- ✅ Slack Events API URL 검증
- ✅ Slash Command 기반 GitHub Actions 트리거(`/platform-deploy`)
- ✅ **특정 버전 배포**: `/platform-deploy v1.2.3` 지원
- ✅ **롤백 기능**: `/platform-rollback` (CodeDeploy, 선택)
- ✅ CI/CD 파이프라인 (Build → Test → Docker → 승인 → 배포)
- ✅ Slack 승인 단계 통합
- ✅ 자동 배포 (Lambda 코드 변경 시)
- ✅ AWS EC2 배포 스크립트 (Secrets 설정 시)

---

## 🚧 향후 구현 계획

- 배포 상태 조회 고도화(`/platform-status` 실제 ECS 값과 연동)
- 롤백 로직 구체화 (이전 버전 추적/태깅 표준화)
- 블루-그린/카나리 배포 전략

---

## 🔐 보안/권한 참고

- GitHub 토큰: classic PAT 권장 스코프 → `repo`, `workflow`
- Organization 정책으로 Actions가 막혀 있으면 run이 생성되지 않음
  - Org Owner가 Actions 허용(Allow all actions & workflows) 설정 필요
  - Repo의 Workflow permissions는 "Read and write" 권장

## ⚠️ 자주 묻는 문제(FAQ)

- Slack은 성공인데, Actions 실행이 안 떠요
  - Org/Repo Actions 권한을 먼저 확인하세요(위 보안/권한 참고)
  - 토큰 스코프에 `workflow`가 없으면 실행이 생성되지 않습니다
  - 워크플로우 파일이 main에 반영된 이후의 dispatch부터 동작합니다

---
