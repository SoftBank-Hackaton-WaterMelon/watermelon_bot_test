# Lambda ChatOps 봇

Slack 메시지로 GitHub Actions를 트리거하는 서버리스 ChatOps 봇.

## 🎯 전체 플로우

```
Slack 메시지: "자동 배포 시작"
    ↓
Lambda 함수 (트리거)
    ↓
GitHub Actions: Build → Test → Docker Build
    ↓
Slack 승인 요청 (버튼 클릭 대기)
    ↓
승인 후 배포 실행
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

| 변수명                         | 설명                           | 필수 |
| ------------------------------ | ------------------------------ | ---- |
| `GITHUB_PERSONAL_ACCESS_TOKEN` | GitHub Fine-grained Token      | ✅   |
| `SLACK_SIGNING_SECRET`         | Slack 앱 Signing Secret        | ⚠️   |
| `SLACK_BOT_TOKEN`              | Slack Bot OAuth Token          | ⚠️   |
| `GITHUB_ID`                    | `SoftBank-Hackaton-WaterMelon` | 선택 |
| `GITHUB_REPO`                  | `watermelon_bot_test`          | 선택 |

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

### 배포 시작

Slack 채널에서 메시지 전송:

```
자동 배포 시작
```

**지원 명령어**:

- `자동 배포 시작`, `배포 시작`, `deploy`, `배포` - 최신 버전 배포
- `배포 v1.2.3` - 특정 버전 배포
- `롤백` - 이전 버전으로 롤백

### Lambda 코드 수정 및 배포

1. `lambda/slack_events.py` 수정
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
    ├── slack_events.py      # Lambda 핵심 코드
    ├── requirements.txt      # Python 의존성
    ├── deploy.sh           # ZIP 파일 생성
    └── .gitignore
```

---

## 👥 역할 분담

- **Lambda 담당**: Lambda 함수 구현 및 관리 (완료 ✅)
- **Slack 봇 담당**: Slack 앱 설정, Secrets 설정, 실제 테스트
- **GitHub Actions 담당**: 워크플로우 모니터링 및 배포 로직 추가
- **인프라 담당**: Terraform, ECS 배포

## ✅ 구현된 기능

- ✅ Slack Events API URL 검증
- ✅ 배포 키워드 감지 및 GitHub Actions 트리거
- ✅ **특정 버전 배포**: `배포 v1.2.3` 지원
- ✅ **롤백 기능**: `롤백` 명령어 처리
- ✅ CI/CD 파이프라인 (Build → Test → Docker → 승인 → 배포)
- ✅ Slack 승인 단계 통합
- ✅ 자동 배포 (Lambda 코드 변경 시)
- ✅ AWS EC2 배포 스크립트 (Secrets 설정 시)

---

## 🚧 향후 구현 계획

- 배포 상태 조회: `배포 상태`
- 롤백 로직 구체화 (이전 버전 추적)
- 블루-그린 배포 전략

---
