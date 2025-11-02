#!/bin/bash
# Lambda 함수 배포 스크립트
# 해커톤 최적 전략: 서버리스 ChatOps 봇 배포

set -e

echo "🚀 Lambda ChatOps 봇 배포 시작..."
echo ""

# 디렉토리 확인
if [ ! -f "slack_events.py" ]; then
    echo "❌ Error: slack_events.py를 찾을 수 없습니다."
    echo "   lambda/ 디렉토리에서 실행해주세요."
    exit 1
fi

# Python 패키지 설치
echo "📦 Python 의존성 설치 중..."
pip install -r requirements.txt -t . 2>&1 | grep -v "already satisfied" || true

# 기존 ZIP 파일 삭제
rm -f lambda_function.zip

# ZIP 파일 생성
echo "📦 ZIP 파일 생성 중..."
zip -r lambda_function.zip . \
    -x "*.pyc" \
    -x "__pycache__/*" \
    -x "*.git*" \
    -x "*.md" \
    -x "deploy.sh" \
    -x ".DS_Store" \
    > /dev/null

echo "✅ ZIP 파일 생성 완료: lambda_function.zip"
echo ""
echo "📊 파일 크기: $(du -h lambda_function.zip | cut -f1)"
echo ""
echo "✅ 다음 단계:"
echo "   1. AWS Lambda Console 접속: https://console.aws.amazon.com/lambda/"
echo "   2. 'Create function' 클릭"
echo "   3. Function name: slackbot-chatops"
echo "   4. Runtime: Python 3.11"
echo "   5. 'Upload from' → '.zip file' → lambda_function.zip 선택"
echo "   6. Handler: slack_events.lambda_handler"
echo ""
echo "   자세한 가이드: ../QUICK_START_LAMBDA.md 참고"

