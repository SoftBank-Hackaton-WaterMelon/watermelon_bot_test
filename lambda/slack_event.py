"""
AWS Lambda function for Slack Events API (v3 - FINAL FULL CODE)
- /platform-deploy (GitHub Trigger)
- /platform-status (ECS Read)
- /platform-rollback (CodeDeploy Trigger)
"""
import json
import os
import hmac
import hashlib
import time
import logging
import requests
import boto3  # <-- 1. boto3 추가됨
import datetime # <-- 2. datetime 추가됨
from typing import Dict, Any
from urllib.parse import parse_qs, unquote # [수정] unquote 추가

# --- (1) AWS 클라이언트 초기화 ---
ecs_client = boto3.client('ecs')
codedeploy_client = boto3.client('codedeploy')
# ------------------------------

# 로깅 설정
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 환경 변수 (CodeDeploy, ECS 정보 추가)
SLACK_SIGNING_SECRET = os.environ.get('SLACK_SIGNING_SECRET')
SLACK_BOT_TOKEN = os.environ.get('SLACK_BOT_TOKEN')
GITHUB_TOKEN = os.environ.get('GITHUB_PERSONAL_ACCESS_TOKEN')
GITHUB_ID = os.environ.get('GITHUB_ID', 'SoftBank-Hackaton-WaterMelon')
GITHUB_REPO = os.environ.get('GITHUB_REPO', 'watermelon_bot_test')

# --- Terraform으로 생성할 AWS 리소스 이름을 환경 변수로 받아옵니다 ---
ECS_CLUSTER_NAME = os.environ.get('ECS_CLUSTER_NAME', 'atlas-cluster') # (예시) Infra팀과 이름 맞출 것
ECS_SERVICE_NAME = os.environ.get('ECS_SERVICE_NAME', 'atlas-app-service') # (예시) Infra팀과 이름 맞출 것
CODEDEPLOY_APP_NAME = os.environ.get('CODEDEPLOY_APP_NAME', 'atlas-codedeploy-app') # (예시) Infra팀과 이름 맞출 것
CODEDEPLOY_GROUP_NAME = os.environ.get('CODEDEPLOY_GROUP_NAME', 'atlas-codedeploy-group') # (예시) Infra팀과 이름 맞출 것


# --- [유지] v2의 헬퍼 함수들 (필수) ---

def get_header_value(headers: Dict[str, Any], key: str) -> str:
    # 직접 매칭 시도
    if key in headers:
        return headers[key]
    
    # 소문자로 시도
    key_lower = key.lower()
    for header_key, header_value in headers.items():
        if header_key.lower() == key_lower:
            return header_value
    
    return ''


def verify_slack_request(event: Dict[str, Any], body_str: str) -> bool:
    if not SLACK_SIGNING_SECRET:
        logger.warning("SLACK_SIGNING_SECRET not set, skipping verification")
        return True
    
    try:
        headers = event.get('headers', {})
        
        # 헤더에서 서명 및 타임스탬프 추출
        slack_signature = get_header_value(headers, 'x-slack-signature')
        slack_timestamp = get_header_value(headers, 'x-slack-request-timestamp')
        
        if not slack_signature or not slack_timestamp:
            logger.warning("Missing Slack signature or timestamp")
            return False
        
        # 타임스탬프 검증 (5분 이내)
        try:
            if abs(time.time() - int(slack_timestamp)) > 60 * 5:
                logger.warning("Request timestamp too old")
                return False
        except ValueError:
            logger.warning(f"Invalid timestamp: {slack_timestamp}")
            return False
        
        # 서명 생성
        sig_basestring = f"v0:{slack_timestamp}:{body_str}"
        my_signature = 'v0=' + hmac.new(
            SLACK_SIGNING_SECRET.encode('utf-8'),
            sig_basestring.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # 비교
        return hmac.compare_digest(my_signature, slack_signature)
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return False


def send_slack_message(channel: str, text: str) -> bool:
    # (v2의 send_slack_message 함수와 동일 - 여기에 있어야 함)
    if not SLACK_BOT_TOKEN:
        logger.warning("SLACK_BOT_TOKEN not set, skipping Slack message")
        return False
    
    url = 'https://slack.com/api/chat.postMessage'
    headers = {
        'Authorization': f'Bearer {SLACK_BOT_TOKEN}',
        'Content-Type': 'application/json',
    }
    payload = {'channel': channel, 'text': text}
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=5)
        result = response.json()
        if result.get('ok'):
            logger.info(f"Slack message sent successfully to channel {channel}")
            return True
        else:
            logger.error(f"Slack API error: {result.get('error', 'Unknown error')}")
            return False
    except Exception as e:
        logger.exception(f"Error sending Slack message: {e}")
        return False

# --- [신규/수정] v3용 함수들 ---

def trigger_github_deployment_from_command(command_text: str, user_id: str) -> Dict[str, Any]:
    # (v2의 함수와 동일 - 여기에 있어야 함)
    url = f'https://api.github.com/repos/{GITHUB_ID}/{GITHUB_REPO}/dispatches'
    headers = {'Accept': 'application/vnd.github.v3+json', 'Authorization': f'Bearer {GITHUB_TOKEN}'}
    payload = {
        'event_type': 'start-deployment', # <-- (주의) GitHub Actions YML의 types와 일치시킬 것
        'client_payload': {'message': command_text, 'user': user_id}
    }
    try:
        logger.info(f"Calling GitHub API from Command: {url}")
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        
        if response.status_code == 204:
            logger.info(f"GitHub repository_dispatch triggered successfully by user {user_id}")
            return {'ok': True, 'message': f"✅ 알겠습니다! GitHub Actions 배포를 트리거했습니다. (전달값: {command_text})"}
        else:
            logger.error(f"GitHub API error: {response.status_code} - {response.text}")
            return {'ok': False, 'message': f'❌ GitHub API 호출 실패! (Code: {response.status_code})\n{response.text}'}
    except Exception as e:
        logger.exception(f"Error calling GitHub API: {e}")
        return {'ok': False, 'message': f'❌ Lambda 내부 에러: {e}'}

def handle_status_command() -> Dict[str, Any]:
    # (v3 신규 함수)
    try:
        response = ecs_client.describe_services(cluster=ECS_CLUSTER_NAME, services=[ECS_SERVICE_NAME])
        if not response.get('services'):
            return {'ok': False, 'message': f"❌ 에러: '{ECS_SERVICE_NAME}' 서비스를 찾을 수 없습니다. (환경변수 확인 필요)"}
        
        service = response['services'][0]
        task_definition_arn = service.get('taskDefinition')
        version = task_definition_arn.split('/')[-1]
        
        message = (
            f"✅ **'{ECS_SERVICE_NAME}'** 서비스 상태\n"
            f"• 🏃 **Running:** `{service.get('runningCount')}`개\n"
            f"• ⏳ **Pending:** `{service.get('pendingCount')}`개\n"
            f"• 🏷️ **Current Version:** `{version}`"
        )
        return {'ok': True, 'message': message}
    except Exception as e:
        logger.exception(f"Error handling /status command: {e}")
        return {'ok': False, 'message': f'❌ 상태 조회 실패: {e}'}

def handle_rollback_command(user_id: str) -> Dict[str, Any]:
    # (v3 신규 함수)
    try:
        # [주의!] Lambda 실행 역할에 'codedeploy:ListDeployments', 'codedeploy:GetDeployment', 'codedeploy:CreateDeployment' 권한이 필요합니다.
        
        # 1. 가장 최근에 성공한 배포 ID 찾기
        response = codedeploy_client.list_deployments(
            applicationName=CODEDEPLOY_APP_NAME,
            deploymentGroupName=CODEDEPLOY_GROUP_NAME,
            includeOnlyStatuses=['Succeeded'],
            createTimeRange={'start': datetime.datetime(2020, 1, 1), 'end': datetime.datetime.now(datetime.timezone.utc)} # UTC 시간 사용
        )
        if not response.get('deployments'):
            return {'ok': False, 'message': "❌ 에러: 롤백할 '성공한 배포' 기록이 없습니다."}
        
        latest_successful_deployment_id = response['deployments'][0]

        # 2. 해당 배포의 설정(revision) 가져오기
        deployment_info = codedeploy_client.get_deployment(deploymentId=latest_successful_deployment_id)
        revision = deployment_info['deploymentInfo']['revision']
        
        # 3. 이 설정으로 "새 롤백 배포" 생성
        rollback_response = codedeploy_client.create_deployment(
            applicationName=CODEDEPLOY_APP_NAME,
            deploymentGroupName=CODEDEPLOY_GROUP_NAME,
            revision=revision,
            deploymentConfigName='CodeDeployDefault.ECSAllAtOnce', # 롤백은 빠르게
            description=f"Slack에서 {user_id}에 의한 수동 롤백"
        )
        
        new_rollback_id = rollback_response.get('deploymentId')
        message = f"🚨 **긴급 롤백 시작!**\n• 타겟 버전: `{latest_successful_deployment_id}`\n• 새 롤백 ID: `{new_rollback_id}`"
        return {'ok': True, 'message': message}
    except Exception as e:
        logger.exception(f"Error handling /rollback command: {e}")
        return {'ok': False, 'message': f'❌ 롤백 실패: {e}'}

def handle_slash_command(payload: Dict[str, Any]) -> Dict[str, Any]:
    # (v3 신규 함수 - 모든 /platform 명령어 라우터)
    command = payload.get('command', [''])[0]
    command_text = payload.get('text', [''])[0]
    user_id = payload.get('user_id', ['unknown'])[0]
    
    if command == '/platform-deploy':
        return trigger_github_deployment_from_command(command_text, user_id)
    elif command == '/platform-status':
        return handle_status_command()
    elif command == '/platform-rollback':
        return handle_rollback_command(user_id)
    else:
        return {'ok': False, 'message': f"알 수 없는 명령어: {command}"}

#
# --- [수정] v3용 lambda_handler (라우터) ---
#
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    try:
        logger.info(f"Event received: {json.dumps(event, default=str)}")
        
        body_str = event.get('body', '{}')
        if event.get('isBase64Encoded', False):
            import base64
            body_str = base64.b64decode(body_str).decode('utf-8')

        # --- (라우터 시작) ---

        # Case 1: "Form" 형식 (Slash Command 또는 Button Click)
        if event.get('headers', {}).get('Content-Type') == 'application/x-www-form-urlencoded':
            
            if not verify_slack_request(event, body_str): # 서명 검증
                logger.warning("Request verification failed")
                return {'statusCode': 403, 'body': json.dumps({'error': 'Forbidden'})}
            
            payload = parse_qs(body_str)
            
            # 1-1: "Slash Command"인가?
            if 'command' in payload:
                result = handle_slash_command(payload)
                return {'statusCode': 200, 'body': result['message']}
            
            # 1-2: "Button Click"인가? (나중을 위해 남겨둠)
            if 'payload' in payload: 
                payload_json = json.loads(unquote(body_str.split('payload=')[1]))
                # (TODO: 버튼 클릭 처리 로직. 예: Terraform Plan 승인)
                logger.info("Interactive payload (button) received.")
                return {'statusCode': 200, 'body': 'Button click received!'}

            logger.warning("Unknown form payload")
            return {'statusCode': 400, 'body': 'Unknown form payload'}

        # Case 2: "JSON" 형식 (URL 챌린지 또는 Message 이벤트)
        try:
            body = json.loads(body_str)
            
            # 2-1: "URL 검증 챌린지"인가?
            if body.get('type') == 'url_verification':
                logger.info("URL verification challenge received.")
                return {'statusCode': 200, 'headers': {'Content-Type': 'text/plain'}, 'body': body.get('challenge')}

            # 2-2: 서명 검증 (JSON 데이터도 서명 검증 필수)
            if not verify_slack_request(event, body_str):
                logger.warning("Request verification failed")
                return {'statusCode': 403, 'body': json.dumps({'error': 'Forbidden'})}
            
            # 2-3: "Message 이벤트"인가? (v2의 handle_message_event)
            if body.get('type') == 'event_callback':
                logger.info("Event Callback (message) received. Ignoring.")
                # (v2의 handle_message_event(body)를 여기서 호출할 수 있으나,
                #  Slash Command로 통일하기 위해 일단 무시합니다.)
                return {'statusCode': 200, 'body': json.dumps({'ok': True})}

        except json.JSONDecodeError:
            logger.error(f"Cannot parse body as Form or JSON: {body_str}")
            return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid request body'})}
        
        # --- (라우터 끝) ---

        logger.info(f"Unhandled event type: {body.get('type')}")
        return {'statusCode': 200, 'body': json.dumps({'ok': True})}
        
    except Exception as e:
        logger.exception(f"Error processing event: {e}")
        return {'statusCode': 500, 'body': json.dumps({'error': 'Internal server error', 'message': str(e)})}
