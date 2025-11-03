"""
AWS Lambda function for Slack Events API
해커톤 요구사항: "ChatOps Engineer (Bot): AWS Lambda + API Gateway"
"""
import json
import os
import hmac
import hashlib
import time
import logging
import requests
from typing import Dict, Any
from urllib.parse import parse_qs

# 로깅 설정
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 환경 변수
SLACK_SIGNING_SECRET = os.environ.get('SLACK_SIGNING_SECRET')
SLACK_BOT_TOKEN = os.environ.get('SLACK_BOT_TOKEN')
GITHUB_TOKEN = os.environ.get('GITHUB_PERSONAL_ACCESS_TOKEN')
GITHUB_ID = os.environ.get('GITHUB_ID', 'SoftBank-Hackaton-WaterMelon')
GITHUB_REPO = os.environ.get('GITHUB_REPO', 'watermelon_bot_test')


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
    """
    Slack Web API를 사용하여 메시지 전송
    chat.postMessage API 호출
    """
    if not SLACK_BOT_TOKEN:
        logger.warning("SLACK_BOT_TOKEN not set, skipping Slack message")
        return False
    
    url = 'https://slack.com/api/chat.postMessage'
    headers = {
        'Authorization': f'Bearer {SLACK_BOT_TOKEN}',
        'Content-Type': 'application/json',
    }
    
    payload = {
        'channel': channel,
        'text': text,
    }
    
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


def trigger_github_deployment(message_text: str, user_id: str, original_message: str) -> Dict[str, Any]:
    """
    GitHub repository_dispatch 이벤트 트리거
    ChatOps: Slack 메시지 → GitHub Actions 워크플로우 실행
    """
    # 배포 키워드 감지
    deploy_keywords = ['자동 배포 시작', '배포 시작', 'deploy', '배포']
    cleaned_text = message_text.lower().strip()
    is_deploy_message = any(keyword.lower() in cleaned_text for keyword in deploy_keywords)
    
    if not is_deploy_message:
        logger.info(f"Message does not contain deploy keywords: {cleaned_text}")
        return {
            'statusCode': 200,
            'body': json.dumps({'ok': True, 'message': 'No deployment triggered'})
        }
    
    # GitHub API 호출
    url = f'https://api.github.com/repos/{GITHUB_ID}/{GITHUB_REPO}/dispatches'
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'Bearer {GITHUB_TOKEN}',
        'Content-Type': 'application/json',
    }
    
    payload = {
        'event_type': 'dev_deploy',
        'client_payload': {
            'message': cleaned_text,
            'original_message': original_message,
            'user': user_id,
            'tag': f'v{os.environ.get("GITHUB_RUN_NUMBER", "lambda")}'
        }
    }
    
    try:
        # 로깅 추가: GitHub API 호출 전 정보 출력
        logger.info(f"Calling GitHub API: {url}")
        logger.info(f"GitHub ID: {GITHUB_ID}, Repo: {GITHUB_REPO}")
        logger.info(f"Payload: {json.dumps(payload, ensure_ascii=False)}")
        
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        
        if response.status_code == 204:
            logger.info(f"GitHub repository_dispatch triggered successfully by user {user_id}")
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'ok': True,
                    'message': f'GitHub Actions workflow triggered by user {user_id}'
                })
            }
        else:
            logger.error(f"GitHub API error: {response.status_code} - {response.text}")
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'ok': False,
                    'error': f'GitHub API error: {response.status_code}'
                })
            }
    except Exception as e:
        logger.exception(f"Error calling GitHub API: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'ok': False,
                'error': str(e)
            })
        }


def handle_message_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Slack 메시지 이벤트 처리
    """
    event = event_data.get('event', {})
    event_type = event.get('type')
    
    if event_type != 'message':
        logger.info(f"Ignoring event type: {event_type}")
        return {
            'statusCode': 200,
            'body': json.dumps({'ok': True})
        }
    
    # 봇 메시지는 무시
    if event.get('bot_id'):
        logger.info("Ignoring bot message")
        return {
            'statusCode': 200,
            'body': json.dumps({'ok': True})
        }
    
    message_text = event.get('text', '')
    user_id = event.get('user', 'unknown')
    channel = event.get('channel', '')
    
    logger.info(f"Processing message from user {user_id} in channel {channel}: {message_text}")
    
    # 배포 키워드 감지
    deploy_keywords = ['자동 배포 시작', '배포 시작', 'deploy', '배포']
    cleaned_text = message_text.lower().strip()
    is_deploy_message = any(keyword.lower() in cleaned_text for keyword in deploy_keywords)
    
    # GitHub deployment 트리거
    result = trigger_github_deployment(message_text, user_id, message_text)
    
    # GitHub 트리거 성공 시 Slack에 응답 메시지 전송
    if result.get('statusCode') == 200:
        body = json.loads(result.get('body', '{}'))
        # 배포 키워드가 감지되고 GitHub 트리거가 성공한 경우에만 Slack 메시지 전송
        if body.get('ok') and is_deploy_message and body.get('message') != 'No deployment triggered' and channel:
            success_message = f"🚀 *배포 요청이 접수되었습니다!*\n\n• 사용자: <@{user_id}>\n• GitHub Actions 워크플로우가 트리거되었습니다.\n• 진행 상황은 GitHub Actions에서 확인할 수 있습니다."
            send_slack_message(channel, success_message)
            logger.info(f"Slack confirmation message sent to channel {channel}")
    
    # Events API는 즉시 200 응답 필요 (Slack 메시지는 비동기)
    return {
        'statusCode': 200,
        'body': json.dumps({'ok': True})
    }

def trigger_github_deployment_from_command(command_text: str, user_id: str) -> Dict[str, Any]:
    """
    GitHub repository_dispatch 이벤트 트리거 (Slash Command용)
    """
    url = f'https://api.github.com/repos/{GITHUB_ID}/{GITHUB_REPO}/dispatches'
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'Bearer {GITHUB_TOKEN}',
    }
    
    payload = {
        'event_type': 'start-deployment', # <-- (주의) GitHub Actions YML의 types와 일치시킬 것
        'client_payload': {
            'message': command_text,
            'user': user_id,
        }
    }
    
    try:
        logger.info(f"Calling GitHub API from Command: {url}")
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        
        if response.status_code == 204:
            logger.info(f"GitHub repository_dispatch triggered successfully by user {user_id}")
            return {'ok': True, 'message': f"✅ 알겠습니다! GitHub Actions 배포를 트리거했습니다. (전달값: {command_text})"}
        else:
            logger.error(f"GitHub API error: {response.status_code} - {response.text}")
            # [중요] GitHub가 보낸 "진짜" 에러를 Slack에 반환합니다.
            return {'ok': False, 'message': f'❌ GitHub API 호출 실패! (Code: {response.status_code})\n{response.text}'}
            
    except Exception as e:
        logger.exception(f"Error calling GitHub API: {e}")
        return {'ok': False, 'message': f'❌ Lambda 내부 에러: {e}'}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda 핸들러 (v2: 라우터 기능 추가)
    - JSON (URL 챌린지, 이벤트)
    - Form (슬래시 명령어, 버튼 클릭)
    """
    try:
        logger.info(f"Event received: {json.dumps(event, default=str)}")
        
        body_str = event.get('body', '{}')
        if event.get('isBase64Encoded', False):
            import base64
            body_str = base64.b64decode(body_str).decode('utf-8')
            logger.info("Body was base64 encoded, decoded successfully")

        # --- (라우터 시작) ---

        # Case 1: "Form" 형식인가? (Slash Command 또는 Button Click)
        if event['headers'].get('Content-Type') == 'application/x-www-form-urlencoded':
            
            # 1-1: 서명 검증 (Form 데이터는 서명 검증이 필수)
            if not verify_slack_request(event, body_str):
                logger.warning("Request verification failed")
                return {'statusCode': 403, 'body': json.dumps({'error': 'Forbidden'})}
            
            logger.info("Form data received. Parsing...")
            payload = parse_qs(body_str)
            
            # 1-2: "Slash Command"인가?
            if 'command' in payload:
                command = payload.get('command', [''])[0]
                command_text = payload.get('text', [''])[0]
                user_id = payload.get('user_id', ['unknown'])[0]
                
                if command == '/platform-deploy':
                    logger.info(f"Slash command '{command} {command_text}' received from user {user_id}")
                    # GitHub 트리거 함수 호출
                    result = trigger_github_deployment_from_command(command_text, user_id)
                    # Slack에 즉시 응답
                    return {'statusCode': 200, 'body': result['message']}
            
            # 1-3: "Button Click"인가? (나중을 위해 남겨둠)
            if 'payload' in payload: 
                # (TODO: 버튼 클릭 처리 로직)
                logger.info("Interactive payload (button) received.")
                return {'statusCode': 200, 'body': 'Button click received!'}

            logger.warning("Unknown form payload")
            return {'statusCode': 400, 'body': 'Unknown form payload'}

        # Case 2: "JSON" 형식인가? (URL 챌린지 또는 Message 이벤트)
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
            
            # 2-3: "Message 이벤트"인가?
            if body.get('type') == 'event_callback':
                logger.info("Event Callback (message) received.")
                # 영민님의 기존 메시지 처리 함수 호출
                return handle_message_event(body)

        except json.JSONDecodeError:
            # Case 1, 2 둘 다 아님
            logger.error(f"Cannot parse body as Form or JSON: {body_str}")
            return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid request body'})}
        
        # --- (라우터 끝) ---

        logger.info(f"Unhandled event type: {body.get('type')}")
        return {'statusCode': 200, 'body': json.dumps({'ok': True})}
        
    except Exception as e:
        logger.exception(f"Error processing event: {e}")
        return {'statusCode': 500, 'body': json.dumps({'error': 'Internal server error', 'message': str(e)})}

