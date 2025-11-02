"""
AWS Lambda function for Slack Events API
해커톤 요구사항: "ChatOps Engineer (Bot): AWS Lambda + API Gateway"
"""
import json
import os
import re
import hmac
import hashlib
import time
import logging
import requests
from typing import Dict, Any, Optional

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


def parse_deploy_command(message_text: str) -> Dict[str, Any]:
    """
    배포 명령어 파싱
    지원 형식:
    - '배포 v1.2.3' 또는 '배포 v1.2.3'
    - '롤백'
    - '자동 배포 시작', '배포 시작', 'deploy', '배포' (최신 버전)
    
    Returns:
        dict: {'action': 'deploy'|'rollback', 'version': '1.2.3'|None}
    """
    text = message_text.strip()
    
    # 롤백 명령어 확인
    if '롤백' in text.lower() or 'rollback' in text.lower():
        logger.info("Rollback command detected")
        return {'action': 'rollback', 'version': None}
    
    # 버전 파싱: '배포 v1.2.3' 또는 '배포 1.2.3' 형식
    version_patterns = [
        r'배포\s+v?(\d+\.\d+\.\d+)',  # '배포 v1.2.3' or '배포 1.2.3'
        r'deploy\s+v?(\d+\.\d+\.\d+)',  # 'deploy v1.2.3'
        r'v(\d+\.\d+\.\d+)',  # 단순 'v1.2.3'
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            version = match.group(1)
            logger.info(f"Version-specific deployment detected: v{version}")
            return {'action': 'deploy', 'version': version}
    
    # 일반 배포 키워드 확인
    deploy_keywords = ['자동 배포 시작', '배포 시작', 'deploy', '배포']
    cleaned_text = text.lower()
    if any(keyword.lower() in cleaned_text for keyword in deploy_keywords):
        logger.info("Latest version deployment detected")
        return {'action': 'deploy', 'version': None}
    
    # 명령어가 없음
    return {'action': None, 'version': None}


def trigger_github_deployment(message_text: str, user_id: str, original_message: str) -> Dict[str, Any]:
    """
    GitHub repository_dispatch 이벤트 트리거
    ChatOps: Slack 메시지 → GitHub Actions 워크플로우 실행
    
    지원 명령어:
    - '배포 v1.2.3': 특정 버전 배포
    - '롤백': 이전 버전으로 롤백
    - '자동 배포 시작', '배포': 최신 버전 배포
    """
    # 명령어 파싱
    command = parse_deploy_command(message_text)
    
    if not command['action']:
        logger.info(f"Message does not contain deploy keywords: {message_text}")
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
    
    # client_payload 구성
    client_payload = {
        'message': message_text.lower().strip(),
        'original_message': original_message,
        'user': user_id,
        'action': command['action'],  # 'deploy' or 'rollback'
    }
    
    # 버전 정보 추가
    if command['version']:
        client_payload['version'] = command['version']
        client_payload['tag'] = f"v{command['version']}"
    else:
        # 최신 버전인 경우 기본 태그 사용
        client_payload['tag'] = f'v{os.environ.get("GITHUB_RUN_NUMBER", "latest")}'
    
    payload = {
        'event_type': 'dev_deploy',
        'client_payload': client_payload
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
    
    # 명령어 파싱
    command = parse_deploy_command(message_text)
    
    # GitHub deployment 트리거
    result = trigger_github_deployment(message_text, user_id, message_text)
    
    # GitHub 트리거 성공 시 Slack에 응답 메시지 전송
    if result.get('statusCode') == 200:
        body = json.loads(result.get('body', '{}'))
        # 명령어가 감지되고 GitHub 트리거가 성공한 경우에만 Slack 메시지 전송
        if body.get('ok') and command['action'] and body.get('message') != 'No deployment triggered' and channel:
            # 메시지 구성
            action_emoji = "↩️" if command['action'] == 'rollback' else "🚀"
            action_text = "롤백" if command['action'] == 'rollback' else "배포"
            version_info = f"v{command['version']}" if command['version'] else "최신 버전"
            
            success_message = (
                f"{action_emoji} *{action_text} 요청이 접수되었습니다!*\n\n"
                f"• 사용자: <@{user_id}>\n"
                f"• 작업: {action_text}\n"
                f"• 버전: {version_info}\n"
                f"• GitHub Actions 워크플로우가 트리거되었습니다.\n"
                f"• 진행 상황은 GitHub Actions에서 확인할 수 있습니다."
            )
            send_slack_message(channel, success_message)
            logger.info(f"Slack confirmation message sent to channel {channel}")
    
    # Events API는 즉시 200 응답 필요 (Slack 메시지는 비동기)
    return {
        'statusCode': 200,
        'body': json.dumps({'ok': True})
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda 핸들러
    Slack Events API 요청을 처리
    """
    try:
        # 이벤트 구조 로깅 (디버깅용)
        logger.info(f"Event received: {json.dumps(event, default=str)}")
        
        # API Gateway Proxy Integration에서 body 처리
        body_str = event.get('body', '{}')
        
        # Base64 디코딩 (API Gateway가 base64로 인코딩한 경우)
        if event.get('isBase64Encoded', False):
            import base64
            try:
                body_str = base64.b64decode(body_str).decode('utf-8')
                logger.info("Body was base64 encoded, decoded successfully")
            except Exception as e:
                logger.error(f"Failed to decode base64 body: {e}")
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Failed to decode body'})
                }
        
        # Body 파싱
        body = {}
        if isinstance(body_str, str):
            try:
                body = json.loads(body_str)
                logger.info(f"Parsed body: {json.dumps(body)}")
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON body: {body_str}, Error: {e}")
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Invalid JSON', 'details': str(e)})
                }
        elif isinstance(body_str, dict):
            # 이미 파싱된 경우
            body = body_str
            body_str = json.dumps(body_str)
        
        # URL 검증 (Event Subscriptions 설정 시) - 검증 전에 먼저 처리
        # URL 검증 요청은 검증을 스킵하고 challenge를 바로 반환해야 함
        if body.get('type') == 'url_verification':
            challenge = body.get('challenge')
            if challenge:
                logger.info(f"URL verification challenge received: {challenge}")
                # API Gateway Proxy Integration 형식으로 반환
                return {
                    'statusCode': 200,
                    'headers': {
                        'Content-Type': 'text/plain'
                    },
                    'body': challenge  # challenge 값 그대로 반환 (문자열)
                }
            else:
                logger.error("URL verification challenge missing")
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Challenge missing'})
                }
        
        # 일반 이벤트는 서명 검증 필요
        if not verify_slack_request(event, body_str):
            logger.warning("Request verification failed")
            return {
                'statusCode': 403,
                'body': json.dumps({'error': 'Forbidden'})
            }
        
        # 이벤트 처리
        if body.get('type') == 'event_callback':
            return handle_message_event(body)
        
        # 기타 이벤트는 200 응답 (Slack 요구사항)
        logger.info(f"Unhandled event type: {body.get('type')}")
        return {
            'statusCode': 200,
            'body': json.dumps({'ok': True})
        }
        
    except Exception as e:
        logger.exception(f"Error processing event: {e}")
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Full traceback: {error_trace}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }

