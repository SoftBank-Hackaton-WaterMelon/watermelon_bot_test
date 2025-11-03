"""
AWS Lambda function for Slack Events API (v5 - GITHUB DISPATCH FIX)
- /platform-deploy (GitHub Trigger) - 비동기 처리 + 디버깅 강화
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
import boto3
import datetime
from typing import Dict, Any
from urllib.parse import parse_qs, unquote
from ghcr_client import get_container_images_with_tags

# AWS 클라이언트 초기화
ecs_client = boto3.client('ecs')
codedeploy_client = boto3.client('codedeploy')
lambda_client = boto3.client('lambda')

# 로깅 설정
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 환경 변수
SLACK_SIGNING_SECRET = os.environ.get('SLACK_SIGNING_SECRET')
SLACK_BOT_TOKEN = os.environ.get('SLACK_BOT_TOKEN')
GITHUB_TOKEN = os.environ.get('GITHUB_PERSONAL_ACCESS_TOKEN')
GITHUB_ID = os.environ.get('GITHUB_ID', 'SoftBank-Hackaton-WaterMelon')
GITHUB_REPO = os.environ.get('GITHUB_REPO', 'demo-backend')
GHCR_MAX_IMAGES = os.environ.get('GHCR_MAX_IMAGES', '20')
GHCR_MAX_TAGS = os.environ.get('GHCR_MAX_TAGS', '5')
ECS_CLUSTER_NAME = os.environ.get('ECS_CLUSTER_NAME', 'atlas-cluster')
ECS_SERVICE_NAME = os.environ.get('ECS_SERVICE_NAME', 'atlas-app-service')
CODEDEPLOY_APP_NAME = os.environ.get('CODEDEPLOY_APP_NAME', 'atlas-codedeploy-app')
CODEDEPLOY_GROUP_NAME = os.environ.get('CODEDEPLOY_GROUP_NAME', 'atlas-codedeploy-group')


def get_header_value(headers: Dict[str, Any], key: str) -> str:
    """대소문자 구분 없이 헤더 값 추출"""
    if key in headers:
        return headers[key]
    
    key_lower = key.lower()
    for header_key, header_value in headers.items():
        if header_key.lower() == key_lower:
            return header_value
    
    return ''


def verify_slack_request(event: Dict[str, Any], body_str: str) -> bool:
    """Slack 요청 서명 검증"""
    if not SLACK_SIGNING_SECRET:
        logger.warning("SLACK_SIGNING_SECRET not set, skipping verification")
        return True
    
    try:
        headers = event.get('headers', {})
        slack_signature = get_header_value(headers, 'x-slack-signature')
        slack_timestamp = get_header_value(headers, 'x-slack-request-timestamp')
        
        if not slack_signature or not slack_timestamp:
            logger.warning("Missing Slack signature or timestamp")
            return False
        
        # 타임스탬프 검증 (5분 이내)
        if abs(time.time() - int(slack_timestamp)) > 60 * 5:
            logger.warning("Request timestamp too old")
            return False
        
        # 서명 생성 및 비교
        sig_basestring = f"v0:{slack_timestamp}:{body_str}"
        my_signature = 'v0=' + hmac.new(
            SLACK_SIGNING_SECRET.encode('utf-8'),
            sig_basestring.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(my_signature, slack_signature)
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return False


def send_slack_message(channel: str, text: str, response_url: str = None) -> bool:
    """Slack 메시지 전송 (채널 또는 response_url)"""
    
    # response_url이 있으면 우선 사용 (더 빠름)
    if response_url:
        try:
            payload = {
                'text': text,
                'response_type': 'in_channel',
                'replace_original': False  # 기존 메시지 유지하고 새 메시지 추가
            }
            response = requests.post(response_url, json=payload, timeout=3)
            if response.status_code == 200:
                logger.info(f"✅ Message sent via response_url")
                return True
            else:
                logger.warning(f"⚠️ response_url failed: {response.status_code}")
        except Exception as e:
            logger.warning(f"⚠️ Failed to send via response_url: {e}")
    
    # response_url 실패 시 또는 없을 때 Bot Token 사용
    if not SLACK_BOT_TOKEN or not channel:
        logger.warning("SLACK_BOT_TOKEN or channel not set")
        return False
    
    url = 'https://slack.com/api/chat.postMessage'
    headers = {
        'Authorization': f'Bearer {SLACK_BOT_TOKEN}',
        'Content-Type': 'application/json',
    }
    payload = {'channel': channel, 'text': text}
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=3)
        result = response.json()
        if result.get('ok'):
            logger.info(f"✅ Message sent to {channel}")
            return True
        else:
            logger.error(f"❌ Slack API error: {result.get('error')}")
            return False
    except Exception as e:
        logger.exception(f"❌ Error sending Slack message: {e}")
        return False


def trigger_github_deployment_async(command_text: str, user_id: str, channel_id: str, response_url: str):
    """GitHub API 호출 (비동기 버전) - 강화된 디버깅"""
    
    # GitHub API URL
    url = f'https://api.github.com/repos/{GITHUB_ID}/{GITHUB_REPO}/dispatches'
    
    # 헤더 구성
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'token {GITHUB_TOKEN}',
        'User-Agent': 'Lambda-Slack-ChatOps',
        'Content-Type': 'application/json'
    }
    
    # Payload 구성
    payload = {
        'event_type': 'dev_deploy',
        'client_payload': {
            'message': command_text,
            'user': user_id,
            'timestamp': str(int(time.time())),
            'source': 'slack-chatops'
        }
    }
    
    try:
        logger.info("=" * 80)
        logger.info("🚀 GitHub API 호출 시작")
        logger.info(f"📍 URL: {url}")
        logger.info(f"🔑 Token (first 10 chars): {GITHUB_TOKEN[:10]}...")
        logger.info(f"📦 Payload:\n{json.dumps(payload, indent=2)}")
        logger.info(f"📋 Headers:\n{json.dumps({k: v if k != 'Authorization' else 'token ***' for k, v in headers.items()}, indent=2)}")
        logger.info("=" * 80)
        
        # GitHub API 호출
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        
        logger.info(f"📥 GitHub API Response:")
        logger.info(f"  - Status Code: {response.status_code}")
        logger.info(f"  - Headers: {dict(response.headers)}")
        logger.info(f"  - Body: {response.text}")
        
        # 성공 (204 No Content)
        if response.status_code == 204:
            success_msg = (
                f"✅ *GitHub Actions 배포 트리거 성공!*\n"
                f"• 요청자: <@{user_id}>\n"
                f"• 메시지: `{command_text}`\n"
                f"• Repository: `{GITHUB_ID}/{GITHUB_REPO}`\n"
                f"• Event Type: `dev_deploy`\n"
                f"• GitHub Actions 페이지에서 워크플로우 실행을 확인하세요:\n"
                f"  https://github.com/{GITHUB_ID}/{GITHUB_REPO}/actions"
            )
            logger.info("✅✅✅ GitHub dispatch 성공!")
            send_slack_message(channel_id, success_msg, response_url)
            return
        
        # 인증 실패 (401)
        elif response.status_code == 401:
            error_msg = (
                f"❌ *GitHub Token 인증 실패!*\n"
                f"• Token: `{GITHUB_TOKEN[:10]}...`\n"
                f"• Response: `{response.text}`\n\n"
                f"*해결 방법:*\n"
                f"1. GitHub Settings > Developer settings > Personal access tokens\n"
                f"2. Token에 `repo` 권한이 있는지 확인\n"
                f"3. Lambda 환경변수 `GITHUB_PERSONAL_ACCESS_TOKEN` 재확인"
            )
            logger.error(f"❌ 401 Unauthorized: {response.text}")
            send_slack_message(channel_id, error_msg, response_url)
            return
        
        # Repository 없음 (404)
        elif response.status_code == 404:
            error_msg = (
                f"❌ *Repository를 찾을 수 없습니다!*\n"
                f"• Owner: `{GITHUB_ID}`\n"
                f"• Repo: `{GITHUB_REPO}`\n"
                f"• URL: `{url}`\n"
                f"• Response: `{response.text}`\n\n"
                f"*해결 방법:*\n"
                f"1. Repository 이름이 정확한지 확인\n"
                f"2. Token에 해당 Repository 접근 권한이 있는지 확인\n"
                f"3. Repository가 Public인지 Private인지 확인"
            )
            logger.error(f"❌ 404 Not Found: {response.text}")
            send_slack_message(channel_id, error_msg, response_url)
            return
        
        # 권한 부족 (403)
        elif response.status_code == 403:
            error_msg = (
                f"❌ *권한 부족!*\n"
                f"• Response: `{response.text}`\n\n"
                f"*해결 방법:*\n"
                f"1. Token에 `workflow` scope 권한 추가 필요\n"
                f"2. Token을 재생성하고 Lambda 환경변수 업데이트"
            )
            logger.error(f"❌ 403 Forbidden: {response.text}")
            send_slack_message(channel_id, error_msg, response_url)
            return
        
        # 기타 에러
        else:
            error_msg = (
                f"❌ *GitHub API 오류*\n"
                f"• Status: `{response.status_code}`\n"
                f"• Response: ```{response.text[:500]}```\n"
                f"• URL: `{url}`"
            )
            logger.error(f"❌ Unexpected status {response.status_code}: {response.text}")
            send_slack_message(channel_id, error_msg, response_url)
            return
            
    except requests.exceptions.Timeout:
        error_msg = "❌ *GitHub API 타임아웃* (15초 초과)"
        logger.error(error_msg)
        send_slack_message(channel_id, error_msg, response_url)
    
    except Exception as e:
        error_msg = f"❌ *Lambda 내부 오류*\n```{str(e)}```"
        logger.exception(f"💥 Exception: {e}")
        send_slack_message(channel_id, error_msg, response_url)


def invoke_async_lambda(function_name: str, payload: Dict[str, Any]):
    """자기 자신을 비동기로 재호출"""
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='Event',  # 비동기 호출
            Payload=json.dumps(payload)
        )
        logger.info(f"✅ 비동기 Lambda 호출 성공")
        logger.info(f"  - Function: {function_name}")
        logger.info(f"  - StatusCode: {response.get('StatusCode')}")
        return True
    except Exception as e:
        logger.error(f"❌ 비동기 Lambda 호출 실패: {e}")
        return False


def handle_status_command() -> Dict[str, Any]:
    """ECS 서비스 상태 조회"""
    try:
        response = ecs_client.describe_services(
            cluster=ECS_CLUSTER_NAME,
            services=[ECS_SERVICE_NAME]
        )
        
        if not response.get('services'):
            return {
                'ok': False,
                'message': f"❌ '{ECS_SERVICE_NAME}' 서비스를 찾을 수 없습니다."
            }
        
        service = response['services'][0]
        task_definition_arn = service.get('taskDefinition', 'N/A')
        version = task_definition_arn.split('/')[-1] if task_definition_arn != 'N/A' else 'Unknown'
        
        message = (
            f"✅ *ECS 서비스 상태*\n"
            f"• 서비스: `{ECS_SERVICE_NAME}`\n"
            f"• 클러스터: `{ECS_CLUSTER_NAME}`\n"
            f"• 🏃 Running: `{service.get('runningCount', 0)}`개\n"
            f"• ⏳ Pending: `{service.get('pendingCount', 0)}`개\n"
            f"• 🏷️ Version: `{version}`"
        )
        return {'ok': True, 'message': message}
        
    except Exception as e:
        logger.exception(f"Status 조회 실패: {e}")
        return {'ok': False, 'message': f'❌ 상태 조회 실패: {str(e)}'}


def handle_rollback_command(user_id: str) -> Dict[str, Any]:
    """CodeDeploy 롤백 실행"""
    try:
        # 최근 성공한 배포 찾기
        response = codedeploy_client.list_deployments(
            applicationName=CODEDEPLOY_APP_NAME,
            deploymentGroupName=CODEDEPLOY_GROUP_NAME,
            includeOnlyStatuses=['Succeeded'],
            createTimeRange={
                'start': datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
                'end': datetime.datetime.now(datetime.timezone.utc)
            }
        )
        
        if not response.get('deployments'):
            return {'ok': False, 'message': "❌ 롤백할 성공한 배포 기록이 없습니다."}
        
        latest_deployment_id = response['deployments'][0]
        
        # 배포 정보 가져오기
        deployment_info = codedeploy_client.get_deployment(deploymentId=latest_deployment_id)
        revision = deployment_info['deploymentInfo']['revision']
        
        # 롤백 배포 생성
        rollback_response = codedeploy_client.create_deployment(
            applicationName=CODEDEPLOY_APP_NAME,
            deploymentGroupName=CODEDEPLOY_GROUP_NAME,
            revision=revision,
            deploymentConfigName='CodeDeployDefault.ECSAllAtOnce',
            description=f"Slack 수동 롤백 by {user_id}"
        )
        
        new_deployment_id = rollback_response.get('deploymentId')
        message = (
            f"🚨 *긴급 롤백 시작*\n"
            f"• 이전 배포 ID: `{latest_deployment_id}`\n"
            f"• 새 롤백 ID: `{new_deployment_id}`\n"
            f"• 요청자: <@{user_id}>"
        )
        return {'ok': True, 'message': message}
        
    except Exception as e:
        logger.exception(f"Rollback 실패: {e}")
        return {'ok': False, 'message': f'❌ 롤백 실패: {str(e)}'}


def handle_container_list_command(channel_id: str, response_url: str) -> Dict[str, Any]:
    """GHCR 컨테이너 이미지 목록 조회 후 Slack 전송"""

    if not GITHUB_TOKEN:
        logger.error("GHCR 조회를 위한 GitHub Token이 설정되지 않았습니다.")
        send_slack_message(
            channel_id,
            "❌ GHCR 조회를 위한 GitHub Token이 설정되지 않았습니다.",
            response_url,
        )
        return {
            'ok': False,
            'message': "❌ GHCR 조회를 위한 GitHub Token이 설정되지 않았습니다."
        }

    owner_name = GITHUB_ID

    ghcr_kwargs = {
        'token': GITHUB_TOKEN,
        'org': owner_name,
    }
    
    try:
        images_with_tags = get_container_images_with_tags(**ghcr_kwargs)
    except ValueError as exc:
        logger.error(f"GHCR 파라미터 오류: {exc}")
        send_slack_message(channel_id, f"❌ GHCR 파라미터 오류: {exc}", response_url)
        return {'ok': False, 'message': f"❌ GHCR 파라미터 오류: {exc}"}
    except requests.RequestException as exc:
        logger.error(f"GHCR 네트워크 오류: {exc}")
        send_slack_message(channel_id, f"❌ GHCR 네트워크 오류: {exc}", response_url)
        return {'ok': False, 'message': f"❌ GHCR 네트워크 오류: {exc}"}
    except Exception as exc:
        logger.exception(f"GHCR 조회 실패: {exc}")
        send_slack_message(channel_id, f"❌ GHCR 조회 실패: {exc}", response_url)
        return {'ok': False, 'message': f"❌ GHCR 조회 실패: {exc}"}

    if not images_with_tags:
        message = (
            "ℹ️ *GHCR 컨테이너 이미지 없음*\n"
            f"• Owner: `{owner_name}`\n"
            "• 조회된 이미지가 없습니다."
        )
        send_slack_message(channel_id, message, response_url)
        return {'ok': True, 'message': message}

    max_images = int(GHCR_MAX_IMAGES)
    max_tags = int(GHCR_MAX_TAGS)

    sorted_items = sorted(images_with_tags.items())
    lines = [
        "📦 *GHCR 컨테이너 이미지 목록*",
        f"• Owner: `{owner_name}`",
        f"• 총 이미지: `{len(sorted_items)}`",
    ]

    for index, (image_name, tags) in enumerate(sorted_items):
        if index >= max_images:
            lines.append(
                f"… (상위 `{max_images}`개만 표시, 총 `{len(sorted_items)}`개)"
            )
            break

        display_tags = tags[:max_tags]
        if display_tags:
            tag_text = ", ".join(display_tags)
            if len(tags) > max_tags:
                tag_text += " …"
        else:
            tag_text = "태그 없음"

        lines.append(f"• `{image_name}` → {tag_text}")

    message = "\n".join(lines)
    send_slack_message(channel_id, message, response_url)
    return {'ok': True, 'message': message}


def handle_slash_command(payload: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Slash Command 라우터"""
    command = payload.get('command', [''])[0]
    command_text = payload.get('text', [''])[0]
    user_id = payload.get('user_id', ['unknown'])[0]
    channel_id = payload.get('channel_id', [''])[0]
    response_url = payload.get('response_url', [''])[0]
    
    logger.info("=" * 80)
    logger.info(f"📝 Slash Command 수신")
    logger.info(f"  - Command: {command}")
    logger.info(f"  - Text: {command_text}")
    logger.info(f"  - User: {user_id}")
    logger.info(f"  - Channel: {channel_id}")
    logger.info(f"  - Response URL: {response_url[:50]}...")
    logger.info("=" * 80)
    
    # /platform-deploy는 비동기 처리 시도 (권한 없으면 동기 처리)
    if command == '/platform-deploy':
        # 즉시 응답 (Slack 3초 제한 회피)
        immediate_response = (
            f"⏳ *배포 요청을 처리 중입니다...*\n"
            f"• 요청자: <@{user_id}>\n"
            f"• 메시지: `{command_text}`\n"
            f"• Repository: `{GITHUB_ID}/{GITHUB_REPO}`\n\n"
            f"_잠시 후 결과를 알려드리겠습니다..._"
        )
        
        # 자기 자신을 비동기로 재호출 시도 (GitHub API 호출용)
        async_payload = {
            'async_task': 'github_deploy',
            'command_text': command_text,
            'user_id': user_id,
            'channel_id': channel_id,
            'response_url': response_url
        }
        
        # Lambda 함수 이름 (현재 실행 중인 함수)
        function_name = context.function_name if context else os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
        
        async_success = False
        if function_name:
            async_success = invoke_async_lambda(function_name, async_payload)
        
        # 비동기 호출 실패 시 동기로 폴백
        if not async_success:
            logger.warning("⚠️ 비동기 호출 실패 또는 권한 없음, 동기 처리로 폴백")
            logger.warning("⚠️ 주의: 3초 타임아웃 발생 가능")
            logger.warning("⚠️ Lambda IAM Role에 lambda:InvokeFunction 권한 추가를 권장합니다")
            
            # 동기로 즉시 처리 (느릴 수 있음)
            trigger_github_deployment_async(command_text, user_id, channel_id, response_url)
        
        return {'ok': True, 'message': immediate_response}
    
    # 다른 명령어는 빠르게 처리 가능
    elif command == '/platform-status':
        return handle_status_command()
    
    elif command == '/platform-rollback':
        return handle_rollback_command(user_id)

    elif command == '/platform-images':
        return handle_container_list_command(channel_id, response_url)
    
    else:
        return {'ok': False, 'message': f"❌ 알 수 없는 명령어: {command}"}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda 핸들러 - 요청 라우팅"""
    try:
        logger.info("🎯 Lambda 실행 시작")
        logger.info(f"📨 Event: {json.dumps(event, default=str, indent=2)}")
        
        # 비동기 작업 처리 (자기 자신이 호출한 경우)
        if 'async_task' in event:
            task_type = event['async_task']
            
            if task_type == 'github_deploy':
                logger.info("🔄🔄🔄 비동기 GitHub 배포 작업 시작")
                trigger_github_deployment_async(
                    event['command_text'],
                    event['user_id'],
                    event['channel_id'],
                    event['response_url']
                )
                return {'statusCode': 200, 'body': json.dumps({'message': 'Async task completed'})}
            
            else:
                logger.warning(f"⚠️ Unknown async task: {task_type}")
                return {'statusCode': 200, 'body': json.dumps({'message': 'Unknown async task'})}
        
        # Body 디코딩
        body_str = event.get('body', '{}')
        if event.get('isBase64Encoded', False):
            import base64
            body_str = base64.b64decode(body_str).decode('utf-8')
        
        headers = event.get('headers', {})
        content_type = get_header_value(headers, 'content-type').lower()
        
        # Case 1: Slash Command (Form data)
        if 'application/x-www-form-urlencoded' in content_type:
            if not verify_slack_request(event, body_str):
                logger.warning("❌ Slack 서명 검증 실패")
                return {'statusCode': 403, 'body': json.dumps({'error': 'Forbidden'})}
            
            payload = parse_qs(body_str)
            
            # Slash Command 처리
            if 'command' in payload:
                result = handle_slash_command(payload, context)
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'text': result['message']})
                }
            
            # Interactive 버튼 처리
            if 'payload' in payload:
                payload_json = json.loads(payload['payload'][0])
                logger.info(f"🔘 Interactive payload: {payload_json}")
                return {
                    'statusCode': 200,
                    'body': json.dumps({'text': '버튼 클릭 수신됨'})
                }
        
        # Case 2: Event (JSON)
        try:
            body = json.loads(body_str)
            
            # URL 검증 챌린지
            if body.get('type') == 'url_verification':
                logger.info("✅ URL 검증 챌린지")
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'text/plain'},
                    'body': body.get('challenge', '')
                }
            
            # 서명 검증
            if not verify_slack_request(event, body_str):
                logger.warning("❌ Slack 서명 검증 실패")
                return {'statusCode': 403, 'body': json.dumps({'error': 'Forbidden'})}
            
            # Event Callback
            if body.get('type') == 'event_callback':
                logger.info("📬 Event callback 수신 (무시)")
                return {'statusCode': 200, 'body': json.dumps({'ok': True})}
        
        except json.JSONDecodeError:
            logger.error(f"❌ JSON 파싱 실패: {body_str}")
            return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid JSON'})}
        
        # 알 수 없는 요청
        logger.warning(f"⚠️ 처리되지 않은 요청")
        return {'statusCode': 200, 'body': json.dumps({'ok': True})}
        
    except Exception as e:
        logger.exception(f"💥💥💥 Lambda 오류: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error', 'message': str(e)})
        }
