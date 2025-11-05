"""
AWS Lambda function for Slack Events API (v5 - GITHUB DISPATCH FIX)
- /platform-deploy (GitHub Trigger) - 비동기 처리 + 디버깅 강화
- /platform-status (ECS Read)
- /platform-rollback (CodeDeploy Trigger)
"""
import base64
import json
import os
import hmac
import hashlib
import time
import logging
import requests
import boto3
import datetime
import uuid
from typing import Dict, Any, List, Optional
from urllib.parse import parse_qs, unquote
from ghcr_client import get_container_images_with_tags

# AWS 클라이언트 초기화
ecs_client = boto3.client('ecs')
codedeploy_client = boto3.client('codedeploy')
lambda_client = boto3.client('lambda')
cloudwatch_client = boto3.client('cloudwatch')

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
MONITORING_METRIC_NAMESPACE = os.environ.get('MONITORING_METRIC_NAMESPACE', '')

_TRUE_VALUES = {'1', 'true', 'yes', 'on'}
DEPLOY_APPROVAL_REQUIRED = os.environ.get('DEPLOY_APPROVAL_REQUIRED', 'false').lower() in _TRUE_VALUES
ROLLBACK_APPROVAL_REQUIRED = os.environ.get('ROLLBACK_APPROVAL_REQUIRED', 'false').lower() in _TRUE_VALUES
SLACK_APPROVER_IDS = {
    approver.strip()
    for approver in os.environ.get('SLACK_APPROVER_IDS', '').split(',')
    if approver.strip()
}


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
                logger.info("✅ Message sent via response_url")
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


def send_slack_message_with_blocks(
    channel: str,
    text: str,
    blocks: Optional[List[Dict[str, Any]]] = None,
    response_url: str = None,
    replace_original: bool = False,
    ephemeral: bool = False,
) -> bool:
    """블록(버튼) 메시지 전송 헬퍼"""
    if response_url:
        try:
            payload: Dict[str, Any] = {
                'text': text,
                'response_type': 'ephemeral' if ephemeral else 'in_channel',
            }
            if replace_original:
                payload['replace_original'] = True
            if blocks:
                payload['blocks'] = blocks
            response = requests.post(response_url, json=payload, timeout=3)
            if response.status_code == 200:
                logger.info("✅ Interactive message sent via response_url")
                return True
            logger.warning(f"⚠️ response_url interactive send failed: {response.status_code}")
        except Exception as exc:
            logger.warning(f"⚠️ Failed to send interactive message via response_url: {exc}")
    
    if not SLACK_BOT_TOKEN or not channel:
        logger.warning("SLACK_BOT_TOKEN or channel not set for interactive message")
        return False
    
    url = 'https://slack.com/api/chat.postMessage'
    headers = {
        'Authorization': f'Bearer {SLACK_BOT_TOKEN}',
        'Content-Type': 'application/json',
    }
    payload: Dict[str, Any] = {'channel': channel, 'text': text}
    if blocks:
        payload['blocks'] = blocks
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=3)
        result = response.json()
        if result.get('ok'):
            logger.info(f"✅ Interactive message sent to {channel}")
            return True
        logger.error(f"❌ Slack API error (interactive): {result.get('error')}")
        return False
    except Exception as exc:
        logger.exception(f"❌ Error sending interactive Slack message: {exc}")
        return False


def log_event(event_type: str, level: str = 'info', **data: Any) -> None:
    """CloudWatch에서 쉽게 필터링할 수 있도록 구조화 로그 출력"""
    payload = {
        'event_type': event_type,
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'data': data,
    }
    message = json.dumps(payload, ensure_ascii=False, default=str)
    if level == 'error':
        logger.error(message)
    elif level == 'warning':
        logger.warning(message)
    else:
        logger.info(message)


def publish_metric(metric_name: str, value: float = 1.0, dimensions: Optional[Dict[str, str]] = None) -> None:
    """커스텀 CloudWatch 메트릭 전송"""
    if not MONITORING_METRIC_NAMESPACE:
        return
    
    metric: Dict[str, Any] = {
        'MetricName': metric_name,
        'Value': value,
    }
    if dimensions:
        metric['Dimensions'] = [{'Name': k, 'Value': v} for k, v in dimensions.items()]
    
    try:
        cloudwatch_client.put_metric_data(
            Namespace=MONITORING_METRIC_NAMESPACE,
            MetricData=[metric]
        )
    except Exception as exc:
        logger.warning(f"⚠️ Failed to publish metric {metric_name}: {exc}")


def encode_action_value(data: Dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')


def decode_action_value(value: str) -> Dict[str, Any]:
    if not value:
        return {}
    return json.loads(base64.b64decode(value.encode('utf-8')).decode('utf-8'))


def is_authorized_approver(user_id: str) -> bool:
    return not SLACK_APPROVER_IDS or user_id in SLACK_APPROVER_IDS


def request_action_approval(
    action_type: str,
    channel_id: str,
    response_url: str,
    command_text: str,
    requested_by: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """승인 요청 메시지 전송"""
    request_id = str(uuid.uuid4())
    label = "배포" if action_type == "deploy" else "롤백"
    metadata = metadata or {}
    
    encoded_value = encode_action_value(
        {
            'request_id': request_id,
            'action_type': action_type,
            'requested_by': requested_by,
            'command_text': command_text,
            'channel_id': channel_id,
            'response_url': response_url,
            'repository': f"{GITHUB_ID}/{GITHUB_REPO}",
            'metadata': metadata,
            'created_at': datetime.datetime.utcnow().isoformat(),
        }
    )
    
    blocks: List[Dict[str, Any]] = [
        {
            'type': 'section',
            'text': {
                'type': 'mrkdwn',
                'text': (
                    f"*{label} 승인 요청*\n"
                    f"• 요청자: <@{requested_by}>\n"
                    f"• 명령: `{command_text or 'N/A'}`\n"
                    f"• 저장소: `{GITHUB_ID}/{GITHUB_REPO}`"
                ),
            },
        },
        {
            'type': 'context',
            'elements': [
                {'type': 'mrkdwn', 'text': '승인자만 버튼을 클릭할 수 있습니다.'}
            ],
        },
        {
            'type': 'actions',
            'elements': [
                {
                    'type': 'button',
                    'text': {'type': 'plain_text', 'text': 'Approve ✅'},
                    'style': 'primary',
                    'action_id': f'approve_{action_type}',
                    'value': encoded_value,
                },
                {
                    'type': 'button',
                    'text': {'type': 'plain_text', 'text': 'Reject ❌'},
                    'style': 'danger',
                    'action_id': f'reject_{action_type}',
                    'value': encoded_value,
                },
            ],
        },
    ]
    
    info_text = (
        f"⏳ *{label} 승인 대기 중...*\n"
        f"• 요청자: <@{requested_by}>\n"
        f"• 승인 채널: <#{channel_id}>"
    )
    
    send_slack_message_with_blocks(
        channel=channel_id,
        text=info_text,
        blocks=blocks,
        response_url=response_url,
    )
    
    log_event(
        'approval.requested',
        action_type=action_type,
        request_id=request_id,
        requested_by=requested_by,
        repository=f"{GITHUB_ID}/{GITHUB_REPO}",
        metadata=metadata,
    )
    publish_metric('ApprovalRequested', dimensions={'Action': action_type})
    
    return info_text


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
        log_event(
            'github.dispatch.requested',
            repository=f"{GITHUB_ID}/{GITHUB_REPO}",
            command=command_text,
            requested_by=user_id,
        )
        
        logger.info("=" * 80)
        logger.info("🚀 GitHub API 호출 시작")
        logger.info(f"📍 URL: {url}")
        logger.info(f"🔑 Token (first 10 chars): {GITHUB_TOKEN[:10]}...")
        logger.info(f"📦 Payload:\n{json.dumps(payload, indent=2)}")
        logger.info(f"📋 Headers:\n{json.dumps({k: v if k != 'Authorization' else 'token ***' for k, v in headers.items()}, indent=2)}")
        logger.info("=" * 80)
        
        # GitHub API 호출
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        
        logger.info("📥 GitHub API Response:")
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
            log_event(
                'github.dispatch.success',
                repository=f"{GITHUB_ID}/{GITHUB_REPO}",
                command=command_text,
                requested_by=user_id,
            )
            publish_metric('DeployDispatchSuccess', dimensions={'Repository': GITHUB_REPO})
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
            log_event(
                'github.dispatch.failed',
                level='error',
                status=401,
                response=response.text,
            )
            publish_metric('DeployDispatchFailure', dimensions={'Repository': GITHUB_REPO, 'Reason': '401'})
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
            log_event(
                'github.dispatch.failed',
                level='error',
                status=404,
                response=response.text,
            )
            publish_metric('DeployDispatchFailure', dimensions={'Repository': GITHUB_REPO, 'Reason': '404'})
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
            log_event(
                'github.dispatch.failed',
                level='error',
                status=403,
                response=response.text,
            )
            publish_metric('DeployDispatchFailure', dimensions={'Repository': GITHUB_REPO, 'Reason': '403'})
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
            log_event(
                'github.dispatch.failed',
                level='error',
                status=response.status_code,
                response=response.text,
            )
            publish_metric('DeployDispatchFailure', dimensions={'Repository': GITHUB_REPO, 'Reason': str(response.status_code)})
            return
            
    except requests.exceptions.Timeout:
        error_msg = "❌ *GitHub API 타임아웃* (15초 초과)"
        logger.error(error_msg)
        send_slack_message(channel_id, error_msg, response_url)
        log_event('github.dispatch.failed', level='error', status='timeout')
        publish_metric('DeployDispatchFailure', dimensions={'Repository': GITHUB_REPO, 'Reason': 'timeout'})
    
    except Exception as e:
        error_msg = f"❌ *Lambda 내부 오류*\n```{str(e)}```"
        logger.exception(f"💥 Exception: {e}")
        send_slack_message(channel_id, error_msg, response_url)
        log_event('github.dispatch.failed', level='error', status='exception', error=str(e))
        publish_metric('DeployDispatchFailure', dimensions={'Repository': GITHUB_REPO, 'Reason': 'exception'})


def invoke_async_lambda(function_name: str, payload: Dict[str, Any]):
    """자기 자신을 비동기로 재호출"""
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='Event',  # 비동기 호출
            Payload=json.dumps(payload)
        )
        logger.info("✅ 비동기 Lambda 호출 성공")
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
            "✅ *ECS 서비스 상태*\n"
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


def execute_codeploy_rollback(requested_by: str, approved_by: Optional[str] = None) -> Dict[str, Any]:
    """CodeDeploy 롤백 실행"""
    try:
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
        
        deployment_info = codedeploy_client.get_deployment(deploymentId=latest_deployment_id)
        revision = deployment_info['deploymentInfo']['revision']
        
        rollback_response = codedeploy_client.create_deployment(
            applicationName=CODEDEPLOY_APP_NAME,
            deploymentGroupName=CODEDEPLOY_GROUP_NAME,
            revision=revision,
            deploymentConfigName='CodeDeployDefault.ECSAllAtOnce',
            description=f"Slack rollback via ChatOps (requested_by={requested_by}, approved_by={approved_by or requested_by})"
        )
        
        new_deployment_id = rollback_response.get('deploymentId')
        message = (
            "🚨 *긴급 롤백 시작*\n"
            f"• 이전 배포 ID: `{latest_deployment_id}`\n"
            f"• 새 롤백 ID: `{new_deployment_id}`\n"
            f"• 요청자: <@{requested_by}>"
        )
        if approved_by:
            message += f"\n• 승인자: <@{approved_by}>"
        
        log_event(
            'codedeploy.rollback.triggered',
            application=CODEDEPLOY_APP_NAME,
            deployment_group=CODEDEPLOY_GROUP_NAME,
            previous_deployment_id=latest_deployment_id,
            new_deployment_id=new_deployment_id,
            requested_by=requested_by,
            approved_by=approved_by,
        )
        publish_metric('RollbackTriggered', dimensions={'Application': CODEDEPLOY_APP_NAME})
        
        return {'ok': True, 'message': message}
        
    except Exception as e:
        logger.exception(f"Rollback 실패: {e}")
        log_event('codedeploy.rollback.failed', level='error', error=str(e))
        publish_metric('RollbackFailure', dimensions={'Application': CODEDEPLOY_APP_NAME})
        return {'ok': False, 'message': f'❌ 롤백 실패: {str(e)}'}


def handle_rollback_command(user_id: str) -> Dict[str, Any]:
    """기존 인터페이스 유지"""
    return execute_codeploy_rollback(requested_by=user_id)


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

        lines.append(f"• `{image_name}`")

        if display_tags:
            lines.extend(f"  - `{tag}`" for tag in display_tags)
            if len(tags) > max_tags:
                lines.append("  - …")
        else:
            lines.append("  - 태그 없음")

    message = "\n".join(lines)
    return {'ok': True, 'message': message}


def handle_slash_command(payload: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Slash Command 라우터"""
    command = payload.get('command', [''])[0]
    command_text = payload.get('text', [''])[0]
    user_id = payload.get('user_id', ['unknown'])[0]
    channel_id = payload.get('channel_id', [''])[0]
    response_url = payload.get('response_url', [''])[0]
    
    logger.info("=" * 80)
    logger.info("📝 Slash Command 수신")
    logger.info(f"  - Command: {command}")
    logger.info(f"  - Text: {command_text}")
    logger.info(f"  - User: {user_id}")
    logger.info(f"  - Channel: {channel_id}")
    logger.info(f"  - Response URL: {response_url[:50]}...")
    logger.info("=" * 80)
    
    # /platform-deploy는 비동기 처리 시도 (권한 없으면 동기 처리)
    if command == '/platform-deploy':
        if DEPLOY_APPROVAL_REQUIRED and '--force' not in command_text:
            approval_text = request_action_approval(
                action_type='deploy',
                channel_id=channel_id,
                response_url=response_url,
                command_text=command_text,
                requested_by=user_id,
                metadata={'repository': f"{GITHUB_ID}/{GITHUB_REPO}"},
            )
            return {'ok': True, 'message': approval_text}
        
        # 즉시 응답 (Slack 3초 제한 회피)
        immediate_response = (
            "⏳ *배포 요청을 처리 중입니다...*\n"
            f"• 요청자: <@{user_id}>\n"
            f"• 메시지: `{command_text}`\n"
            f"• Repository: `{GITHUB_ID}/{GITHUB_REPO}`\n\n"
            "_잠시 후 결과를 알려드리겠습니다..._"
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
        if ROLLBACK_APPROVAL_REQUIRED:
            approval_text = request_action_approval(
                action_type='rollback',
                channel_id=channel_id,
                response_url=response_url,
                command_text='rollback-latest',
                requested_by=user_id,
                metadata={
                    'application': CODEDEPLOY_APP_NAME,
                    'deployment_group': CODEDEPLOY_GROUP_NAME,
                },
            )
            return {'ok': True, 'message': approval_text}
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
            
            if task_type == 'execute_rollback':
                logger.info("🔄🔄🔄 비동기 CodeDeploy 롤백 작업 시작")
                result = execute_codeploy_rollback(
                    requested_by=event['requested_by'],
                    approved_by=event.get('approved_by'),
                )
                send_slack_message(
                    channel=event['channel_id'],
                    text=result['message'],
                    response_url=event.get('response_url')
                )
                return {'statusCode': 200, 'body': json.dumps({'message': 'Rollback task completed'})}
            
            logger.warning(f"⚠️ Unknown async task: {task_type}")
            return {'statusCode': 200, 'body': json.dumps({'message': 'Unknown async task'})}
        
        # Body 디코딩
        body_str = event.get('body', '{}')
        if event.get('isBase64Encoded', False):
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
                
                actions = payload_json.get('actions') or []
                if not actions:
                    return {'statusCode': 200, 'body': json.dumps({'ok': True})}
                
                action = actions[0]
                action_id = action.get('action_id')
                response_url = payload_json.get('response_url')
                approver_id = payload_json.get('user', {}).get('id', '')
                channel_id = payload_json.get('channel', {}).get('id') or payload_json.get('container', {}).get('channel_id', '')
                
                if not is_authorized_approver(approver_id):
                    send_slack_message_with_blocks(
                        channel=channel_id,
                        text="🚫 승인 권한이 없습니다.",
                        blocks=None,
                        response_url=response_url,
                        replace_original=False,
                        ephemeral=True,
                    )
                    log_event('approval.denied.unauthorized', level='warning', approver=approver_id, action_id=action_id)
                    publish_metric('ApprovalRejected', dimensions={'Action': 'unauthorized'})
                    return {'statusCode': 200, 'body': json.dumps({'ok': True})}
                
                decoded_value = decode_action_value(action.get('value', ''))
                requested_by = decoded_value.get('requested_by', 'unknown')
                command_text = decoded_value.get('command_text', '')
                request_id = decoded_value.get('request_id', '')
                function_name = context.function_name if context else os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
                
                log_event(
                    'approval.button.clicked',
                    action_type=decoded_value.get('action_type'),
                    action_id=action_id,
                    approver=approver_id,
                    requested_by=requested_by,
                    request_id=request_id,
                )
                
                if action_id == 'approve_deploy':
                    send_slack_message_with_blocks(
                        channel=channel_id,
                        text=f"✅ <@{approver_id}> 님이 배포를 승인했습니다.",
                        blocks=None,
                        response_url=response_url,
                        replace_original=True,
                    )
                    send_slack_message(
                        channel_id,
                        f"🚀 *배포 승인 완료*\n• 요청자: <@{requested_by}>\n• 승인자: <@{approver_id}>\n• 명령: `{command_text}`"
                    )
                    publish_metric('ApprovalGranted', dimensions={'Action': 'deploy'})
                    log_event(
                        'approval.granted',
                        action_type='deploy',
                        approver=approver_id,
                        requested_by=requested_by,
                        request_id=request_id,
                        command=command_text,
                    )
                    async_payload = {
                        'async_task': 'github_deploy',
                        'command_text': command_text,
                        'user_id': requested_by,
                        'channel_id': decoded_value.get('channel_id', channel_id),
                        'response_url': decoded_value.get('response_url', response_url),
                    }
                    if function_name:
                        invoke_async_lambda(function_name, async_payload)
                    else:
                        trigger_github_deployment_async(
                            command_text,
                            requested_by,
                            decoded_value.get('channel_id', channel_id),
                            decoded_value.get('response_url', response_url),
                        )
                    return {'statusCode': 200, 'body': json.dumps({'ok': True})}
                
                if action_id == 'reject_deploy':
                    send_slack_message_with_blocks(
                        channel=channel_id,
                        text=f"❌ <@{approver_id}> 님이 배포를 거절했습니다.",
                        blocks=None,
                        response_url=response_url,
                        replace_original=True,
                    )
                    send_slack_message(
                        channel_id,
                        f"⚠️ *배포 거절됨*\n• 요청자: <@{requested_by}>\n• 거절자: <@{approver_id}>\n• 명령: `{command_text}`"
                    )
                    publish_metric('ApprovalRejected', dimensions={'Action': 'deploy'})
                    log_event(
                        'approval.rejected',
                        action_type='deploy',
                        approver=approver_id,
                        requested_by=requested_by,
                        request_id=request_id,
                        command=command_text,
                    )
                    return {'statusCode': 200, 'body': json.dumps({'ok': True})}
                
                if action_id == 'approve_rollback':
                    send_slack_message_with_blocks(
                        channel=channel_id,
                        text=f"✅ <@{approver_id}> 님이 롤백을 승인했습니다.",
                        blocks=None,
                        response_url=response_url,
                        replace_original=True,
                    )
                    publish_metric('ApprovalGranted', dimensions={'Action': 'rollback'})
                    log_event(
                        'approval.granted',
                        action_type='rollback',
                        approver=approver_id,
                        requested_by=requested_by,
                        request_id=request_id,
                    )
                    async_payload = {
                        'async_task': 'execute_rollback',
                        'requested_by': requested_by,
                        'approved_by': approver_id,
                        'channel_id': decoded_value.get('channel_id', channel_id),
                        'response_url': decoded_value.get('response_url', response_url),
                    }
                    if function_name:
                        invoke_async_lambda(function_name, async_payload)
                    else:
                        result = execute_codeploy_rollback(requested_by=requested_by, approved_by=approver_id)
                        send_slack_message(channel_id, result['message'], decoded_value.get('response_url', response_url))
                    return {'statusCode': 200, 'body': json.dumps({'ok': True})}
                
                if action_id == 'reject_rollback':
                    send_slack_message_with_blocks(
                        channel=channel_id,
                        text=f"❌ <@{approver_id}> 님이 롤백을 거절했습니다.",
                        blocks=None,
                        response_url=response_url,
                        replace_original=True,
                    )
                    send_slack_message(
                        channel_id,
                        f"⚠️ *롤백 거절됨*\n• 요청자: <@{requested_by}>\n• 거절자: <@{approver_id}>"
                    )
                    publish_metric('ApprovalRejected', dimensions={'Action': 'rollback'})
                    log_event(
                        'approval.rejected',
                        action_type='rollback',
                        approver=approver_id,
                        requested_by=requested_by,
                        request_id=request_id,
                    )
                    return {'statusCode': 200, 'body': json.dumps({'ok': True})}
                
                return {'statusCode': 200, 'body': json.dumps({'ok': True})}
        
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
        logger.warning("⚠️ 처리되지 않은 요청")
        return {'statusCode': 200, 'body': json.dumps({'ok': True})}
        
    except Exception as e:
        logger.exception(f"💥💥💥 Lambda 오류: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error', 'message': str(e)})
        }
