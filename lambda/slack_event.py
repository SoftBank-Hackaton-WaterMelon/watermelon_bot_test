# AWS Lambda function for Slack Events API (v6 - CHIIKAWA COMPLETE)
# - /platform-deploy (GitHub Trigger) - 비동기 처리 + 디버깅 강화 + 치이카와 대화
# - /platform-status (ECS Read)
# - /platform-rollback (CodeDeploy Trigger)
#
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
import random

from approve_deploy import approve_deploy
from urllib.parse import parse_qs, unquote
from ghcr_client import get_container_images_with_tags

# AWS 클라이언트 초기화
ecs_client = boto3.client('ecs')
codedeploy_client = boto3.client('codedeploy')
dynamodb_client = boto3.client('dynamodb')
lambda_client = boto3.client('lambda')
cloudwatch_client = boto3.client('cloudwatch')

# 로깅 설정
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 환경 변수 (이하 동일)
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
DEPLOY_APPROVAL_TABLE = os.environ.get('DEPLOY_APPROVAL_TABLE', 'softbank_deploy')

_TRUE_VALUES = {'1', 'true', 'yes', 'on'}
DEPLOY_APPROVAL_REQUIRED = os.environ.get('DEPLOY_APPROVAL_REQUIRED', 'false').lower() in _TRUE_VALUES
ROLLBACK_APPROVAL_REQUIRED = os.environ.get('ROLLBACK_APPROVAL_REQUIRED', 'false').lower() in _TRUE_VALUES
SLACK_APPROVER_IDS = {
    approver.strip()
    for approver in os.environ.get('SLACK_APPROVER_IDS', '').split(',')
    if approver.strip()
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 치이카와 대화 시스템 (✨ 수정됨)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CHIIKAWA_DIALOGS = {
    'approval_request': {
        'text': '새 버전 배포 요청이 도착했어요. 승인해주실래요?\n 「新しいバージョンのデプロ이リクエストが届きました！承認してくれますか？」',
        'image': 'https://github.com/SoftBank-Hackaton-WaterMelon/Chiikawa/blob/main/rollback_success.gif?raw=true'
    },
    'deploy_start': {
        'text': '“배포가 시작됐어요~\n「デプロイが始まりました〜！」', # 'test' -> 'text' 수정
        'image': 'https://github.com/SoftBank-Hackaton-WaterMelon/Chiikawa/blob/main/deploy_start.gif?raw=true'
    },
    'deploy_approved': {
        'text': '배포가 승인되었어요! 🎉 이제 깃허브 액션으로 워크플로우를 실행할게요.\n「デプロイが承認されました！🎉sこれから GitHub Actions でワークフローを実行しますね！」',
        'image': 'https://github.com/SoftBank-Hackaton-WaterMelon/Chiikawa/blob/main/deployment_trigger_success.gif?raw=true' # 누락된 따옴표 추가
    },
    'deploy_completed': {
        'text': '“배포가 성공적으로 완료됐어요! 이제 서비스가 새 버전으로 반짝✨하고 있어요!\n「デプロイが無事に完了しました！サービスが新しいバージョンでキラキラ✨していますよ！」',
        'image': 'https://github.com/SoftBank-Hackaton-WaterMelon/Chiikawa/blob/main/deploy_complete.gif?raw=true'
    },
    # --- ✨ 코드에서 사용하지만 누락되었던 키 추가 ---
    'github_trigger_success': {
        'text': 'GitHub Actions 워크플로우 실행을 성공적으로 요청했어요!\n「GitHub Actions ワークフローの実行リクエストが成功しました！」',
        'image': 'https://github.com/SoftBank-Hackaton-WaterMelon/Chiikawa/blob/main/deployment_trigger_success.gif?raw=true'
    },
    'github_trigger_failed': {
        'text': '앗! GitHub API 호출에 실패했어요... (땀;)\n「あ！GitHub API の呼び出しに失敗しました…（汗;）」',
        'image': 'https://github.com/SoftBank-Hackaton-WaterMelon/Chiikawa/blob/main/error.gif?raw=true'
    },
    'deploy_request': {
        'text': '배포 요청을 접수했어요! 처리 중... \n「デプロイリクエストを受け付けました！処理中…」',
        'image': 'https://github.com/SoftBank-Hackaton-WaterMelon/Chiikawa/blob/main/deploy_start.gif?raw=true'
    },
    'status_check': {
        'text': '지금 서비스 상태를 확인해볼게요!\n「今からサービスの状態を確認しますね！」',
        'image': 'https://github.com/SoftBank-Hackaton-WaterMelon/Chiikawa/blob/main/checking.gif?raw=true'
    },
    'rollback_start': {
        'text': '앗! 롤백을 시작해요. 이전 버전으로... (총총)\n「あ！ロールバックを開始します。前のバージョンに…（トコトコ）」',
        'image': 'https://github.com/SoftBank-Hackaton-WaterMelon/Chiikawa/blob/main/rollback.gif?raw=true'
    },
    'rollback_success': {
        'text': '롤백 완료! 이전 버전으로 돌아왔어요.\n「ロールバック完了！前のバージョンに戻りました。」',
        'image': 'https://github.com/SoftBank-Hackaton-WaterMelon/Chiikawa/blob/main/deploy_complete.gif?raw=true'
    }
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
    """Slack 메시지 전송 (채널 또는 response_url) - ✨ 수정됨: 텍스트 전용"""
    
    # response_url이 있으면 우선 사용 (더 빠름)
    if response_url:
        try:
            payload = {
                'text': text,
                'response_type': 'in_channel',
                'replace_original': False
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
    
    # ✨ 수정됨: 잘못 하드코딩된 치이카와 블록 제거. 텍스트만 보내도록 수정.
    payload = {
        "channel": channel,
        "text": text
    }
    
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
    text: str, # Fallback text
    blocks: Optional[List[Dict[str, Any]]] = None,
    response_url: str = None,
    replace_original: bool = False,
    ephemeral: bool = False,
) -> bool:
    """블록(버튼/이미지) 메시지 전송 헬퍼"""
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


# --- (log_event, publish_metric, encode/decode, is_authorized_approver... 등은 변경 없음) ---
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
    """승인 요청 메시지 전송 - ✨ 수정됨: 블록 순서 변경"""
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
    
    # 🐹 치이카와: 배포 승인 대기
    dialog_key = 'approval_request'
    dialog = CHIIKAWA_DIALOGS.get(dialog_key, {})
    chiikawa_text = dialog.get('text', '승인 요청이 도착했어요.')
    chiikawa_image = dialog.get('image')

    # ✨ 수정됨: 블록 순서를 요청에 맞게 변경
    blocks: List[Dict[str, Any]] = [
        {
            # 1. (먼저) 배포 승인 요청
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
            # 2. (다음) 치이카와 텍스트
            'type': 'section',
            'text': {
                'type': 'mrkdwn',
                'text': f"*{chiikawa_text}*",
            },
        },
        {
            # 3. (마지막) 치이카와 이미지
            "type": "image",
            "image_url": chiikawa_image,
            "alt_text": "Approval Request"
        },
        {
            # (이하 동일)
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
    
    # Fallback 텍스트 (알림용)
    info_text = (
        f"*{label} 승인 요청*\n"
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
# ----------------------------------------------------------------


def trigger_github_deployment_async(command_text: str, user_id: str, channel_id: str, response_url: str):
    """GitHub API 호출 (비동기 버전) - 강화된 디버깅 - ✨ 수정됨: 블록 전송"""
    
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
            requested_by=user_id
        )
        
        logger.info("=" * 80)
        logger.info("🚀 GitHub API 호출 시작")
        logger.info(f"📍 URL: {url}")
        logger.info(f"🔑 Token (first 10 chars): {GITHUB_TOKEN[:10]}...")
        logger.info(f"📦 Payload:\n{json.dumps(payload, indent=2)}")
        logger.info("=" * 80)
        
        # GitHub API 호출
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        
        logger.info("📥 GitHub API Response:")
        logger.info(f"  - Status Code: {response.status_code}")
        logger.info(f"  - Body: {response.text}")
        
        # 성공 (204 No Content)
        # 성공 (204 No Content)
        if response.status_code == 204:
            
            # ✨ 수정됨: 
            # 'approve_deploy'에서 이미 승인 메시지를 보냈으므로,
            # 중복되는 성공 메시지는 보내지 않고 로그만 남깁니다.
            
            logger.info("✅ GitHub dispatch 성공!")
            
            # ✨ 아래 send_slack_message_with_blocks 관련 로직 전체를 주석 처리/삭제합니다.
            # -----------------------------------------------------------------
            # dialog_key = 'github_trigger_success'
            # dialog = CHIIKAWA_DIALOGS.get(dialog_key, {})
            # chiikawa_text = dialog.get('text', 'GitHub Actions 배포 트리거 성공!')

            # details_mrkdwn = (
            #     f"• 요청자: <@{user_id}>\n"
            #     f"• 메시지: `{command_text}`\n"
            #     f"• Repository: `{GITHUB_ID}/{GITHUB_REPO}`\n"
            #     f"• Event Type: `dev_deploy`\n\n"
            #     f"GitHub Actions 페이지에서 워크플로우 실행을 확인하세요:\n"
            #     f"https://github.com/{GITHUB_ID}/{GITHUB_REPO}/actions"
            # )

            # blocks = [
            #     {
            #         "type": "section",
            #         "text": {"type": "mrkdwn", "text": f"✅ *GitHub Actions 배포 트리거 성공!*\n\n{details_mrkdwn}"}
            #     }
            # ]
            
            # send_slack_message_with_blocks(
            #     channel=channel_id,
            #     text="✅ GitHub Actions 배포 트리거 성공!", # Fallback text
            #     blocks=blocks,
            #     response_url=response_url
            # )
            # -----------------------------------------------------------------
            
            log_event(
                'github.dispatch.success',
                repository=f"{GITHUB_ID}/{GITHUB_REPO}",
                command=command_text,
                requested_by=user_id
            )
            publish_metric('DeployDispatchSuccess', dimensions={'Repository': GITHUB_REPO})
            return
        
        # 에러 응답 (401, 404, 403 등)
        else:
            # 🐹 치이카와: GitHub 트리거 실패 (✨ 수정됨)
            dialog_key = 'github_trigger_failed'
            dialog = CHIIKAWA_DIALOGS.get(dialog_key, {})
            chiikawa_text = dialog.get('text', 'GitHub API 오류')
            chiikawa_image = dialog.get('image')

            details_mrkdwn = (
                f"❌ *GitHub API 오류*\n"
                f"• Status: `{response.status_code}`\n"
                f"• Response: ```{response.text[:500]}```\n"
                f"• URL: `{url}`"
            )

            blocks = [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*{chiikawa_text}*"}
                },
                {
                    "type": "image",
                    "image_url": chiikawa_image,
                    "alt_text": "GitHub Trigger Failed"
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": details_mrkdwn}
                }
            ]
            logger.error(f"❌ Status {response.status_code}: {response.text}")
            send_slack_message_with_blocks(
                channel=channel_id,
                text="❌ GitHub API 오류", # Fallback
                blocks=blocks,
                response_url=response_url
            )
            log_event(
                'github.dispatch.failed',
                level='error',
                status=response.status_code,
                response=response.text,
            )
            publish_metric('DeployDispatchFailure', dimensions={'Repository': GITHUB_REPO, 'Reason': str(response.status_code)})
            return
            
    except requests.exceptions.Timeout:
        # ✨ 수정됨 (Timeout)
        dialog_key = 'github_trigger_failed'
        dialog = CHIIKAWA_DIALOGS.get(dialog_key, {})
        chiikawa_text = dialog.get('text', 'GitHub API 타임아웃')
        chiikawa_image = dialog.get('image')
        
        blocks = [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{chiikawa_text}*"}},
            {"type": "image", "image_url": chiikawa_image, "alt_text": "GitHub Timeout"},
            {"type": "section", "text": {"type": "mrkdwn", "text": "❌ *GitHub API 타임아웃* (15초 초과)"}}
        ]
        logger.error("GitHub API 타임아웃")
        send_slack_message_with_blocks(channel_id, "❌ GitHub API 타임아웃", blocks, response_url)
        log_event('github.dispatch.failed', level='error', status='timeout')
        publish_metric('DeployDispatchFailure', dimensions={'Repository': GITHUB_REPO, 'Reason': 'timeout'})
    
    except Exception as e:
        # ✨ 수정됨 (Exception)
        dialog_key = 'github_trigger_failed'
        dialog = CHIIKAWA_DIALOGS.get(dialog_key, {})
        chiikawa_text = dialog.get('text', 'Lambda 내부 오류')
        chiikawa_image = dialog.get('image')

        blocks = [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{chiikawa_text}*"}},
            {"type": "image", "image_url": chiikawa_image, "alt_text": "Lambda Error"},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"❌ *Lambda 내부 오류*\n```{str(e)}```"}}
        ]
        logger.exception(f"💥 Exception: {e}")
        send_slack_message_with_blocks(channel_id, "❌ Lambda 내부 오류", blocks, response_url)
        log_event('github.dispatch.failed', level='error', status='exception', error=str(e))
        publish_metric('DeployDispatchFailure', dimensions={'Repository': GITHUB_REPO, 'Reason': 'exception'})


def invoke_async_lambda(function_name: str, payload: Dict[str, Any]):
    """자기 자신을 비동기로 재호출"""
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='Event',
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
    """ECS 서비스 상태 조회 - ✨ 수정됨: 블록 반환"""
    try:
        # 🐹 치이카와: 상태 조회
        dialog_key = 'status_check'
        dialog = CHIIKAWA_DIALOGS.get(dialog_key, {})
        chiikawa_text = dialog.get('text', 'ECS 서비스 상태')
        chiikawa_image = dialog.get('image')
        
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
        
        details_mrkdwn = (
            "✅ *ECS 서비스 상태*\n"
            f"• 서비스: `{ECS_SERVICE_NAME}`\n"
            f"• 클러스터: `{ECS_CLUSTER_NAME}`\n"
            f"• 🏃 Running: `{service.get('runningCount', 0)}`개\n"
            f"• ⏳ Pending: `{service.get('pendingCount', 0)}`개\n"
            f"• 🏷️ Version: `{version}`"
        )
        
        # ✨ 수정됨: 블록 생성
        blocks = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{chiikawa_text}*"}
            },
            {
                "type": "image",
                "image_url": chiikawa_image,
                "alt_text": "Status Check"
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": details_mrkdwn}
            }
        ]

        return {'ok': True, 'message': "ECS 서비스 상태", 'blocks': blocks}
        
    except Exception as e:
        logger.exception(f"Status 조회 실패: {e}")
        return {'ok': False, 'message': f'❌ 상태 조회 실패: {str(e)}'}


def handle_deploy_approve_command(command_text: str, approver_id: str, channel_id: str, response_url: str) -> Dict[str, Any]:
    """CodeDeploy 라이프사이클 훅 승인. - ✨ 수정됨: 배포 완료 메시지 전송"""
    deployment_id = (command_text or '').strip().split()[0] if command_text else ''

    if not deployment_id:
        guidance = "예: `/platform-deploy-approve d-XXXXXXXXX`"
        message = "❌ deployment_id를 입력하세요.\n" + guidance
        return {'ok': False, 'message': message}

    try:
        approve_deploy(
            codedeploy_client=codedeploy_client,
            dynamodb_client=dynamodb_client,
            deployment_id=deployment_id,
            table_name=DEPLOY_APPROVAL_TABLE,
        )
        log_event(
            'codedeploy.approval.succeeded',
            deployment_id=deployment_id,
            approved_by=approver_id,
            table_name=DEPLOY_APPROVAL_TABLE,
        )
        publish_metric('DeployHookApproval', dimensions={'Result': 'Success'})
        
        # 🐹 치이카와: 배포 완료 (✨ 수정됨)
        # 1. 텍스트는 'deploy_completed' 딕셔너리에서 가져옴
        dialog_key = 'deploy_completed'
        dialog = CHIIKAWA_DIALOGS.get(dialog_key, {})
        chiikawa_text = dialog.get('text', "배포가 성공적으로 완료됐어요! ✨")
        
        # 2. ✨ 이미지는 요청하신 URL로 하드코딩 (raw=true 추가)
        chiikawa_image = "https://github.com/SoftBank-Hackaton-WaterMelon/Chiikawa/blob/main/deploy_complete.gif?raw=true"
        
        details_mrkdwn = (
            "✅ *CodeDeploy 배포 승인 완료*\n"
            f"• Deployment ID: `{deployment_id}`\n"
            f"• 승인자: <@{approver_id}>\n"
            "• 서비스가 새 버전으로 업데이트되었습니다."
        )
        
        blocks = [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{chiikawa_text}*"}},
            {"type": "image", "image_url": chiikawa_image, "alt_text": "Deploy Complete"},
            {"type": "section", "text": {"type": "mrkdwn", "text": details_mrkdwn}}
        ]
        
        send_slack_message_with_blocks(
            channel=channel_id,
            text="✅ 배포 완료!", # Fallback text
            blocks=blocks,
            response_url=response_url
        )
        
        # ✨ 수정됨: 불필요한 비공개(ephemeral) 응답을 보내지 않도록 None 반환
        return {'ok': True, 'message': None}
        
    except Exception as exc:
        logger.exception("CodeDeploy 배포 승인 실패: %s", exc)
        log_event(
            'codedeploy.approval.failed',
            level='error',
            deployment_id=deployment_id,
            approved_by=approver_id,
            error=str(exc),
        )
        publish_metric('DeployHookApproval', dimensions={'Result': 'Failed'})
        message = (
            "❌ *CodeDeploy 배포 승인 실패*\n"
            f"• Deployment ID: `{deployment_id}`\n"
            f"• 오류: `{exc}`"
        )
        return {'ok': False, 'message': message}


def execute_codeploy_rollback(requested_by: str, approved_by: Optional[str] = None) -> Dict[str, Any]:
    """CodeDeploy 롤백 실행 - ✨ 수정됨: 블록 반환"""
    try:
        # 🐹 치이카와: 롤백 시작
        dialog_key_start = 'rollback_start'
        dialog_start = CHIIKAWA_DIALOGS.get(dialog_key_start, {})
        chiikawa_start_text = dialog_start.get('text', '롤백 시작')
        chiikawa_start_image = dialog_start.get('image')

        response = codedeploy_client.list_deployments(
            # ... (list_deployments logic) ...
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
            # ... (create_deployment logic) ...
            applicationName=CODEDEPLOY_APP_NAME,
            deploymentGroupName=CODEDEPLOY_GROUP_NAME,
            revision=revision,
            deploymentConfigName='CodeDeployDefault.ECSAllAtOnce',
            description=f"Slack rollback via ChatOps (requested_by={requested_by}, approved_by={approved_by or requested_by})"
        )
        
        new_deployment_id = rollback_response.get('deploymentId')
        
        # 🐹 치이카와: 롤백 성공
        dialog_key_success = 'rollback_success'
        dialog_success = CHIIKAWA_DIALOGS.get(dialog_key_success, {})
        chiikawa_success_text = dialog_success.get('text', '롤백 성공')
        
        details_mrkdwn = (
            "🚨 *긴급 롤백 시작*\n"
            f"• 이전 배포 ID: `{latest_deployment_id}`\n"
            f"• 새 롤백 ID: `{new_deployment_id}`\n"
            f"• 요청자: <@{requested_by}>"
        )
        if approved_by:
            details_mrkdwn += f"\n• 승인자: <@{approved_by}>"
        
        # ✨ 수정됨: 블록 생성
        blocks = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{chiikawa_start_text}*"}
            },
            {
                "type": "image",
                "image_url": chiikawa_start_image,
                "alt_text": "Rollback Start"
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": details_mrkdwn}
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{chiikawa_success_text}*"}
            }
        ]
        
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
        
        # ✨ 수정됨: 블록 반환
        return {'ok': True, 'message': "롤백 시작됨", 'blocks': blocks}
        
    except Exception as e:
        logger.exception(f"Rollback 실패: {e}")
        log_event('codedeploy.rollback.failed', level='error', error=str(e))
        publish_metric('RollbackFailure', dimensions={'Application': CODEDEPLOY_APP_NAME})
        return {'ok': False, 'message': f'❌ 롤백 실패: {str(e)}'}


def handle_rollback_command(user_id: str) -> Dict[str, Any]:
    """기존 인터페이스 유지"""
    return execute_codeploy_rollback(requested_by=user_id)


def handle_container_list_command(channel_id: str, response_url: str) -> Dict[str, Any]:
    """GHCR 컨테이너 이미지 목록 조회 후 Slack 전송 (✨ 수정됨: 블록 반환)"""
    if not GITHUB_TOKEN:
        logger.error("GHCR 조회를 위한 GitHub Token이 설정되지 않았습니다.")
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
    except Exception as exc:
        logger.exception(f"GHCR 조회 실패: {exc}")
        return {'ok': False, 'message': f"❌ GHCR 조회 실패: {exc}"}

    if not images_with_tags:
        message = (
            "ℹ️ *GHCR 컨테이너 이미지 없음*\n"
            f"• Owner: `{owner_name}`\n"
            "• 조회된 이미지가 없습니다."
        )
        return {'ok': True, 'message': message} # 이미지가 없으면 텍스트만 반환

    max_images = int(GHCR_MAX_IMAGES)
    max_tags = int(GHCR_MAX_TAGS)

    sorted_items = sorted(images_with_tags.items())
    
    # ✨ 수정됨: Slack 메시지를 Block Kit으로 구성
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "📦 GHCR 컨테이너 이미지 목록"
            }
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"• Owner: `{owner_name}`"},
                {"type": "mrkdwn", "text": f"• 총 이미지: `{len(sorted_items)}`"}
            ]
        },
        {"type": "divider"}
    ]

    for index, (image_name, tags) in enumerate(sorted_items):
        if index >= max_images:
            blocks.append({
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"… (상위 `{max_images}`개만 표시, 총 `{len(sorted_items)}`개)"}
                ]
            })
            break

        tag_lines = []
        if tags:
            for version_tags in tags[:max_tags]:
                if version_tags:
                    formatted_tags = ", ".join(f"`{tag}`" for tag in version_tags)
                    tag_lines.append(f"  - {formatted_tags}")
                else:
                    tag_lines.append("  - (빈 버전)")
            if len(tags) > max_tags:
                tag_lines.append("  - …")
        else:
            tag_lines.append("  - 태그 없음")

        image_section = {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"• `{image_name}`\n" + "\n".join(tag_lines)
            }
        }
        blocks.append(image_section)

    # Slack Block Kit은 50개가 한계. 넘어가면 자름.
    if len(blocks) > 50:
        blocks = blocks[:49]
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "... (결과가 너무 많아 일부만 표시)"}]
        })

    return {'ok': True, 'message': "GHCR 이미지 목록", 'blocks': blocks}


def handle_slash_command(payload: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Slash Command 라우터 - ✨ 수정됨: 블록 반환 지원"""
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
    logger.info("=" * 80)
    
    # /platform-deploy는 비동기 처리 시도
    # /platform-deploy는 비동기 처리 시도
    if command == '/platform-deploy':
        if DEPLOY_APPROVAL_REQUIRED and '--force' not in command_text:
            # ✨ 1. 함수가 텍스트를 반환하지만, 변수에 저장하지 않고 호출만 합니다.
            request_action_approval(
                action_type='deploy',
                channel_id=channel_id,
                response_url=response_url,
                command_text=command_text,
                requested_by=user_id,
                metadata={'repository': f"{GITHUB_ID}/{GITHUB_REPO}"},
            )
            return {'ok': True, 'message': None}
        
        # 🐹 치이카와: 배포 요청 시작 (✨ 수정됨)
        dialog_key = 'deploy_request'
        dialog = CHIIKAWA_DIALOGS.get(dialog_key, {})
        chiikawa_text = dialog.get('text', '배포 요청을 처리 중입니다...')
        chiikawa_image = dialog.get('image')

        details_mrkdwn = (
            "⏳ *배포 요청을 처리 중입니다...*\n"
            f"• 요청자: <@{user_id}>\n"
            f"• 메시지: `{command_text}`\n"
            f"• Repository: `{GITHUB_ID}/{GITHUB_REPO}`\n\n"
            "_잠시 후 결과를 알려드리겠습니다..._"
        )
        
        # ✨ 수정됨: 즉시 응답을 Block Kit으로 구성
        blocks = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{chiikawa_text}*"}
            },
            {
                "type": "image",
                "image_url": chiikawa_image,
                "alt_text": "Deploy Request"
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": details_mrkdwn}
            }
        ]
        
        # 자기 자신을 비동기로 재호출 시도
        async_payload = {
            'async_task': 'github_deploy',
            'command_text': command_text,
            'user_id': user_id,
            'channel_id': channel_id,
            'response_url': response_url
        }
        
        function_name = context.function_name if context else os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
        
        async_success = False
        if function_name:
            async_success = invoke_async_lambda(function_name, async_payload)
        
        if not async_success:
            logger.warning("⚠️ 비동기 호출 실패, 동기 처리로 폴백")
            # 동기 호출 시에는 이 함수가 응답을 보내므로,
            # 여기서는 즉각적인 응답을 보낼 필요가 없습니다.
            trigger_github_deployment_async(command_text, user_id, channel_id, response_url)
            # 동기 응답은 이미 전송되었으므로, Slack에 200 OK만 반환
            return {'ok': True, 'message': None} # message: None은 응답 안 함
        
        # 비동기 호출 성공 시, 블록으로 즉시 응답
        return {'ok': True, 'message': "배포 요청 처리 중...", 'blocks': blocks}
    
    elif command == '/platform-deploy-approve':
        # 이 함수는 직접 send_slack_message_with_blocks를 호출합니다.
        result = handle_deploy_approve_command(command_text, user_id, channel_id, response_url)
        # Slack에는 텍스트만 즉시 응답합니다.
        return {'ok': result['ok'], 'message': result['message']}

    elif command == '/platform-status':
        return handle_status_command() # 이 함수는 'blocks'를 포함한 dict 반환
    
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
        return handle_rollback_command(user_id) # 이 함수는 'blocks'를 포함한 dict 반환

    elif command == '/platform-images':
        result = handle_container_list_command(channel_id, response_url)
        # 이 함수는 반환된 블록을 즉시 응답으로 사용합니다.
        # (참고: /platform-images는 메시지가 길어질 수 있어 비동기 처리가 더 낫습니다)
        return result
    
    else:
        return {'ok': False, 'message': f"❌ 알 수 없는 명령어: {command}"}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda 핸들러 - 요청 라우팅"""
    try:
        logger.info("🎯 Lambda 실행 시작")
        
        # 비동기 작업 처리
        if 'async_task' in event:
            task_type = event['async_task']
            
            if task_type == 'github_deploy':
                logger.info("🔄 비동기 GitHub 배포 작업 시작")
                trigger_github_deployment_async(
                    event['command_text'],
                    event['user_id'],
                    event['channel_id'],
                    event['response_url']
                )
                return {'statusCode': 200, 'body': json.dumps({'message': 'Async task completed'})}
            
            if task_type == 'execute_rollback':
                logger.info("🔄 비동기 롤백 작업 시작")
                result = execute_codeploy_rollback(
                    requested_by=event['requested_by'],
                    approved_by=event.get('approved_by'),
                )
                # ✨ 수정됨: 롤백 결과가 블록일 수 있으므로 send_slack_message_with_blocks 사용
                send_slack_message_with_blocks(
                    channel=event['channel_id'],
                    text=result['message'],
                    blocks=result.get('blocks'), # 블록이 있으면 블록 전송
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
                
                # ✨ 수정됨: handle_slash_command가 'blocks'를 반환하면 사용
                if result.get('message') is None: # 동기 처리 완료, 응답 없음
                    return {'statusCode': 200}
                
                response_body = {'text': result['message']}
                if 'blocks' in result:
                    response_body['blocks'] = result['blocks']
                    # 블록이 있을 경우, 텍스트는 알림용 Fallback으로만 사용됨
                    response_body['text'] = result.get('message', 'Slack 응답') 
                
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps(response_body)
                }
            
            # Interactive 버튼 처리
            if 'payload' in payload:
                payload_json = json.loads(payload['payload'][0])
                logger.info(f"🔘 Interactive payload 수신")
                
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
                    log_event('approval.denied.unauthorized', level='warning', approver=approver_id)
                    return {'statusCode': 200, 'body': json.dumps({'ok': True})}
                
                decoded_value = decode_action_value(action.get('value', ''))
                requested_by = decoded_value.get('requested_by', 'unknown')
                command_text = decoded_value.get('command_text', '')
                function_name = context.function_name if context else os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
                
                if action_id == 'approve_deploy':
                    # 🐹 치이카와: 배포 승인됨 (✨ 수정됨)
                    dialog_key = 'deploy_approved'
                    dialog = CHIIKAWA_DIALOGS.get(dialog_key, {})
                    chiikawa_text = dialog.get('text', '배포가 승인되었습니다!')
                    chiikawa_image = dialog.get('image')

                    # ✨ 수정됨: 요청하신 순서대로 블록 순서 변경
                    blocks = [
                        {
                            # 1. (먼저) 승인자/요청자 텍스트
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"✅ <@{approver_id}> 님이 배포를 승인했습니다. 🚀\n• 요청자: <@{requested_by}>"}
                        },
                        {
                            # 2. (다음) 치이카와 텍스트
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*{chiikawa_text}*"}
                        },
                        {
                            # 3. (마지막) 치이카와 이미지
                            "type": "image",
                            "image_url": chiikawa_image,
                            "alt_text": "Deploy Approved"
                        }
                    ]
                    
                    send_slack_message_with_blocks(
                        channel=channel_id,
                        text="✅ 배포 승인됨",
                        blocks=blocks,
                        response_url=response_url,
                        replace_original=True, # 원본 메시지 교체
                    )
                    
                    publish_metric('ApprovalGranted', dimensions={'Action': 'deploy'})
                    log_event(
                        'approval.granted',
                        action_type='deploy',
                        approver=approver_id,
                        requested_by=requested_by,
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
                    # (이 부분은 치이카와 이미지가 없었으므로 기존 로직 유지)
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
                    return {'statusCode': 200, 'body': json.dumps({'ok': True})}
                
                if action_id == 'approve_rollback':
                    # 🐹 치이카와: 롤백 시작 (✨ 수정됨)
                    dialog_key = 'rollback_start' # 롤백 시작 이미지 사용
                    dialog = CHIIKAWA_DIALOGS.get(dialog_key, {})
                    chiikawa_text = dialog.get('text', '롤백이 승인되었습니다!')
                    chiikawa_image = dialog.get('image')

                    blocks = [
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*{chiikawa_text}*"}
                        },
                        {
                            "type": "image",
                            "image_url": chiikawa_image,
                            "alt_text": "Rollback Approved"
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"✅ <@{approver_id}> 님이 롤백을 승인했습니다. 롤백을 시작합니다..."}
                        }
                    ]

                    send_slack_message_with_blocks(
                        channel=channel_id,
                        text=f"✅ <@{approver_id}> 님이 롤백을 승인했습니다.",
                        blocks=blocks,
                        response_url=response_url,
                        replace_original=True,
                    )
                    publish_metric('ApprovalGranted', dimensions={'Action': 'rollback'})
                    
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
                        # ✨ 수정됨: 롤백 결과 블록 전송
                        send_slack_message_with_blocks(
                            channel_id,
                            result['message'],
                            result.get('blocks'),
                            decoded_value.get('response_url', response_url)
                        )
                    return {'statusCode': 200, 'body': json.dumps({'ok': True})}
                
                if action_id == 'reject_rollback':
                    send_slack_message_with_blocks(
                        channel=channel_id,
                        text=f"❌ <@{approver_id}> 님이 롤백을 거절했습니다.",
                        blocks=None,
                        response_url=response_url,
                        replace_original=True,
                    )
                    publish_metric('ApprovalRejected', dimensions={'Action': 'rollback'})
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
                logger.info("📬 Event callback 수신")
                return {'statusCode': 200, 'body': json.dumps({'ok': True})}
        
        except json.JSONDecodeError:
            logger.error(f"❌ JSON 파싱 실패")
            return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid JSON'})}
        
        return {'statusCode': 200, 'body': json.dumps({'ok': True})}
        
    except Exception as e:
        logger.exception(f"💥 Lambda 오류: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }
