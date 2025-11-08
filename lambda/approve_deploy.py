import logging
import os
from typing import Optional


class DeploymentApprover:
    """CodeDeploy 배포를 승인하기 위한 헬퍼 클래스"""

    def __init__(
        self,
        codedeploy_client,
        dynamodb_client,
        table_name: Optional[str] = None,
    ) -> None:
        self.codedeploy_client = codedeploy_client
        self.dynamodb_client = dynamodb_client
        self.table_name = table_name or os.environ.get('DEPLOY_APPROVAL_TABLE', 'softbank_deploy')
        self.logger = logging.getLogger(__name__)

    def approve(self, deployment_id: str) -> None:
        """deployment_id에 해당하는 라이프사이클 훅을 성공 처리한다."""
        if not deployment_id:
            raise ValueError('deployment_id는 필수 값입니다.')

        hook_execution_id = self._get_hook_execution_id(deployment_id)

        self.codedeploy_client.put_lifecycle_event_hook_execution_status(
            deploymentId=deployment_id,
            lifecycleEventHookExecutionId=hook_execution_id,
            status='Succeeded',
        )

        self.logger.info(
            "Deployment %s 승인 완료 (hook_execution_id=%s)",
            deployment_id,
            hook_execution_id,
        )

    def _get_hook_execution_id(self, deployment_id: str) -> str:
        response = self.dynamodb_client.get_item(
            TableName=self.table_name,
            Key={'deployment_id': {'S': deployment_id}},
            ConsistentRead=True,
        )

        item = response.get('Item')
        if not item:
            raise LookupError(f"DynamoDB에서 deployment_id '{deployment_id}' 항목을 찾을 수 없습니다.")

        hook_value = item.get('hook_execution_id')
        if not hook_value:
            raise LookupError(
                f"DynamoDB 항목에 hook_execution_id 속성이 없습니다. deployment_id='{deployment_id}'"
            )

        if isinstance(hook_value, dict):
            value = hook_value.get('S') or hook_value.get('s')
        else:
            value = str(hook_value)

        if not value:
            raise LookupError(
                f"hook_execution_id 값을 읽을 수 없습니다. deployment_id='{deployment_id}', value={hook_value}"
            )

        return value


def approve_deploy(
    codedeploy_client,
    dynamodb_client,
    deployment_id: str,
    table_name: Optional[str] = None,
) -> None:
    DeploymentApprover(
        codedeploy_client=codedeploy_client,
        dynamodb_client=dynamodb_client,
        table_name=table_name,
    ).approve(deployment_id)

