"""GitHub Container Registry 이미지 및 태그 열람 도구.

GitHub Packages REST API를 사용하여 지정된 사용자 혹은 조직의 컨테이너
이미지 목록과 각 이미지의 태그를 수집합니다. 문서화된 모범 사례를 기반으로
인증, 페이지네이션, 오류 처리를 포괄하는 `GHCRClient` 클래스를 제공합니다.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Optional

import requests


LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"


class GHCRClient:
    """GitHub Container Registry와 상호작용하기 위한 클라이언트.

    GitHub Packages REST API를 활용하여 컨테이너 이미지와 각 이미지에 존재하는
    태그를 조회합니다.
    """

    BASE_URL = "https://api.github.com"

    def __init__(
        self,
        *,
        username: Optional[str] = None,
        org: Optional[str] = None,
        token: str,
        session: Optional[requests.Session] = None,
    ) -> None:
        if not username and not org:
            raise ValueError("username 혹은 org 중 최소 하나는 지정되어야 합니다.")
        if username and org:
            raise ValueError("username과 org는 동시에 지정할 수 없습니다.")
        if not token:
            raise ValueError("GitHub Personal Access Token이 필요합니다.")

        self.owner_type = "orgs" if org else "users"
        self.owner_name = org or username
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"token {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    def list_images(self) -> List[str]:
        """해당 소유자의 모든 GHCR 컨테이너 이미지 이름을 반환합니다."""

        logging.info("'%s'의 GHCR 컨테이너 이미지 목록을 조회합니다.", self.owner_name)
        url = f"{self.BASE_URL}/{self.owner_type}/{self.owner_name}/packages"
        params = {"package_type": "container", "per_page": 100}

        packages = self._paginate(url, params)
        image_names = [pkg.get("name") for pkg in packages if pkg.get("name")]
        logging.info("총 %d개의 이미지를 찾았습니다.", len(image_names))
        return image_names

    def list_tags(self, image_name: str) -> List[List[str]]:
        """지정된 컨테이너 이미지에 존재하는 태그 목록을 버전 단위로 반환합니다."""

        if not image_name:
            raise ValueError("image_name은 비어 있을 수 없습니다.")

        logging.info("'%s' 이미지의 태그를 조회합니다.", image_name)
        url = (
            f"{self.BASE_URL}/{self.owner_type}/"
            f"{self.owner_name}/packages/container/{image_name}/versions"
        )

        versions = self._paginate(url, {"per_page": 100})
        tags_by_version: List[List[str]] = []
        for version in versions:
            metadata = version.get("metadata", {})
            container_meta = metadata.get("container", {})
            tags = container_meta.get("tags", [])
            if tags:
                tags_by_version.append(list(tags))

        logging.info(
            "'%s' 이미지에서 태그 목록 %d세트를 찾았습니다.",
            image_name,
            len(tags_by_version),
        )
        return tags_by_version

    def list_images_with_tags(
        self, images: Optional[Iterable[str]] = None
    ) -> Dict[str, List[List[str]]]:
        """이미지와 태그 목록(버전별)을 매핑한 딕셔너리를 반환합니다."""

        image_names = list(images) if images is not None else self.list_images()
        output: Dict[str, List[str]] = {}
        for image_name in image_names:
            try:
                output[image_name] = self.list_tags(image_name)
            except requests.HTTPError as exc:  # pragma: no cover - 런타임 에러 메시지용
                logging.warning(
                    "이미지 '%s'의 태그 조회 중 HTTP 오류가 발생했습니다: %s",
                    image_name,
                    exc,
                )
            except requests.RequestException as exc:  # pragma: no cover
                logging.error(
                    "이미지 '%s'의 태그 조회 중 네트워크 오류가 발생했습니다: %s",
                    image_name,
                    exc,
                )
        return output

    def _paginate(self, url: str, params: Optional[Dict[str, int]] = None) -> List[dict]:
        """Link 헤더 기반의 페이지네이션을 처리하여 전체 결과를 반환합니다."""

        results: List[dict] = []
        next_url: Optional[str] = url
        request_params = params

        while next_url:
            response = self.session.get(next_url, params=request_params, timeout=30)
            response.raise_for_status()

            if not isinstance(response.json(), list):
                raise ValueError(
                    "예상치 못한 응답 형식입니다. 리스트가 아닙니다: %s",
                    response.json(),
                )

            results.extend(response.json())
            next_link = response.links.get("next")
            next_url = next_link.get("url") if next_link else None
            request_params = None  # 이후 요청에서는 params를 사용하지 않음

        return results


def _validate_identity(username: Optional[str], org: Optional[str]) -> None:
    if bool(username) == bool(org):
        raise ValueError("username 또는 org 중 하나만 지정해야 합니다.")


def get_container_images(
    *,
    token: str,
    username: Optional[str] = None,
    org: Optional[str] = None,
    session: Optional[requests.Session] = None,
) -> List[str]:
    """GHCR에서 컨테이너 이미지 목록만 반환합니다."""

    _validate_identity(username, org)
    client = GHCRClient(username=username, org=org, token=token, session=session)
    return client.list_images()


def get_container_images_with_tags(
    *,
    token: str,
    username: Optional[str] = None,
    org: Optional[str] = None,
    images: Optional[Iterable[str]] = None,
    session: Optional[requests.Session] = None,
) -> Dict[str, List[List[str]]]:
    """GHCR에서 이미지와 태그 목록(버전별)을 딕셔너리 형태로 반환합니다."""

    _validate_identity(username, org)
    client = GHCRClient(username=username, org=org, token=token, session=session)
    return client.list_images_with_tags(images)


__all__ = [
    "GHCRClient",
    "get_container_images",
    "get_container_images_with_tags",
]

