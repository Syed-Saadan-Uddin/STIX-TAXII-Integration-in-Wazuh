"""
TAXII 2.0/2.1 client for fetching threat intelligence feeds.
"""

from datetime import datetime
from typing import Optional
from app.utils.logger import get_logger

logger = get_logger(__name__)


class TAXIIAuthError(Exception):
    pass


class TAXIICollectionError(Exception):
    pass


class TAXIIClient:
    def __init__(self, url: str, username: str = None, password: str = None):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self._server = None

    def _get_server(self):
        if self._server is None:
            try:
                from taxii2client.v21 import Server as Server21
            except ImportError:
                from taxii2client import Server as Server21

            kwargs = {}
            if self.username and self.password:
                kwargs["user"] = self.username
                kwargs["password"] = self.password

            try:
                self._server = Server21(self.url, **kwargs)
                _ = self._server.title
            except Exception as e:
                logger.error(f"Failed to connect to TAXII server at {self.url}: {e}")
                raise

        return self._server

    def get_collections(self) -> list:
        try:
            server = self._get_server()
            collections = []
            for api_root in server.api_roots:
                for collection in api_root.collections:
                    collections.append({
                        "id": collection.id,
                        "title": getattr(collection, "title", ""),
                        "description": getattr(collection, "description", ""),
                    })
            logger.info(f"Discovered {len(collections)} collections from {self.url}")
            return collections
        except Exception as e:
            if "401" in str(e):
                raise TAXIIAuthError(f"Authentication failed for {self.url}")
            logger.error(f"Error discovering collections: {e}")
            return []

    def fetch_objects(self, collection_id: str, added_after: Optional[datetime] = None) -> list:
        import requests

        try:
            server = self._get_server()
            target_collection = None

            for api_root in server.api_roots:
                for collection in api_root.collections:
                    if collection.id == collection_id:
                        target_collection = collection
                        break
                if target_collection:
                    break

            if target_collection is None:
                raise TAXIICollectionError(f"Collection '{collection_id}' not found on {self.url}")

            # Build URL for raw HTTP fetch
            raw_url = f"{self.url}/api-root/collections/{collection_id}/objects/"
            headers = {"Accept": "application/taxii+json;version=2.1"}
            params = {}
            if added_after:
                params["added_after"] = added_after.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)

            resp = requests.get(raw_url, headers=headers, params=params, auth=auth, timeout=30)

            if resp.status_code == 401:
                raise TAXIIAuthError(f"Authentication failed for {self.url}")
            if resp.status_code == 404:
                raise TAXIICollectionError(f"Collection '{collection_id}' not found")

            resp.raise_for_status()
            all_objects = resp.json().get("objects", [])

            logger.info(f"Fetched {len(all_objects)} objects from collection '{collection_id}'")
            return all_objects

        except (TAXIIAuthError, TAXIICollectionError):
            raise
        except Exception as e:
            logger.error(f"Unexpected error fetching from {self.url}: {e}")
            return []

    def test_connection(self) -> bool:
        try:
            server = self._get_server()
            _ = server.title
            logger.info(f"TAXII connection test successful: {self.url}")
            return True
        except Exception as e:
            logger.warning(f"TAXII connection test failed for {self.url}: {e}")
            return False
