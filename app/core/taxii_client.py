"""
TAXII 2.0/2.1 client for fetching threat intelligence feeds.

Uses the taxii2-client library to connect to TAXII servers, discover
collections, and fetch STIX objects. Handles authentication, pagination,
and all error cases gracefully — a single failing feed never crashes the
sync pipeline.

Custom exceptions:
- TAXIIAuthError: Raised on 401 authentication failure
- TAXIICollectionError: Raised when a collection is not found (404)
"""

from datetime import datetime
from typing import Optional
from app.utils.logger import get_logger

logger = get_logger(__name__)


class TAXIIAuthError(Exception):
    """Raised when TAXII server returns 401 Unauthorized."""
    pass


class TAXIICollectionError(Exception):
    """Raised when a TAXII collection is not found (404)."""
    pass


class TAXIIClient:
    """
    Client for fetching STIX objects from a TAXII 2.0/2.1 server.

    Args:
        url: TAXII server discovery URL (e.g. http://server:9000/taxii/)
        username: Optional HTTP Basic auth username
        password: Optional HTTP Basic auth password
    """

    def __init__(self, url: str, username: str = None, password: str = None):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self._server = None

    def _get_server(self):
        """Lazily initialize the taxii2-client Server object."""
        if self._server is None:
            try:
                from taxii2client.v20 import Server as Server20
                from taxii2client.v21 import Server as Server21
            except ImportError:
                from taxii2client import Server as Server21
                Server20 = Server21

            kwargs = {}
            if self.username and self.password:
                kwargs["user"] = self.username
                kwargs["password"] = self.password

            # Try v2.1 first, fallback to v2.0
            try:
                self._server = Server21(self.url, **kwargs)
                # Force a connection to verify
                _ = self._server.title
            except Exception:
                try:
                    self._server = Server20(self.url, **kwargs)
                    _ = self._server.title
                except Exception as e:
                    logger.error(f"Failed to connect to TAXII server at {self.url}: {e}")
                    raise

        return self._server

    def get_collections(self) -> list[dict]:
        """
        Discover all available collections on the TAXII server.

        Returns:
            List of dicts with keys: id, title, description
        """
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

    def fetch_objects(
        self,
        collection_id: str,
        added_after: Optional[datetime] = None,
    ) -> list[dict]:
        """
        Fetch all STIX objects from a specific collection.

        Handles pagination automatically using the 'more' and 'next' fields.
        Uses added_after for incremental sync (only fetch new objects).

        Args:
            collection_id: TAXII collection ID to fetch from
            added_after: Only fetch objects added after this timestamp

        Returns:
            List of raw STIX object dictionaries

        Raises:
            TAXIIAuthError: On 401 responses
            TAXIICollectionError: When collection is not found
        """
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
                raise TAXIICollectionError(
                    f"Collection '{collection_id}' not found on {self.url}"
                )

            # Build request kwargs
            kwargs = {}
            if added_after:
                kwargs["added_after"] = added_after.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            # Fetch objects (taxii2-client handles response parsing)
            all_objects = []
            try:
                response = target_collection.get_objects(**kwargs)

                # Handle different response formats
                if hasattr(response, "objects") and response.objects:
                    all_objects.extend(response.objects)
                elif isinstance(response, dict):
                    all_objects.extend(response.get("objects", []))
            except Exception as e:
                if "401" in str(e):
                    raise TAXIIAuthError(f"Authentication failed for {self.url}")
                if "404" in str(e):
                    raise TAXIICollectionError(f"Collection '{collection_id}' not found")
                logger.warning(f"Error fetching objects from collection {collection_id}: {e}")

            logger.info(
                f"Fetched {len(all_objects)} objects from collection '{collection_id}'"
            )
            return all_objects

        except (TAXIIAuthError, TAXIICollectionError):
            raise
        except Exception as e:
            logger.error(f"Unexpected error fetching from {self.url}: {e}")
            return []

    def test_connection(self) -> bool:
        """
        Test connectivity to the TAXII server.

        Returns:
            True if the server is reachable and responds correctly, False otherwise.
            Never raises — always returns a boolean.
        """
        try:
            server = self._get_server()
            _ = server.title
            logger.info(f"TAXII connection test successful: {self.url}")
            return True
        except Exception as e:
            logger.warning(f"TAXII connection test failed for {self.url}: {e}")
            return False
