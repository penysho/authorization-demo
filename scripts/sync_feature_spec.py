#!/usr/bin/env python3
"""Sync feature spec from Google Drive to local directory.

This script downloads Google Docs from a specified folder and converts them to Markdown format.
The downloaded files are saved to the docs/feature-spec directory.

Usage:
    python scripts/sync_feature_spec.py
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import parse_qs, urlparse

from dotenv import dotenv_values, find_dotenv, load_dotenv
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""


class GoogleDriveError(Exception):
    """Raised when Google Drive API operations fail."""


@dataclass(frozen=True)
class Configuration:
    """Configuration settings for Google Drive sync operation.

    Attributes:
        folder_url: Google Drive folder URL to sync from
        credentials_file: Path to Google API credentials JSON file
        token_file: Path to store OAuth2 token
        output_dir: Local directory to save downloaded documents
        scopes: Google API scopes required for the operation
        export_mime_type: MIME type for document export
    """

    folder_url: str
    credentials_file: str
    token_file: str
    output_dir: Path
    scopes: list[str]
    export_mime_type: str


def load_configuration() -> Configuration:
    """Load and validate configuration from environment variables.

    Returns:
        Configuration dataclass with validated configuration values

    Raises:
        ConfigurationError: If required configuration is missing or invalid
    """
    # Load from .env file if it exists
    dotenv_path = find_dotenv()
    if dotenv_path:
        load_dotenv(dotenv_path)

    # Use dotenv_values for better configuration management
    env_config = dotenv_values(dotenv_path) if dotenv_path else {}

    # Override with actual environment variables
    config = {
        **env_config,
        **{k: v for k, v in os.environ.items() if k.startswith(("GOOGLE_", "OUTPUT_"))},
    }

    # Validate required configuration
    folder_url = config.get("GOOGLE_DRIVE_FOLDER_URL", "")
    if not folder_url:
        raise ConfigurationError(
            "GOOGLE_DRIVE_FOLDER_URL environment variable is required. "
            "Please set it in your .env file or environment"
        )

    return Configuration(
        folder_url=folder_url,
        credentials_file=config.get("GOOGLE_CREDENTIALS_FILE", "credentials.json"),
        token_file=config.get("GOOGLE_TOKEN_FILE", "token.json"),
        output_dir=Path(config.get("OUTPUT_DIR", "../docs/feature-spec")),
        scopes=["https://www.googleapis.com/auth/drive.readonly"],
        export_mime_type="text/markdown",
    )


class GoogleDocsDownloader:
    """Downloads Google Docs from a specified folder and converts them to Markdown format.

    This class handles Google Drive API authentication, folder traversal,
    and document export with comprehensive error handling.
    """

    def __init__(self, config: Configuration):
        """Initialize the downloader with configuration.

        Args:
            config: Configuration dataclass from load_configuration()

        Raises:
            GoogleDriveError: If authentication fails
        """
        self.config = config
        self.drive_service = None
        self._authenticate()

    def _authenticate(self) -> None:
        """Authenticate with Google APIs using OAuth2.

        Uses modern Google Auth practices with proper error handling.

        Raises:
            GoogleDriveError: If authentication fails
        """
        creds = None
        token_file = Path(self.config.token_file)
        credentials_file = Path(self.config.credentials_file)

        # Load existing token if available
        if token_file.exists():
            try:
                creds = Credentials.from_authorized_user_file(
                    str(token_file), self.config.scopes
                )
            except Exception as e:
                raise GoogleDriveError(
                    f"Failed to load existing credentials: {e}"
                ) from e

        # If there are no valid credentials, request authorization
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except Exception as e:
                    raise GoogleDriveError(f"Failed to refresh credentials: {e}") from e
            else:
                if not credentials_file.exists():
                    raise GoogleDriveError(
                        f"Credentials file not found: {credentials_file}\n"
                        "Please download credentials.json from Google Cloud Console"
                    )

                try:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        str(credentials_file), self.config.scopes
                    )
                    creds = flow.run_local_server(port=0)
                except Exception as e:
                    raise GoogleDriveError(f"OAuth flow failed: {e}") from e

            # Save credentials for next run
            try:
                token_file.write_text(creds.to_json(), encoding="utf-8")
            except OSError as e:
                raise GoogleDriveError(f"Failed to save credentials: {e}") from e

        # Build service object with proper error handling
        try:
            self.drive_service = build("drive", "v3", credentials=creds)
        except Exception as e:
            raise GoogleDriveError(f"Failed to build Drive service: {e}") from e

    def _extract_folder_id(self, folder_url: str) -> str:
        """Extract folder ID from Google Drive folder URL.

        Args:
            folder_url: Google Drive folder URL

        Returns:
            Folder ID extracted from URL

        Raises:
            ValueError: If URL format is invalid
        """
        if not folder_url:
            raise ValueError("Folder URL is empty")

        # Handle different URL formats
        if "/folders/" in folder_url:
            return folder_url.split("/folders/")[1].split("?")[0]
        elif "id=" in folder_url:
            parsed = urlparse(folder_url)
            query_params = parse_qs(parsed.query)
            if "id" in query_params:
                return query_params["id"][0]

        raise ValueError(f"Invalid Google Drive folder URL: {folder_url}")

    def _get_folder_contents(self, folder_id: str) -> list[dict[str, Any]]:
        """Get all files and folders within a specified folder.

        Args:
            folder_id: Google Drive folder ID

        Returns:
            List of file/folder metadata

        Raises:
            GoogleDriveError: If API call fails
        """
        try:
            results = (
                self.drive_service.files()
                .list(
                    q=f"'{folder_id}' in parents and trashed=false",
                    fields="files(id,name,mimeType,parents)",
                )
                .execute()
            )
            return results.get("files", [])
        except HttpError as error:
            # Modern error handling for Google API client
            error_details = getattr(error, "error_details", "Unknown error")
            raise GoogleDriveError(
                f"Failed to get folder contents (status: {error.status_code}): {error_details}"
            ) from error
        except Exception as error:
            raise GoogleDriveError(
                f"Unexpected error getting folder contents: {error}"
            ) from error

    def _get_docs_recursively(
        self, folder_id: str, path_prefix: str = ""
    ) -> list[dict[str, Any]]:
        """Recursively get all Google Docs from a folder and its subfolders.

        Args:
            folder_id: Google Drive folder ID
            path_prefix: Path prefix for nested folders

        Returns:
            List of Google Docs metadata with file paths
        """
        docs = []
        contents = self._get_folder_contents(folder_id)

        for item in contents:
            item_name = item["name"]
            item_path = f"{path_prefix}/{item_name}" if path_prefix else item_name

            if item["mimeType"] == "application/vnd.google-apps.document":
                docs.append({"id": item["id"], "name": item_name, "path": item_path})
            elif item["mimeType"] == "application/vnd.google-apps.folder":
                # Recursively get docs from subfolder
                subdocs = self._get_docs_recursively(item["id"], item_path)
                docs.extend(subdocs)

        return docs

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for filesystem using modern approach.

        Args:
            filename: Original filename

        Returns:
            Sanitized filename safe for filesystem
        """
        # Remove or replace invalid characters
        sanitized = re.sub(r'[<>:"/\\|?*]', "_", filename)
        # Remove leading/trailing spaces and dots
        sanitized = sanitized.strip(" .")
        # Ensure it's not empty
        if not sanitized:
            sanitized = "unnamed_document"

        return sanitized

    def _export_doc_as_markdown(self, doc_id: str, file_path: Path) -> bool:
        """Export a Google Doc as Markdown format using Drive API export.

        Args:
            doc_id: Google Docs document ID
            file_path: Local file path to save the document

        Returns:
            True if successful, False otherwise
        """
        try:
            # Export document directly as Markdown using Drive API
            export_response = (
                self.drive_service.files()
                .export(fileId=doc_id, mimeType=self.config.export_mime_type)
                .execute()
            )

            # Decode the Markdown content
            markdown_content = export_response.decode("utf-8")

            # Create directory if it doesn't exist using modern pathlib
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # Write content to file with proper encoding
            file_path.write_text(markdown_content, encoding="utf-8")

            print(f"Exported as Markdown: {file_path}")
            return True

        except HttpError as error:
            error_details = getattr(error, "error_details", "Unknown error")
            print(
                f"Error exporting document {doc_id} (status: {error.status_code}): {error_details}"
            )
            return False
        except OSError as error:
            print(f"File system error for document {doc_id}: {error}")
            return False
        except Exception as error:
            print(f"Unexpected error processing document {doc_id}: {error}")
            return False

    def download_all_docs(self) -> None:
        """Download all Google Docs from the configured folder to the output directory.

        Raises:
            GoogleDriveError: If download process fails
        """
        try:
            # Extract folder ID from URL
            folder_id = self._extract_folder_id(self.config.folder_url)
            print(f"Downloading documents from folder ID: {folder_id}")

            # Get all docs recursively
            docs = self._get_docs_recursively(folder_id)
            print(f"Found {len(docs)} Google Docs")

            if not docs:
                print("No Google Docs found in the specified folder")
                return

            # Create output directory using modern pathlib
            output_dir = self.config.output_dir
            output_dir.mkdir(parents=True, exist_ok=True)

            # Download each document
            success_count = 0
            for doc in docs:
                # Create file path using modern pathlib
                sanitized_name = self._sanitize_filename(doc["name"])
                if not sanitized_name.endswith(".md"):
                    sanitized_name += ".md"

                # Handle nested folders
                relative_path = doc["path"].replace(doc["name"], sanitized_name)
                file_path = output_dir / relative_path

                # Export document as Markdown
                if self._export_doc_as_markdown(doc["id"], file_path):
                    success_count += 1

            print(
                f"\nDownload completed: {success_count}/{len(docs)} documents "
                f"successfully downloaded"
            )

        except ValueError as error:
            raise GoogleDriveError(f"Invalid configuration: {error}") from error
        except Exception as error:
            raise GoogleDriveError(f"Download process failed: {error}") from error


def main() -> None:
    """Main entry point for the script."""
    try:
        # Load and validate configuration
        config = load_configuration()

        # Initialize and run downloader
        downloader = GoogleDocsDownloader(config)
        downloader.download_all_docs()

    except ConfigurationError as error:
        print(f"Configuration error: {error}")
        sys.exit(1)
    except GoogleDriveError as error:
        print(f"Google Drive error: {error}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as error:
        print(f"Unexpected error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
