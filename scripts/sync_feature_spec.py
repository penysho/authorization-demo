#!/usr/bin/env python3
"""
Sync feature spec from Google Drive to local directory

This script downloads Google Docs from a specified folder and converts them to Markdown format.
The downloaded files are saved to the docs/feature-spec directory.

Usage:
    python scripts/sync_feature_spec.py
"""

import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

from dotenv import find_dotenv, load_dotenv
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Configuration constants
GOOGLE_DRIVE_FOLDER_URL = os.getenv("GOOGLE_DRIVE_FOLDER_URL", "")
CREDENTIALS_FILE = os.getenv("GOOGLE_CREDENTIALS_FILE", "credentials.json")
TOKEN_FILE = os.getenv("GOOGLE_TOKEN_FILE", "token.json")
OUTPUT_DIR = Path("../docs/feature-spec")
SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]

# MIME types
GOOGLE_DOCS_MIME_TYPE = "application/vnd.google-apps.document"
FOLDER_MIME_TYPE = "application/vnd.google-apps.folder"
EXPORT_MIME_TYPE = "text/markdown"  # Export directly as Markdown


class GoogleDocsDownloader:
    """
    Downloads Google Docs from a specified folder and converts them to Markdown format.
    """

    def __init__(self):
        """Initialize the downloader with Google API credentials."""
        self.drive_service = None
        self._authenticate()

    def _authenticate(self) -> None:
        """
        Authenticate with Google APIs using OAuth2.

        Raises:
            Exception: If authentication fails
        """
        creds = None

        # Load existing token if available
        if os.path.exists(TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

        # If there are no valid credentials, request authorization
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(CREDENTIALS_FILE):
                    raise FileNotFoundError(
                        f"Credentials file not found: {CREDENTIALS_FILE}\n"
                        "Please download credentials.json from Google Cloud Console"
                    )

                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)

            # Save credentials for next run
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())

        # Build service object
        self.drive_service = build('drive', 'v3', credentials=creds)

    def _extract_folder_id(self, folder_url: str) -> str:
        """
        Extract folder ID from Google Drive folder URL.

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

    def _get_folder_contents(self, folder_id: str) -> List[Dict[str, Any]]:
        """
        Get all files and folders within a specified folder.

        Args:
            folder_id: Google Drive folder ID

        Returns:
            List of file/folder metadata
        """
        try:
            results = self.drive_service.files().list(
                q=f"'{folder_id}' in parents and trashed=false",
                fields="files(id,name,mimeType,parents)"
            ).execute()

            return results.get('files', [])
        except HttpError as error:
            print(f"Error getting folder contents: {error}")
            return []

    def _get_docs_recursively(self, folder_id: str, path_prefix: str = "") -> List[Dict[str, Any]]:
        """
        Recursively get all Google Docs from a folder and its subfolders.

        Args:
            folder_id: Google Drive folder ID
            path_prefix: Path prefix for nested folders

        Returns:
            List of Google Docs metadata with file paths
        """
        docs = []
        contents = self._get_folder_contents(folder_id)

        for item in contents:
            item_name = item['name']
            item_path = f"{path_prefix}/{item_name}" if path_prefix else item_name

            if item['mimeType'] == GOOGLE_DOCS_MIME_TYPE:
                docs.append({
                    'id': item['id'],
                    'name': item_name,
                    'path': item_path
                })
            elif item['mimeType'] == FOLDER_MIME_TYPE:
                # Recursively get docs from subfolder
                subdocs = self._get_docs_recursively(item['id'], item_path)
                docs.extend(subdocs)

        return docs

    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename for filesystem.

        Args:
            filename: Original filename

        Returns:
            Sanitized filename safe for filesystem
        """
        # Remove or replace invalid characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Remove leading/trailing spaces and dots
        sanitized = sanitized.strip(' .')
        # Ensure it's not empty
        if not sanitized:
            sanitized = "unnamed_document"

        return sanitized

    def _export_doc_as_markdown(self, doc_id: str, file_path: str) -> bool:
        """
        Export a Google Doc as Markdown format using Drive API export.

        Args:
            doc_id: Google Docs document ID
            file_path: Local file path to save the document

        Returns:
            True if successful, False otherwise
        """
        try:
            # Export document directly as Markdown using Drive API
            export_response = self.drive_service.files().export(
                fileId=doc_id,
                mimeType=EXPORT_MIME_TYPE
            ).execute()

            # Decode the Markdown content
            markdown_content = export_response.decode('utf-8')

            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Write content to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(markdown_content)

            print(f"Exported as Markdown: {file_path}")
            return True

        except HttpError as error:
            print(f"Error exporting document {doc_id}: {error}")
            return False
        except Exception as error:
            print(f"Error processing document {doc_id}: {error}")
            return False

    def download_all_docs(self) -> None:
        """
        Download all Google Docs from the configured folder to the output directory.
        """
        try:
            # Extract folder ID from URL
            folder_id = self._extract_folder_id(GOOGLE_DRIVE_FOLDER_URL)
            print(f"Downloading documents from folder ID: {folder_id}")

            # Get all docs recursively
            docs = self._get_docs_recursively(folder_id)
            print(f"Found {len(docs)} Google Docs")

            if not docs:
                print("No Google Docs found in the specified folder")
                return

            # Download each document
            success_count = 0
            for doc in docs:
                # Create file path
                sanitized_name = self._sanitize_filename(doc['name'])
                if not sanitized_name.endswith('.md'):
                    sanitized_name += '.md'

                # Handle nested folders
                relative_path = doc['path'].replace(doc['name'], sanitized_name)
                file_path = OUTPUT_DIR / relative_path

                # Export document as Markdown
                if self._export_doc_as_markdown(doc['id'], str(file_path)):
                    success_count += 1

            print(f"\nDownload completed: {success_count}/{len(docs)} documents "
                  f"successfully downloaded")

        except Exception as error:
            print(f"Error during download process: {error}")
            sys.exit(1)


def main():
    """Main entry point for the script."""
    # Load environment variables from .env file
    dotenv_path = find_dotenv()
    if dotenv_path:
        load_dotenv(dotenv_path)
    else:
        print("No .env file found. Please create one with GOOGLE_DRIVE_FOLDER_URL")

    # Re-read environment variables after loading .env
    global GOOGLE_DRIVE_FOLDER_URL
    GOOGLE_DRIVE_FOLDER_URL = os.getenv("GOOGLE_DRIVE_FOLDER_URL", "")

    # Validate required environment variables
    if not GOOGLE_DRIVE_FOLDER_URL:
        print("Error: GOOGLE_DRIVE_FOLDER_URL environment variable is required")
        print("Please set it in your .env file or environment")
        sys.exit(1)

    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Initialize and run downloader
    downloader = GoogleDocsDownloader()
    downloader.download_all_docs()


if __name__ == "__main__":
    main()
