"""Shared S3/Azure Blob/GCS upload, download and signed-URL logic.

Mirrors llm_client.py's pattern: one backend selected by STORAGE_BACKEND
("s3", default, "azure-blob", or "gcs"), so publish_reports.py and
fetch_previous_scan.py don't duplicate the client setup for each cloud.
"""
import os
from datetime import datetime, timedelta, timezone


def backend_name() -> str:
    return os.environ.get("STORAGE_BACKEND", "s3")


def upload(local_path: str, key: str, content_type: str) -> None:
    name = backend_name()
    if name == "s3":
        _upload_s3(local_path, key, content_type)
    elif name == "azure-blob":
        _upload_azure_blob(local_path, key, content_type)
    elif name == "gcs":
        _upload_gcs(local_path, key, content_type)
    else:
        raise ValueError(f"unknown STORAGE_BACKEND: {name}")


def download(key: str, local_path: str) -> bool:
    """Downloads `key` to `local_path`. Returns False (no exception) if the
    object doesn't exist -- the normal case for "first scan, no history yet"."""
    name = backend_name()
    if name == "s3":
        return _download_s3(key, local_path)
    if name == "azure-blob":
        return _download_azure_blob(key, local_path)
    if name == "gcs":
        return _download_gcs(key, local_path)
    raise ValueError(f"unknown STORAGE_BACKEND: {name}")


def signed_url(key: str, expiry_seconds: int) -> str:
    name = backend_name()
    if name == "s3":
        return _signed_url_s3(key, expiry_seconds)
    if name == "azure-blob":
        return _signed_url_azure_blob(key, expiry_seconds)
    if name == "gcs":
        return _signed_url_gcs(key, expiry_seconds)
    raise ValueError(f"unknown STORAGE_BACKEND: {name}")


# --- S3 ---------------------------------------------------------------

def _s3_client():
    import boto3

    return boto3.client("s3")


def _upload_s3(local_path: str, key: str, content_type: str) -> None:
    bucket = os.environ["S3_REPORTS_BUCKET"]
    _s3_client().upload_file(local_path, bucket, key, ExtraArgs={"ContentType": content_type})


def _download_s3(key: str, local_path: str) -> bool:
    import botocore

    bucket = os.environ["S3_REPORTS_BUCKET"]
    try:
        _s3_client().download_file(bucket, key, local_path)
        return True
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return False
        raise


def _signed_url_s3(key: str, expiry_seconds: int) -> str:
    bucket = os.environ["S3_REPORTS_BUCKET"]
    return _s3_client().generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=expiry_seconds
    )


# --- Azure Blob ---------------------------------------------------------

def _blob_service_client():
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient

    account = os.environ["AZURE_STORAGE_ACCOUNT"]
    account_url = f"https://{account}.blob.core.windows.net"
    return BlobServiceClient(account_url, credential=DefaultAzureCredential())


def _container_name() -> str:
    # See publish_reports.py's _expiry_seconds() comment: an unset GH Actions
    # `vars.*` arrives as an empty string, not an absent env var, so `.get()`
    # alone won't fall back -- `or` is required.
    return os.environ.get("AZURE_STORAGE_CONTAINER") or "reports"


def _upload_azure_blob(local_path: str, key: str, content_type: str) -> None:
    client = _blob_service_client().get_blob_client(_container_name(), key)
    with open(local_path, "rb") as f:
        client.upload_blob(f, overwrite=True, content_type=content_type)


def _download_azure_blob(key: str, local_path: str) -> bool:
    from azure.core.exceptions import ResourceNotFoundError

    client = _blob_service_client().get_blob_client(_container_name(), key)
    try:
        with open(local_path, "wb") as f:
            f.write(client.download_blob().readall())
        return True
    except ResourceNotFoundError:
        os.remove(local_path)
        return False


def _signed_url_azure_blob(key: str, expiry_seconds: int) -> str:
    from azure.storage.blob import BlobSasPermissions, generate_blob_sas

    account = os.environ["AZURE_STORAGE_ACCOUNT"]
    container = _container_name()
    service_client = _blob_service_client()
    key_start = datetime.now(timezone.utc)
    key_expiry = key_start + timedelta(seconds=expiry_seconds)
    delegation_key = service_client.get_user_delegation_key(key_start, key_expiry)
    sas = generate_blob_sas(
        account_name=account,
        container_name=container,
        blob_name=key,
        user_delegation_key=delegation_key,
        permission=BlobSasPermissions(read=True),
        expiry=key_expiry,
    )
    return f"https://{account}.blob.core.windows.net/{container}/{key}?{sas}"


# --- GCS ------------------------------------------------------------------

def _gcs_bucket():
    from google.cloud import storage

    bucket_name = os.environ["GCS_REPORTS_BUCKET"]
    return storage.Client().bucket(bucket_name)


def _upload_gcs(local_path: str, key: str, content_type: str) -> None:
    blob = _gcs_bucket().blob(key)
    blob.upload_from_filename(local_path, content_type=content_type)


def _download_gcs(key: str, local_path: str) -> bool:
    from google.cloud.exceptions import NotFound

    blob = _gcs_bucket().blob(key)
    try:
        blob.download_to_filename(local_path)
        return True
    except NotFound:
        # Confirmed for real on 2026-09-08: unlike S3/Blob (which open the
        # destination file for writing before the request, so it exists,
        # empty, on a 404), GCS's download_to_filename never creates the
        # local file at all if the object is missing -- os.remove() here
        # would raise FileNotFoundError on the very first scan for a
        # project (the expected "no history yet" case, not an error).
        if os.path.exists(local_path):
            os.remove(local_path)
        return False


def _signed_url_gcs(key: str, expiry_seconds: int) -> str:
    # GCS V4 signed URLs need something that can sign bytes -- this identity
    # only ever has short-lived Workload Identity Federation credentials, no
    # private key to sign with locally. Wrapping in a self-impersonated
    # credential (infra/gcp grants roles/iam.serviceAccountTokenCreator on
    # the service account to itself for exactly this) routes the signing
    # through the IAM Credentials API's signBlob instead -- the GCP
    # equivalent of Azure's user-delegation SAS key.
    import google.auth
    from google.auth import impersonated_credentials

    credentials, _ = google.auth.default()
    signing_credentials = impersonated_credentials.Credentials(
        source_credentials=credentials,
        target_principal=os.environ["GCP_SERVICE_ACCOUNT_EMAIL"],
        target_scopes=[],
    )
    blob = _gcs_bucket().blob(key)
    return blob.generate_signed_url(
        version="v4", expiration=timedelta(seconds=expiry_seconds), credentials=signing_credentials
    )
