"""S3 invoice storage service."""
import boto3
from botocore.exceptions import ClientError

from src.core.config import settings

_s3 = boto3.client(
    "s3",
    aws_access_key_id=settings.aws_access_key_id,
    aws_secret_access_key=settings.aws_secret_access_key,
)


def upload_invoice_pdf(invoice_id: str, pdf_bytes: bytes) -> str:
    key = f"invoices/{invoice_id}.pdf"
    _s3.put_object(
        Bucket=settings.s3_bucket,
        Key=key,
        Body=pdf_bytes,
        ContentType="application/pdf",
        ServerSideEncryption="AES256",
    )
    return key


def get_invoice_download_url(s3_key: str, expires_in: int = 3600) -> str:
    return _s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": settings.s3_bucket, "Key": s3_key},
        ExpiresIn=expires_in,
    )


def delete_invoice(s3_key: str) -> bool:
    try:
        _s3.delete_object(Bucket=settings.s3_bucket, Key=s3_key)
        return True
    except ClientError:
        return False
