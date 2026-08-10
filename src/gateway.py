import asyncio
import json
import os
import re
import time
import urllib.parse
from datetime import datetime, timezone
from azure.storage.blob.aio import BlobServiceClient

BACKEND_HOST = "10.0.2.4"
BACKEND_PORT = 8080
GATEWAY_PORT = 8080
CONTAINER_NAME = "threat-logs"
BLOB_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

DPI_PATTERNS = [
    re.compile(r"(?i)('\s*OR\s*'1'\s*=\s*'1|UNION\s+SELECT|SELECT\s+.*\s+FROM|DROP\s+TABLE)"),
    re.compile(r"(?i)(<script>|javascript:|onerror\s*=|<iframe)"),
    re.compile(r"(?i)(sqlmap|nikto|nmap|gobuster|dirbuster)"),
]

rate_limit_store = {}


def is_rate_limited(client_ip):
    now = time.time()
    if client_ip not in rate_limit_store:
        rate_limit_store[client_ip] = []

    rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if now - t < 10]

    if len(rate_limit_store[client_ip]) >= 10:
        return True

    rate_limit_store[client_ip].append(now)
    return False


def inspect_payload(payload_str):
    for pattern in DPI_PATTERNS:
        if pattern.search(payload_str):
            return True, pattern.pattern
    return False, None


async def log_threat_to_azure(log_data):
    if not BLOB_CONNECTION_STRING:
        print("[-] Azure Storage connection string not configured.")
        return

    try:
        blob_service_client = BlobServiceClient.from_connection_string(BLOB_CONNECTION_STRING)
        async with blob_service_client:
            container_client = blob_service_client.get_container_client(CONTAINER_NAME)
            blob_name = f"threat_{int(time.time())}_{log_data['client_ip']}.json"
            blob_client = container_client.get_blob_client(blob_name)
            await blob_client.upload_blob(json.dumps(log_data), overwrite=True)
            print(f"[+] Offloaded threat log to Azure Blob Storage: {blob_name}")
    except Exception as e:
        print(f"[-] Failed to upload telemetry: {e}")


async def handle_client(reader, writer):
    client_addr = writer.get_extra_info("peername")
    client_ip = client_addr[0] if client_addr else "UNKNOWN"

    if is_rate_limited(client_ip):
        print(f"[BLOCKED] Rate limit exceeded for IP: {client_ip}")
        writer.write(b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\r\nRate limit exceeded.\n")
        await writer.drain()
        writer.close()
        return

    data = await reader.read(4096)
    payload = data.decode("utf-8", errors="ignore")
    decoded_payload = urllib.parse.unquote_plus(payload)

    is_malicious, signature = inspect_payload(decoded_payload)
    if is_malicious:
        print(f"[ALERT] Threat detected from {client_ip} | Signature matched: {signature}")
        writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by Cloud Gateway DPI Engine.\n")
        await writer.drain()
        writer.close()

        threat_log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": client_ip,
            "matched_pattern": signature,
            "raw_payload": payload[:500],
        }
        asyncio.create_task(log_threat_to_azure(threat_log))
        return

    try:
        backend_reader, backend_writer = await asyncio.open_connection(BACKEND_HOST, BACKEND_PORT)
        backend_writer.write(data)
        await backend_writer.drain()

        response = await backend_reader.read(4096)
        writer.write(response)
        await backend_writer.drain()

        backend_writer.close()
        print(f"[FORWARDED] Clean request from {client_ip} -> {BACKEND_HOST}:{BACKEND_PORT}")
    except Exception as e:
        print(f"[-] Proxy Error: {e}")
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\nGateway Error.\n")
        await writer.drain()

    writer.close()


async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", GATEWAY_PORT)
    print(f"[*] Cloud Gateway DPI Engine active on port {GATEWAY_PORT}...")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())