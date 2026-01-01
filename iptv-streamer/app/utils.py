# app/utils.py
import requests
from flask import Response, stream_with_context
import logging

logger = logging.getLogger(__name__)

def is_stream_healthy(url, timeout=5):
    try:
        if url.startswith(('http://', 'https://')):
            resp = requests.head(url, timeout=timeout, allow_redirects=True)
            return resp.status_code == 200
        return True  # Can't check RTMP/UDP easily
    except Exception as e:
        logger.debug(f"Health check failed for {url}: {e}")
        return False

def proxy_stream(url):
    """Proxy the stream to handle CORS, headers, and direct playback."""
    try:
        resp = requests.get(url, stream=True, timeout=10)
        if resp.status_code != 200:
            logger.warning(f"Upstream returned {resp.status_code}")
            return None

        def generate():
            for chunk in resp.iter_content(chunk_size=8192):
                yield chunk

        return Response(
            stream_with_context(generate()),
            content_type=resp.headers.get('content-type', 'video/mp2t'),
            status=resp.status_code,
            headers={
                'Cache-Control': 'no-cache',
                'Access-Control-Allow-Origin': '*',
                'Connection': 'keep-alive',
            }
        )
    except Exception as e:
        logger.error(f"Proxy error for {url}: {e}")
        return None
