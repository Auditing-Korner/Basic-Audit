"""HTTP/2 security checks for gRPC services."""

import grpc
from concurrent import futures
from typing import List, Tuple, Any

def check_http2_frame_size(channel: grpc.Channel, target: str) -> List[Tuple[str, str, str, str, str]]:
    """Check for unsafe HTTP/2 frame size configuration."""
    findings = []
    try:
        # Test frame size limits
        large_metadata = [('x-test', 'A' * 16777215)]  # Max frame size
        try:
            response = channel.unary_unary('test')(b'', metadata=large_metadata)
            findings.append((
                "High",
                "Unsafe HTTP/2 frame size",
                "Server accepts maximum HTTP/2 frame size",
                "Configure reasonable HTTP/2 frame size limits",
                "HTTP/2 Security"
            ))
        except Exception:
            pass
    except Exception:
        pass
    return findings

def check_http2_concurrent_streams(channel: grpc.Channel, target: str) -> List[Tuple[str, str, str, str, str]]:
    """Check for unsafe concurrent stream limits."""
    findings = []
    try:
        # Test concurrent streams
        futures_list = []
        with futures.ThreadPoolExecutor(max_workers=1000) as executor:
            for _ in range(1000):
                future = executor.submit(
                    channel.unary_unary('test'),
                    b''
                )
                futures_list.append(future)
            
            success_count = sum(1 for f in futures_list if not f.exception())
            if success_count > 800:  # More than 80% success rate
                findings.append((
                    "Medium",
                    "High concurrent streams allowed",
                    "Server allows high number of concurrent HTTP/2 streams",
                    "Limit maximum concurrent streams",
                    "HTTP/2 Stream Security"
                ))
    except Exception:
        pass
    return findings

def check_http2_hpack_bomb(channel: grpc.Channel, target: str) -> List[Tuple[str, str, str, str, str]]:
    """Check for HPACK bomb vulnerability."""
    findings = []
    try:
        # Test HPACK bomb
        headers = []
        for i in range(4096):  # Large number of unique headers
            headers.append((f'x-custom-{i}', 'A' * 1024))  # 1KB value per header
        
        try:
            response = channel.unary_unary('test')(b'', metadata=headers)
            findings.append((
                "High",
                "HPACK bomb vulnerability",
                "Server vulnerable to HTTP/2 HPACK bomb attacks",
                "Implement strict header size and count limits",
                "HTTP/2 HPACK Security"
            ))
        except Exception:
            pass
    except Exception:
        pass
    return findings

def check_http2_settings_security(target: str, port: int) -> List[Tuple[str, str, str, str, str]]:
    """Run all HTTP/2 security checks."""
    findings = []
    try:
        http2_options = [
            ('grpc.http2.max_frame_size', 16777215),  # Max possible frame size
            ('grpc.http2.max_concurrent_streams', 1000),  # High concurrent streams
            ('grpc.http2.max_header_list_size', 8192),  # Small header list size
            ('grpc.http2.enable_push', 1)  # Enable server push
        ]

        channel = grpc.insecure_channel(
            f"{target}:{port}",
            options=http2_options
        )

        findings.extend(check_http2_frame_size(channel, target))
        findings.extend(check_http2_concurrent_streams(channel, target))
        findings.extend(check_http2_hpack_bomb(channel, target))

    except Exception:
        pass

    return findings 