"""
Rate limiting middleware for API endpoints and WebSocket connections
"""
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Optional
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimiter:
    """
    Token bucket rate limiter with configurable limits
    """
    
    def __init__(self, requests_per_minute: int = 60, burst_size: int = 10):
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.refill_rate = requests_per_minute / 60.0  # tokens per second
        
        # Store buckets: {identifier: {'tokens': float, 'last_update': float}}
        self.buckets: Dict[str, dict] = {}
        
    def _get_bucket(self, identifier: str) -> dict:
        """Get or create a token bucket for an identifier"""
        if identifier not in self.buckets:
            self.buckets[identifier] = {
                'tokens': self.burst_size,
                'last_update': time.time()
            }
        return self.buckets[identifier]
    
    def _refill_tokens(self, bucket: dict) -> None:
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - bucket['last_update']
        
        # Add tokens based on elapsed time
        bucket['tokens'] = min(
            self.burst_size,
            bucket['tokens'] + (elapsed * self.refill_rate)
        )
        bucket['last_update'] = now
    
    def is_allowed(self, identifier: str, cost: float = 1.0) -> bool:
        """
        Check if request is allowed and consume tokens
        
        Args:
            identifier: Unique identifier (IP, username, etc.)
            cost: Number of tokens to consume (default 1.0)
            
        Returns:
            True if request is allowed, False otherwise
        """
        bucket = self._get_bucket(identifier)
        self._refill_tokens(bucket)
        
        if bucket['tokens'] >= cost:
            bucket['tokens'] -= cost
            return True
        
        return False
    
    def cleanup_old_buckets(self, max_age_seconds: int = 3600):
        """Remove buckets that haven't been used recently"""
        now = time.time()
        to_remove = [
            identifier for identifier, bucket in self.buckets.items()
            if now - bucket['last_update'] > max_age_seconds
        ]
        for identifier in to_remove:
            del self.buckets[identifier]


class LoginRateLimiter:
    """
    Specialized rate limiter for login attempts with exponential backoff
    """
    
    def __init__(self):
        # Store failed attempts: {identifier: [timestamp1, timestamp2, ...]}
        self.failed_attempts: Dict[str, list] = defaultdict(list)
        self.lockout_duration = 300  # 5 minutes lockout after too many failures
        
    def record_failed_attempt(self, identifier: str) -> None:
        """Record a failed login attempt"""
        now = datetime.utcnow()
        
        # Clean old attempts (older than 1 hour)
        cutoff = now - timedelta(hours=1)
        self.failed_attempts[identifier] = [
            ts for ts in self.failed_attempts[identifier]
            if ts > cutoff
        ]
        
        # Add new attempt
        self.failed_attempts[identifier].append(now)
    
    def is_locked_out(self, identifier: str) -> bool:
        """Check if identifier is locked out due to too many failures"""
        if identifier not in self.failed_attempts:
            return False
        
        attempts = self.failed_attempts[identifier]
        
        # Check if locked out (5+ failures in last 5 minutes)
        recent_cutoff = datetime.utcnow() - timedelta(seconds=self.lockout_duration)
        recent_failures = [ts for ts in attempts if ts > recent_cutoff]
        
        return len(recent_failures) >= 5
    
    def clear_attempts(self, identifier: str) -> None:
        """Clear failed attempts after successful login"""
        if identifier in self.failed_attempts:
            del self.failed_attempts[identifier]
    
    def get_wait_time(self, identifier: str) -> Optional[int]:
        """Get seconds to wait before next attempt"""
        if not self.is_locked_out(identifier):
            return None
        
        attempts = self.failed_attempts[identifier]
        if not attempts:
            return None
        
        last_attempt = max(attempts)
        unlock_time = last_attempt + timedelta(seconds=self.lockout_duration)
        remaining = (unlock_time - datetime.utcnow()).total_seconds()
        
        return max(0, int(remaining))


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware to apply rate limiting to API endpoints
    """
    
    def __init__(self, app):
        super().__init__(app)
        
        # Different rate limits for different endpoint types
        self.api_limiter = RateLimiter(requests_per_minute=60, burst_size=20)
        self.login_limiter = LoginRateLimiter()
        
        # Endpoints that should bypass rate limiting (health checks, etc.)
        self.exempt_paths = {'/health', '/system-status'}
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for exempt paths
        if request.url.path in self.exempt_paths:
            return await call_next(request)
        
        # Get client identifier (IP address)
        client_ip = request.client.host if request.client else "unknown"
        
        # Check rate limit
        if not self.api_limiter.is_allowed(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later.",
                headers={"Retry-After": "60"}
            )
        
        # Process request
        response = await call_next(request)
        
        # Cleanup old buckets periodically (1% chance per request)
        import random
        if random.random() < 0.01:
            self.api_limiter.cleanup_old_buckets()
        
        return response


class WebSocketRateLimiter:
    """
    Rate limiter for WebSocket messages
    """
    
    def __init__(self):
        # Messages per minute per user
        self.message_limiter = RateLimiter(requests_per_minute=30, burst_size=10)
        
        # Typing indicators (more lenient)
        self.typing_limiter = RateLimiter(requests_per_minute=60, burst_size=5)
    
    def check_message(self, username: str) -> bool:
        """Check if user can send a message"""
        return self.message_limiter.is_allowed(f"msg:{username}")
    
    def check_typing(self, username: str) -> bool:
        """Check if user can send typing indicator"""
        return self.typing_limiter.is_allowed(f"typing:{username}")
    
    def cleanup(self):
        """Cleanup old rate limit buckets"""
        self.message_limiter.cleanup_old_buckets()
        self.typing_limiter.cleanup_old_buckets()


# Global instances
login_rate_limiter = LoginRateLimiter()
ws_rate_limiter = WebSocketRateLimiter()
