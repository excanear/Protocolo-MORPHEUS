"""
Cliente HTTP assíncrono com rate limiting e retry.
"""

import asyncio
import aiohttp
import random
from typing import Optional, Dict, Any
from dataclasses import dataclass

from morpheus.core.config import Config


@dataclass
class HTTPResponse:
    """Resposta HTTP padronizada."""
    status: int
    headers: Dict[str, str]
    text: str
    json_data: Optional[Dict[str, Any]] = None
    url: str = ""


class AsyncHTTPClient:
    """Cliente HTTP assíncrono com funcionalidades avançadas."""
    
    def __init__(self, config: Config):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore = asyncio.Semaphore(10)  # Max conexões simultâneas
        self._last_request_time = 0.0
    
    @property
    def session(self) -> aiohttp.ClientSession:
        """Retorna ou cria sessão HTTP."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
            connector = aiohttp.TCPConnector(limit=100, ssl=False)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
            )
        return self._session
    
    def _get_headers(self, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Retorna headers com User-Agent rotativo."""
        headers = {
            "User-Agent": random.choice(self.config.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if extra_headers:
            headers.update(extra_headers)
        return headers
    
    async def _rate_limit(self):
        """Aplica rate limiting entre requisições."""
        import time
        min_interval = 1.0 / self.config.rate_limit
        elapsed = time.time() - self._last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.time()
    
    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        retry: int = 3,
    ) -> HTTPResponse:
        """
        Realiza requisição GET.
        
        Args:
            url: URL para requisitar
            headers: Headers adicionais
            allow_redirects: Seguir redirects
            retry: Número de tentativas
        
        Returns:
            HTTPResponse com resultado
        """
        async with self._semaphore:
            await self._rate_limit()
            
            for attempt in range(retry):
                try:
                    async with self.session.get(
                        url,
                        headers=self._get_headers(headers),
                        allow_redirects=allow_redirects,
                        proxy=self.config.proxy,
                    ) as response:
                        text = await response.text()
                        
                        json_data = None
                        if "application/json" in response.content_type:
                            try:
                                json_data = await response.json()
                            except:
                                pass
                        
                        return HTTPResponse(
                            status=response.status,
                            headers=dict(response.headers),
                            text=text,
                            json_data=json_data,
                            url=str(response.url),
                        )
                        
                except aiohttp.ClientError as e:
                    if attempt == retry - 1:
                        raise
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    
                except asyncio.TimeoutError:
                    if attempt == retry - 1:
                        raise
                    await asyncio.sleep(2 ** attempt)
        
        raise Exception("Max retries exceeded")
    
    async def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> HTTPResponse:
        """
        Realiza requisição POST.
        """
        async with self._semaphore:
            await self._rate_limit()
            
            async with self.session.post(
                url,
                headers=self._get_headers(headers),
                data=data,
                json=json_data,
                proxy=self.config.proxy,
            ) as response:
                text = await response.text()
                
                json_response = None
                if "application/json" in response.content_type:
                    try:
                        json_response = await response.json()
                    except:
                        pass
                
                return HTTPResponse(
                    status=response.status,
                    headers=dict(response.headers),
                    text=text,
                    json_data=json_response,
                    url=str(response.url),
                )
    
    async def head(self, url: str, headers: Optional[Dict[str, str]] = None) -> HTTPResponse:
        """Realiza requisição HEAD."""
        async with self._semaphore:
            await self._rate_limit()
            
            async with self.session.head(
                url,
                headers=self._get_headers(headers),
                allow_redirects=True,
                proxy=self.config.proxy,
            ) as response:
                return HTTPResponse(
                    status=response.status,
                    headers=dict(response.headers),
                    text="",
                    url=str(response.url),
                )
    
    async def close(self):
        """Fecha a sessão HTTP."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
