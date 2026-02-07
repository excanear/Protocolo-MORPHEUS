"""
MÓDULO I: SINAPSE DA IDENTIDADE DIGITAL
Investigação de pessoas físicas através de identificadores digitais.
"""

import asyncio
import aiohttp
import hashlib
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from urllib.parse import quote_plus

from morpheus.core.config import Config, SOCIAL_PLATFORMS
from morpheus.core.logger import MorpheusLogger
from morpheus.utils.http import AsyncHTTPClient


@dataclass
class PlatformResult:
    """Resultado de verificação em plataforma."""
    platform: str
    url: str
    found: bool
    status_code: int = 0
    response_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EmailAnalysis:
    """Resultado de análise de email."""
    email: str
    valid_format: bool = False
    domain: str = ""
    domain_exists: bool = False
    mx_records: List[str] = field(default_factory=list)
    disposable: bool = False
    provider: str = ""
    gravatar_exists: bool = False
    gravatar_url: str = ""
    breach_count: int = 0
    associated_accounts: List[str] = field(default_factory=list)


class IdentitySynapse:
    """
    Módulo de investigação de identidade digital.
    Correlaciona informações públicas de pessoas físicas.
    """
    
    MODULE_NAME = "IDENTITY"
    
    def __init__(self, config: Config, logger: MorpheusLogger):
        self.config = config
        self.logger = logger
        self.http = AsyncHTTPClient(config)
        
        # Plataformas para verificação
        self.platforms = SOCIAL_PLATFORMS
        
        # Domínios de email descartáveis conhecidos
        self.disposable_domains = {
            "tempmail.com", "throwaway.email", "guerrillamail.com", "10minutemail.com",
            "mailinator.com", "yopmail.com", "sharklasers.com", "trashmail.com",
            "fakeinbox.com", "maildrop.cc", "getairmail.com", "temp-mail.org"
        }
    
    async def check_username(self, username: str, platforms: Optional[List[str]] = None) -> Dict[str, PlatformResult]:
        """
        Verifica a existência de um username em múltiplas plataformas.
        
        Args:
            username: Nome de usuário a verificar
            platforms: Lista de plataformas específicas (None = todas)
        
        Returns:
            Dicionário com resultados por plataforma
        """
        self.logger.info(f"Verificando username '{username}' em plataformas sociais", self.MODULE_NAME)
        
        target_platforms = platforms or list(self.platforms.keys())
        results: Dict[str, PlatformResult] = {}
        
        # Cria semáforo para limitar conexões simultâneas
        semaphore = asyncio.Semaphore(10)
        
        async def check_platform(platform: str, url_template: str):
            async with semaphore:
                url = url_template.format(username=username)
                result = await self._check_url(platform, url)
                results[platform] = result
                
                if result.found:
                    self.logger.found(f"{platform}: {url}", self.MODULE_NAME)
                else:
                    self.logger.debug(f"{platform}: Não encontrado", self.MODULE_NAME)
        
        # Executa verificações em paralelo
        tasks = [
            check_platform(platform, url_template)
            for platform, url_template in self.platforms.items()
            if platform in target_platforms
        ]
        
        total = len(tasks)
        for i, task in enumerate(asyncio.as_completed(tasks), 1):
            await task
            self.logger.progress(i, total, "Verificando plataformas")
        
        # Resumo
        found_count = sum(1 for r in results.values() if r.found)
        self.logger.success(f"Encontrado em {found_count}/{len(results)} plataformas", self.MODULE_NAME)
        
        return results
    
    async def _check_url(self, platform: str, url: str) -> PlatformResult:
        """Verifica se URL existe (retorna 200)."""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"User-Agent": self.config.user_agents[0]}
                
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.request_timeout),
                    allow_redirects=True,
                    ssl=False
                ) as response:
                    # Alguns sites retornam 200 mesmo para usuários inexistentes
                    # Precisamos verificar o conteúdo em alguns casos
                    found = await self._validate_response(platform, response)
                    
                    return PlatformResult(
                        platform=platform,
                        url=url,
                        found=found,
                        status_code=response.status,
                        metadata={"content_type": response.content_type}
                    )
                    
        except asyncio.TimeoutError:
            return PlatformResult(platform=platform, url=url, found=False, metadata={"error": "timeout"})
        except Exception as e:
            return PlatformResult(platform=platform, url=url, found=False, metadata={"error": str(e)})
    
    async def _validate_response(self, platform: str, response: aiohttp.ClientResponse) -> bool:
        """Valida se a resposta indica que o usuário existe."""
        if response.status == 404:
            return False
        if response.status != 200:
            return False
        
        # Plataformas com comportamento especial
        special_cases = {
            "instagram": ["Página não encontrada", "Sorry, this page isn't available"],
            "twitter": ["This account doesn't exist", "Hmm...this page doesn't exist"],
            "tiktok": ["Couldn't find this account"],
            "github": ["This is not the web page you are looking for"],
        }
        
        if platform in special_cases:
            try:
                text = await response.text()
                for indicator in special_cases[platform]:
                    if indicator.lower() in text.lower():
                        return False
            except:
                pass
        
        return True
    
    async def analyze_email(self, email: str) -> EmailAnalysis:
        """
        Analisa um endereço de email em profundidade.
        
        Args:
            email: Endereço de email a analisar
        
        Returns:
            EmailAnalysis com todas as informações coletadas
        """
        self.logger.info(f"Analisando email: {email}", self.MODULE_NAME)
        
        analysis = EmailAnalysis(email=email)
        
        # Valida formato
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        analysis.valid_format = bool(re.match(email_pattern, email))
        
        if not analysis.valid_format:
            self.logger.warning(f"Formato de email inválido: {email}", self.MODULE_NAME)
            return analysis
        
        # Extrai domínio
        analysis.domain = email.split('@')[1].lower()
        self.logger.result("Domínio", analysis.domain)
        
        # Verifica se é email descartável
        analysis.disposable = analysis.domain in self.disposable_domains
        if analysis.disposable:
            self.logger.warning("Email detectado como descartável/temporário", self.MODULE_NAME)
        
        # Identifica provedor
        analysis.provider = self._identify_provider(analysis.domain)
        self.logger.result("Provedor", analysis.provider or "Desconhecido")
        
        # Verifica registros MX do domínio
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(analysis.domain, 'MX')
            analysis.mx_records = [str(r.exchange) for r in mx_records]
            analysis.domain_exists = True
            self.logger.result("Registros MX", str(len(analysis.mx_records)))
        except:
            self.logger.debug("Não foi possível verificar registros MX", self.MODULE_NAME)
        
        # Verifica Gravatar
        gravatar_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(gravatar_url) as response:
                    analysis.gravatar_exists = response.status == 200
                    if analysis.gravatar_exists:
                        analysis.gravatar_url = f"https://www.gravatar.com/avatar/{gravatar_hash}"
                        self.logger.found(f"Gravatar encontrado: {analysis.gravatar_url}", self.MODULE_NAME)
        except:
            pass
        
        # Busca contas associadas (via username do email)
        email_username = email.split('@')[0]
        if len(email_username) >= 3:
            self.logger.info("Buscando contas com mesmo username do email", self.MODULE_NAME)
            platform_results = await self.check_username(email_username)
            analysis.associated_accounts = [
                r.url for r in platform_results.values() if r.found
            ]
        
        return analysis
    
    def _identify_provider(self, domain: str) -> str:
        """Identifica o provedor de email pelo domínio."""
        providers = {
            "gmail.com": "Google Gmail",
            "googlemail.com": "Google Gmail",
            "outlook.com": "Microsoft Outlook",
            "hotmail.com": "Microsoft Hotmail",
            "live.com": "Microsoft Live",
            "yahoo.com": "Yahoo",
            "yahoo.com.br": "Yahoo Brasil",
            "protonmail.com": "ProtonMail",
            "proton.me": "ProtonMail",
            "icloud.com": "Apple iCloud",
            "me.com": "Apple",
            "aol.com": "AOL",
            "zoho.com": "Zoho",
            "mail.com": "Mail.com",
            "yandex.com": "Yandex",
            "gmx.com": "GMX",
            "tutanota.com": "Tutanota",
            "fastmail.com": "Fastmail",
        }
        return providers.get(domain, "")
    
    async def search_by_name(self, full_name: str) -> Dict[str, Any]:
        """
        Busca informações por nome completo.
        
        Args:
            full_name: Nome completo para buscar
        
        Returns:
            Dicionário com resultados encontrados
        """
        self.logger.info(f"Buscando por nome: {full_name}", self.MODULE_NAME)
        
        results = {
            "name": full_name,
            "variations": [],
            "search_results": [],
            "social_profiles": [],
        }
        
        # Gera variações do nome
        parts = full_name.lower().split()
        if len(parts) >= 2:
            variations = [
                full_name.lower().replace(" ", ""),
                full_name.lower().replace(" ", "_"),
                full_name.lower().replace(" ", "."),
                f"{parts[0]}{parts[-1]}",
                f"{parts[0]}_{parts[-1]}",
                f"{parts[0]}.{parts[-1]}",
                f"{parts[-1]}{parts[0]}",
                f"{parts[0][0]}{parts[-1]}",
            ]
            results["variations"] = list(set(variations))
            
            # Testa cada variação como username
            for variation in results["variations"][:5]:  # Limita a 5 variações
                self.logger.debug(f"Testando variação: {variation}", self.MODULE_NAME)
                platform_results = await self.check_username(variation)
                found = [r.url for r in platform_results.values() if r.found]
                if found:
                    results["social_profiles"].extend(found)
        
        # Remove duplicatas
        results["social_profiles"] = list(set(results["social_profiles"]))
        
        self.logger.success(f"Encontrados {len(results['social_profiles'])} perfis potenciais", self.MODULE_NAME)
        return results
    
    async def analyze_phone(self, phone: str) -> Dict[str, Any]:
        """
        Analisa número de telefone.
        
        Args:
            phone: Número de telefone
        
        Returns:
            Dicionário com informações do número
        """
        self.logger.info(f"Analisando telefone: {phone}", self.MODULE_NAME)
        
        # Limpa o número
        cleaned = re.sub(r'[^\d+]', '', phone)
        
        result = {
            "original": phone,
            "cleaned": cleaned,
            "valid": False,
            "country": "",
            "carrier": "",
            "type": "",
            "region": "",
        }
        
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, timezone
            
            # Parse do número
            parsed = phonenumbers.parse(cleaned, None)
            result["valid"] = phonenumbers.is_valid_number(parsed)
            
            if result["valid"]:
                result["country"] = geocoder.description_for_number(parsed, "pt")
                result["carrier"] = carrier.name_for_number(parsed, "pt")
                result["region"] = geocoder.description_for_number(parsed, "pt")
                result["type"] = self._get_phone_type(phonenumbers.number_type(parsed))
                
                self.logger.result("País", result["country"])
                self.logger.result("Operadora", result["carrier"] or "Desconhecida")
                self.logger.result("Tipo", result["type"])
                
        except ImportError:
            self.logger.warning("Biblioteca phonenumbers não instalada", self.MODULE_NAME)
        except Exception as e:
            self.logger.debug(f"Erro ao analisar telefone: {e}", self.MODULE_NAME)
        
        return result
    
    def _get_phone_type(self, type_code: int) -> str:
        """Converte código de tipo de telefone para string."""
        types = {
            0: "Fixo",
            1: "Móvel",
            2: "Fixo ou Móvel",
            3: "Gratuito",
            4: "Premium",
            5: "Custo compartilhado",
            6: "VoIP",
            7: "Número pessoal",
            8: "Pager",
            9: "UAN",
            10: "Voicemail",
        }
        return types.get(type_code, "Desconhecido")
    
    async def correlate_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlaciona dados coletados para identificar conexões.
        
        Args:
            data: Dados já coletados de outras análises
        
        Returns:
            Correlações identificadas
        """
        self.logger.info("Correlacionando dados coletados", self.MODULE_NAME)
        
        correlations = {
            "confidence_score": 0.0,
            "unique_platforms": [],
            "common_usernames": [],
            "data_points": 0,
            "connections": [],
        }
        
        # Extrai plataformas únicas
        if "platforms" in data:
            found_platforms = [p for p, r in data["platforms"].items() if r.found]
            correlations["unique_platforms"] = found_platforms
            correlations["data_points"] += len(found_platforms)
        
        # Analisa padrões de username
        usernames = set()
        if "username" in data:
            usernames.add(data["username"])
        if "email" in data and isinstance(data["email"], EmailAnalysis):
            email_user = data["email"].email.split("@")[0]
            usernames.add(email_user)
        
        correlations["common_usernames"] = list(usernames)
        
        # Calcula score de confiança
        if correlations["data_points"] > 0:
            correlations["confidence_score"] = min(
                (correlations["data_points"] / 10) * 100, 100
            )
        
        self.logger.result("Score de Confiança", f"{correlations['confidence_score']:.1f}%")
        self.logger.result("Pontos de Dados", str(correlations["data_points"]))
        
        return correlations
    
    async def generate_wordlist(self, data: Dict[str, Any]) -> List[str]:
        """
        Gera wordlist personalizada baseada nos dados coletados.
        Útil para testes de segurança autorizados.
        
        Args:
            data: Dados do alvo
        
        Returns:
            Lista de palavras geradas
        """
        words = set()
        
        # Adiciona usernames encontrados
        for username in data.get("common_usernames", []):
            words.add(username)
            words.add(username + "123")
            words.add(username + "!")
            words.add(username.capitalize())
        
        # Variações com anos
        current_year = 2026
        for word in list(words):
            for year in range(current_year - 5, current_year + 1):
                words.add(f"{word}{year}")
        
        return sorted(words)
