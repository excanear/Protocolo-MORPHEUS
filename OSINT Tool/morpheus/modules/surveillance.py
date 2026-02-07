"""
MÓDULO III: SINAPSE DO ÉTER DIGITAL
Vigilância passiva de repositórios públicos e vazamentos de dados.
"""

import asyncio
import aiohttp
import re
import hashlib
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import quote_plus

from morpheus.core.config import Config
from morpheus.core.logger import MorpheusLogger
from morpheus.utils.http import AsyncHTTPClient


@dataclass
class PasteResult:
    """Resultado de busca em paste sites."""
    source: str
    url: str
    title: str = ""
    content_preview: str = ""
    date: str = ""
    matches: List[str] = field(default_factory=list)


@dataclass
class BreachResult:
    """Resultado de verificação de vazamento."""
    email: str
    breached: bool = False
    breach_count: int = 0
    breaches: List[Dict[str, Any]] = field(default_factory=list)
    paste_count: int = 0


@dataclass 
class GitHubResult:
    """Resultado de busca no GitHub."""
    repository: str
    file_path: str
    url: str
    matches: List[str] = field(default_factory=list)
    context: str = ""


@dataclass
class ExposureRisk:
    """Análise de risco de exposição."""
    overall_risk: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class SurveillanceSynapse:
    """
    Módulo de vigilância passiva.
    Monitora repositórios públicos e vazamentos de dados.
    """
    
    MODULE_NAME = "SURVEILLANCE"
    
    def __init__(self, config: Config, logger: MorpheusLogger):
        self.config = config
        self.logger = logger
        self.http = AsyncHTTPClient(config)
        
        # Padrões sensíveis para detecção
        self.sensitive_patterns = {
            "api_key": r'(?:api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            "password": r'(?:password|passwd|pwd)["\s:=]+["\']?([^\s"\']{6,})["\']?',
            "secret": r'(?:secret|token)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            "aws_key": r'AKIA[0-9A-Z]{16}',
            "aws_secret": r'(?:aws)?_?(?:secret)?_?(?:access)?_?(?:key)?["\s:=]+["\']?([a-zA-Z0-9/+=]{40})["\']?',
            "private_key": r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
            "email_password": r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+):([^\s:]+)',
            "connection_string": r'(?:mongodb|mysql|postgres|redis):\/\/[^\s"\']+',
            "jwt_token": r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        }
    
    async def search_github(self, keywords: List[str]) -> List[GitHubResult]:
        """
        Busca por palavras-chave em repositórios públicos do GitHub.
        
        Args:
            keywords: Lista de termos para buscar
        
        Returns:
            Lista de resultados encontrados
        """
        self.logger.info(f"Buscando no GitHub: {', '.join(keywords[:3])}", self.MODULE_NAME)
        
        results: List[GitHubResult] = []
        
        # Usa GitHub API se token disponível
        github_token = self.config.api_keys.get("github", "")
        headers = {"Accept": "application/vnd.github.v3+json"}
        if github_token:
            headers["Authorization"] = f"token {github_token}"
        
        async with aiohttp.ClientSession() as session:
            for keyword in keywords:
                try:
                    # Busca em código
                    search_url = f"https://api.github.com/search/code?q={quote_plus(keyword)}&per_page=10"
                    
                    async with session.get(search_url, headers=headers) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            for item in data.get("items", []):
                                result = GitHubResult(
                                    repository=item.get("repository", {}).get("full_name", ""),
                                    file_path=item.get("path", ""),
                                    url=item.get("html_url", ""),
                                    matches=[keyword],
                                )
                                results.append(result)
                                self.logger.found(f"GitHub: {result.repository}/{result.file_path}", self.MODULE_NAME)
                        
                        elif response.status == 403:
                            self.logger.warning("Rate limit do GitHub atingido", self.MODULE_NAME)
                            break
                            
                except Exception as e:
                    self.logger.debug(f"Erro na busca GitHub: {e}", self.MODULE_NAME)
                
                # Rate limiting
                await asyncio.sleep(2)
        
        self.logger.success(f"Encontrados {len(results)} resultados no GitHub", self.MODULE_NAME)
        return results
    
    async def search_paste_sites(self, keywords: List[str]) -> List[PasteResult]:
        """
        Busca em sites de paste (Pastebin e similares).
        Nota: Muitos sites restringem scraping, usamos APIs quando disponíveis.
        
        Args:
            keywords: Termos para buscar
        
        Returns:
            Lista de pastes encontrados
        """
        self.logger.info(f"Buscando em paste sites: {', '.join(keywords[:3])}", self.MODULE_NAME)
        
        results: List[PasteResult] = []
        
        # Lista de fontes para buscar
        paste_sources = [
            self._search_pastebin_scraping,
            self._search_ghostbin,
            self._search_dpaste,
        ]
        
        for search_func in paste_sources:
            try:
                source_results = await search_func(keywords)
                results.extend(source_results)
            except Exception as e:
                self.logger.debug(f"Erro em paste source: {e}", self.MODULE_NAME)
        
        self.logger.success(f"Encontrados {len(results)} pastes potenciais", self.MODULE_NAME)
        return results
    
    async def _search_pastebin_scraping(self, keywords: List[str]) -> List[PasteResult]:
        """
        Busca no Pastebin via scraping do arquivo público.
        Nota: Pastebin limita acesso, este é um método básico.
        """
        results = []
        
        # Pastebin não permite busca direta sem API pro
        # Verificamos pastes recentes públicos
        try:
            url = "https://pastebin.com/api_scraping.php?limit=100"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        pastes = await response.json()
                        
                        for paste in pastes[:50]:
                            paste_key = paste.get("key", "")
                            paste_url = f"https://pastebin.com/raw/{paste_key}"
                            
                            # Busca conteúdo
                            async with session.get(paste_url) as content_response:
                                if content_response.status == 200:
                                    content = await content_response.text()
                                    
                                    # Verifica se contém keywords
                                    for keyword in keywords:
                                        if keyword.lower() in content.lower():
                                            results.append(PasteResult(
                                                source="Pastebin",
                                                url=f"https://pastebin.com/{paste_key}",
                                                title=paste.get("title", "Sem título"),
                                                content_preview=content[:200],
                                                date=paste.get("date", ""),
                                                matches=[keyword]
                                            ))
                                            self.logger.found(f"Pastebin: {paste_key}", self.MODULE_NAME)
                                            break
                            
                            await asyncio.sleep(0.5)  # Rate limiting
                            
        except Exception as e:
            self.logger.debug(f"Erro Pastebin: {e}", self.MODULE_NAME)
        
        return results
    
    async def _search_ghostbin(self, keywords: List[str]) -> List[PasteResult]:
        """Busca em Ghostbin."""
        # Ghostbin foi descontinuado, incluído como exemplo de extensibilidade
        return []
    
    async def _search_dpaste(self, keywords: List[str]) -> List[PasteResult]:
        """Busca em dpaste.org."""
        # dpaste não tem API de busca pública
        return []
    
    async def check_breaches(self, emails: List[str]) -> List[BreachResult]:
        """
        Verifica se emails aparecem em vazamentos conhecidos.
        Usa Have I Been Pwned API ou alternativas.
        
        Args:
            emails: Lista de emails para verificar
        
        Returns:
            Resultados de vazamentos
        """
        self.logger.info(f"Verificando vazamentos para {len(emails)} emails", self.MODULE_NAME)
        
        results: List[BreachResult] = []
        
        for email in emails:
            result = BreachResult(email=email)
            
            try:
                # Have I Been Pwned
                hibp_result = await self._check_hibp(email)
                if hibp_result:
                    result.breached = True
                    result.breaches = hibp_result
                    result.breach_count = len(hibp_result)
                    
                    self.logger.alert(f"VAZAMENTO: {email} encontrado em {result.breach_count} breaches", self.MODULE_NAME)
                else:
                    self.logger.info(f"{email}: Nenhum vazamento conhecido", self.MODULE_NAME)
                    
            except Exception as e:
                self.logger.debug(f"Erro ao verificar {email}: {e}", self.MODULE_NAME)
            
            results.append(result)
            await asyncio.sleep(1.5)  # Rate limiting HIBP
        
        breached_count = sum(1 for r in results if r.breached)
        self.logger.success(f"{breached_count}/{len(results)} emails encontrados em vazamentos", self.MODULE_NAME)
        
        return results
    
    async def _check_hibp(self, email: str) -> List[Dict[str, Any]]:
        """
        Verifica email no Have I Been Pwned.
        Nota: Requer API key para uso comercial.
        """
        breaches = []
        
        try:
            # Versão k-anonymity (não requer API key)
            sha1_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        text = await response.text()
                        hashes = text.split("\r\n")
                        
                        for hash_line in hashes:
                            if ":" in hash_line:
                                hash_suffix, count = hash_line.split(":")
                                if hash_suffix == suffix:
                                    breaches.append({
                                        "type": "password_exposure",
                                        "count": int(count),
                                    })
                                    break
                                    
        except Exception as e:
            self.logger.debug(f"Erro HIBP: {e}", self.MODULE_NAME)
        
        return breaches
    
    async def search_engines(self, keywords: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Busca termos em motores de busca via dorks.
        Usa técnicas de OSINT para busca avançada.
        
        Args:
            keywords: Termos para buscar
        
        Returns:
            Resultados por motor de busca
        """
        self.logger.info("Executando buscas em motores de busca", self.MODULE_NAME)
        
        results = {
            "google_dorks": [],
            "bing": [],
            "duckduckgo": [],
        }
        
        # Gera Google Dorks úteis
        for keyword in keywords:
            dorks = [
                f'"{keyword}" site:pastebin.com',
                f'"{keyword}" site:github.com password OR secret OR api_key',
                f'"{keyword}" filetype:sql',
                f'"{keyword}" filetype:env',
                f'"{keyword}" filetype:log',
                f'"{keyword}" inurl:admin',
                f'"{keyword}" inurl:login',
                f'"{keyword}" "index of"',
                f'"{keyword}" ext:conf OR ext:cfg OR ext:ini',
            ]
            
            for dork in dorks:
                results["google_dorks"].append({
                    "dork": dork,
                    "url": f"https://www.google.com/search?q={quote_plus(dork)}",
                })
        
        self.logger.info(f"Gerados {len(results['google_dorks'])} Google Dorks", self.MODULE_NAME)
        
        # DuckDuckGo (respeita privacidade, permite automação limitada)
        for keyword in keywords[:3]:
            try:
                ddg_results = await self._search_duckduckgo(keyword)
                results["duckduckgo"].extend(ddg_results)
            except:
                pass
        
        return results
    
    async def _search_duckduckgo(self, query: str) -> List[Dict[str, Any]]:
        """Busca no DuckDuckGo via HTML (limitado)."""
        results = []
        
        try:
            url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
            headers = {"User-Agent": self.config.user_agents[0]}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        html = await response.text()
                        
                        # Extrai resultados básicos
                        links = re.findall(r'href="([^"]+)"[^>]*>([^<]+)</a>', html)
                        for href, title in links[:10]:
                            if href.startswith("http") and "duckduckgo" not in href:
                                results.append({
                                    "title": title.strip(),
                                    "url": href,
                                })
                                
        except Exception as e:
            self.logger.debug(f"Erro DuckDuckGo: {e}", self.MODULE_NAME)
        
        return results
    
    async def analyze_exposure_risk(self, surveillance_data: Dict[str, Any]) -> ExposureRisk:
        """
        Analisa o risco de exposição baseado nos dados coletados.
        
        Args:
            surveillance_data: Dados de vigilância coletados
        
        Returns:
            Análise de risco
        """
        self.logger.info("Analisando risco de exposição", self.MODULE_NAME)
        
        risk = ExposureRisk()
        findings = []
        
        # Analisa GitHub
        github_results = surveillance_data.get("github", [])
        if github_results:
            findings.append({
                "type": "code_exposure",
                "severity": "MEDIUM",
                "description": f"Encontradas {len(github_results)} menções em repositórios GitHub",
                "count": len(github_results),
            })
            risk.risk_score += len(github_results) * 10
        
        # Analisa Pastes
        paste_results = surveillance_data.get("pastes", [])
        if paste_results:
            findings.append({
                "type": "paste_exposure",
                "severity": "HIGH",
                "description": f"Encontradas {len(paste_results)} menções em paste sites",
                "count": len(paste_results),
            })
            risk.risk_score += len(paste_results) * 20
        
        # Analisa Breaches
        breach_results = surveillance_data.get("breaches", [])
        breached_emails = [b for b in breach_results if isinstance(b, BreachResult) and b.breached]
        if breached_emails:
            total_breaches = sum(b.breach_count for b in breached_emails)
            findings.append({
                "type": "data_breach",
                "severity": "CRITICAL",
                "description": f"{len(breached_emails)} emails encontrados em {total_breaches} vazamentos",
                "count": total_breaches,
            })
            risk.risk_score += total_breaches * 25
        
        # Determina nível de risco
        if risk.risk_score >= 100:
            risk.overall_risk = "CRITICAL"
        elif risk.risk_score >= 50:
            risk.overall_risk = "HIGH"
        elif risk.risk_score >= 20:
            risk.overall_risk = "MEDIUM"
        else:
            risk.overall_risk = "LOW"
        
        risk.findings = findings
        
        # Gera recomendações
        risk.recommendations = self._generate_recommendations(findings)
        
        # Log do resultado
        color_map = {"LOW": "GREEN", "MEDIUM": "YELLOW", "HIGH": "RED", "CRITICAL": "RED"}
        self.logger.result("Nível de Risco", risk.overall_risk)
        self.logger.result("Score de Risco", str(risk.risk_score))
        self.logger.result("Descobertas", str(len(findings)))
        
        return risk
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Gera recomendações baseadas nas descobertas."""
        recommendations = []
        
        for finding in findings:
            if finding["type"] == "code_exposure":
                recommendations.append("Revise repositórios públicos e remova informações sensíveis")
                recommendations.append("Use git-secrets ou similar para prevenir commits de segredos")
            
            elif finding["type"] == "paste_exposure":
                recommendations.append("Solicite remoção de pastes que contenham dados sensíveis")
                recommendations.append("Monitore continuamente por novas exposições")
            
            elif finding["type"] == "data_breach":
                recommendations.append("Altere imediatamente as senhas dos emails expostos")
                recommendations.append("Habilite autenticação de dois fatores (2FA)")
                recommendations.append("Considere usar um gerenciador de senhas")
        
        # Recomendações gerais
        recommendations.extend([
            "Implemente monitoramento contínuo de exposição de dados",
            "Treine equipe sobre práticas de segurança da informação",
        ])
        
        return list(set(recommendations))
    
    async def monitor_continuous(
        self,
        keywords: List[str],
        interval_seconds: int = 3600,
        callback=None
    ):
        """
        Monitora continuamente por novas exposições.
        
        Args:
            keywords: Termos para monitorar
            interval_seconds: Intervalo entre verificações
            callback: Função a chamar quando encontrar algo
        """
        self.logger.info(f"Iniciando monitoramento contínuo (intervalo: {interval_seconds}s)", self.MODULE_NAME)
        
        previous_results = set()
        
        while True:
            try:
                # Busca novas exposições
                github_results = await self.search_github(keywords)
                paste_results = await self.search_paste_sites(keywords)
                
                # Identifica novos resultados
                current_results = set()
                
                for r in github_results:
                    result_id = f"github:{r.url}"
                    current_results.add(result_id)
                    
                    if result_id not in previous_results:
                        self.logger.alert(f"NOVA EXPOSIÇÃO: {r.url}", self.MODULE_NAME)
                        if callback:
                            callback("github", r)
                
                for r in paste_results:
                    result_id = f"paste:{r.url}"
                    current_results.add(result_id)
                    
                    if result_id not in previous_results:
                        self.logger.alert(f"NOVA EXPOSIÇÃO: {r.url}", self.MODULE_NAME)
                        if callback:
                            callback("paste", r)
                
                previous_results = current_results
                
                self.logger.info(f"Próxima verificação em {interval_seconds}s", self.MODULE_NAME)
                await asyncio.sleep(interval_seconds)
                
            except asyncio.CancelledError:
                self.logger.info("Monitoramento cancelado", self.MODULE_NAME)
                break
            except Exception as e:
                self.logger.error(f"Erro no monitoramento: {e}", self.MODULE_NAME)
                await asyncio.sleep(60)  # Espera antes de tentar novamente
