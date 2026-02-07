"""
MÓDULO II: SINAPSE DA ANATOMIA CORPORATIVA
Investigação de empresas e domínios através de análise de infraestrutura.
"""

import asyncio
import aiohttp
import socket
import ssl
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import re
from urllib.parse import urljoin, urlparse

from morpheus.core.config import Config, SUBDOMAIN_WORDLIST
from morpheus.core.logger import MorpheusLogger
from morpheus.utils.http import AsyncHTTPClient


@dataclass
class SubdomainResult:
    """Resultado de enumeração de subdomínio."""
    subdomain: str
    ip_address: Optional[str] = None
    alive: bool = False
    status_code: int = 0
    title: str = ""
    server: str = ""
    technologies: List[str] = field(default_factory=list)


@dataclass
class DNSRecord:
    """Registro DNS."""
    record_type: str
    value: str
    ttl: int = 0


@dataclass
class SSLCertificate:
    """Informações de certificado SSL."""
    issuer: str = ""
    subject: str = ""
    valid_from: str = ""
    valid_until: str = ""
    san_domains: List[str] = field(default_factory=list)
    expired: bool = False
    days_remaining: int = 0


class CorporateSynapse:
    """
    Módulo de investigação corporativa.
    Analisa infraestrutura, tecnologias e presença digital de empresas.
    """
    
    MODULE_NAME = "CORPORATE"
    
    def __init__(self, config: Config, logger: MorpheusLogger):
        self.config = config
        self.logger = logger
        self.http = AsyncHTTPClient(config)
        
        # Wordlist de subdomínios
        self.subdomain_wordlist = SUBDOMAIN_WORDLIST
        
        # Padrões de tecnologias
        self.tech_patterns = self._load_tech_patterns()
    
    async def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Consulta WHOIS do domínio.
        
        Args:
            domain: Domínio para consultar
        
        Returns:
            Informações WHOIS
        """
        self.logger.info(f"Consultando WHOIS para: {domain}", self.MODULE_NAME)
        
        result = {
            "domain": domain,
            "registrar": "",
            "creation_date": "",
            "expiration_date": "",
            "updated_date": "",
            "name_servers": [],
            "status": [],
            "registrant": {},
        }
        
        try:
            import whois
            w = whois.whois(domain)
            
            result["registrar"] = w.registrar or ""
            result["creation_date"] = str(w.creation_date) if w.creation_date else ""
            result["expiration_date"] = str(w.expiration_date) if w.expiration_date else ""
            result["updated_date"] = str(w.updated_date) if w.updated_date else ""
            result["name_servers"] = w.name_servers if w.name_servers else []
            result["status"] = w.status if isinstance(w.status, list) else [w.status] if w.status else []
            
            if w.registrant:
                result["registrant"] = {
                    "name": getattr(w, 'registrant_name', ''),
                    "organization": getattr(w, 'org', ''),
                    "country": getattr(w, 'country', ''),
                }
            
            self.logger.result("Registrador", result["registrar"])
            self.logger.result("Criação", result["creation_date"])
            self.logger.result("Expiração", result["expiration_date"])
            
        except ImportError:
            self.logger.warning("Biblioteca python-whois não instalada", self.MODULE_NAME)
        except Exception as e:
            self.logger.debug(f"Erro WHOIS: {e}", self.MODULE_NAME)
        
        return result
    
    async def enumerate_subdomains(self, domain: str) -> List[SubdomainResult]:
        """
        Enumera subdomínios usando múltiplas técnicas.
        
        Args:
            domain: Domínio para enumerar
        
        Returns:
            Lista de subdomínios encontrados
        """
        self.logger.info(f"Enumerando subdomínios de: {domain}", self.MODULE_NAME)
        
        subdomains = set()
        results: List[SubdomainResult] = []
        
        # 1. Busca em Certificate Transparency Logs
        self.logger.debug("Consultando logs de transparência de certificados", self.MODULE_NAME)
        ct_subs = await self._crt_sh_lookup(domain)
        subdomains.update(ct_subs)
        
        # 2. Brute force com wordlist
        self.logger.debug("Executando brute force de subdomínios", self.MODULE_NAME)
        for word in self.subdomain_wordlist:
            subdomains.add(f"{word}.{domain}")
        
        # 3. Verifica cada subdomínio
        self.logger.info(f"Verificando {len(subdomains)} subdomínios potenciais", self.MODULE_NAME)
        
        semaphore = asyncio.Semaphore(20)
        
        async def check_subdomain(subdomain: str):
            async with semaphore:
                result = await self._verify_subdomain(subdomain)
                if result.alive:
                    results.append(result)
                    self.logger.found(f"{subdomain} -> {result.ip_address}", self.MODULE_NAME)
        
        tasks = [check_subdomain(sub) for sub in subdomains]
        
        total = len(tasks)
        for i, task in enumerate(asyncio.as_completed(tasks), 1):
            await task
            if i % 50 == 0 or i == total:
                self.logger.progress(i, total, "Verificando subdomínios")
        
        self.logger.success(f"Encontrados {len(results)} subdomínios ativos", self.MODULE_NAME)
        return results
    
    async def _crt_sh_lookup(self, domain: str) -> List[str]:
        """Consulta crt.sh para certificados."""
        subdomains = []
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if sub.endswith(domain) and "*" not in sub:
                                    subdomains.append(sub)
        except Exception as e:
            self.logger.debug(f"Erro crt.sh: {e}", self.MODULE_NAME)
        
        return list(set(subdomains))
    
    async def _verify_subdomain(self, subdomain: str) -> SubdomainResult:
        """Verifica se um subdomínio está ativo."""
        result = SubdomainResult(subdomain=subdomain)
        
        try:
            # Resolve DNS
            result.ip_address = socket.gethostbyname(subdomain)
            result.alive = True
            
            # Tenta HTTP/HTTPS
            for protocol in ["https", "http"]:
                try:
                    url = f"{protocol}://{subdomain}"
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=10),
                            allow_redirects=True,
                            ssl=False
                        ) as response:
                            result.status_code = response.status
                            result.server = response.headers.get("Server", "")
                            
                            # Extrai título da página
                            if response.status == 200:
                                html = await response.text()
                                title_match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
                                if title_match:
                                    result.title = title_match.group(1).strip()[:100]
                            break
                except:
                    continue
                    
        except socket.gaierror:
            pass
        except Exception:
            pass
        
        return result
    
    async def analyze_dns(self, domain: str) -> Dict[str, List[DNSRecord]]:
        """
        Analisa todos os registros DNS do domínio.
        
        Args:
            domain: Domínio para analisar
        
        Returns:
            Registros DNS por tipo
        """
        self.logger.info(f"Analisando registros DNS de: {domain}", self.MODULE_NAME)
        
        records = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": [],
            "SOA": [],
        }
        
        try:
            import dns.resolver
            
            for record_type in records.keys():
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for rdata in answers:
                        record = DNSRecord(
                            record_type=record_type,
                            value=str(rdata),
                            ttl=answers.ttl
                        )
                        records[record_type].append(record)
                        self.logger.debug(f"{record_type}: {rdata}", self.MODULE_NAME)
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    self.logger.warning(f"Domínio não existe: {domain}", self.MODULE_NAME)
                    break
                except Exception:
                    continue
            
            # Resumo
            for rtype, recs in records.items():
                if recs:
                    self.logger.result(f"Registros {rtype}", str(len(recs)))
                    
        except ImportError:
            self.logger.warning("Biblioteca dnspython não instalada", self.MODULE_NAME)
        
        return records
    
    async def dns_history(self, domain: str) -> List[Dict[str, Any]]:
        """
        Busca histórico de DNS do domínio.
        Requer API SecurityTrails/VirusTotal ou usa serviços públicos.
        """
        self.logger.info(f"Buscando histórico DNS de: {domain}", self.MODULE_NAME)
        
        history = []
        
        # Tenta SecurityTrails se API disponível
        if self.config.api_keys.get("securitytrails"):
            history = await self._securitytrails_history(domain)
        else:
            self.logger.debug("API SecurityTrails não configurada", self.MODULE_NAME)
        
        return history
    
    async def _securitytrails_history(self, domain: str) -> List[Dict[str, Any]]:
        """Consulta histórico DNS via SecurityTrails."""
        history = []
        api_key = self.config.api_keys.get("securitytrails", "")
        
        if not api_key:
            return history
        
        try:
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            headers = {"APIKEY": api_key}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        for record in data.get("records", []):
                            history.append({
                                "type": "A",
                                "value": record.get("values", [{}])[0].get("ip", ""),
                                "first_seen": record.get("first_seen", ""),
                                "last_seen": record.get("last_seen", ""),
                            })
        except Exception as e:
            self.logger.debug(f"Erro SecurityTrails: {e}", self.MODULE_NAME)
        
        return history
    
    async def detect_technologies(self, domain: str) -> Dict[str, Any]:
        """
        Detecta tecnologias utilizadas pelo site.
        
        Args:
            domain: Domínio para analisar
        
        Returns:
            Tecnologias detectadas por categoria
        """
        self.logger.info(f"Detectando stack tecnológico de: {domain}", self.MODULE_NAME)
        
        technologies = {
            "cms": [],
            "javascript_frameworks": [],
            "web_servers": [],
            "programming_languages": [],
            "cdn": [],
            "analytics": [],
            "security": [],
            "hosting": [],
            "other": [],
        }
        
        try:
            url = f"https://{domain}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=30),
                    allow_redirects=True,
                    ssl=False
                ) as response:
                    headers = dict(response.headers)
                    html = await response.text()
                    
                    # Web Server
                    if "Server" in headers:
                        server = headers["Server"]
                        technologies["web_servers"].append(server)
                        self.logger.result("Servidor Web", server)
                    
                    # X-Powered-By
                    if "X-Powered-By" in headers:
                        powered = headers["X-Powered-By"]
                        technologies["programming_languages"].append(powered)
                        self.logger.result("Powered By", powered)
                    
                    # CDN Detection
                    cdn_headers = ["cf-ray", "x-cdn", "x-cache", "x-amz-cf-id"]
                    for cdn_header in cdn_headers:
                        if cdn_header.lower() in [h.lower() for h in headers]:
                            if "cf-ray" in headers:
                                technologies["cdn"].append("Cloudflare")
                            elif "x-amz-cf-id" in headers:
                                technologies["cdn"].append("AWS CloudFront")
                    
                    # Detecção por padrões no HTML
                    for category, patterns in self.tech_patterns.items():
                        for tech_name, pattern in patterns.items():
                            if re.search(pattern, html, re.I):
                                if tech_name not in technologies.get(category, []):
                                    technologies[category].append(tech_name)
                                    self.logger.found(f"{tech_name} ({category})", self.MODULE_NAME)
                                    
        except Exception as e:
            self.logger.debug(f"Erro na detecção de tecnologias: {e}", self.MODULE_NAME)
        
        return technologies
    
    def _load_tech_patterns(self) -> Dict[str, Dict[str, str]]:
        """Carrega padrões para detecção de tecnologias."""
        return {
            "cms": {
                "WordPress": r'wp-content|wp-includes|WordPress',
                "Drupal": r'Drupal|drupal\.js|sites/all',
                "Joomla": r'Joomla|/media/jui/|joomla',
                "Magento": r'Magento|/skin/frontend/',
                "Shopify": r'cdn\.shopify\.com|Shopify\.theme',
                "Wix": r'wix\.com|X-Wix-',
                "Squarespace": r'squarespace\.com|static\.squarespace',
                "Ghost": r'ghost\.io|ghost\.org',
            },
            "javascript_frameworks": {
                "React": r'react\.development\.js|react\.production|__NEXT_DATA__|reactroot',
                "Vue.js": r'vue\.js|vue\.min\.js|Vue\.',
                "Angular": r'angular\.js|ng-app|angular\.min\.js',
                "jQuery": r'jquery\.js|jquery\.min\.js|jQuery',
                "Next.js": r'_next/static|__NEXT_DATA__',
                "Nuxt.js": r'_nuxt/|nuxt\.js',
                "Svelte": r'svelte',
            },
            "analytics": {
                "Google Analytics": r'google-analytics\.com|gtag|ga\.js|analytics\.js',
                "Google Tag Manager": r'googletagmanager\.com',
                "Facebook Pixel": r'fbq\(|facebook\.com/tr',
                "Hotjar": r'hotjar\.com|static\.hotjar\.com',
                "Mixpanel": r'mixpanel\.com',
            },
            "security": {
                "Cloudflare": r'cloudflare|__cfduid',
                "Sucuri": r'sucuri\.net',
                "reCAPTCHA": r'recaptcha|g-recaptcha',
                "hCaptcha": r'hcaptcha\.com|h-captcha',
            },
        }
    
    async def extract_emails(self, domain: str) -> List[str]:
        """
        Extrai emails associados ao domínio.
        
        Args:
            domain: Domínio para buscar emails
        
        Returns:
            Lista de emails encontrados
        """
        self.logger.info(f"Extraindo emails de: {domain}", self.MODULE_NAME)
        
        emails = set()
        
        # 1. Busca no site principal
        try:
            url = f"https://{domain}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30), ssl=False) as response:
                    html = await response.text()
                    
                    # Regex para emails
                    email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(domain)
                    found = re.findall(email_pattern, html.lower())
                    emails.update(found)
        except:
            pass
        
        # 2. Usa Hunter.io se API disponível
        if self.config.api_keys.get("hunter"):
            hunter_emails = await self._hunter_search(domain)
            emails.update(hunter_emails)
        
        # 3. Padrões comuns de email
        common_prefixes = ["info", "contact", "admin", "support", "sales", "hello", "team"]
        for prefix in common_prefixes:
            emails.add(f"{prefix}@{domain}")
        
        email_list = list(emails)
        self.logger.success(f"Encontrados {len(email_list)} emails", self.MODULE_NAME)
        
        for email in email_list[:10]:
            self.logger.list_item(email)
        
        return email_list
    
    async def _hunter_search(self, domain: str) -> List[str]:
        """Busca emails via Hunter.io API."""
        emails = []
        api_key = self.config.api_keys.get("hunter", "")
        
        if not api_key:
            return emails
        
        try:
            url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for email_data in data.get("data", {}).get("emails", []):
                            emails.append(email_data.get("value", ""))
        except Exception as e:
            self.logger.debug(f"Erro Hunter.io: {e}", self.MODULE_NAME)
        
        return emails
    
    async def analyze_ssl(self, domain: str) -> SSLCertificate:
        """
        Analisa certificado SSL do domínio.
        
        Args:
            domain: Domínio para analisar
        
        Returns:
            Informações do certificado SSL
        """
        self.logger.info(f"Analisando certificado SSL de: {domain}", self.MODULE_NAME)
        
        cert_info = SSLCertificate()
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Issuer
                    issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                    cert_info.issuer = issuer_parts.get("organizationName", "")
                    
                    # Subject
                    subject_parts = dict(x[0] for x in cert.get("subject", []))
                    cert_info.subject = subject_parts.get("commonName", "")
                    
                    # Datas
                    cert_info.valid_from = cert.get("notBefore", "")
                    cert_info.valid_until = cert.get("notAfter", "")
                    
                    # SAN (Subject Alternative Names)
                    san = cert.get("subjectAltName", [])
                    cert_info.san_domains = [name for type_, name in san if type_ == "DNS"]
                    
                    # Verifica expiração
                    from datetime import datetime
                    expiry_date = datetime.strptime(cert_info.valid_until, "%b %d %H:%M:%S %Y %Z")
                    cert_info.days_remaining = (expiry_date - datetime.now()).days
                    cert_info.expired = cert_info.days_remaining < 0
                    
                    self.logger.result("Emissor", cert_info.issuer)
                    self.logger.result("Subject", cert_info.subject)
                    self.logger.result("Expira em", f"{cert_info.days_remaining} dias")
                    self.logger.result("Domínios SAN", str(len(cert_info.san_domains)))
                    
                    if cert_info.expired:
                        self.logger.warning("Certificado EXPIRADO!", self.MODULE_NAME)
                    
        except Exception as e:
            self.logger.debug(f"Erro ao analisar SSL: {e}", self.MODULE_NAME)
        
        return cert_info
    
    async def map_infrastructure(self, domain: str) -> Dict[str, Any]:
        """
        Mapeia infraestrutura do domínio.
        Usa Shodan se API disponível.
        
        Args:
            domain: Domínio para mapear
        
        Returns:
            Informações de infraestrutura
        """
        self.logger.info(f"Mapeando infraestrutura de: {domain}", self.MODULE_NAME)
        
        infrastructure = {
            "ip_addresses": [],
            "ports": [],
            "services": [],
            "asn": "",
            "isp": "",
            "location": {},
        }
        
        # Resolve IP
        try:
            ip = socket.gethostbyname(domain)
            infrastructure["ip_addresses"].append(ip)
            self.logger.result("IP Principal", ip)
            
            # Usa Shodan se disponível
            if self.config.api_keys.get("shodan"):
                shodan_data = await self._shodan_lookup(ip)
                infrastructure.update(shodan_data)
            else:
                self.logger.debug("API Shodan não configurada", self.MODULE_NAME)
                
        except Exception as e:
            self.logger.debug(f"Erro ao mapear infraestrutura: {e}", self.MODULE_NAME)
        
        return infrastructure
    
    async def _shodan_lookup(self, ip: str) -> Dict[str, Any]:
        """Consulta Shodan para informações do IP."""
        result = {}
        api_key = self.config.api_keys.get("shodan", "")
        
        if not api_key:
            return result
        
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = {
                            "ports": data.get("ports", []),
                            "asn": data.get("asn", ""),
                            "isp": data.get("isp", ""),
                            "location": {
                                "country": data.get("country_name", ""),
                                "city": data.get("city", ""),
                            },
                            "services": [
                                {
                                    "port": svc.get("port"),
                                    "protocol": svc.get("transport", ""),
                                    "product": svc.get("product", ""),
                                    "version": svc.get("version", ""),
                                }
                                for svc in data.get("data", [])
                            ],
                        }
                        
                        self.logger.result("ASN", result["asn"])
                        self.logger.result("ISP", result["isp"])
                        self.logger.result("Portas", str(result["ports"]))
                        
        except Exception as e:
            self.logger.debug(f"Erro Shodan: {e}", self.MODULE_NAME)
        
        return result
    
    async def search_company(self, company_name: str) -> Dict[str, Any]:
        """
        Busca informações sobre empresa por nome.
        
        Args:
            company_name: Nome da empresa
        
        Returns:
            Informações da empresa
        """
        self.logger.info(f"Buscando empresa: {company_name}", self.MODULE_NAME)
        
        result = {
            "name": company_name,
            "domains": [],
            "social_profiles": [],
            "employees": [],
        }
        
        # Busca domínios potenciais
        name_clean = company_name.lower().replace(" ", "")
        potential_domains = [
            f"{name_clean}.com",
            f"{name_clean}.com.br",
            f"{name_clean}.io",
            f"{name_clean}.co",
            f"{name_clean}.net",
        ]
        
        for domain in potential_domains:
            try:
                socket.gethostbyname(domain)
                result["domains"].append(domain)
                self.logger.found(f"Domínio: {domain}", self.MODULE_NAME)
            except:
                pass
        
        return result
