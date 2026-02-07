"""
Motor principal do Protocolo Morpheus.
Orquestra todos os módulos de OSINT.
"""

import asyncio
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import json

from morpheus.core.config import Config
from morpheus.core.logger import MorpheusLogger
from morpheus.modules.identity import IdentitySynapse
from morpheus.modules.corporate import CorporateSynapse
from morpheus.modules.surveillance import SurveillanceSynapse
from morpheus.utils.report import ReportGenerator


@dataclass
class IntelligenceDossier:
    """Dossiê de inteligência consolidado."""
    
    target: str
    target_type: str  # "person", "company", "domain"
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Resultados por módulo
    identity_data: Dict[str, Any] = field(default_factory=dict)
    corporate_data: Dict[str, Any] = field(default_factory=dict)
    surveillance_data: Dict[str, Any] = field(default_factory=dict)
    
    # Metadados
    modules_executed: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return {
            "target": self.target,
            "target_type": self.target_type,
            "timestamp": self.timestamp.isoformat(),
            "identity_data": self.identity_data,
            "corporate_data": self.corporate_data,
            "surveillance_data": self.surveillance_data,
            "modules_executed": self.modules_executed,
            "execution_time": self.execution_time,
            "errors": self.errors,
        }
    
    def save(self, filepath: Path):
        """Salva dossiê em JSON."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)


class MorpheusEngine:
    """
    Motor central do Protocolo Morpheus.
    Coordena os três módulos sinápticos para coleta de inteligência.
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.logger = MorpheusLogger(
            verbose=self.config.verbose,
            debug=self.config.debug
        )
        
        # Inicializa módulos
        self.identity = IdentitySynapse(self.config, self.logger)
        self.corporate = CorporateSynapse(self.config, self.logger)
        self.surveillance = SurveillanceSynapse(self.config, self.logger)
        
        # Gerador de relatórios
        self.report_gen = ReportGenerator(self.config, self.logger)
    
    async def investigate_person(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None,
        full_name: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> IntelligenceDossier:
        """
        MÓDULO I: Sinapse da Identidade Digital
        Investiga pessoa física através de identificadores.
        """
        target = username or email or full_name or "unknown"
        dossier = IntelligenceDossier(target=target, target_type="person")
        
        self.logger.section("SINAPSE DA IDENTIDADE DIGITAL")
        self.logger.info(f"Iniciando investigação de pessoa: {target}", "IDENTITY")
        
        start_time = datetime.now()
        
        try:
            # Busca por username em plataformas
            if username:
                self.logger.subsection("Verificação de Username em Plataformas")
                platforms = await self.identity.check_username(username)
                dossier.identity_data["platforms"] = platforms
                dossier.identity_data["username"] = username
            
            # Busca informações de email
            if email:
                self.logger.subsection("Análise de Email")
                email_info = await self.identity.analyze_email(email)
                dossier.identity_data["email"] = email_info
            
            # Busca por nome completo
            if full_name:
                self.logger.subsection("Busca por Nome Completo")
                name_results = await self.identity.search_by_name(full_name)
                dossier.identity_data["name_search"] = name_results
            
            # Busca por telefone
            if phone:
                self.logger.subsection("Análise de Telefone")
                phone_info = await self.identity.analyze_phone(phone)
                dossier.identity_data["phone"] = phone_info
            
            # Correlação de dados
            if len(dossier.identity_data) > 1:
                self.logger.subsection("Correlação de Dados")
                correlations = await self.identity.correlate_data(dossier.identity_data)
                dossier.identity_data["correlations"] = correlations
            
            dossier.modules_executed.append("identity")
            
        except Exception as e:
            self.logger.error(f"Erro no módulo de identidade: {e}", "IDENTITY")
            dossier.errors.append(str(e))
        
        dossier.execution_time = (datetime.now() - start_time).total_seconds()
        return dossier
    
    async def investigate_company(
        self,
        domain: Optional[str] = None,
        company_name: Optional[str] = None,
    ) -> IntelligenceDossier:
        """
        MÓDULO II: Sinapse da Anatomia Corporativa
        Investiga empresa/domínio através de análise de infraestrutura.
        """
        target = domain or company_name or "unknown"
        dossier = IntelligenceDossier(target=target, target_type="company")
        
        self.logger.section("SINAPSE DA ANATOMIA CORPORATIVA")
        self.logger.info(f"Iniciando investigação corporativa: {target}", "CORPORATE")
        
        start_time = datetime.now()
        
        try:
            if domain:
                # Informações WHOIS
                self.logger.subsection("Informações WHOIS")
                whois_data = await self.corporate.whois_lookup(domain)
                dossier.corporate_data["whois"] = whois_data
                
                # Enumeração de subdomínios
                self.logger.subsection("Enumeração de Subdomínios")
                subdomains = await self.corporate.enumerate_subdomains(domain)
                dossier.corporate_data["subdomains"] = subdomains
                
                # Análise de DNS
                self.logger.subsection("Análise de Registros DNS")
                dns_records = await self.corporate.analyze_dns(domain)
                dossier.corporate_data["dns"] = dns_records
                
                # Histórico DNS
                self.logger.subsection("Histórico de DNS")
                dns_history = await self.corporate.dns_history(domain)
                dossier.corporate_data["dns_history"] = dns_history
                
                # Detecção de tecnologias
                self.logger.subsection("Detecção de Stack Tecnológico")
                tech_stack = await self.corporate.detect_technologies(domain)
                dossier.corporate_data["technologies"] = tech_stack
                
                # Extração de emails
                self.logger.subsection("Extração de Emails Corporativos")
                emails = await self.corporate.extract_emails(domain)
                dossier.corporate_data["emails"] = emails
                
                # Certificados SSL
                self.logger.subsection("Análise de Certificados SSL")
                ssl_info = await self.corporate.analyze_ssl(domain)
                dossier.corporate_data["ssl"] = ssl_info
                
                # Portas e serviços (via Shodan se disponível)
                self.logger.subsection("Mapeamento de Infraestrutura")
                infrastructure = await self.corporate.map_infrastructure(domain)
                dossier.corporate_data["infrastructure"] = infrastructure
            
            if company_name:
                # Busca por nome da empresa
                self.logger.subsection("Busca por Nome da Empresa")
                company_info = await self.corporate.search_company(company_name)
                dossier.corporate_data["company_info"] = company_info
            
            dossier.modules_executed.append("corporate")
            
        except Exception as e:
            self.logger.error(f"Erro no módulo corporativo: {e}", "CORPORATE")
            dossier.errors.append(str(e))
        
        dossier.execution_time = (datetime.now() - start_time).total_seconds()
        return dossier
    
    async def monitor_exposure(
        self,
        keywords: List[str],
        domains: Optional[List[str]] = None,
        emails: Optional[List[str]] = None,
        continuous: bool = False,
        interval: int = 3600,
    ) -> IntelligenceDossier:
        """
        MÓDULO III: Sinapse do Éter Digital
        Monitora exposição em repositórios públicos e vazamentos.
        """
        target = ", ".join(keywords[:3])
        dossier = IntelligenceDossier(target=target, target_type="surveillance")
        
        self.logger.section("SINAPSE DO ÉTER DIGITAL")
        self.logger.info(f"Iniciando vigilância passiva: {target}", "SURVEILLANCE")
        
        start_time = datetime.now()
        
        try:
            all_targets = keywords + (domains or []) + (emails or [])
            
            # Monitoramento de GitHub
            self.logger.subsection("Varredura de Repositórios GitHub")
            github_results = await self.surveillance.search_github(all_targets)
            dossier.surveillance_data["github"] = github_results
            
            # Monitoramento de Pastebin e similares
            self.logger.subsection("Varredura de Paste Sites")
            paste_results = await self.surveillance.search_paste_sites(all_targets)
            dossier.surveillance_data["pastes"] = paste_results
            
            # Verificação de vazamentos conhecidos
            self.logger.subsection("Verificação de Vazamentos de Dados")
            breach_results = await self.surveillance.check_breaches(emails or [])
            dossier.surveillance_data["breaches"] = breach_results
            
            # Busca em motores de busca
            self.logger.subsection("Varredura em Motores de Busca")
            search_results = await self.surveillance.search_engines(all_targets)
            dossier.surveillance_data["search_results"] = search_results
            
            # Análise de exposição
            self.logger.subsection("Análise de Risco de Exposição")
            risk_analysis = await self.surveillance.analyze_exposure_risk(dossier.surveillance_data)
            dossier.surveillance_data["risk_analysis"] = risk_analysis
            
            dossier.modules_executed.append("surveillance")
            
            # Monitoramento contínuo
            if continuous:
                self.logger.alert("Modo de monitoramento contínuo ativado", "SURVEILLANCE")
                # Implementar loop de monitoramento
            
        except Exception as e:
            self.logger.error(f"Erro no módulo de vigilância: {e}", "SURVEILLANCE")
            dossier.errors.append(str(e))
        
        dossier.execution_time = (datetime.now() - start_time).total_seconds()
        return dossier
    
    async def full_investigation(
        self,
        target: str,
        target_type: str = "auto",
    ) -> IntelligenceDossier:
        """
        Investigação completa usando todos os módulos aplicáveis.
        """
        self.logger.print_banner()
        self.logger.section("INVESTIGAÇÃO COMPLETA")
        self.logger.info(f"Alvo: {target}", "ENGINE")
        
        # Auto-detecta tipo do alvo
        if target_type == "auto":
            target_type = self._detect_target_type(target)
            self.logger.info(f"Tipo detectado: {target_type}", "ENGINE")
        
        # Executa módulos apropriados
        if target_type == "email":
            dossier = await self.investigate_person(email=target)
            # Também verifica vazamentos
            surv = await self.monitor_exposure(keywords=[target], emails=[target])
            dossier.surveillance_data = surv.surveillance_data
            
        elif target_type == "username":
            dossier = await self.investigate_person(username=target)
            surv = await self.monitor_exposure(keywords=[target])
            dossier.surveillance_data = surv.surveillance_data
            
        elif target_type == "domain":
            dossier = await self.investigate_company(domain=target)
            surv = await self.monitor_exposure(keywords=[target], domains=[target])
            dossier.surveillance_data = surv.surveillance_data
            
        elif target_type == "phone":
            dossier = await self.investigate_person(phone=target)
            
        else:
            # Trata como nome completo
            dossier = await self.investigate_person(full_name=target)
            surv = await self.monitor_exposure(keywords=[target])
            dossier.surveillance_data = surv.surveillance_data
        
        # Gera relatório
        self.logger.section("GERAÇÃO DE RELATÓRIO")
        report_path = await self.report_gen.generate(dossier)
        self.logger.success(f"Relatório salvo em: {report_path}", "ENGINE")
        
        return dossier
    
    def _detect_target_type(self, target: str) -> str:
        """Detecta automaticamente o tipo do alvo."""
        import re
        
        # Email
        if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
            return "email"
        
        # Domínio
        if re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", target):
            return "domain"
        
        # Telefone
        if re.match(r"^[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[0-9]{3,}[-\s\.]?[0-9]{4,}$", target):
            return "phone"
        
        # Username (sem espaços)
        if " " not in target and len(target) <= 30:
            return "username"
        
        # Default: nome completo
        return "name"
    
    def run(self, target: str, target_type: str = "auto") -> IntelligenceDossier:
        """Executa investigação de forma síncrona."""
        return asyncio.run(self.full_investigation(target, target_type))
