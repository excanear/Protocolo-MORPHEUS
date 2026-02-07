"""
Gerador de relatórios do Protocolo Morpheus.
Produz relatórios em múltiplos formatos.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import asdict

from morpheus.core.config import Config
from morpheus.core.logger import MorpheusLogger


class ReportGenerator:
    """Gera relatórios de inteligência em múltiplos formatos."""
    
    def __init__(self, config: Config, logger: MorpheusLogger):
        self.config = config
        self.logger = logger
    
    async def generate(
        self,
        dossier,
        format: str = "all",
        output_dir: Optional[Path] = None
    ) -> Path:
        """
        Gera relatório do dossiê.
        
        Args:
            dossier: IntelligenceDossier com os dados
            format: Formato do relatório (json, html, md, all)
            output_dir: Diretório de saída
        
        Returns:
            Caminho do relatório principal
        """
        output_dir = output_dir or self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self._sanitize_filename(dossier.target)
        base_name = f"morpheus_{safe_target}_{timestamp}"
        
        paths = []
        
        if format in ("json", "all"):
            json_path = output_dir / f"{base_name}.json"
            await self._generate_json(dossier, json_path)
            paths.append(json_path)
        
        if format in ("html", "all"):
            html_path = output_dir / f"{base_name}.html"
            await self._generate_html(dossier, html_path)
            paths.append(html_path)
        
        if format in ("md", "all"):
            md_path = output_dir / f"{base_name}.md"
            await self._generate_markdown(dossier, md_path)
            paths.append(md_path)
        
        self.logger.success(f"Relatórios gerados em: {output_dir}", "REPORT")
        return paths[0] if paths else output_dir
    
    def _sanitize_filename(self, name: str) -> str:
        """Remove caracteres inválidos do nome de arquivo."""
        invalid_chars = '<>:"/\\|?*@'
        for char in invalid_chars:
            name = name.replace(char, "_")
        return name[:50]
    
    async def _generate_json(self, dossier, filepath: Path):
        """Gera relatório JSON."""
        data = self._dossier_to_dict(dossier)
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        self.logger.info(f"JSON: {filepath}", "REPORT")
    
    async def _generate_html(self, dossier, filepath: Path):
        """Gera relatório HTML estilizado."""
        data = self._dossier_to_dict(dossier)
        
        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Morpheus Report - {dossier.target}</title>
    <style>
        :root {{
            --bg-primary: #0a0a0a;
            --bg-secondary: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #eee;
            --text-secondary: #888;
            --accent: #00ff88;
            --accent-alt: #00d9ff;
            --warning: #ffaa00;
            --danger: #ff4444;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Segoe UI', 'Inter', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        header {{
            text-align: center;
            margin-bottom: 3rem;
            padding: 2rem;
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
            border-radius: 16px;
            border: 1px solid rgba(0, 255, 136, 0.2);
        }}
        
        h1 {{
            font-size: 2.5rem;
            background: linear-gradient(135deg, var(--accent), var(--accent-alt));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        
        .subtitle {{
            color: var(--text-secondary);
            font-size: 1.1rem;
        }}
        
        .target-info {{
            margin-top: 1.5rem;
            padding: 1rem;
            background: rgba(0, 255, 136, 0.1);
            border-radius: 8px;
            display: inline-block;
        }}
        
        .target-info strong {{
            color: var(--accent);
        }}
        
        .section {{
            background: var(--bg-card);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .section h2 {{
            color: var(--accent);
            font-size: 1.3rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid rgba(0, 255, 136, 0.3);
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }}
        
        .card {{
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}
        
        .card h3 {{
            color: var(--accent-alt);
            font-size: 1rem;
            margin-bottom: 0.5rem;
        }}
        
        .data-row {{
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}
        
        .data-row:last-child {{
            border-bottom: none;
        }}
        
        .data-label {{
            color: var(--text-secondary);
        }}
        
        .data-value {{
            color: var(--text-primary);
            font-weight: 500;
        }}
        
        .tag {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.85rem;
            margin: 0.25rem;
        }}
        
        .tag-success {{
            background: rgba(0, 255, 136, 0.2);
            color: var(--accent);
        }}
        
        .tag-warning {{
            background: rgba(255, 170, 0, 0.2);
            color: var(--warning);
        }}
        
        .tag-danger {{
            background: rgba(255, 68, 68, 0.2);
            color: var(--danger);
        }}
        
        .tag-info {{
            background: rgba(0, 217, 255, 0.2);
            color: var(--accent-alt);
        }}
        
        .platform-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }}
        
        .platform-item {{
            padding: 0.5rem 1rem;
            background: rgba(0, 217, 255, 0.1);
            border-radius: 8px;
            font-size: 0.9rem;
        }}
        
        .platform-item.found {{
            background: rgba(0, 255, 136, 0.2);
            border: 1px solid var(--accent);
        }}
        
        .platform-item a {{
            color: var(--accent);
            text-decoration: none;
        }}
        
        .platform-item a:hover {{
            text-decoration: underline;
        }}
        
        .risk-indicator {{
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            font-weight: 600;
            font-size: 1.2rem;
        }}
        
        .risk-low {{ background: rgba(0, 255, 136, 0.2); color: var(--accent); }}
        .risk-medium {{ background: rgba(255, 170, 0, 0.2); color: var(--warning); }}
        .risk-high {{ background: rgba(255, 68, 68, 0.2); color: var(--danger); }}
        .risk-critical {{ background: rgba(255, 0, 0, 0.3); color: #ff0000; animation: pulse 2s infinite; }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}
        
        pre {{
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.85rem;
        }}
        
        footer {{
            text-align: center;
            margin-top: 3rem;
            padding: 1rem;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        
        .timestamp {{
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>◆ PROTOCOLO MORPHEUS</h1>
            <p class="subtitle">Relatório de Inteligência de Fontes Abertas</p>
            <div class="target-info">
                <strong>Alvo:</strong> {dossier.target}<br>
                <strong>Tipo:</strong> {dossier.target_type}<br>
                <span class="timestamp">Gerado em: {dossier.timestamp.strftime("%d/%m/%Y %H:%M:%S")}</span>
            </div>
        </header>
        
        {self._generate_html_identity_section(data.get("identity_data", {}))}
        {self._generate_html_corporate_section(data.get("corporate_data", {}))}
        {self._generate_html_surveillance_section(data.get("surveillance_data", {}))}
        
        <section class="section">
            <h2>◆ Metadados da Investigação</h2>
            <div class="grid">
                <div class="card">
                    <h3>Execução</h3>
                    <div class="data-row">
                        <span class="data-label">Tempo de execução</span>
                        <span class="data-value">{dossier.execution_time:.2f}s</span>
                    </div>
                    <div class="data-row">
                        <span class="data-label">Módulos executados</span>
                        <span class="data-value">{len(dossier.modules_executed)}</span>
                    </div>
                    <div class="data-row">
                        <span class="data-label">Erros</span>
                        <span class="data-value">{len(dossier.errors)}</span>
                    </div>
                </div>
            </div>
        </section>
        
        <footer>
            <p>Gerado pelo Protocolo Morpheus v1.0.0</p>
            <p>Framework de Inteligência de Fontes Abertas</p>
        </footer>
    </div>
</body>
</html>"""
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        
        self.logger.info(f"HTML: {filepath}", "REPORT")
    
    def _generate_html_identity_section(self, data: Dict[str, Any]) -> str:
        """Gera seção HTML de identidade."""
        if not data:
            return ""
        
        platforms_html = ""
        if "platforms" in data:
            platforms = data["platforms"]
            found_list = []
            for platform, result in platforms.items():
                if hasattr(result, 'found') and result.found:
                    url = result.url if hasattr(result, 'url') else '#'
                    found_list.append(f'<div class="platform-item found"><a href="{url}" target="_blank">{platform}</a></div>')
            
            if found_list:
                platforms_html = f"""
                <div class="card">
                    <h3>Plataformas Encontradas ({len(found_list)})</h3>
                    <div class="platform-list">
                        {''.join(found_list)}
                    </div>
                </div>
                """
        
        return f"""
        <section class="section">
            <h2>◆ Sinapse da Identidade Digital</h2>
            <div class="grid">
                {platforms_html}
            </div>
        </section>
        """
    
    def _generate_html_corporate_section(self, data: Dict[str, Any]) -> str:
        """Gera seção HTML corporativa."""
        if not data:
            return ""
        
        whois_html = ""
        if "whois" in data:
            whois = data["whois"]
            whois_html = f"""
            <div class="card">
                <h3>WHOIS</h3>
                <div class="data-row">
                    <span class="data-label">Registrador</span>
                    <span class="data-value">{whois.get('registrar', 'N/A')}</span>
                </div>
                <div class="data-row">
                    <span class="data-label">Criação</span>
                    <span class="data-value">{whois.get('creation_date', 'N/A')}</span>
                </div>
                <div class="data-row">
                    <span class="data-label">Expiração</span>
                    <span class="data-value">{whois.get('expiration_date', 'N/A')}</span>
                </div>
            </div>
            """
        
        subdomains_html = ""
        if "subdomains" in data and data["subdomains"]:
            subs = data["subdomains"]
            count = len(subs) if isinstance(subs, list) else 0
            subdomains_html = f"""
            <div class="card">
                <h3>Subdomínios ({count})</h3>
                <div class="platform-list">
                    {self._format_subdomains_html(subs)}
                </div>
            </div>
            """
        
        return f"""
        <section class="section">
            <h2>◆ Sinapse da Anatomia Corporativa</h2>
            <div class="grid">
                {whois_html}
                {subdomains_html}
            </div>
        </section>
        """
    
    def _format_subdomains_html(self, subdomains) -> str:
        """Formata subdomínios para HTML."""
        if not subdomains:
            return ""
        
        items = []
        for sub in subdomains[:20]:  # Limita a 20
            if hasattr(sub, 'subdomain'):
                items.append(f'<div class="platform-item">{sub.subdomain}</div>')
            elif isinstance(sub, str):
                items.append(f'<div class="platform-item">{sub}</div>')
        
        return ''.join(items)
    
    def _generate_html_surveillance_section(self, data: Dict[str, Any]) -> str:
        """Gera seção HTML de vigilância."""
        if not data:
            return ""
        
        risk = data.get("risk_analysis", {})
        if hasattr(risk, 'overall_risk'):
            risk_level = risk.overall_risk
            risk_score = risk.risk_score
        else:
            risk_level = risk.get("overall_risk", "LOW") if isinstance(risk, dict) else "LOW"
            risk_score = risk.get("risk_score", 0) if isinstance(risk, dict) else 0
        
        risk_class = f"risk-{risk_level.lower()}"
        
        return f"""
        <section class="section">
            <h2>◆ Sinapse do Éter Digital</h2>
            <div class="grid">
                <div class="card">
                    <h3>Análise de Risco</h3>
                    <div class="risk-indicator {risk_class}">
                        Nível: {risk_level} (Score: {risk_score})
                    </div>
                </div>
            </div>
        </section>
        """
    
    async def _generate_markdown(self, dossier, filepath: Path):
        """Gera relatório Markdown."""
        data = self._dossier_to_dict(dossier)
        
        md = f"""# 🔮 PROTOCOLO MORPHEUS - Relatório de Inteligência

**Alvo:** {dossier.target}  
**Tipo:** {dossier.target_type}  
**Data:** {dossier.timestamp.strftime("%d/%m/%Y %H:%M:%S")}  
**Tempo de execução:** {dossier.execution_time:.2f}s

---

## 📋 Sumário Executivo

- Módulos executados: {', '.join(dossier.modules_executed)}
- Erros encontrados: {len(dossier.errors)}

---

"""
        
        # Seção de Identidade
        if data.get("identity_data"):
            md += "## 👤 Sinapse da Identidade Digital\n\n"
            identity = data["identity_data"]
            
            if "platforms" in identity:
                found = [p for p, r in identity["platforms"].items() 
                        if hasattr(r, 'found') and r.found]
                if found:
                    md += f"### Plataformas Encontradas ({len(found)})\n\n"
                    for platform in found:
                        result = identity["platforms"][platform]
                        url = result.url if hasattr(result, 'url') else ""
                        md += f"- **{platform}**: [{url}]({url})\n"
                    md += "\n"
            
            if "email" in identity:
                email_data = identity["email"]
                md += "### Análise de Email\n\n"
                if hasattr(email_data, 'email'):
                    md += f"- Email: {email_data.email}\n"
                    md += f"- Domínio: {email_data.domain}\n"
                    md += f"- Gravatar: {'Sim' if email_data.gravatar_exists else 'Não'}\n"
                md += "\n"
        
        # Seção Corporativa
        if data.get("corporate_data"):
            md += "## 🏢 Sinapse da Anatomia Corporativa\n\n"
            corporate = data["corporate_data"]
            
            if "whois" in corporate:
                whois = corporate["whois"]
                md += "### WHOIS\n\n"
                md += f"| Campo | Valor |\n|-------|-------|\n"
                md += f"| Registrador | {whois.get('registrar', 'N/A')} |\n"
                md += f"| Criação | {whois.get('creation_date', 'N/A')} |\n"
                md += f"| Expiração | {whois.get('expiration_date', 'N/A')} |\n"
                md += "\n"
            
            if "subdomains" in corporate:
                subs = corporate["subdomains"]
                count = len(subs) if isinstance(subs, list) else 0
                md += f"### Subdomínios ({count})\n\n"
                for sub in (subs[:20] if isinstance(subs, list) else []):
                    name = sub.subdomain if hasattr(sub, 'subdomain') else str(sub)
                    md += f"- {name}\n"
                md += "\n"
        
        # Seção de Vigilância
        if data.get("surveillance_data"):
            md += "## 🔍 Sinapse do Éter Digital\n\n"
            surveillance = data["surveillance_data"]
            
            risk = surveillance.get("risk_analysis", {})
            if risk:
                risk_level = risk.overall_risk if hasattr(risk, 'overall_risk') else risk.get("overall_risk", "LOW")
                risk_score = risk.risk_score if hasattr(risk, 'risk_score') else risk.get("risk_score", 0)
                
                md += "### Análise de Risco\n\n"
                md += f"- **Nível de Risco:** {risk_level}\n"
                md += f"- **Score:** {risk_score}\n"
                md += "\n"
        
        # Footer
        md += """---

*Relatório gerado pelo Protocolo Morpheus v1.0.0*  
*Framework de Inteligência de Fontes Abertas*
"""
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md)
        
        self.logger.info(f"Markdown: {filepath}", "REPORT")
    
    def _dossier_to_dict(self, dossier) -> Dict[str, Any]:
        """Converte dossiê para dicionário serializável."""
        def convert_value(value):
            if hasattr(value, '__dataclass_fields__'):
                return {k: convert_value(v) for k, v in asdict(value).items()}
            elif isinstance(value, dict):
                return {k: convert_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [convert_value(item) for item in value]
            elif isinstance(value, datetime):
                return value.isoformat()
            else:
                return value
        
        return {
            "target": dossier.target,
            "target_type": dossier.target_type,
            "timestamp": dossier.timestamp.isoformat(),
            "identity_data": convert_value(dossier.identity_data),
            "corporate_data": convert_value(dossier.corporate_data),
            "surveillance_data": convert_value(dossier.surveillance_data),
            "modules_executed": dossier.modules_executed,
            "execution_time": dossier.execution_time,
            "errors": dossier.errors,
        }
