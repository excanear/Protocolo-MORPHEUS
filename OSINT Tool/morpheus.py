#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          PROTOCOLO MORPHEUS                                   ║
║                         Interface de Linha de Comando                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

Framework de Inteligência de Fontes Abertas (OSINT)
Uso exclusivamente ético e legal.
"""

import asyncio
import argparse
import sys
from pathlib import Path

from morpheus.core.engine import MorpheusEngine
from morpheus.core.config import Config
from morpheus.core.logger import MorpheusLogger


def create_parser() -> argparse.ArgumentParser:
    """Cria o parser de argumentos."""
    parser = argparse.ArgumentParser(
        prog="morpheus",
        description="Protocolo Morpheus - Framework OSINT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════════════════════════╗
║ Exemplos de uso:                                                              ║
║                                                                               ║
║   # Investigação completa (auto-detecta tipo do alvo)                         ║
║   python morpheus.py --target johndoe                                         ║
║                                                                               ║
║   # Investigação de pessoa por username                                       ║
║   python morpheus.py --module identity --username johndoe                     ║
║                                                                               ║
║   # Investigação de pessoa por email                                          ║
║   python morpheus.py --module identity --email john@example.com               ║
║                                                                               ║
║   # Investigação corporativa por domínio                                      ║
║   python morpheus.py --module corporate --domain example.com                  ║
║                                                                               ║
║   # Vigilância passiva por keywords                                           ║
║   python morpheus.py --module surveillance --keywords "company,secret,api"    ║
║                                                                               ║
║   # Monitoramento contínuo                                                    ║
║   python morpheus.py --module surveillance --keywords "target" --continuous   ║
║                                                                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
    )
    
    # Modo de operação
    mode_group = parser.add_argument_group("Modo de Operação")
    mode_group.add_argument(
        "--target", "-t",
        help="Alvo da investigação (detecta tipo automaticamente)",
        type=str
    )
    mode_group.add_argument(
        "--module", "-m",
        choices=["identity", "corporate", "surveillance", "full"],
        default="full",
        help="Módulo específico a executar (default: full)"
    )
    
    # Módulo de Identidade
    identity_group = parser.add_argument_group("Módulo I: Identidade Digital")
    identity_group.add_argument(
        "--username", "-u",
        help="Username para verificar em plataformas",
        type=str
    )
    identity_group.add_argument(
        "--email", "-e",
        help="Email para analisar",
        type=str
    )
    identity_group.add_argument(
        "--name", "-n",
        help="Nome completo para buscar",
        type=str
    )
    identity_group.add_argument(
        "--phone", "-p",
        help="Número de telefone para analisar",
        type=str
    )
    
    # Módulo Corporativo
    corporate_group = parser.add_argument_group("Módulo II: Anatomia Corporativa")
    corporate_group.add_argument(
        "--domain", "-d",
        help="Domínio para investigar",
        type=str
    )
    corporate_group.add_argument(
        "--company", "-c",
        help="Nome da empresa para buscar",
        type=str
    )
    
    # Módulo de Vigilância
    surveillance_group = parser.add_argument_group("Módulo III: Vigilância Passiva")
    surveillance_group.add_argument(
        "--keywords", "-k",
        help="Palavras-chave para monitorar (separadas por vírgula)",
        type=str
    )
    surveillance_group.add_argument(
        "--continuous",
        action="store_true",
        help="Ativa modo de monitoramento contínuo"
    )
    surveillance_group.add_argument(
        "--interval",
        type=int,
        default=3600,
        help="Intervalo entre verificações em segundos (default: 3600)"
    )
    
    # Configurações de saída
    output_group = parser.add_argument_group("Configurações de Saída")
    output_group.add_argument(
        "--output", "-o",
        help="Diretório de saída para relatórios",
        type=str,
        default="./output"
    )
    output_group.add_argument(
        "--format", "-f",
        choices=["json", "html", "md", "all"],
        default="all",
        help="Formato do relatório (default: all)"
    )
    
    # Configurações gerais
    general_group = parser.add_argument_group("Configurações Gerais")
    general_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=True,
        help="Modo verboso (default: True)"
    )
    general_group.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Modo silencioso (apenas erros)"
    )
    general_group.add_argument(
        "--debug",
        action="store_true",
        help="Modo debug (informações detalhadas)"
    )
    general_group.add_argument(
        "--rate-limit",
        type=float,
        default=2.0,
        help="Requisições por segundo (default: 2.0)"
    )
    general_group.add_argument(
        "--proxy",
        type=str,
        help="Proxy HTTP/SOCKS para requisições"
    )
    general_group.add_argument(
        "--version",
        action="version",
        version="Protocolo Morpheus v1.0.0"
    )
    
    return parser


async def run_identity_module(engine: MorpheusEngine, args):
    """Executa módulo de identidade."""
    return await engine.investigate_person(
        username=args.username,
        email=args.email,
        full_name=args.name,
        phone=args.phone
    )


async def run_corporate_module(engine: MorpheusEngine, args):
    """Executa módulo corporativo."""
    return await engine.investigate_company(
        domain=args.domain,
        company_name=args.company
    )


async def run_surveillance_module(engine: MorpheusEngine, args):
    """Executa módulo de vigilância."""
    keywords = args.keywords.split(",") if args.keywords else []
    domains = [args.domain] if args.domain else None
    emails = [args.email] if args.email else None
    
    return await engine.monitor_exposure(
        keywords=keywords,
        domains=domains,
        emails=emails,
        continuous=args.continuous,
        interval=args.interval
    )


async def main_async(args):
    """Função principal assíncrona."""
    # Configura
    config = Config(
        output_dir=Path(args.output),
        rate_limit=args.rate_limit,
        verbose=not args.quiet,
        debug=args.debug,
        proxy=args.proxy,
    )
    
    # Inicializa engine
    engine = MorpheusEngine(config)
    
    # Mostra banner
    if not args.quiet:
        engine.logger.print_banner()
    
    dossier = None
    
    try:
        # Executa módulo apropriado
        if args.target:
            # Investigação completa
            dossier = await engine.full_investigation(args.target)
            
        elif args.module == "identity":
            if not any([args.username, args.email, args.name, args.phone]):
                engine.logger.error("Módulo de identidade requer --username, --email, --name ou --phone")
                return 1
            dossier = await run_identity_module(engine, args)
            
        elif args.module == "corporate":
            if not any([args.domain, args.company]):
                engine.logger.error("Módulo corporativo requer --domain ou --company")
                return 1
            dossier = await run_corporate_module(engine, args)
            
        elif args.module == "surveillance":
            if not args.keywords:
                engine.logger.error("Módulo de vigilância requer --keywords")
                return 1
            dossier = await run_surveillance_module(engine, args)
            
        else:
            # Modo full sem target
            engine.logger.error("Especifique um --target ou use --module com parâmetros específicos")
            return 1
        
        # Gera relatório
        if dossier:
            report_path = await engine.report_gen.generate(
                dossier,
                format=args.format,
                output_dir=Path(args.output)
            )
            
            engine.logger.section("INVESTIGAÇÃO CONCLUÍDA")
            engine.logger.success(f"Relatório salvo em: {report_path}")
            engine.logger.result("Tempo total", f"{dossier.execution_time:.2f}s")
            engine.logger.result("Módulos executados", str(len(dossier.modules_executed)))
            
            if dossier.errors:
                engine.logger.warning(f"Erros encontrados: {len(dossier.errors)}")
        
        return 0
        
    except KeyboardInterrupt:
        engine.logger.warning("Operação cancelada pelo usuário")
        return 130
    except Exception as e:
        engine.logger.error(f"Erro fatal: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


def main():
    """Ponto de entrada principal."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Valida argumentos
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    
    # Executa
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
