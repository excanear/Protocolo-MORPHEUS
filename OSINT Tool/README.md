# 🔮 PROTOCOLO MORPHEUS

<div align="center">

```
███╗   ███╗ ██████╗ ██████╗ ██████╗ ██╗  ██╗███████╗██╗   ██╗███████╗
████╗ ████║██╔═══██╗██╔══██╗██╔══██╗██║  ██║██╔════╝██║   ██║██╔════╝
██╔████╔██║██║   ██║██████╔╝██████╔╝███████║█████╗  ██║   ██║███████╗
██║╚██╔╝██║██║   ██║██╔══██╗██╔═══╝ ██╔══██║██╔══╝  ██║   ██║╚════██║
██║ ╚═╝ ██║╚██████╔╝██║  ██║██║     ██║  ██║███████╗╚██████╔╝███████║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝
```

**Framework de Inteligência de Fontes Abertas (OSINT)**

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

</div>

---

## 📖 Sobre

O **Protocolo Morpheus** é um framework OSINT modular desenvolvido em Python para correlação de informações publicamente acessíveis. Projetado para profissionais de segurança, investigadores e pesquisadores que necessitam construir dossiês de inteligência de forma ética e legal.

> ⚠️ **Aviso Legal**: Este framework destina-se exclusivamente para uso ético e legal. Utilize apenas para investigações autorizadas, testes de segurança em sistemas que você possui ou tem permissão, e pesquisa acadêmica.

---

## 🧠 Arquitetura Modular

O framework é composto por três módulos sinápticos principais:

### 🔷 Módulo I: Sinapse da Identidade Digital
**Alvo: Pessoa Física**

Investiga identidades digitais através de:
- Verificação de username em **100+ plataformas sociais**
- Análise de email (provedor, Gravatar, domínio)
- Busca por nome completo com geração de variações
- Análise de número de telefone (país, operadora, tipo)
- Correlação de dados para identificar conexões

### 🔷 Módulo II: Sinapse da Anatomia Corporativa
**Alvo: Empresa/Domínio**

Executa dissecação corporativa:
- Consulta WHOIS detalhada
- Enumeração de subdomínios via Certificate Transparency
- Análise completa de registros DNS
- Histórico de DNS
- Detecção de stack tecnológico
- Extração de emails corporativos
- Análise de certificados SSL
- Mapeamento de infraestrutura (Shodan)

### 🔷 Módulo III: Sinapse do Éter Digital
**Alvo: Vigilância Passiva**

Monitora exposição digital:
- Varredura de repositórios GitHub
- Busca em paste sites (Pastebin, etc.)
- Verificação de vazamentos de dados
- Geração de Google Dorks
- Análise de risco de exposição
- Monitoramento contínuo

---

## 🚀 Instalação

### Requisitos
- Python 3.9 ou superior
- pip (gerenciador de pacotes)

### Instalação Rápida

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/morpheus-protocol.git
cd morpheus-protocol

# Crie um ambiente virtual (recomendado)
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Instale as dependências
pip install -r requirements.txt

# Configure as variáveis de ambiente (opcional)
cp .env.example .env
# Edite .env com suas chaves de API
```

---

## 💻 Uso

### Interface de Linha de Comando

```bash
# Investigação completa (detecta tipo automaticamente)
python morpheus.py --target johndoe

# Investigação de pessoa por username
python morpheus.py --module identity --username johndoe

# Investigação de pessoa por email
python morpheus.py --module identity --email john@example.com

# Investigação corporativa por domínio
python morpheus.py --module corporate --domain example.com

# Vigilância passiva por keywords
python morpheus.py --module surveillance --keywords "company,secret,api"

# Monitoramento contínuo
python morpheus.py --module surveillance --keywords "target" --continuous

# Mais opções
python morpheus.py --help
```

### Uso Programático

```python
import asyncio
from morpheus.core.engine import MorpheusEngine
from morpheus.core.config import Config

async def main():
    # Configuração personalizada
    config = Config(
        rate_limit=3.0,
        verbose=True
    )
    
    # Inicializa o engine
    engine = MorpheusEngine(config)
    
    # Investigação completa
    dossier = await engine.full_investigation("target@example.com")
    
    # Ou módulos específicos
    identity = await engine.investigate_person(username="johndoe")
    corporate = await engine.investigate_company(domain="example.com")
    surveillance = await engine.monitor_exposure(keywords=["secret", "api"])
    
    print(f"Encontrados: {len(dossier.identity_data.get('platforms', {}))}")

asyncio.run(main())
```

---

## 📊 Relatórios

O Morpheus gera relatórios em múltiplos formatos:

| Formato | Descrição |
|---------|-----------|
| **JSON** | Dados estruturados para processamento programático |
| **HTML** | Relatório visual estilizado com interface moderna |
| **Markdown** | Documentação legível para compartilhamento |

Os relatórios são salvos automaticamente no diretório `./output/`.

---

## 🔑 APIs Suportadas (Opcional)

O framework funciona sem APIs externas, mas elas aumentam as capacidades:

| API | Uso | Link |
|-----|-----|------|
| **Shodan** | Mapeamento de infraestrutura | [shodan.io](https://shodan.io) |
| **Hunter.io** | Extração de emails | [hunter.io](https://hunter.io) |
| **VirusTotal** | Análise de reputação | [virustotal.com](https://virustotal.com) |
| **SecurityTrails** | Histórico DNS | [securitytrails.com](https://securitytrails.com) |
| **GitHub** | Busca em repositórios | [github.com](https://github.com/settings/tokens) |

Configure as chaves no arquivo `.env`.

---

## 📁 Estrutura do Projeto

```
morpheus-protocol/
├── morpheus/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py      # Motor principal
│   │   ├── config.py      # Configurações
│   │   └── logger.py      # Sistema de logging
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── identity.py    # Módulo I: Identidade
│   │   ├── corporate.py   # Módulo II: Corporativo
│   │   └── surveillance.py # Módulo III: Vigilância
│   └── utils/
│       ├── __init__.py
│       ├── http.py        # Cliente HTTP
│       └── report.py      # Gerador de relatórios
├── morpheus.py            # CLI principal
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## ⚙️ Configuração Avançada

### Variáveis de Ambiente

```bash
# Diretório de saída
export MORPHEUS_OUTPUT_DIR=./output

# Rate limit (requisições/segundo)
export MORPHEUS_RATE_LIMIT=2.0

# Proxy (HTTP ou SOCKS)
export MORPHEUS_PROXY=socks5://127.0.0.1:9050

# Modo verboso
export MORPHEUS_VERBOSE=true
```

### Opções de Linha de Comando

```
--output, -o     Diretório de saída
--format, -f     Formato do relatório (json/html/md/all)
--rate-limit     Requisições por segundo
--proxy          Proxy HTTP/SOCKS
--verbose, -v    Modo verboso
--quiet, -q      Modo silencioso
--debug          Modo debug
```

---

## 🛡️ Considerações de Segurança

1. **Rate Limiting**: O framework implementa rate limiting automático para evitar bloqueios
2. **Proxy Support**: Suporta proxies HTTP e SOCKS para anonimização
3. **User-Agent Rotation**: Rotaciona User-Agents para evitar fingerprinting
4. **Logs**: Todas as operações são registradas para auditoria

---

## 📜 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## ⚠️ Disclaimer

O Protocolo Morpheus é uma ferramenta de pesquisa e deve ser utilizado de forma responsável e ética. Os desenvolvedores não se responsabilizam pelo uso indevido desta ferramenta. 

**Use apenas para:**
- Investigações autorizadas
- Testes de segurança em sistemas próprios
- Pesquisa acadêmica
- Due diligence legalmente autorizada

---

<div align="center">

**Desenvolvido com 🧠 por Morpheus Protocol**

*"A verdade está lá fora, nos dados públicos."*

</div>
