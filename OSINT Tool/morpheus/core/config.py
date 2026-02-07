"""
Configurações centrais do Protocolo Morpheus.
"""

import os
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from pathlib import Path


@dataclass
class Config:
    """Configuração global do framework."""
    
    # Diretórios
    output_dir: Path = field(default_factory=lambda: Path("./output"))
    cache_dir: Path = field(default_factory=lambda: Path("./.morpheus_cache"))
    
    # Rate limiting (requisições por segundo)
    rate_limit: float = 2.0
    request_timeout: int = 30
    max_retries: int = 3
    
    # User agents para requisições
    user_agents: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ])
    
    # APIs (configurar com suas próprias chaves)
    api_keys: Dict[str, str] = field(default_factory=lambda: {
        "shodan": os.getenv("SHODAN_API_KEY", ""),
        "hunter": os.getenv("HUNTER_API_KEY", ""),
        "virustotal": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "securitytrails": os.getenv("SECURITYTRAILS_API_KEY", ""),
        "github": os.getenv("GITHUB_TOKEN", ""),
    })
    
    # Proxy (opcional)
    proxy: Optional[str] = None
    
    # Verbosidade
    verbose: bool = True
    debug: bool = False
    
    def __post_init__(self):
        """Cria diretórios necessários."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def from_env(cls) -> "Config":
        """Carrega configuração de variáveis de ambiente."""
        return cls(
            output_dir=Path(os.getenv("MORPHEUS_OUTPUT_DIR", "./output")),
            rate_limit=float(os.getenv("MORPHEUS_RATE_LIMIT", "2.0")),
            proxy=os.getenv("MORPHEUS_PROXY"),
            verbose=os.getenv("MORPHEUS_VERBOSE", "true").lower() == "true",
            debug=os.getenv("MORPHEUS_DEBUG", "false").lower() == "true",
        )


# Plataformas para verificação de username
SOCIAL_PLATFORMS = {
    "github": "https://github.com/{username}",
    "twitter": "https://twitter.com/{username}",
    "instagram": "https://www.instagram.com/{username}/",
    "facebook": "https://www.facebook.com/{username}",
    "linkedin": "https://www.linkedin.com/in/{username}",
    "reddit": "https://www.reddit.com/user/{username}",
    "youtube": "https://www.youtube.com/@{username}",
    "tiktok": "https://www.tiktok.com/@{username}",
    "pinterest": "https://www.pinterest.com/{username}/",
    "tumblr": "https://{username}.tumblr.com/",
    "medium": "https://medium.com/@{username}",
    "devto": "https://dev.to/{username}",
    "stackoverflow": "https://stackoverflow.com/users/{username}",
    "hackernews": "https://news.ycombinator.com/user?id={username}",
    "keybase": "https://keybase.io/{username}",
    "gitlab": "https://gitlab.com/{username}",
    "bitbucket": "https://bitbucket.org/{username}/",
    "twitch": "https://www.twitch.tv/{username}",
    "spotify": "https://open.spotify.com/user/{username}",
    "soundcloud": "https://soundcloud.com/{username}",
    "behance": "https://www.behance.net/{username}",
    "dribbble": "https://dribbble.com/{username}",
    "flickr": "https://www.flickr.com/people/{username}/",
    "vimeo": "https://vimeo.com/{username}",
    "patreon": "https://www.patreon.com/{username}",
    "telegram": "https://t.me/{username}",
    "discord": "https://discord.com/users/{username}",
    "snapchat": "https://www.snapchat.com/add/{username}",
    "clubhouse": "https://www.clubhouse.com/@{username}",
    "mastodon": "https://mastodon.social/@{username}",
    "threads": "https://www.threads.net/@{username}",
    "bluesky": "https://bsky.app/profile/{username}",
    "quora": "https://www.quora.com/profile/{username}",
    "producthunt": "https://www.producthunt.com/@{username}",
    "angellist": "https://angel.co/u/{username}",
    "aboutme": "https://about.me/{username}",
    "gravatar": "https://gravatar.com/{username}",
    "wordpress": "https://{username}.wordpress.com/",
    "blogger": "https://{username}.blogspot.com/",
    "wix": "https://{username}.wixsite.com/",
    "slack": "https://{username}.slack.com/",
    "trello": "https://trello.com/{username}",
    "npmjs": "https://www.npmjs.com/~{username}",
    "pypi": "https://pypi.org/user/{username}/",
    "rubygems": "https://rubygems.org/profiles/{username}",
    "codepen": "https://codepen.io/{username}",
    "replit": "https://replit.com/@{username}",
    "kaggle": "https://www.kaggle.com/{username}",
    "huggingface": "https://huggingface.co/{username}",
    "leetcode": "https://leetcode.com/{username}/",
    "hackerrank": "https://www.hackerrank.com/{username}",
    "codeforces": "https://codeforces.com/profile/{username}",
    "chess": "https://www.chess.com/member/{username}",
    "lichess": "https://lichess.org/@/{username}",
    "steam": "https://steamcommunity.com/id/{username}",
    "xbox": "https://www.xbox.com/en-US/play/user/{username}",
    "playstation": "https://psnprofiles.com/{username}",
    "itch": "https://{username}.itch.io/",
    "roblox": "https://www.roblox.com/users/profile?username={username}",
    "ebay": "https://www.ebay.com/usr/{username}",
    "etsy": "https://www.etsy.com/shop/{username}",
    "fiverr": "https://www.fiverr.com/{username}",
    "upwork": "https://www.upwork.com/freelancers/~{username}",
    "buymeacoffee": "https://www.buymeacoffee.com/{username}",
    "kofi": "https://ko-fi.com/{username}",
    "gumroad": "https://{username}.gumroad.com/",
    "substack": "https://{username}.substack.com/",
    "notion": "https://www.notion.so/{username}",
    "linktree": "https://linktr.ee/{username}",
    "carrd": "https://{username}.carrd.co/",
    "500px": "https://500px.com/p/{username}",
    "unsplash": "https://unsplash.com/@{username}",
    "pexels": "https://www.pexels.com/@{username}",
    "vsco": "https://vsco.co/{username}/gallery",
    "myspace": "https://myspace.com/{username}",
    "deviantart": "https://www.deviantart.com/{username}",
    "artstation": "https://www.artstation.com/{username}",
    "newgrounds": "https://{username}.newgrounds.com/",
    "pornhub": "https://www.pornhub.com/users/{username}",
    "openstreetmap": "https://www.openstreetmap.org/user/{username}",
    "geocaching": "https://www.geocaching.com/p/?u={username}",
    "strava": "https://www.strava.com/athletes/{username}",
    "goodreads": "https://www.goodreads.com/{username}",
    "letterboxd": "https://letterboxd.com/{username}/",
    "last.fm": "https://www.last.fm/user/{username}",
    "rateyourmusic": "https://rateyourmusic.com/~{username}",
    "discogs": "https://www.discogs.com/user/{username}",
    "bandcamp": "https://{username}.bandcamp.com/",
    "mixcloud": "https://www.mixcloud.com/{username}/",
    "dailymotion": "https://www.dailymotion.com/{username}",
    "rumble": "https://rumble.com/user/{username}",
    "odysee": "https://odysee.com/@{username}",
    "bitchute": "https://www.bitchute.com/channel/{username}/",
    "minds": "https://www.minds.com/{username}",
    "gab": "https://gab.com/{username}",
    "parler": "https://parler.com/{username}",
    "truth_social": "https://truthsocial.com/@{username}",
    "gettr": "https://gettr.com/user/{username}",
    "pinterest_br": "https://br.pinterest.com/{username}/",
    "yelp": "https://www.yelp.com/user_details?userid={username}",
    "tripadvisor": "https://www.tripadvisor.com/members/{username}",
    "airbnb": "https://www.airbnb.com/users/show/{username}",
    "couchsurfing": "https://www.couchsurfing.com/people/{username}",
    "duolingo": "https://www.duolingo.com/profile/{username}",
    "memrise": "https://www.memrise.com/user/{username}/",
    "coursera": "https://www.coursera.org/user/{username}",
    "udemy": "https://www.udemy.com/user/{username}/",
    "skillshare": "https://www.skillshare.com/user/{username}",
}

# Domínios de email para verificação
EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com",
    "icloud.com", "aol.com", "zoho.com", "mail.com", "yandex.com",
    "gmx.com", "fastmail.com", "tutanota.com", "pm.me", "hey.com"
]

# Extensões comuns para busca de subdomínios
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "admin", "api", "app", "blog", "cdn", "cloud", "cms", "cpanel", "dashboard",
    "db", "dev", "dns", "docs", "download", "files", "forum", "git", "gitlab",
    "help", "home", "img", "images", "imap", "jira", "jenkins", "kubernetes",
    "k8s", "ldap", "login", "m", "mobile", "monitor", "mysql", "news", "owa",
    "panel", "portal", "postgres", "prod", "production", "proxy", "rdp", "remote",
    "repo", "s3", "secure", "server", "shop", "ssh", "ssl", "stage", "staging",
    "static", "stats", "status", "store", "support", "test", "testing", "tools",
    "upload", "video", "vpn", "web", "webdisk", "wiki", "ws", "www1", "www2",
]
