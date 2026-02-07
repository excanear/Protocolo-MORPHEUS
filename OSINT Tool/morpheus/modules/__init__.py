"""Módulos OSINT do Protocolo Morpheus."""

from morpheus.modules.identity import IdentitySynapse
from morpheus.modules.corporate import CorporateSynapse
from morpheus.modules.surveillance import SurveillanceSynapse

__all__ = ["IdentitySynapse", "CorporateSynapse", "SurveillanceSynapse"]
