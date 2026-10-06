"""RaSTA and SCI-TDS (NeuPro BL5) vocabulary, taken from the NeuPro Lua dissectors and the telegram spec."""

from enum import IntEnum


class RastaType(IntEnum):
    CONNECTION_REQUEST = 6200
    CONNECTION_RESPONSE = 6201
    RETRANSMISSION_REQUEST = 6212
    RETRANSMISSION_RESPONSE = 6213
    DISCONNECTION_REQUEST = 6216
    HEARTBEAT = 6220
    DATA = 6240
    RETRANSMITTED_DATA = 6241


class DisconnectReason(IntEnum):
    USER_REQUEST = 0
    UNDEFINED_MESSAGE_TYPE = 1
    MESSAGE_TYPE_NOT_ALLOWED = 2
    SEQUENCE_NUMBER_ERROR = 3
    TIMEOUT = 4
    SERVICE_NOT_ALLOWED = 5
    WRONG_PROTOCOL_VERSION = 6
    RETRANSMISSION_FAILED = 7
    PROTOCOL_FAILURE = 8


SCI_PROTOCOL_TYPE_TDS = 0x20


class SciMessage(IntEnum):
    """SCI-TDS telegram codes (BTP[01..02], little-endian on the wire)."""

    KOMMANDO_AZG = 0x0001
    KOMMANDO_ACHSZAEHLFUELLSTAND_AKTUALISIERUNG = 0x0002
    KOMMANDO_AZGH = 0x0003
    MELDUNG_KOMMANDO_ABGEWIESEN = 0x0006
    MELDUNG_GFMA_BELEGUNGSZUSTAND = 0x0007
    MELDUNG_AZGH_QUITTUNG = 0x0009
    KOMMANDO_ZDP_AKTIVIERUNG = 0x000A
    MELDUNG_ZDP_BEFAHRUNGSZUSTAND = 0x000B
    # Common SCI telegrams (connection start-up)
    KOMMANDO_AUFRUESTANFORDERUNG = 0x0021
    MELDUNG_AUFRUESTBEGINN = 0x0022
    MELDUNG_AUFRUESTENDE = 0x0023
    KOMMANDO_BTP_VERSIONSABGLEICH = 0x0024
    MELDUNG_BTP_VERSIONSABGLEICH = 0x0025

    @property
    def is_command(self) -> bool:
        return self.name.startswith("KOMMANDO_")

    @property
    def spec_section(self) -> str | None:
        return SPEC_SECTION.get(self)


SPEC_SECTION = {
    SciMessage.KOMMANDO_AZG: "3.4.6",
    SciMessage.KOMMANDO_ACHSZAEHLFUELLSTAND_AKTUALISIERUNG: "3.4.7",
    SciMessage.KOMMANDO_AZGH: "3.4.8",
    SciMessage.KOMMANDO_ZDP_AKTIVIERUNG: "3.4.9",
    SciMessage.MELDUNG_KOMMANDO_ABGEWIESEN: "3.4.10",
    SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND: "3.4.11",
    SciMessage.MELDUNG_AZGH_QUITTUNG: "3.4.12",
    SciMessage.MELDUNG_ZDP_BEFAHRUNGSZUSTAND: "3.4.13",
}

# BTP header: protocol type (1) + message type (2) + sender (20) + receiver (20)
BTP_HEADER_LENGTH = 43

# Telegram lengths in bytes for BL5, verified against the RealOC capture.
BL5_TELEGRAM_LENGTH = {
    SciMessage.KOMMANDO_AZG: 44,
    SciMessage.KOMMANDO_ACHSZAEHLFUELLSTAND_AKTUALISIERUNG: 43,
    SciMessage.KOMMANDO_AZGH: 43,
    SciMessage.MELDUNG_GFMA_BELEGUNGSZUSTAND: 47,
}


class Belegung(IntEnum):
    """Belegungszustand of a GFM-A (BTP[43])."""

    UNGUELTIG = 0
    FREI = 1
    BELEGT = 2
    GESTOERT = 3
    WARTEN_AUF_ZUGFAHRT = 4
    WARTEN_AUF_QUITTUNG = 5


class Grundstellbarkeit(IntEnum):
    """Grundstellungsfähigkeit of a GFM-A (BTP[44]), BL5 coding. BL6/BL7 use 1/2 instead."""

    NICHT_GRUNDSTELLBAR = 0
    GRUNDSTELLBAR = 1


class Grundstellungsart(IntEnum):
    """Parameter of Kommando AZG."""

    AZDG = 0x01
    AZEG = 0x02
    AZVGQ = 0x03
    AZVG = 0x04


class Abweisungsgrund(IntEnum):
    """Reason in Meldung Kommando abgewiesen."""

    BETRIEBLICH = 0x01
    TECHNISCH = 0x02
