from sqlalchemy import (
    Column, Integer, String, ForeignKey, UniqueConstraint,
    DateTime, Boolean, func
)
from app.database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    display_name = Column(String, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Decision(Base):
    __tablename__ = "decisions"
    id = Column(Integer, primary_key=True)

    # título e data da votação
    title = Column(String, nullable=False)
    occurred_at = Column(DateTime(timezone=True), nullable=True)

    # origem oficial (camara/senado) + id externo
    source = Column(String, nullable=True)      # "camara" | "senado"
    external_id = Column(String, nullable=True) # id da API oficial
    url = Column(String, nullable=True)
    has_official_votes = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    archived = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_decision_source_external"),
    )

class Politician(Base):
    __tablename__ = "politicians"
    id = Column(Integer, primary_key=True)

    name = Column(String, nullable=False)
    role = Column(String, nullable=False)      # deputado_federal | senador
    scope = Column(String, nullable=False)     # federal
    uf = Column(String, nullable=True)

    source = Column(String, nullable=False)    # "camara" | "senado"
    external_id = Column(String, nullable=False)

    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_politician_source_external"),
    )

class CitizenVote(Base):
    __tablename__ = "citizen_votes"
    id = Column(Integer, primary_key=True)
    decision_id = Column(Integer, ForeignKey("decisions.id"), nullable=False)
    voter_id = Column(String, nullable=False)
    choice = Column(String, nullable=False)  # concordo | discordo
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("decision_id", "voter_id", name="uq_citizen_vote_decision_voter"),
    )


class WalletTx(Base):
    __tablename__ = "wallet_txs"
    id = Column(Integer, primary_key=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Integer, nullable=False)  # em T$ (inteiro)
    kind = Column(String, nullable=False)     # ex: vote_reward

    decision_id = Column(Integer, ForeignKey("decisions.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    __table_args__ = (
        UniqueConstraint("user_id", "decision_id", "kind", name="uq_wallet_tx_user_decision_kind"),
    )

class OfficialVote(Base):
    __tablename__ = "official_votes"
    id = Column(Integer, primary_key=True)
    decision_id = Column(Integer, ForeignKey("decisions.id"), nullable=False)
    politician_id = Column(Integer, ForeignKey("politicians.id"), nullable=False)

    # padronizado no Unebrasil
    choice = Column(String, nullable=False)  # concordo | discordo | abstencao | ausente

    __table_args__ = (
        UniqueConstraint("decision_id", "politician_id", name="uq_official_vote_decision_politician"),
    )
