"""DAO Voting System in Python.

Core features:
- Proposal creation with title/description/deadline
- YES/NO voting with one vote per member per proposal
- Wallet-style signature verification for identity checks
- Immutable, hash-linked vote ledger for transparency
- Public vote inspection and result summaries

Optional advanced features included:
- Token-weighted voting
- Proposal comments
- Notifications
- Admin dashboard metrics
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
from pathlib import Path
import secrets
from typing import Any, Dict, List


class VoteChoice(str, Enum):
    YES = "YES"
    NO = "NO"


class Wallet:
    """Simple wallet simulator for signing actions.

    This uses HMAC for demonstration so the example remains dependency-free.
    """

    def __init__(self, private_key: str | None = None) -> None:
        self._private_key = private_key or secrets.token_hex(32)
        self.address = "0x" + hashlib.sha256(self._private_key.encode("utf-8")).hexdigest()[:40]

    def sign(self, message: str) -> str:
        return hmac.new(
            self._private_key.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, message: str, signature: str) -> bool:
        expected = self.sign(message)
        return hmac.compare_digest(expected, signature)

    @property
    def private_key(self) -> str:
        return self._private_key


@dataclass
class Member:
    address: str
    display_name: str
    tokens: int = 1
    can_create_proposals: bool = True
    is_admin: bool = False
    joined_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class VoteTx:
    proposal_id: str
    voter: str
    choice: VoteChoice
    weight: int
    timestamp: str
    signature: str


@dataclass(frozen=True)
class VoteBlock:
    index: int
    previous_hash: str
    tx: VoteTx
    block_hash: str


@dataclass
class Comment:
    author: str
    text: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Proposal:
    proposal_id: str
    title: str
    description: str
    deadline: datetime
    creator: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    yes_votes: int = 0
    no_votes: int = 0
    yes_weight: int = 0
    no_weight: int = 0
    voted_addresses: set[str] = field(default_factory=set)
    comments: List[Comment] = field(default_factory=list)
    finalized: bool = False

    def is_open(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return current < self.deadline and not self.finalized


class VoteLedger:
    """Append-only, hash-linked ledger of votes."""

    def __init__(self) -> None:
        genesis_tx = VoteTx(
            proposal_id="GENESIS",
            voter="SYSTEM",
            choice=VoteChoice.YES,
            weight=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            signature="GENESIS",
        )
        genesis_hash = self._hash_block_parts(0, "0" * 64, genesis_tx)
        self.blocks: List[VoteBlock] = [
            VoteBlock(index=0, previous_hash="0" * 64, tx=genesis_tx, block_hash=genesis_hash)
        ]

    @staticmethod
    def _hash_block_parts(index: int, previous_hash: str, tx: VoteTx) -> str:
        body = {
            "index": index,
            "previous_hash": previous_hash,
            "tx": {
                "proposal_id": tx.proposal_id,
                "voter": tx.voter,
                "choice": tx.choice.value,
                "weight": tx.weight,
                "timestamp": tx.timestamp,
                "signature": tx.signature,
            },
        }
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def add_vote(self, tx: VoteTx) -> VoteBlock:
        previous = self.blocks[-1]
        index = previous.index + 1
        block_hash = self._hash_block_parts(index, previous.block_hash, tx)
        block = VoteBlock(index=index, previous_hash=previous.block_hash, tx=tx, block_hash=block_hash)
        self.blocks.append(block)
        return block

    def verify(self) -> bool:
        for i, block in enumerate(self.blocks):
            expected_hash = self._hash_block_parts(block.index, block.previous_hash, block.tx)
            if expected_hash != block.block_hash:
                return False
            if i == 0:
                continue
            if block.previous_hash != self.blocks[i - 1].block_hash:
                return False
        return True

    def votes_for_proposal(self, proposal_id: str) -> List[VoteBlock]:
        return [b for b in self.blocks[1:] if b.tx.proposal_id == proposal_id]


class DAOVotingSystem:
    def __init__(self) -> None:
        self.members: Dict[str, Member] = {}
        self._wallets: Dict[str, Wallet] = {}
        self.proposals: Dict[str, Proposal] = {}
        self.ledger = VoteLedger()
        self.notifications: Dict[str, List[str]] = {}
        self._proposal_counter = 0

    @staticmethod
    def _canonical_action(action: str, payload: Dict[str, Any]) -> str:
        data = {"action": action, **payload}
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def login_message(nonce: str) -> str:
        return DAOVotingSystem._canonical_action("login", {"nonce": nonce})

    @staticmethod
    def create_proposal_message(title: str, description: str, deadline: datetime) -> str:
        if deadline.tzinfo is None:
            normalized_deadline = deadline.replace(tzinfo=timezone.utc)
        else:
            normalized_deadline = deadline.astimezone(timezone.utc)
        return DAOVotingSystem._canonical_action(
            "create_proposal",
            {
                "title": title,
                "description": description,
                "deadline": normalized_deadline.isoformat(),
            },
        )

    @staticmethod
    def vote_message(proposal_id: str, choice: VoteChoice | str, token_weighted: bool = False) -> str:
        normalized = VoteChoice(choice).value
        return DAOVotingSystem._canonical_action(
            "cast_vote",
            {"proposal_id": proposal_id, "choice": normalized, "token_weighted": token_weighted},
        )

    @staticmethod
    def comment_message(proposal_id: str, text: str) -> str:
        return DAOVotingSystem._canonical_action(
            "add_comment",
            {"proposal_id": proposal_id, "text": text},
        )

    def register_member(
        self,
        wallet: Wallet,
        display_name: str,
        tokens: int = 1,
        can_create_proposals: bool = True,
        is_admin: bool = False,
    ) -> Member:
        if wallet.address in self.members:
            raise ValueError("Member already registered")

        if tokens < 0:
            raise ValueError("tokens must be >= 0")

        member = Member(
            address=wallet.address,
            display_name=display_name,
            tokens=tokens,
            can_create_proposals=can_create_proposals,
            is_admin=is_admin,
        )
        self.members[wallet.address] = member
        self._wallets[wallet.address] = wallet
        self.notifications[wallet.address] = ["Welcome to the DAO."]
        return member

    def authenticate(self, address: str, nonce: str, signature: str) -> bool:
        if address not in self.members:
            return False
        message = self.login_message(nonce)
        return self._wallets[address].verify(message, signature)

    def _verify_action_signature(self, address: str, message: str, signature: str) -> None:
        if address not in self.members:
            raise PermissionError("Only registered DAO members are allowed")
        if not self._wallets[address].verify(message, signature):
            raise PermissionError("Invalid wallet signature")

    @staticmethod
    def _normalize_deadline(deadline: datetime) -> datetime:
        if deadline.tzinfo is None:
            return deadline.replace(tzinfo=timezone.utc)
        return deadline.astimezone(timezone.utc)

    def create_proposal(
        self,
        creator_address: str,
        title: str,
        description: str,
        deadline: datetime,
        signature: str,
    ) -> Proposal:
        if not title.strip():
            raise ValueError("title cannot be empty")

        member = self.members.get(creator_address)
        if not member:
            raise PermissionError("Only registered DAO members are allowed")
        if not member.can_create_proposals:
            raise PermissionError("Member does not have proposal creation permission")

        normalized_deadline = self._normalize_deadline(deadline)
        if normalized_deadline <= datetime.now(timezone.utc):
            raise ValueError("deadline must be in the future")

        message = self.create_proposal_message(title, description, normalized_deadline)
        self._verify_action_signature(creator_address, message, signature)

        self._proposal_counter += 1
        proposal_id = f"P-{self._proposal_counter:04d}"
        proposal = Proposal(
            proposal_id=proposal_id,
            title=title,
            description=description,
            deadline=normalized_deadline,
            creator=creator_address,
        )
        self.proposals[proposal_id] = proposal

        for address in self.notifications:
            if address == creator_address:
                continue
            self.notifications[address].append(f"New proposal {proposal_id}: {title}")

        return proposal

    def cast_vote(
        self,
        voter_address: str,
        proposal_id: str,
        choice: VoteChoice | str,
        signature: str,
        token_weighted: bool = False,
    ) -> VoteBlock:
        member = self.members.get(voter_address)
        if not member:
            raise PermissionError("Only registered DAO members can vote")

        proposal = self.proposals.get(proposal_id)
        if not proposal:
            raise ValueError("Proposal does not exist")
        if not proposal.is_open():
            raise RuntimeError("Voting is closed for this proposal")
        if voter_address in proposal.voted_addresses:
            raise RuntimeError("Member has already voted on this proposal")

        normalized_choice = VoteChoice(choice)
        message = self.vote_message(proposal_id, normalized_choice, token_weighted)
        self._verify_action_signature(voter_address, message, signature)

        weight = member.tokens if token_weighted else 1
        tx = VoteTx(
            proposal_id=proposal_id,
            voter=voter_address,
            choice=normalized_choice,
            weight=weight,
            timestamp=datetime.now(timezone.utc).isoformat(),
            signature=signature,
        )
        block = self.ledger.add_vote(tx)

        proposal.voted_addresses.add(voter_address)
        if normalized_choice is VoteChoice.YES:
            proposal.yes_votes += 1
            proposal.yes_weight += weight
        else:
            proposal.no_votes += 1
            proposal.no_weight += weight

        return block

    def add_comment(self, author_address: str, proposal_id: str, text: str, signature: str) -> Comment:
        if not text.strip():
            raise ValueError("Comment text cannot be empty")
        if author_address not in self.members:
            raise PermissionError("Only registered DAO members can comment")

        proposal = self.proposals.get(proposal_id)
        if not proposal:
            raise ValueError("Proposal does not exist")

        message = self.comment_message(proposal_id, text)
        self._verify_action_signature(author_address, message, signature)

        comment = Comment(author=author_address, text=text)
        proposal.comments.append(comment)
        return comment

    def get_results(self, proposal_id: str) -> Dict[str, Any]:
        proposal = self.proposals.get(proposal_id)
        if not proposal:
            raise ValueError("Proposal does not exist")

        return {
            "proposal_id": proposal.proposal_id,
            "title": proposal.title,
            "yes_votes": proposal.yes_votes,
            "no_votes": proposal.no_votes,
            "yes_weight": proposal.yes_weight,
            "no_weight": proposal.no_weight,
            "total_voters": proposal.yes_votes + proposal.no_votes,
            "total_weight": proposal.yes_weight + proposal.no_weight,
            "open": proposal.is_open(),
            "deadline": proposal.deadline.isoformat(),
        }

    def get_public_votes(self, proposal_id: str) -> List[Dict[str, Any]]:
        if proposal_id not in self.proposals:
            raise ValueError("Proposal does not exist")

        public_records: List[Dict[str, Any]] = []
        for block in self.ledger.votes_for_proposal(proposal_id):
            public_records.append(
                {
                    "block_index": block.index,
                    "proposal_id": block.tx.proposal_id,
                    "voter": block.tx.voter,
                    "choice": block.tx.choice.value,
                    "weight": block.tx.weight,
                    "timestamp": block.tx.timestamp,
                    "block_hash": block.block_hash,
                    "previous_hash": block.previous_hash,
                }
            )
        return public_records

    def verify_vote_integrity(self) -> bool:
        return self.ledger.verify()

    def get_notifications(self, address: str) -> List[str]:
        if address not in self.notifications:
            raise PermissionError("Unknown member")
        return list(self.notifications[address])

    def finalize_expired_proposals(self, now: datetime | None = None) -> List[str]:
        current = now or datetime.now(timezone.utc)
        finalized_ids: List[str] = []

        for proposal in self.proposals.values():
            if proposal.finalized:
                continue
            if current < proposal.deadline:
                continue

            proposal.finalized = True
            finalized_ids.append(proposal.proposal_id)
            result = f"Results for {proposal.proposal_id}: YES={proposal.yes_votes}, NO={proposal.no_votes}"
            for address in self.notifications:
                self.notifications[address].append(result)

        return finalized_ids

    def admin_dashboard(self, admin_address: str) -> Dict[str, Any]:
        member = self.members.get(admin_address)
        if not member or not member.is_admin:
            raise PermissionError("Admin access required")

        total_votes = sum(p.yes_votes + p.no_votes for p in self.proposals.values())
        open_proposals = sum(1 for p in self.proposals.values() if p.is_open())
        closed_proposals = len(self.proposals) - open_proposals

        participation: Dict[str, int] = {}
        for proposal in self.proposals.values():
            for voter in proposal.voted_addresses:
                participation[voter] = participation.get(voter, 0) + 1

        return {
            "total_members": len(self.members),
            "total_proposals": len(self.proposals),
            "open_proposals": open_proposals,
            "closed_proposals": closed_proposals,
            "total_votes": total_votes,
            "ledger_valid": self.verify_vote_integrity(),
            "top_participants": sorted(participation.items(), key=lambda item: item[1], reverse=True)[:5],
        }

    @staticmethod
    def _datetime_to_iso(value: datetime) -> str:
        if value.tzinfo is None:
            normalized = value.replace(tzinfo=timezone.utc)
        else:
            normalized = value.astimezone(timezone.utc)
        return normalized.isoformat()

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def to_dict(self) -> Dict[str, Any]:
        members_data: List[Dict[str, Any]] = []
        for address, member in self.members.items():
            wallet = self._wallets.get(address)
            notifications = self.notifications.get(address, [])
            members_data.append(
                {
                    "address": member.address,
                    "display_name": member.display_name,
                    "name": member.display_name,
                    "tokens": member.tokens,
                    "can_create_proposals": member.can_create_proposals,
                    "canCreate": member.can_create_proposals,
                    "is_admin": member.is_admin,
                    "isAdmin": member.is_admin,
                    "joined_at": self._datetime_to_iso(member.joined_at),
                    "joinedAt": self._datetime_to_iso(member.joined_at),
                    "private_key": wallet.private_key if wallet else "",
                    "privateKey": wallet.private_key if wallet else "",
                    "notifications": list(notifications),
                }
            )

        proposals_data: List[Dict[str, Any]] = []
        for proposal in self.proposals.values():
            comments = [
                {
                    "author": comment.author,
                    "text": comment.text,
                    "created_at": self._datetime_to_iso(comment.created_at),
                    "createdAt": self._datetime_to_iso(comment.created_at),
                }
                for comment in proposal.comments
            ]
            proposals_data.append(
                {
                    "proposal_id": proposal.proposal_id,
                    "id": proposal.proposal_id,
                    "title": proposal.title,
                    "description": proposal.description,
                    "deadline": self._datetime_to_iso(proposal.deadline),
                    "deadlineMs": int(proposal.deadline.timestamp() * 1000),
                    "creator": proposal.creator,
                    "created_at": self._datetime_to_iso(proposal.created_at),
                    "createdAt": self._datetime_to_iso(proposal.created_at),
                    "yes_votes": proposal.yes_votes,
                    "yesVotes": proposal.yes_votes,
                    "no_votes": proposal.no_votes,
                    "noVotes": proposal.no_votes,
                    "yes_weight": proposal.yes_weight,
                    "yesWeight": proposal.yes_weight,
                    "no_weight": proposal.no_weight,
                    "noWeight": proposal.no_weight,
                    "voted_addresses": sorted(proposal.voted_addresses),
                    "voters": sorted(proposal.voted_addresses),
                    "comments": comments,
                    "finalized": proposal.finalized,
                }
            )

        ledger_data: List[Dict[str, Any]] = []
        for block in self.ledger.blocks:
            ledger_data.append(
                {
                    "index": block.index,
                    "previous_hash": block.previous_hash,
                    "tx": {
                        "proposal_id": block.tx.proposal_id,
                        "voter": block.tx.voter,
                        "choice": block.tx.choice.value,
                        "weight": block.tx.weight,
                        "timestamp": block.tx.timestamp,
                        "signature": block.tx.signature,
                    },
                    "block_hash": block.block_hash,
                }
            )

        return {
            "version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "members": members_data,
            "proposals": proposals_data,
            "ledger": ledger_data,
            "proposal_counter": self._proposal_counter,
            "proposalCounter": self._proposal_counter,
            "activeWallet": next(iter(self.members.keys()), None),
        }

    def save_json(self, path: str | Path) -> None:
        output_path = Path(path)
        output_path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DAOVotingSystem":
        dao = cls()
        dao.members = {}
        dao._wallets = {}
        dao.proposals = {}
        dao.notifications = {}
        dao.ledger = VoteLedger()
        dao._proposal_counter = 0

        raw_members = data.get("members", [])
        if not isinstance(raw_members, list):
            raw_members = []

        for raw_member in raw_members:
            if not isinstance(raw_member, dict):
                continue

            address = str(raw_member.get("address", "")).strip()
            private_key = str(
                raw_member.get("private_key")
                or raw_member.get("privateKey")
                or ""
            ).strip()
            if not address or not private_key:
                continue

            wallet = Wallet(private_key=private_key)
            if wallet.address != address:
                raise ValueError(f"Wallet key/address mismatch for member: {address}")

            joined_at_raw = raw_member.get("joined_at") or raw_member.get("joinedAt")
            joined_at = cls._parse_datetime(str(joined_at_raw)) if joined_at_raw else datetime.now(timezone.utc)

            member = Member(
                address=address,
                display_name=str(raw_member.get("display_name") or raw_member.get("name") or "Member"),
                tokens=max(0, cls._safe_int(raw_member.get("tokens"), 1)),
                can_create_proposals=bool(
                    raw_member.get("can_create_proposals", raw_member.get("canCreate", True))
                ),
                is_admin=bool(raw_member.get("is_admin", raw_member.get("isAdmin", False))),
                joined_at=joined_at,
            )

            dao.members[address] = member
            dao._wallets[address] = wallet
            notes = raw_member.get("notifications")
            if isinstance(notes, list):
                dao.notifications[address] = [str(note) for note in notes]
            else:
                dao.notifications[address] = ["Welcome to the DAO."]

        raw_proposals = data.get("proposals", [])
        if not isinstance(raw_proposals, list):
            raw_proposals = []

        max_counter = 0
        for raw_proposal in raw_proposals:
            if not isinstance(raw_proposal, dict):
                continue

            proposal_id = str(raw_proposal.get("proposal_id") or raw_proposal.get("id") or "").strip()
            if not proposal_id:
                continue

            created_raw = raw_proposal.get("created_at") or raw_proposal.get("createdAt")
            created_at = cls._parse_datetime(str(created_raw)) if created_raw else datetime.now(timezone.utc)

            deadline_raw = raw_proposal.get("deadline")
            if deadline_raw:
                deadline = cls._parse_datetime(str(deadline_raw))
            else:
                deadline_ms = raw_proposal.get("deadlineMs")
                if deadline_ms is None:
                    deadline = datetime.now(timezone.utc) + timedelta(hours=1)
                else:
                    try:
                        deadline = datetime.fromtimestamp(float(deadline_ms) / 1000, tz=timezone.utc)
                    except (TypeError, ValueError):
                        deadline = datetime.now(timezone.utc) + timedelta(hours=1)

            comments_raw = raw_proposal.get("comments", [])
            comments: List[Comment] = []
            if isinstance(comments_raw, list):
                for raw_comment in comments_raw:
                    if not isinstance(raw_comment, dict):
                        continue
                    comment_created_raw = raw_comment.get("created_at") or raw_comment.get("createdAt")
                    comment_created = (
                        cls._parse_datetime(str(comment_created_raw))
                        if comment_created_raw
                        else datetime.now(timezone.utc)
                    )
                    comments.append(
                        Comment(
                            author=str(raw_comment.get("author", "")),
                            text=str(raw_comment.get("text", "")),
                            created_at=comment_created,
                        )
                    )

            voted_raw = raw_proposal.get("voted_addresses", raw_proposal.get("voters", []))
            voted_addresses = set()
            if isinstance(voted_raw, list):
                voted_addresses = {str(address) for address in voted_raw}

            proposal = Proposal(
                proposal_id=proposal_id,
                title=str(raw_proposal.get("title", "")),
                description=str(raw_proposal.get("description", "")),
                deadline=deadline,
                creator=str(raw_proposal.get("creator", "")),
                created_at=created_at,
                yes_votes=cls._safe_int(raw_proposal.get("yes_votes", raw_proposal.get("yesVotes", 0)), 0),
                no_votes=cls._safe_int(raw_proposal.get("no_votes", raw_proposal.get("noVotes", 0)), 0),
                yes_weight=cls._safe_int(raw_proposal.get("yes_weight", raw_proposal.get("yesWeight", 0)), 0),
                no_weight=cls._safe_int(raw_proposal.get("no_weight", raw_proposal.get("noWeight", 0)), 0),
                voted_addresses=voted_addresses,
                comments=comments,
                finalized=bool(raw_proposal.get("finalized", False)),
            )
            dao.proposals[proposal_id] = proposal

            if proposal_id.startswith("P-"):
                suffix = proposal_id[2:]
                if suffix.isdigit():
                    max_counter = max(max_counter, int(suffix))

        raw_ledger = data.get("ledger", [])
        if isinstance(raw_ledger, list) and raw_ledger:
            parsed_blocks: List[VoteBlock] = []
            for raw_block in raw_ledger:
                if not isinstance(raw_block, dict):
                    continue
                tx_data = raw_block.get("tx")
                if not isinstance(tx_data, dict):
                    continue

                raw_choice = str(tx_data.get("choice", "YES")).upper()
                choice = VoteChoice.YES if raw_choice not in {"YES", "NO"} else VoteChoice(raw_choice)
                tx = VoteTx(
                    proposal_id=str(tx_data.get("proposal_id", "")),
                    voter=str(tx_data.get("voter", "")),
                    choice=choice,
                    weight=cls._safe_int(tx_data.get("weight"), 0),
                    timestamp=str(tx_data.get("timestamp", datetime.now(timezone.utc).isoformat())),
                    signature=str(tx_data.get("signature", "")),
                )
                block_index = cls._safe_int(raw_block.get("index"), 0)
                previous_hash = str(raw_block.get("previous_hash", "0" * 64))
                block_hash = str(raw_block.get("block_hash", ""))
                if not block_hash:
                    block_hash = VoteLedger._hash_block_parts(block_index, previous_hash, tx)
                parsed_blocks.append(
                    VoteBlock(
                        index=block_index,
                        previous_hash=previous_hash,
                        tx=tx,
                        block_hash=block_hash,
                    )
                )
            if parsed_blocks:
                dao.ledger.blocks = parsed_blocks

        raw_counter = data.get("proposal_counter", data.get("proposalCounter"))
        saved_counter = cls._safe_int(raw_counter, 0)
        dao._proposal_counter = saved_counter if saved_counter > 0 else max_counter

        for address in dao.members:
            dao.notifications.setdefault(address, ["Welcome to the DAO."])

        return dao

    @classmethod
    def load_json(cls, path: str | Path) -> "DAOVotingSystem":
        input_path = Path(path)
        raw = input_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Invalid JSON structure")
        return cls.from_dict(data)


def _build_demo_system() -> tuple[DAOVotingSystem, str]:
    dao = DAOVotingSystem()

    alice_wallet = Wallet()
    bob_wallet = Wallet()

    dao.register_member(alice_wallet, "Alice", tokens=10, can_create_proposals=True, is_admin=True)
    dao.register_member(bob_wallet, "Bob", tokens=3)

    deadline = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=30)

    create_msg = dao.create_proposal_message(
        "Fund Open Source Tooling",
        "Allocate treasury funds to developer tooling grants.",
        deadline,
    )
    proposal = dao.create_proposal(
        creator_address=alice_wallet.address,
        title="Fund Open Source Tooling",
        description="Allocate treasury funds to developer tooling grants.",
        deadline=deadline,
        signature=alice_wallet.sign(create_msg),
    )

    vote_msg = dao.vote_message(proposal.proposal_id, VoteChoice.YES, token_weighted=True)
    dao.cast_vote(
        voter_address=bob_wallet.address,
        proposal_id=proposal.proposal_id,
        choice=VoteChoice.YES,
        signature=bob_wallet.sign(vote_msg),
        token_weighted=True,
    )
    return dao, proposal.proposal_id


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DAO Voting System demo and JSON import/export.")
    parser.add_argument(
        "--import-json",
        dest="import_json",
        help="Load DAO state from a JSON file (supports Python and HTML export formats).",
    )
    parser.add_argument(
        "--export-json",
        dest="export_json",
        help="Save current DAO state to a JSON file.",
    )
    args = parser.parse_args()

    if args.import_json:
        dao = DAOVotingSystem.load_json(args.import_json)
    else:
        dao, _ = _build_demo_system()

    proposal_id = next(iter(dao.proposals.keys()), None)
    if proposal_id:
        print("Results:", json.dumps(dao.get_results(proposal_id), indent=2))
        print("Public votes:", json.dumps(dao.get_public_votes(proposal_id), indent=2))
    else:
        print("No proposals found.")

    if args.export_json:
        dao.save_json(args.export_json)
        print(f"Saved DAO state to: {args.export_json}")
