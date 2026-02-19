import unittest
from datetime import datetime, timedelta, timezone

from dao_voting import DAOVotingSystem, VoteBlock, VoteChoice, Wallet


class TestDAOVotingSystem(unittest.TestCase):
    def setUp(self) -> None:
        self.dao = DAOVotingSystem()
        self.alice = Wallet("alice-private-key")
        self.bob = Wallet("bob-private-key")
        self.charlie = Wallet("charlie-private-key")

        self.dao.register_member(
            self.alice,
            "Alice",
            tokens=10,
            can_create_proposals=True,
            is_admin=True,
        )
        self.dao.register_member(
            self.bob,
            "Bob",
            tokens=3,
            can_create_proposals=True,
            is_admin=False,
        )
        self.dao.register_member(
            self.charlie,
            "Charlie",
            tokens=0,
            can_create_proposals=False,
            is_admin=False,
        )

    def _create_default_proposal(self) -> str:
        deadline = datetime.now(timezone.utc) + timedelta(hours=1)
        title = "Fund Research"
        description = "Allocate funds to research grants"
        create_msg = self.dao.create_proposal_message(title, description, deadline)
        proposal = self.dao.create_proposal(
            creator_address=self.alice.address,
            title=title,
            description=description,
            deadline=deadline,
            signature=self.alice.sign(create_msg),
        )
        return proposal.proposal_id

    def test_wallet_authentication(self) -> None:
        nonce = "session-1"
        msg = self.dao.login_message(nonce)
        self.assertTrue(self.dao.authenticate(self.alice.address, nonce, self.alice.sign(msg)))
        self.assertFalse(self.dao.authenticate(self.alice.address, nonce, "bad-signature"))

    def test_member_without_permission_cannot_create_proposal(self) -> None:
        deadline = datetime.now(timezone.utc) + timedelta(hours=1)
        title = "Unauthorized"
        description = "Should fail"
        create_msg = self.dao.create_proposal_message(title, description, deadline)
        with self.assertRaises(PermissionError):
            self.dao.create_proposal(
                creator_address=self.charlie.address,
                title=title,
                description=description,
                deadline=deadline,
                signature=self.charlie.sign(create_msg),
            )

    def test_only_registered_member_can_vote(self) -> None:
        proposal_id = self._create_default_proposal()
        outsider = Wallet("outsider-private-key")
        vote_msg = self.dao.vote_message(proposal_id, VoteChoice.YES)

        with self.assertRaises(PermissionError):
            self.dao.cast_vote(
                voter_address=outsider.address,
                proposal_id=proposal_id,
                choice=VoteChoice.YES,
                signature=outsider.sign(vote_msg),
            )

    def test_member_can_vote_only_once(self) -> None:
        proposal_id = self._create_default_proposal()
        vote_msg = self.dao.vote_message(proposal_id, VoteChoice.YES)

        self.dao.cast_vote(
            voter_address=self.bob.address,
            proposal_id=proposal_id,
            choice=VoteChoice.YES,
            signature=self.bob.sign(vote_msg),
        )

        with self.assertRaises(RuntimeError):
            self.dao.cast_vote(
                voter_address=self.bob.address,
                proposal_id=proposal_id,
                choice=VoteChoice.NO,
                signature=self.bob.sign(self.dao.vote_message(proposal_id, VoteChoice.NO)),
            )

    def test_weighted_and_unweighted_results(self) -> None:
        proposal_id = self._create_default_proposal()

        bob_vote = self.dao.vote_message(proposal_id, VoteChoice.YES, token_weighted=True)
        self.dao.cast_vote(
            voter_address=self.bob.address,
            proposal_id=proposal_id,
            choice=VoteChoice.YES,
            signature=self.bob.sign(bob_vote),
            token_weighted=True,
        )

        alice_vote = self.dao.vote_message(proposal_id, VoteChoice.NO, token_weighted=False)
        self.dao.cast_vote(
            voter_address=self.alice.address,
            proposal_id=proposal_id,
            choice=VoteChoice.NO,
            signature=self.alice.sign(alice_vote),
            token_weighted=False,
        )

        results = self.dao.get_results(proposal_id)
        self.assertEqual(results["yes_votes"], 1)
        self.assertEqual(results["no_votes"], 1)
        self.assertEqual(results["yes_weight"], 3)
        self.assertEqual(results["no_weight"], 1)

    def test_voting_stops_after_deadline(self) -> None:
        proposal_id = self._create_default_proposal()
        self.dao.proposals[proposal_id].deadline = datetime.now(timezone.utc) - timedelta(seconds=1)

        vote_msg = self.dao.vote_message(proposal_id, VoteChoice.YES)
        with self.assertRaises(RuntimeError):
            self.dao.cast_vote(
                voter_address=self.bob.address,
                proposal_id=proposal_id,
                choice=VoteChoice.YES,
                signature=self.bob.sign(vote_msg),
            )

    def test_public_votes_and_ledger_integrity(self) -> None:
        proposal_id = self._create_default_proposal()
        vote_msg = self.dao.vote_message(proposal_id, VoteChoice.YES)

        self.dao.cast_vote(
            voter_address=self.bob.address,
            proposal_id=proposal_id,
            choice=VoteChoice.YES,
            signature=self.bob.sign(vote_msg),
        )

        public_votes = self.dao.get_public_votes(proposal_id)
        self.assertEqual(len(public_votes), 1)
        self.assertEqual(public_votes[0]["voter"], self.bob.address)
        self.assertTrue(self.dao.verify_vote_integrity())

        original = self.dao.ledger.blocks[1]
        self.dao.ledger.blocks[1] = VoteBlock(
            index=original.index,
            previous_hash="f" * 64,
            tx=original.tx,
            block_hash=original.block_hash,
        )
        self.assertFalse(self.dao.verify_vote_integrity())

    def test_comments_notifications_and_dashboard(self) -> None:
        proposal_id = self._create_default_proposal()

        bob_notifications = self.dao.get_notifications(self.bob.address)
        self.assertTrue(any("New proposal" in note for note in bob_notifications))

        comment_text = "I support this proposal."
        comment_msg = self.dao.comment_message(proposal_id, comment_text)
        self.dao.add_comment(
            author_address=self.bob.address,
            proposal_id=proposal_id,
            text=comment_text,
            signature=self.bob.sign(comment_msg),
        )
        self.assertEqual(len(self.dao.proposals[proposal_id].comments), 1)

        self.dao.proposals[proposal_id].deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
        finalized = self.dao.finalize_expired_proposals()
        self.assertIn(proposal_id, finalized)

        alice_notifications = self.dao.get_notifications(self.alice.address)
        self.assertTrue(any("Results for" in note for note in alice_notifications))

        dashboard = self.dao.admin_dashboard(self.alice.address)
        self.assertEqual(dashboard["total_members"], 3)
        self.assertGreaterEqual(dashboard["total_proposals"], 1)


if __name__ == "__main__":
    unittest.main()