"""End-to-end acceptance: the full attack scenario and a live chain-break.

This is CLAUDE.md section 8 as an automated fixture, not a manual demo. It drives
the real proxy pipeline (deterministic signatures, field-level taint, and the
trajectory rule — no model weights) through the scripted attack, then tampers a
*past* audit row directly in SQLite and proves the verifier detects it and
pinpoints the first broken link:

1-2. Scrape a page carrying a prompt-injection payload -> Guard BLOCKs it.
3.   Read a secret the agent is permitted to read     -> ALLOW.
4-5. Try to exfiltrate the secret by email            -> taint BLOCKs it before
     any inference (and a paraphrase is caught by the trajectory backstop).
6.   A past log row is edited in SQLite (a BLOCK rewritten to ALLOW).
7.   The chain verifier returns CHAIN_BROKEN with the seq of that first bad link.
"""

import json
from pathlib import Path
from typing import Any

import aiosqlite

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.verifier import ChainStatus, ChainVerifier
from secureSG.demo.driver import StepOutcome, run_demo
from secureSG.demo.scenario import DEMO_GENESIS_SEED
from secureSG.schemas.verdict import Verdict


def _silent(_message: str) -> None:
    """Swallow the demo driver's progress output during tests."""


async def _run_attack(db_path: Path) -> tuple[list[StepOutcome], str]:
    """Run the scripted attack into a fresh chain and return outcomes + genesis."""
    outcomes = await run_demo(db_path, emit=_silent)
    return outcomes, derive_genesis_hash(DEMO_GENESIS_SEED)


async def _forge_oldest_block_to_allow(db_path: Path) -> int:
    """Rewrite the oldest BLOCK entry's recorded verdict to ALLOW, in place.

    Simulates an attacker editing history to hide that a tool call was blocked.
    Returns the seq of the tampered row, asserting it is a *past* (non-tail) link.

    Time complexity: O(n) over the chain. Space complexity: O(1).
    """
    async with aiosqlite.connect(str(db_path)) as conn:
        async with conn.execute(
            "SELECT seq, payload FROM audit_log WHERE verdict = ? ORDER BY seq",
            (Verdict.BLOCK.value,),
        ) as cursor:
            block_row = await cursor.fetchone()
        async with conn.execute("SELECT MAX(seq) FROM audit_log") as cursor:
            tail_row = await cursor.fetchone()
        assert block_row is not None, "expected a BLOCK entry in the populated chain"
        assert tail_row is not None
        target_seq, payload_text = int(block_row[0]), str(block_row[1])
        assert target_seq != int(tail_row[0]), "must tamper a past, non-tail link"
        forged: dict[str, Any] = json.loads(payload_text)
        forged["verdict"] = Verdict.ALLOW.value
        await conn.execute(
            "UPDATE audit_log SET payload = ? WHERE seq = ?",
            (json.dumps(forged, sort_keys=True, separators=(",", ":")), target_seq),
        )
        await conn.commit()
    return target_seq


async def test_full_attack_blocks_every_exfiltration_path(tmp_path: Path) -> None:
    """Each scripted step hits its defense: injection, taint, then trajectory."""
    outcomes, _genesis = await _run_attack(tmp_path / "audit.db")
    assert [outcome.rule_id for outcome in outcomes] == [
        "injection.signature",
        None,
        "taint.high_to_external",
        "trajectory.sensitive_to_external",
    ]
    assert all(outcome.matched_expectation for outcome in outcomes)


async def test_audit_chain_is_intact_after_a_clean_run(tmp_path: Path) -> None:
    """A faithful run produces an unbroken SHA-256 hash chain."""
    db_path = tmp_path / "audit.db"
    _outcomes, genesis = await _run_attack(db_path)
    result = await ChainVerifier(db_path, genesis).verify()
    assert result.status is ChainStatus.CHAIN_OK
    assert result.first_invalid_seq is None


async def test_tampering_a_past_entry_breaks_the_chain_at_that_link(
    tmp_path: Path,
) -> None:
    """Editing a past log row is detected and the first broken seq is reported."""
    db_path = tmp_path / "audit.db"
    _outcomes, genesis = await _run_attack(db_path)
    verifier = ChainVerifier(db_path, genesis)
    assert (await verifier.verify()).status is ChainStatus.CHAIN_OK

    tampered_seq = await _forge_oldest_block_to_allow(db_path)

    result = await verifier.verify()
    assert result.status is ChainStatus.CHAIN_BROKEN
    assert result.first_invalid_seq == tampered_seq
