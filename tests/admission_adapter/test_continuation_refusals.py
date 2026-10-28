"""Only malformed predecessor metadata/early refusal; no receipts/history constructed."""
import unittest
from dl2_adapter_fixtures import continuation_refuses


class ContinuationEarlyRefusals(unittest.TestCase):
    def test_original_counter_is_strict_zero_before_predecessor_access(self):
        """Catch rebased original recipes or booleans masquerading as continuation origins."""
        for counter in (True,False,1,-1,"0",None):
            with self.subTest(counter=counter):
                continuation_refuses(self,"bad_seed",{"collision_counter":counter},None)

    def test_missing_counter_is_not_defaulted(self):
        """Catch accepting missing original counter by silently choosing a seed origin."""
        continuation_refuses(self,"bad_value",{},None)

    def test_missing_or_wrong_predecessor_shape_fails_closed(self):
        """Catch treating no predecessor as an empty accepted history and starting fill."""
        recipe={"collision_counter":0}
        for previous in (None,[],{}, {"other":"not-a-receipt"}):
            with self.subTest(previous=previous):
                continuation_refuses(self,"bad_value",recipe,previous)

    def test_incomplete_receipt_marker_is_not_history(self):
        """Catch permissive predecessor receipt shapes without synthesizing a valid receipt."""
        for marker in (None,[],{}, {"unit_marker":"not-receipt"}):
            with self.subTest(marker=marker):
                continuation_refuses(self,"unknown_key",{"collision_counter":0},{"receipt":marker})
