"""Case identity and four tiny direct draw vectors; never full partition generation."""
import copy
import hashlib
import unittest
from dl2_admission_fixtures import g, field_document, loop_recipe, refuse_without_fill


class CaseIdentityTests(unittest.TestCase):
    def test_missing_empty_and_length_framing_golden_hashes(self):
        """Catch hashing physical empty bytes instead of presence/count/length-framed cases."""
        vectors=((False,[],"c45f41ac63a379681e2df22930fe85e8ccffc1d42420d9a7f488770933b93c6a"),
                 (True,[],"8c433ce39711db5f15b71730d5444b8ecaee02a20becc13b4bdb362c3cd3e3de"),
                 (True,[b'A',b'B'],"ab4066a84a43032f894e33fcbb422a2d68e8d97dd1e253373421e4c30319a6af"),
                 (True,[b'AB'],"422c5fdbf17f0c7214c54f6651a3257d6ebdf7479cbda0db193242f92769b89e"))
        for present,records,digest in vectors:
            with self.subTest(present=present,records=records):
                case=g.bundle(present,records)
                self.assertIs(case["input_present"],present)
                self.assertEqual(case["records"],records)
                self.assertEqual(case["case_sha256"],digest)

    def test_record_order_multiplicity_and_raw_lf_are_bound(self):
        """Catch sorting/deduplication/newline normalization before full-case hashing."""
        cases=[g.bundle(True,rows) for rows in ([b'A',b'B'],[b'B',b'A'],[b'A',b'A'],[b'A'],[b'A\n'])]
        self.assertEqual(len({c["case_sha256"] for c in cases}),5)
        self.assertEqual(cases[-1]["records"],[b'A\n'])
        # bundle is framing-only; encode_value separately rejects LF input values.

    def test_bundle_strict_presence_types_and_count_refuse(self):
        """Catch absent-with-records, bool coercion and non-byte row acceptance."""
        for present,rows,code in ((1,[],"bad_scenario"),(True,(),"bad_scenario"),
             (False,[b'A'],"bad_record_count"),(True,[b'A']*65,"bad_record_count"),
             (True,['A'],"bad_value"),(True,[bytearray(b'A')],"bad_value")):
            with self.subTest(present=present,rows_type=type(rows)):
                with self.assertRaises(g.AdmissionError) as caught:g.bundle(present,rows)
                self.assertEqual(caught.exception.code,code)
        self.assertEqual(len(g.bundle(True,[b'A']*64)["records"]),64)


class SeedDrawTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Four returned synthetic bundles total. No native generate/prepare calls.
        cls.identity=["unit-v1","builder-unit","unit-program","unit-task","loop"]
        cls.seed=bytes.fromhex("aa83b99b1ab1442476f4aab13bca32d5ae7e44aaeea53228f2f8de3cf862940a")
        field={"name":"X","kind":"X","width":33}
        cls.zero=g.seeded_case([field],cls.seed,0,3)
        cls.next=g.seeded_case([field],cls.seed,1,1)
        changed=["unit-v1","builder-unit","unit-program","changed-unit","loop"]
        cls.changed=g.seeded_case([field],hashlib.sha256(g.canonical(changed)).digest(),0,1)
        numeric=[{"name":"N","kind":"9","width":2,"digits":2,"scale":0,"signed":False},
                 {"name":"S","kind":"S9","width":3,"digits":2,"scale":1,"signed":True}]
        cls.numeric=g.seeded_case(numeric,cls.seed,0,1)

    def test_seed_tuple_canonical_identity_and_counter_zero_golden(self):
        """Catch seed tuple reordering or starting original draws at counter1."""
        self.assertEqual(g.canonical(self.identity),b'["unit-v1","builder-unit","unit-program","unit-task","loop"]')
        self.assertEqual(hashlib.sha256(g.canonical(self.identity)).digest(),self.seed)
        self.assertTrue(self.zero["input_present"])
        self.assertEqual(len(self.zero["records"]),2) # sentinel draw modulo3 is1
        self.assertEqual(self.zero["records"],[
            bytes.fromhex("37362849424e576824247c3d5f35467b7c665735454f28233b7c7630396c33375d"),
            bytes.fromhex("564255425d3a5c4c30605a3a632c622a5037454b395f4d244e3e6d266129736453")])

    def test_x_block_continuation_and_separate_counter_draw(self):
        """Catch repeated block0 for X byte33 or ignoring U64 counter advancement."""
        self.assertEqual(self.zero["records"][0][-1:],b']')
        self.assertEqual(self.next["records"],[bytes.fromhex("65215e2f515626314155645b78456a51456f207e4f45285b3355515b52763e6154")])
        self.assertEqual(self.next["records"][0][-1:],b'T')
        self.assertNotEqual(self.zero["case_sha256"],self.next["case_sha256"])

    def test_task_seed_domain_separation_and_numeric_field_indices(self):
        """Catch reusing original task seed or sharing one draw across numeric field indices."""
        self.assertEqual(self.changed["records"],[bytes.fromhex("3a614a365e5d4a326646465c452e42482f2121662973327a27475b7478295f674e")])
        self.assertNotEqual(self.changed["records"][0],self.zero["records"][0])
        # Published SHA draw0 modulo100=85; field1 draw modulo199-99=91.
        self.assertEqual(self.numeric["records"],[b'85+91'])


class EarlyRecipeRefusalTests(unittest.TestCase):
    def test_full_loop_count_floor_is_not_relaxed_for_units(self):
        """Catch accepting a tiny target_count instead of immutable loop floor32."""
        doc=field_document()
        for count in (0,1,4,True,31,33):
            recipe=loop_recipe(doc);recipe["fill"]["target_count"]=count
            with self.subTest(count=count):refuse_without_fill(self,doc,recipe,"bad_record_count")

    def test_original_counter_requires_strict_integer_zero(self):
        """Catch using continuation counter as a rewritten original recipe seed origin."""
        doc=field_document()
        for counter in (True,False,1,-1,"0"):
            recipe=loop_recipe(doc);recipe["collision_counter"]=counter
            with self.subTest(counter=counter):refuse_without_fill(self,doc,recipe,"bad_seed")

    def test_seed_tuple_and_raw_field_hash_cannot_substitute(self):
        """Catch identity tuple mismatch or raw field artifact hash replacing canonical commitment."""
        doc=field_document();recipe=loop_recipe(doc)
        recipe["fill"]["seed_material"][3]="different-task"
        refuse_without_fill(self,doc,recipe,"bad_seed")
        recipe=loop_recipe(doc)
        raw=b' '+g.canonical(doc)+b'\n'
        recipe["fields_sha256"]=hashlib.sha256(raw).hexdigest()
        self.assertNotEqual(recipe["fields_sha256"],g.digest(doc))
        refuse_without_fill(self,doc,recipe,"bad_hash")

    def test_recipe_closed_shape_scenario_and_row_refusals(self):
        """Catch unsupported recipe keys, missing/empty records or incomplete field maps."""
        doc=field_document()
        recipe=loop_recipe(doc);recipe["split"]="dev"
        refuse_without_fill(self,doc,recipe,"unknown_key")
        for scenario,rows,code in (("other",[],"bad_scenario"),("empty",[{"N":"1"}],"bad_record_count"),
                                  ("records",[],"bad_record_count"),("records",[{}],"missing_field")):
            recipe=loop_recipe(doc);recipe.update(scenario=scenario,records=rows)
            refuse_without_fill(self,doc,recipe,code)

    def test_boundary_ids_vocabulary_and_eof_field_refusals(self):
        """Catch duplicate labels/unknown boundary kind or null field for non-eof obligation."""
        doc=field_document();base={"id":"unit-zero","field":"N","kind":"zero",
                                   "scenario":"records","records":[{"N":"0","S":"0","X":""}]}
        for change in ({"kind":"invented"},{"field":None},{"field":"FOREIGN"}):
            recipe=loop_recipe(doc);recipe["boundaries"]=[dict(base,**change)]
            refuse_without_fill(self,doc,recipe,"bad_boundary")
        recipe=loop_recipe(doc);recipe["boundaries"]=[base,copy.deepcopy(base)]
        refuse_without_fill(self,doc,recipe,"bad_boundary")

    def test_excluded_explicit_boundary_refuses_before_fill(self):
        """Catch silently skipping an explicitly required cross-partition collision."""
        doc=field_document();recipe=loop_recipe(doc)
        boundary={"id":"unit-empty","field":None,"kind":"eof","scenario":"empty","records":[]}
        recipe["boundaries"]=[boundary]
        empty="8c433ce39711db5f15b71730d5444b8ecaee02a20becc13b4bdb362c3cd3e3de"
        refuse_without_fill(self,doc,recipe,"partition_collision",[empty])
        recipe=loop_recipe(doc)
        refuse_without_fill(self,doc,recipe,"bad_hash",["bad"])
