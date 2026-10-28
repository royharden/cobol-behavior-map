"""Spec-intended schema/decimal/DISPLAY unit vectors; no oracle observations."""
import copy
import hashlib
import unittest
from dl2_admission_fixtures import g, field_document


class SchemaEncodingTests(unittest.TestCase):
    def refuses(self, code, function, *args):
        with self.assertRaises(g.AdmissionError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)

    def test_strict_json_nested_duplicates_refuse(self):
        """Catch duplicate keys being silently overwritten, including nested mappings."""
        for raw in (b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}'):
            with self.subTest(raw=raw): self.refuses("duplicate_key", g.load_document, raw)

    def test_json_numeric_encoding_and_syntax_refusals(self):
        """Catch floats/constants/BOM/invalid UTF8 or non-byte documents entering schema validation."""
        for raw in (b'1.0', b'1e2', b'NaN', b'Infinity', b'-Infinity', b'123456789012345678901',
                    b'\xef\xbb\xbf{}', b'\xff', b'{} trailing', b'{', '{}', bytearray(b'{}')):
            with self.subTest(raw=raw): self.refuses("bad_value", g.load_document, raw)
        self.assertEqual(g.load_document(b'{"x":-123,"y":true,"z":null}'), {"x":-123,"y":True,"z":None})

    def test_canonical_json_raw_bytes_and_digest_namespaces(self):
        """Catch raw artifact digest substitution for canonical inner document commitment."""
        first=b'{ "b":2, "a":"\\u00e9" }\n'
        second=b'{"a":"\\u00e9","b":2}'
        left,right=g.load_document(first),g.load_document(second)
        self.assertEqual(left,right)
        self.assertEqual(g.canonical(left), b'{"a":"\\u00e9","b":2}')
        self.assertNotEqual(hashlib.sha256(first).hexdigest(),hashlib.sha256(second).hexdigest())
        self.assertEqual(g.digest(left),hashlib.sha256(second).hexdigest())
        self.assertNotEqual(g.digest(left),hashlib.sha256(first).hexdigest())
        self.assertNotEqual(g.digest(["a","b"]),g.digest(["b","a"]))

    def test_closed_keys_strict_integer_identifier_hash(self):
        """Catch bool-as-int and permissive shape/identifier/hash acceptance."""
        for obj in ({"a":1,"b":2},{},[],None): self.refuses("unknown_key",g.keys,obj,"a")
        for value in (True,False,1.0,"1",-1,3): self.refuses("field_limit",g.integer,value,0,2)
        self.assertEqual(g.integer(0,0,2),0);self.assertEqual(g.integer(2,0,2),2)
        for value in ("A","a/","a " ,"é","",True,"a"*65): self.refuses("bad_identifier",g.identifier,value)
        for value in ("A"*64,"0"*63,"g"*64,True): self.refuses("bad_hash",g.hash_value,value)
        self.assertEqual(g.identifier("unit-a_1"),"unit-a_1")
        self.assertEqual(g.hash_value("a"*64),"a"*64)

    def test_layout_metadata_and_record_encoding_are_exact(self):
        """Catch dropped sign byte/implied scale, reordered fields or alpha trimming."""
        doc=field_document();before=copy.deepcopy(doc);fields=g.validate_fields(doc)
        self.assertEqual(doc,before)
        self.assertEqual([(f["name"],f["kind"],f["digits"],f["signed"]) for f in fields],
                         [("N","9",3,False),("S","S9",2,True),("X","X",2,False)])
        self.assertEqual(g.encode_record({"X":"A","S":"-0.0","N":"1.2"},fields),b'012-00A ')
        self.assertEqual(g.encode_record({"N":"99.9","S":"9.9","X":" ~"},fields),b'999+99 ~')

    def test_external_packed_sign_layout_and_unknown_keys_refuse(self):
        """Catch external packed fields, sign shorthand, gaps, width and scale disagreement."""
        for key,value in (("usage","COMP-3"),("sign","leading"),("offset",1),("width",4),("scale",True),("pic","9(0)")):
            doc=field_document();doc["fields"][0][key]=value
            with self.subTest(key=key): self.refuses("bad_layout_or_sign",g.validate_fields,doc)
        for location in ("root","field"):
            doc=field_document();(doc if location=="root" else doc["fields"][0])["unknown"]=0
            self.refuses("unknown_key",g.validate_fields,doc)
        doc=field_document();doc["fields"][1]["name"]="N"
        self.refuses("bad_identifier",g.validate_fields,doc)
        doc=field_document();doc["record_width"]=9
        self.refuses("bad_layout_or_sign",g.validate_fields,doc)

    def test_layout_numeric_digit_scale_and_field_count_limits(self):
        """Catch allowing nine numeric digits, scale5 or empty/33field documents."""
        for pic,scale in (("9(9)",0),("9(1)V9(5)",5)):
            doc=field_document();doc["fields"][0].update(pic=pic,scale=scale)
            self.refuses("field_limit",g.validate_fields,doc)
        for fields in ([],field_document()["fields"]*11):
            doc=field_document();doc["fields"]=fields
            self.refuses("field_limit",g.validate_fields,doc)
        doc=field_document();doc["manifest_version"]=True
        self.refuses("manifest_version",g.validate_fields,doc)

    def test_decimal_strings_do_not_round_or_accept_alternate_syntax(self):
        """Catch floating conversion, exponent/plus/space syntax and silently rounded fraction."""
        for value,scale,expected in (("0001.2",2,120),("-1.25",2,-125),("0",4,0),("-0.00",2,0)):
            self.assertEqual(g.units(value,scale),expected)
        for value in ("+1"," 1","1 ","1e2",".1","1.","1,0","1.001",1,True):
            self.refuses("bad_value",g.units,value,2)
        self.refuses("value_out_of_range",g.units,"123456789",0)
        self.assertEqual(g.decimal_string(-125,2),"-1.25")
        self.assertEqual(g.decimal_string(1,3),"0.001")
        self.assertEqual(g.decimal_string(12,0),"12")

    def test_signed_negative_zero_unsigned_refusal_and_range(self):
        """Catch erasing lexical minus zero or allowing unsigned negative input."""
        unsigned,signed,alpha=g.validate_fields(field_document())
        self.assertEqual(g.encode_value("-0.0",signed),b'-00')
        self.assertEqual(g.encode_value("0",signed),b'+00')
        self.assertEqual(g.encode_value("-9.9",signed),b'-99')
        for value in ("-0","-0.0","-1"):self.refuses("negative_unsigned",g.encode_value,value,unsigned)
        self.refuses("value_out_of_range",g.encode_value,"100.0",unsigned)
        self.refuses("value_out_of_range",g.encode_value,"10.0",signed)

    def test_alpha_fit_and_complete_record_refusals_preserve_pointer(self):
        """Catch truncation/control encoding, incomplete rows and lost field diagnostic pointer."""
        fields=g.validate_fields(field_document());alpha=fields[2]
        self.assertEqual(g.encode_value("",alpha),b'  ')
        for value in ("ABC","é","A\n","\t",b'A'):
            self.refuses("bad_value",g.encode_value,value,alpha)
        self.refuses("missing_field",g.encode_record,{"N":"1","S":"0"},fields)
        self.refuses("unknown_field",g.encode_record,{"N":"1","S":"0","X":"A","Y":"x"},fields)
        with self.assertRaises(g.AdmissionError) as caught:g.encode_record({"N":"1.01","S":"0","X":"A"},fields)
        self.assertEqual((caught.exception.code,caught.exception.pointer),("bad_value","/N"))
