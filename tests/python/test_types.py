import pickle
from datetime import datetime, timedelta, timezone

import pytest

import openiec61850 as iec
from openiec61850 import FC, ObjectReference
from openiec61850._values import TypeNeeded, decode, encode, spec_from_tagged


def roundtrip(v, spec=None):
    t = encode(v, spec)
    return decode(iec._core._roundtrip(t), spec)


class TestObjectReference:
    def test_parse_and_parts(self):
        r = ObjectReference("IED1LD0/MMXU1.PhV.phsA.cVal.mag.f[MX]")
        assert r.ld == "IED1LD0"
        assert r.ln == "MMXU1"
        assert r.fc is FC.MX
        assert [str(p) for p in r.path] == ["PhV", "phsA", "cVal", "mag", "f"]
        assert r.leaf == ("f", None)
        assert r.ln_parts == ("", "MMXU", "1")
        assert str(r) == "IED1LD0/MMXU1.PhV.phsA.cVal.mag.f[MX]"
        assert r.text == "IED1LD0/MMXU1.PhV.phsA.cVal.mag.f"

    def test_equality_with_strings_and_hash(self):
        r = ObjectReference("IED1LD0/LLN0.Mod[ST]")
        assert r == "IED1LD0/LLN0.Mod[ST]"
        assert r != ObjectReference("IED1LD0/LLN0.Mod")
        assert {r: 1}["IED1LD0/LLN0.Mod[ST]"] == 1
        assert sorted([ObjectReference("A/LLN0.b"), ObjectReference("A/LLN0.a")])[0] == "A/LLN0.a"
        assert pickle.loads(pickle.dumps(r)) == r

    def test_navigation(self):
        r = ObjectReference("IED1LD0/MMXU1.TotW", FC.MX)
        child = r / "mag" / "f"
        assert child == "IED1LD0/MMXU1.TotW.mag.f[MX]"
        assert child.parent.parent == r
        assert r.child("arr", 3) == "IED1LD0/MMXU1.TotW.arr(3)[MX]"
        assert (r / "arr(2)").leaf == ("arr", 2)
        assert child.is_within("IED1LD0/MMXU1")
        assert child.is_within(r.with_fc(None))
        assert not r.is_within(child)
        assert ObjectReference("IED1LD0") / "LLN0" == "IED1LD0/LLN0"
        assert ObjectReference("IED1LD0/LLN0").parent == "IED1LD0"
        assert r.with_fc(FC.CF).fc is FC.CF

    def test_make_and_association_specific(self):
        assert ObjectReference.make("LD", "LLN0", ["Mod", "stVal"], "ST") == "LD/LLN0.Mod.stVal[ST]"
        aa = ObjectReference.association_specific("tmp")
        assert aa.is_association_specific
        assert str(aa) == "@tmp"

    def test_mms_mapping(self):
        r = ObjectReference("IED1LD0/MMXU1.TotW.mag.f[MX]")
        assert r.to_mms() == "IED1LD0/MMXU1$MX$TotW$mag$f"
        assert ObjectReference.from_mms("IED1LD0/MMXU1$MX$TotW$mag$f") == r
        ds = ObjectReference("IED1LD0/LLN0.DS1")
        assert ds.to_mms_data_set() == "IED1LD0/LLN0$DS1"
        assert ObjectReference.from_mms_data_set("@x") == "@x"
        scope, domain, item, alt = r.to_mms_variable()
        assert (domain, item, alt) == ("IED1LD0", "MMXU1$MX$TotW$mag$f", b"")

    @pytest.mark.parametrize("text", ["", "1LD/LLN0", "LD/LLN0.", "LD/LLN0.x[ZZ]", "LD/LLN0.a(01)"])
    def test_invalid(self, text):
        with pytest.raises(iec.InvalidReference) as e:
            ObjectReference(text)
        assert isinstance(e.value, ValueError)

    def test_strict_ln_names(self):
        with pytest.raises(iec.InvalidReference):
            ObjectReference("LD/mything.x")
        assert ObjectReference("LD/mything.x", strict_ln_names=False).ln == "mything"


class TestValues:
    def test_quality(self):
        q = iec.Quality(iec.Validity.QUESTIONABLE, old_data=True, source=iec.Source.SUBSTITUTED)
        assert str(q) == "questionable|oldData|substituted"
        assert q.old_data and not q.test and q.source is iec.Source.SUBSTITUTED
        assert iec.Quality.from_bitstring(q.to_bitstring()) == q
        assert iec.Quality.from_raw(2).validity is iec.Validity.INVALID
        assert iec.Quality.from_raw(2).to_bitstring() == iec.BitString("0100000000000")
        assert q.replace(old_data=False) == iec.Quality(iec.Validity.QUESTIONABLE, source=iec.Source.SUBSTITUTED)
        assert roundtrip(q) == q

    def test_timestamp(self):
        when = datetime(2024, 5, 6, 7, 8, 9, 123456, tzinfo=timezone.utc)
        ts = iec.Timestamp(when, accuracy=iec.TimeAccuracy.T1, clock_not_synchronized=True)
        assert abs(ts.datetime - when) < timedelta(microseconds=1)
        assert ts.accuracy == 10 and ts.clock_not_synchronized and not ts.clock_failure
        assert ts.accuracy_seconds == 2.0**-10
        back = roundtrip(ts)
        assert back == ts and isinstance(back, iec.Timestamp)
        assert iec.Timestamp.from_raw(1, 1 << 23).nanoseconds == 1_500_000_000
        with pytest.raises(ValueError):
            iec.Timestamp(datetime(2024, 1, 1))
        assert roundtrip(when) == iec.Timestamp(when)  # a plain datetime is a utc-time

    def test_entry_time_and_id(self):
        when = datetime(2020, 1, 2, 3, 4, 5, 6000, tzinfo=timezone.utc)
        et = iec.EntryTime.from_datetime(when)
        assert et.datetime == when
        assert roundtrip(et) == et
        eid = iec.EntryID("0000000000000102")
        assert bytes(eid) == b"\0\0\0\0\0\0\x01\x02" and not eid.is_zero and iec.EntryID().is_zero
        assert str(eid) == "0000000000000102"
        assert decode(encode(eid), None) == bytes(eid)
        with pytest.raises(ValueError):
            iec.EntryID(b"123")

    def test_bit_strings_and_enums(self):
        b = iec.BitString("0110")
        assert len(b) == 4 and b[1] and not b[0] and b.to_int() == 0b0110
        assert iec.BitString.from_int(6, 4) == b
        assert roundtrip(b) == b
        assert iec.DbPos.OFF.to_bitstring() == iec.BitString("01")
        assert iec.DbPos.from_bitstring(iec.BitString("10")) is iec.DbPos.ON
        trg = iec.TrgOps.DATA_CHANGE | iec.TrgOps.GENERAL_INTERROGATION
        assert iec.TrgOps.from_bitstring(trg.to_bitstring()) == trg
        assert len((iec.OptFlds.SEQUENCE_NUMBER).to_bitstring()) == 10

    def test_scalars_need_types(self):
        with pytest.raises(TypeNeeded):
            encode(5)
        with pytest.raises(TypeNeeded):
            encode("text")
        assert encode(iec.Int32(5)) == (5, 5)
        assert encode(iec.UInt8(5)) == (6, 5)
        assert encode(iec.Float64(1.5)) == (7, 1.5, True)
        assert encode(iec.VisibleString("a")) == (10, "a")
        assert encode(iec.UnicodeString("ã")) == (16, "ã")
        assert encode(b"\x01") == (9, b"\x01")
        assert encode(True) == (3, True)
        assert encode(iec.CtlModel.STATUS_ONLY) == (5, 0)
        with pytest.raises(OverflowError):
            iec.Int8(200)
        with pytest.raises(OverflowError):
            iec.UInt16(-1)

    def test_structures_follow_a_spec(self):
        value = iec.Struct([iec.Float32(1.5), iec.Quality(), iec.Timestamp.from_raw(5, 0)])
        spec = spec_from_tagged(encode(value))
        back = roundtrip([2.5, iec.Quality(iec.Validity.INVALID), datetime(2024, 1, 1, tzinfo=timezone.utc)], spec)
        assert isinstance(back, iec.Struct) and back[0] == 2.5
        assert back[1].validity is iec.Validity.INVALID
        with pytest.raises(ValueError):
            encode([1.0], spec)
        with pytest.raises(OverflowError):
            encode(300, spec_from_tagged((5, 0)) ._replace(size=8))
        arr = iec.Array([iec.Int16(1), iec.Int16(2)])
        assert roundtrip(arr) == [1, 2]
        assert roundtrip(iec.ObjectIdentifier("1.0.9506")) == (1, 0, 9506)

    def test_strings_survive_any_octets(self):
        t = (10, "caf\udce9")  # surrogate-escaped 0xE9
        assert iec._core._roundtrip(t) == t
        assert iec._core._encode(t) == b"\x8a\x04caf\xe9"

    def test_struct_names(self):
        s = iec.Struct({"mag": 1.0, "q": iec.Quality()})
        assert s["mag"] == 1.0 and s[1] == iec.Quality() and s.names == ("mag", "q")
        assert s.get("zz") is None
        assert s == [1.0, iec.Quality()]
