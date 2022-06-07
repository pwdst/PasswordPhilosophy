from main import PasswordProcessor

import pytest


class TestTryParsePasswordEntry:
    @classmethod
    def setup_class(cls):
        cls.password_processor = PasswordProcessor()

    @pytest.mark.parametrize("entry,expected_min_count,expected_max_count,expected_character,expected_password_string",
                             [("1-3 a: abcde", 1, 3, "a", "abcde"),
                              ("1-3 b: cdefg", 1, 3, "b", "cdefg"),
                              ("2-9 c: ccccccccc", 2, 9, "c", "ccccccccc")])
    def test_try_parse_password_entry_succeeds_valid_input(self, entry: str, expected_min_count: int, expected_max_count: int,
                                                           expected_character: str, expected_password_string: str):
        (successfully_parsed, password_validation_entry) = self.password_processor._try_parse_password_entry(entry)

        assert successfully_parsed is True
        assert password_validation_entry is not None
        assert expected_character == password_validation_entry.match_character
        assert expected_min_count == password_validation_entry.min_count
        assert expected_max_count == password_validation_entry.max_count
        assert expected_password_string == password_validation_entry.password_string

    @pytest.mark.parametrize("entry",
                             ["1 -3 a: abcde", "1- 3 b: cdefg", "2-9 c : ccccccccc",
                              "13 a: abcde", "1--3 b: cdefg", "2-9 c:: ccccccccc",
                              "1~3 a: abcde", "-1-3 b: cdefg", "2-9 c= ccccccccc"]) 
    def test_try_parse_password_entry_fails_invalid_input(self, entry: str):
        (successfully_parsed, password_validation_entry) = self.password_processor._try_parse_password_entry(entry)

        assert successfully_parsed is False
        assert password_validation_entry is None
