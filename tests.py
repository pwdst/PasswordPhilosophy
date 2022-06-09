from main import PasswordProcessor, PasswordValidationEntry

import pytest


class TestPasswordProcessor:
    @classmethod
    def setup_class(cls):
        cls.password_processor = PasswordProcessor()

    @pytest.mark.parametrize("entry",
                             ["1-3 a: abcde", "2-9 c: ccccccccc", "3-7 e: efghefghefgh"])
    def test_check_password_entry_valid_entry_returns_true(self, entry: str):
        check_password_result = self.password_processor.check_password_entry(entry)

        assert check_password_result is True

    @pytest.mark.parametrize("entry",
                             ["1-3 b: cdefg", "2-8 c: ccccccccc", "3-7 e: efghefgh"])
    def test_check_password_entry_invalid_entry_returns_false(self, entry: str):
        check_password_result = self.password_processor.check_password_entry(entry)

        assert check_password_result is False

    @pytest.mark.parametrize("entry,expected_min_count,expected_max_count,expected_character,expected_password_string",
                             [("1-3 a: abcde", 1, 3, "a", "abcde"),
                              ("1-3 b: cdefg", 1, 3, "b", "cdefg"),
                              ("2-9 c: ccccccccc", 2, 9, "c", "ccccccccc"),
                              ("1-10 a: abcde", 1, 10, "a", "abcde"),
                              ("1-40 b: cdefg", 1, 40, "b", "cdefg"),
                              ("2-100 c: ccccccccc", 2, 100, "c", "ccccccccc")
                              ])
    def test_try_parse_password_entry_succeeds_valid_input(self, entry: str, expected_min_count: int,
                                                           expected_max_count: int,
                                                           expected_character: str, expected_password_string: str):
        (successfully_parsed, password_validation_entry) = self.password_processor._try_parse_password_entry(entry)

        assert successfully_parsed is True
        assert password_validation_entry is not None
        assert expected_character == password_validation_entry.match_character
        assert expected_min_count == password_validation_entry.min_count
        assert expected_max_count == password_validation_entry.max_count
        assert expected_password_string == password_validation_entry.password_string

    @pytest.mark.parametrize("entry,expected_min_count,expected_max_count,expected_character,expected_password_string",
                             [("3-3 a: abcde", 3, 3, "a", "abcde"),
                              ("3-3 b: cdefg", 3, 3, "b", "cdefg"),
                              ("9-9 c: ccccccccc", 9, 9, "c", "ccccccccc")])
    def test_try_parse_password_entry_succeeds_minimum_count_equal_maximum(self, entry: str,
                                                                           expected_min_count: int,
                                                                           expected_max_count: int,
                                                                           expected_character: str,
                                                                           expected_password_string: str):
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
                              "1~3 a: abcde", "-1-3 b: cdefg", "2-9 c= ccccccccc",
                              "1-3 ab: abcde"])
    def test_try_parse_password_entry_fails_invalid_input(self, entry: str):
        (successfully_parsed, password_validation_entry) = self.password_processor._try_parse_password_entry(entry)

        assert successfully_parsed is False
        assert password_validation_entry is None

    # Passwords cannot be validated when the minimum number of occurrences of a character is greater than the maximum
    @pytest.mark.parametrize("entry",
                             ["3-1 a: abcde", "4-3 b: cdefg", "999999-9 c : ccccccccc"])
    def test_try_parse_password_entry_fails_impossible_bounds(self, entry: str):
        (successfully_parsed, password_validation_entry) = self.password_processor._try_parse_password_entry(entry)

        assert successfully_parsed is False
        assert password_validation_entry is None

    @pytest.mark.parametrize("match_character,min_count,max_count,password_string",
                             [("a", 1, 3, "abcdeabcde"), ("d", 1, 3, "cdefgcdefg"), ("c", 2, 9, "aaabbbccc")])
    def test_character_count_between_max_min_returns_true(self, match_character: str, min_count: int, max_count: int,
                                                          password_string: str):
        result = self._prepare_run_validate_password_entry(match_character, min_count, max_count, password_string)

        assert result is True

    @pytest.mark.parametrize("match_character,min_count,max_count,password_string",
                             [("a", 1, 3, "abcde"), ("e", 1, 3, "cdefg"), ("c", 2, 9, "aabbccddee")])
    def test_character_count_equal_min_returns_true(self, match_character: str, min_count: int, max_count: int,
                                                    password_string: str):
        result = self._prepare_run_validate_password_entry(match_character, min_count, max_count, password_string)

        assert result is True

    @pytest.mark.parametrize("match_character,min_count,max_count,password_string",
                             [("a", 1, 2, "abcdeabcde"), ("f", 1, 2, "cdefgcdefg"), ("c", 2, 9, "ccccccccc")])
    def test_character_count_equal_max_returns_true(self, match_character: str, min_count: int, max_count: int,
                                                    password_string: str):
        result = self._prepare_run_validate_password_entry(match_character, min_count, max_count, password_string)

        assert result is True

    @pytest.mark.parametrize("match_character,min_count,max_count,password_string",
                             [("x", 1, 3, "abcde"), ("b", 1, 3, "cdefg"), ("z", 2, 9, "ccccccccc")])
    def test_character_does_not_occur_returns_false(self, match_character: str, min_count: int, max_count: int,
                                                    password_string: str):
        result = self._prepare_run_validate_password_entry(match_character, min_count, max_count, password_string)

        assert result is False

    @pytest.mark.parametrize("match_character,min_count,max_count,password_string",
                             [("a", 2, 3, "abcde"), ("d", 2, 3, "cdefg"), ("c", 4, 9, "abcabcabc")])
    def test_character_count_lower_than_min_returns_false(self, match_character: str, min_count: int, max_count: int,
                                                    password_string: str):
        result = self._prepare_run_validate_password_entry(match_character, min_count, max_count, password_string)

        assert result is False

    @pytest.mark.parametrize("match_character,min_count,max_count,password_string",
                             [("c", 2, 8, "ccccccccc"), ("a", 1, 3, "abcabcabcabc"), ("y", 2, 4, "xyzyyyxyz")])
    def test_character_count_higher_than_max_returns_false(self, match_character: str, min_count: int, max_count: int,
                                                    password_string: str):
        result = self._prepare_run_validate_password_entry(match_character, min_count, max_count, password_string)

        assert result is False

    def _prepare_run_validate_password_entry(self, match_character: str, min_count: int, max_count: int,
                                             password_string: str):
        password_validation_entry = PasswordValidationEntry(min_count=min_count, max_count=max_count,
                                                            match_character=match_character,
                                                            password_string=password_string)

        return self.password_processor._validate_password_entry(password_validation_entry)
