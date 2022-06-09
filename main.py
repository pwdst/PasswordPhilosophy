from dataclasses import dataclass
import re
from typing import List, Optional


def _get_exercise_lines() -> List[str]:
    # https://docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files
    with open("exercise_part_one_input.txt", 'r') as f:
        read_data = f.read()

    file_lines = read_data.split("\n")

    return file_lines


@dataclass(frozen=True)
class PasswordValidationEntry:
    min_count: int
    max_count: int
    match_character: str
    password_string: str


class PasswordProcessor:
    def __init__(self):
        self.compiled_regex = re.compile(self.INPUT_STRING_PATTERN)

    INPUT_STRING_PATTERN = r'^(?P<min_count>\d+)\-(?P<max_count>[1-9]+) (?P<match_character>[A-Za-z]): (?P<password_string>\w+)$'

    def _try_parse_password_entry(self, entry: str) -> (bool, Optional[PasswordValidationEntry]):
        regex_match = self.compiled_regex.match(entry)

        if regex_match is None:
            return False, None

        # The Regex pattern tells us that the min and max count groups should be valid integers
        password_validation_entry = PasswordValidationEntry(min_count=int(regex_match.group('min_count')),
                                                            max_count=int(regex_match.group('max_count')),
                                                            match_character=regex_match.group('match_character'),
                                                            password_string=regex_match.group('password_string'))

        if password_validation_entry.max_count < password_validation_entry.min_count:
            return False, None

        return True, password_validation_entry

    @staticmethod
    def _validate_password_entry(password_validation_entry: PasswordValidationEntry) -> bool:
        character_count = password_validation_entry.password_string.count(password_validation_entry.match_character)

        if character_count < password_validation_entry.min_count:
            return False

        if character_count > password_validation_entry.max_count:
            return False

        return True


if __name__ == '__main__':
    exercise_lines = _get_exercise_lines()

    password_processor = PasswordProcessor()

    for exercise_line in exercise_lines:
        print(exercise_line)
        (successfully_parsed, password_validation_entry) = password_processor._try_parse_password_entry(exercise_line)
        print(successfully_parsed)
        print(password_validation_entry)
