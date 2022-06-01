from typing import List


def _get_exercise_lines() -> List[str]:
    # https://docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files
    with open("exercise_part_one_input.txt", 'r') as f:
        read_data = f.read()

    file_lines = read_data.split("\n")

    return file_lines


if __name__ == '__main__':
    exercise_lines = _get_exercise_lines()
