import unittest

from wordcount import count


class CountTest(unittest.TestCase):
    def test_counts_words_lines_chars(self):
        self.assertEqual(count("hello world\nbye\n"), {"lines": 2, "words": 3, "chars": 16})

    def test_empty(self):
        self.assertEqual(count(""), {"lines": 0, "words": 0, "chars": 0})


if __name__ == "__main__":
    unittest.main()
