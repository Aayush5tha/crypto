# app.py
def add(a, b):
    return a + b
#print name
def greet(name):
    return f"Hello, {name}!"
# test_app.py
from app import add, greet
def test_add():
    assert add(2, 3) == 5
​
def test_greet():
    assert greet("Alice") == "Hello, Alice!"
# .yml 
name: Basic CI Pipeline

on: [push, pull_request]

jobs:
  test:

    runs-on: ubuntu-latest
    steps:

      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5

        with:
          python-version: '3.10'

      - name: Install dependencies
        run: pip install pytest

      - name: Run tests
        run: pytest
