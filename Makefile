.PHONY: clean dist test

clean:
	rm -rf __pycache__ build dist

dist: clean
	python setup.py register
	python setup.py bdist_wheel upload
	python setup.py bdist_egg upload
	python setup.py sdist upload

test:
	py.test --verbose --cov-report term --cov=netstoragekit tests.py
