build:
	mkdir -p out && javac -d out src/main/java/jarscan/*.java src/test/java/jarscan/*.java

test: build
	java -cp out jarscan.JarScanTest

sample: build
	mkdir -p docs site
	java -cp out jarscan.Main examples > docs/sample-output.txt; true
	java -cp out jarscan.Main examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "jar-scan" "Finds known-vulnerable libraries inside JAR, WAR and EAR files, including shaded and nested ones. Java." "Synthetic archives that contain only entry names, no real library code."
